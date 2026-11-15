"""Decode a CRC- and hash-checked register log. Never access target hardware."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import zlib

HERE = Path(__file__).resolve().parent
OFFSETS = dict(zip(
    ['BFPR', 'HSFSTS_HSFC', 'FRAP', *[f'FREG{i}' for i in range(6)],
     *[f'PR{i}' for i in range(5)]],
    [0, 4, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x84, 0x88, 0x8c, 0x90, 0x94]))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def bound(p):
    return {'path': str(p.resolve()), 'sha256': sha(p), 'bytes': p.stat().st_size}

def decode(folder):
    folder = folder.resolve()
    manifest_path = folder / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    raw = (folder / 'hardware-log.txt').read_bytes()
    assert len(raw) == manifest['bytes']
    assert f'{zlib.crc32(raw):08X}' == manifest['crc32']
    assert hashlib.sha256(raw).hexdigest() == manifest['sha256']
    for name, digest in manifest['files'].items():
        item = (folder / name).resolve()
        assert item.is_relative_to(folder) and sha(item) == digest, name
    log = raw.decode('ascii')
    assert log.startswith('SPI-INVENTORY-') and log.endswith('PROBE_COMPLETE\r\n')
    assert 'IDENTITY_GATE=Pro WS W790E-SAGE SE; BIOS=1904' in log
    observations = []
    for match in re.finditer(r'^(?:(ROOT|CPU|CPU_IO2) )?([A-Z0-9_]+) OFFSET=0x([0-9A-Fa-f]+) (RAW|STATUS)=0x([0-9A-Fa-f]+)', log, re.M):
        method, name, offset, kind, value = match.groups()
        assert name in OFFSETS and int(offset, 16) == OFFSETS[name]
        observations.append({'method': method or 'PCI_IO', 'register': name,
                             'offset': int(offset, 16), kind.lower(): int(value, 16)})
    decoded = {}
    for method in dict.fromkeys(x['method'] for x in observations):
        values = {x['register']: x['raw'] for x in observations
                  if x['method'] == method and 'raw' in x}
        if set(values) != set(OFFSETS) or any(x == 0xffffffff for x in values.values()):
            continue
        hsfs = values['HSFSTS_HSFC']
        frap = values['FRAP']
        protections = []
        for i in range(5):
            value = values[f'PR{i}']
            lo, hi = (value & 0x7fff) << 12, (((value >> 16) & 0x7fff) << 12) | 0xfff
            protections.append({'index': i, 'base': lo, 'limit': hi, 'valid_range': lo <= hi,
                                'read_protect': bool(value & 0x8000), 'write_protect': bool(value & 0x80000000)})
        regions = []
        for i in range(6):
            value = values[f'FREG{i}']
            lo, hi = (value & 0x7fff) << 12, (((value >> 16) & 0x7fff) << 12) | 0xfff
            regions.append({'index': i, 'base': lo, 'limit': hi, 'enabled': lo <= hi,
                            'BRRA_bit_set': bool(frap & (1 << i)),
                            'BRWA_bit_set': bool(frap & (1 << (8 + i))),
                            'overlapping_read_protect_ranges': [p['index'] for p in protections
                                if lo <= hi and p['valid_range'] and p['read_protect']
                                and lo <= p['limit'] and hi >= p['base']]})
        decoded[method] = {'raw_registers': values, 'regions_0_to_5': regions,
                           'protected_ranges': protections,
                           'descriptor_valid': bool(hsfs & (1 << 14)),
                           'flash_configuration_locked': bool(hsfs & (1 << 15)),
                           'cycle_in_progress': bool(hsfs & (1 << 5)),
                           'BRRA': frap & 255, 'BRWA': (frap >> 8) & 255,
                           'BMRAG': (frap >> 16) & 255, 'BMWAG': (frap >> 24) & 255}
    reference = HERE / 'spi_inventory_candidate03/source/reference_documents/spibar0.xml'
    return {'status': 'REGISTER_VALUES_DECODED' if decoded else 'NO_COMPLETE_MMIO_REGISTER_SET',
            'scope': 'Offline interpretation of collected register observations; no flash contents were read.',
            'log': bound(folder / 'hardware-log.txt'), 'manifest': bound(manifest_path),
            'qr': {'pages': manifest['pages'], 'bytes': len(raw), 'crc32': manifest['crc32'],
                   'all_manifest_file_hashes_verified': True},
            'register_definitions': bound(reference), 'observations': observations, 'decoded': decoded,
            'metadata': [line for line in log.splitlines() if line.startswith((
                'PCI_VID_DID=', 'SPI_REV_CLASS=', 'PCI_COMMAND_STATUS=', 'SPIBAR0_RAW=',
                'BIOS_CNTL=', 'UEFI_MAP_', 'CPU_IO2=', 'ROOT_GATE=', 'ROOT_FALLBACK=',
                'CPU_GATE=', 'CPU_FALLBACK=', 'CPU_IO2_GATE=', 'CPU_IO2_FALLBACK=', 'INVENTORY_STATUS='))],
            'limits': ['EFI_UNSUPPORTED means an interface operation is unsupported, not that flash reads are denied.',
                       'A memory-map descriptor describes an address range; it does not prove access permission.',
                       'Only FREG0 through FREG5 and the listed PRs are interpreted. Extension slot9 is not inferred.',
                       'No JEDEC/SFDP, flash READ cycle, density measurement, full backup or recovery test is claimed.',
                       'Register permissions are observations at acquisition time, not a successful read of the flash.']}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('folder', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = decode(args.folder)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'output': str(args.output), 'sha256': sha(args.output)}))
