"""Offline CAP descriptor evidence only: no network, device, or firmware access.

Reads the already downloaded, SHA-bound ASUS release capsule. The release
descriptor is a template/reference, never evidence of the live board's grants.
"""
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[2]
CAP = CASE.parent / 'official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
EXPECTED = 'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'


def decode_region(raw):
    # Modern Intel descriptor fields use 15-bit units of 4 KiB.
    base = (raw & 0x7fff) << 12
    limit = (((raw >> 16) & 0x7fff) << 12) | 0xfff
    return {'base': base, 'limit': limit, 'enabled': base <= limit,
            'length': limit - base + 1 if base <= limit else 0}


def main():
    # Two meaningful boundary assertions: 64-MiB addressing must not be
    # truncated to the obsolete 13-bit region layout; disabled slots stay so.
    assert decode_region(0x3fff3000) == {
        'base': 0x3000000, 'limit': 0x3ffffff,
        'enabled': True, 'length': 0x1000000}
    assert not decode_region(0x00007fff)['enabled']
    cap = CAP.read_bytes()
    assert hashlib.sha256(cap).hexdigest() == EXPECTED
    assert len(cap) == 4096 + 64 * 1024 * 1024
    body = cap[4096:]
    u32 = lambda offset: struct.unpack_from('<I', body, offset)[0]
    assert u32(0x10) == 0x0ff0a55a
    map0, map1 = u32(0x14), u32(0x18)
    fcba = (map0 & 255) << 4
    frba = ((map0 >> 16) & 255) << 4
    fmba = (map1 & 255) << 4
    components = ((map0 >> 8) & 3) + 1
    assert components == 1
    density_code = u32(fcba) & 15
    assert density_code == 7
    names = {0: 'Descriptor', 1: 'BIOS', 2: 'ME/CSME', 3: 'GbE',
             4: 'Platform Data', 9: 'Slot 9: semantics not established for live device'}
    regions = []
    master = u32(fmba)
    read_mask = ((master >> 8) & 0xfff) | ((master & 15) << 12)
    write_mask = ((master >> 20) & 0xfff) | (((master >> 4) & 15) << 12)
    for index in range(16):
        raw = u32(frba + 4 * index)
        region = decode_region(raw)
        if not region['enabled']:
            continue
        assert region['limit'] < len(body)
        payload = body[region['base']:region['limit'] + 1]
        regions.append({'slot': index, 'name': names.get(index, 'Unknown'),
                        'raw': f'0x{raw:08X}', **region,
                        'base_hex': f"0x{region['base']:08X}",
                        'limit_hex': f"0x{region['limit']:08X}",
                        'release_host_read_grant': bool(read_mask & (1 << index)),
                        'release_host_write_grant': bool(write_mask & (1 << index)),
                        'release_all_ff': payload.count(255) == len(payload)})
    report = {
        'status': 'OFFLINE_RELEASE_REFERENCE_ONLY',
        'hardware_access': False, 'live_readability_confirmed': False,
        'capsule': str(CAP), 'capsule_sha256': EXPECTED,
        'capsule_header_bytes': 4096, 'release_body_bytes': len(body),
        'descriptor_sha256': hashlib.sha256(body[:4096]).hexdigest(),
        'reference_component_count': components,
        'reference_density_code': density_code,
        'reference_component_bytes': 1 << (19 + density_code),
        'flmap0': f'0x{map0:08X}', 'flmap1': f'0x{map1:08X}',
        'flcomp': f'0x{u32(fcba):08X}', 'flmstr1': f'0x{master:08X}',
        'release_host_read_mask': f'0x{read_mask:04X}',
        'release_host_write_mask': f'0x{write_mask:04X}',
        'enabled_reference_slots': regions,
        'limits': [
            'These permissions, chip count and density come from the public CAP, not this machine.',
            'Slot 9 is retained as a raw descriptor observation; its live meaning and accessibility are unknown.',
            'Release all-FF padding must never be substituted for inaccessible live bytes.',
            'BIOS occupies only 16 MiB at FLA 0x03000000; the 64 MiB body is not a CPU physical mapping.',
            'No backup, physical read or recovery validation is produced by this script.'
        ]
    }
    out = HERE / 'host_backup_feasibility.cap_reference.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({'status': report['status'], 'out': str(out),
                      'reference_body_bytes': len(body),
                      'bios_bytes': regions[1]['length'],
                      'hardware_access': False}, indent=2))


if __name__ == '__main__':
    main()
