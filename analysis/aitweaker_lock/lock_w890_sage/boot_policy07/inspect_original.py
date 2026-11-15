"""Read-only original W890 0603 FIT and AMITSE container structure inventory.

No BIOS candidates, keys, signatures, firmware calls, or hardware operations.
This is a bounded raw-format parser, not a REA native-execution claim.
"""
from pathlib import Path
import hashlib
import json
import lzma
import struct
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
WORK = ROOT / 'analysis/workstation_20261008'
ORIGINAL = WORK / 'W890_SAGE_0603/Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'
ZIP = ROOT / 'Pro-WS-W890E-SAGE-SE-ASUS-0603.zip'
CAP_SHA = 'c7b12934cd0904a9cd4cfca53f656931bd5164e3bc30b99b043c2c2cb39a92d1'
ZIP_SHA = '5bad35967954afb2f10123828e3698c1f36b413b21ce127f15778ed424997df8'
TSE = 'b1da0adf-4f77-4070-a88e-bffe1c60529a'
LZMA_GUID = uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le
SIGNATURES = (b'_FIT_   ', b'__ACBP__', b'__KEYM__', b'__IBBS__', b'__PMSG__', b'__PMDA__', b'BTGC')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bind(path):
    path = Path(path)
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def hits(raw, signature):
    result = []
    at = 0
    while True:
        at = raw.find(signature, at)
        if at < 0:
            return result
        result.append(at)
        at += 1


def u16(raw, off):
    assert 0 <= off <= len(raw) - 2
    return struct.unpack_from('<H', raw, off)[0]


def u32(raw, off):
    assert 0 <= off <= len(raw) - 4
    return struct.unpack_from('<I', raw, off)[0]


def u64(raw, off):
    assert 0 <= off <= len(raw) - 8
    return struct.unpack_from('<Q', raw, off)[0]


def sections(raw):
    out = []
    at = 0
    while at < len(raw):
        assert at + 4 <= len(raw)
        size = int.from_bytes(raw[at:at + 3], 'little')
        head = 4
        if size == 0xffffff:
            size = u32(raw, at + 4)
            head = 8
        assert head <= size <= len(raw) - at
        out.append({'offset': at, 'size': size, 'header': head, 'type': raw[at + 3]})
        end = at + size
        if end == len(raw):
            break
        at = (end + 3) & ~3
        assert at <= len(raw) and not any(raw[end:at])
    return out


def guided(raw):
    assert len(raw) >= 37 and raw[3] == 2 and raw[4:20] == LZMA_GUID
    assert int.from_bytes(raw[:3], 'little') == len(raw)
    assert u16(raw, 20) == 24 and u16(raw, 22) == 1
    expected_size = u64(raw, 29)
    assert 0 < expected_size <= 64 * 1024 * 1024
    result = lzma.decompress(raw[24:], format=lzma.FORMAT_ALONE)
    assert len(result) == expected_size
    return result


def ffs(raw, at):
    assert at + 24 <= len(raw)
    n = int.from_bytes(raw[at + 20:at + 23], 'little')
    assert n != 0xffffff and 24 <= n <= len(raw) - at
    file = raw[at:at + n]
    assert (sum(file[:24]) - file[17] - file[23]) & 255 == 0
    assert not file[19] & 1
    assert (sum(file[24:]) + file[17]) & 255 == 0 if file[19] & 0x40 else file[17] == 0xaa
    return file


def main():
    cap = ORIGINAL.read_bytes()
    assert sha(cap) == CAP_SHA and bind(ZIP)['sha256'] == ZIP_SHA
    with zipfile.ZipFile(ZIP) as package:
        assert package.read(ORIGINAL.name) == cap
    assert len(cap) == 0x4001000 and u32(cap, 16) == 0x1000
    body = cap[0x1000:]
    physical_base = 0x100000000 - len(body)
    assert physical_base == 0xfc000000 and u32(body, 0x10) == 0x0ff0a55a

    def location(physical, size):
        off = physical - physical_base
        assert 0 <= off <= len(body) and 0 <= size <= len(body) - off
        return {'physical': hex(physical), 'spi_offset': hex(off),
                'cap_offset': hex(off + 0x1000), 'bytes': size,
                'sha256': sha(body[off:off + size])}

    fit_address = u64(body, len(body) - 0x40)
    fit_offset = fit_address - physical_base
    assert body[fit_offset:fit_offset + 8] == b'_FIT_   '
    count = int.from_bytes(body[fit_offset + 8:fit_offset + 11], 'little')
    assert 1 <= count <= 4096 and 0xff000000 <= fit_address < 0xffffffc0
    fit = body[fit_offset:fit_offset + count * 16]
    assert len(fit) == count * 16 and fit_address % 16 == 0
    names = {0: 'HEADER', 1: 'MICROCODE', 2: 'STARTUP_ACM', 3: 'DIAGNOSTIC_ACM',
             4: 'PLATFORM_BOOT_POLICY', 7: 'BIOS_STARTUP_MODULE', 10: 'TXT_POLICY',
             11: 'KEY_MANIFEST', 12: 'BOOT_POLICY_MANIFEST'}
    entries = []
    for i in range(count):
        raw = fit[i * 16:(i + 1) * 16]
        typ = raw[14] & 127
        entry = {'index': i, 'type': typ, 'type_name': names.get(typ, 'OTHER'),
                 'raw': raw.hex(), 'address': hex(u64(raw, 0)),
                 'size_field_16B_units': int.from_bytes(raw[8:11], 'little'),
                 'reserved': raw[11], 'version': hex(u16(raw, 12)),
                 'checksum_enabled': bool(raw[14] & 128), 'checksum_byte': raw[15]}
        if i:
            address = u64(raw, 0)
            off = address - physical_base
            assert 0 <= off < len(body)
            if typ == 1:
                total = u32(body, off + 32)
                assert total and total <= len(body) - off
                block = body[off:off + total]
                entry['microcode'] = {**location(address, total), 'header_version': u32(block, 0),
                    'revision': hex(u32(block, 4)), 'date_raw': hex(u32(block, 8)),
                    'cpu_signature': hex(u32(block, 12)), 'loader_revision': u32(block, 20),
                    'data_bytes': u32(block, 28), 'dword_checksum_zero': sum(struct.unpack('<' + 'I' * (total // 4), block)) & 0xffffffff == 0}
            elif typ == 4:
                observed = body[off:off + 0x58]
                assert len(observed) == 0x58 and observed[20:24] == b'BTGC'
                entry['opaque_payload'] = {**location(address, 0x58), 'raw': observed.hex(),
                    'first_u32_raw': u32(observed, 0), 'BTGC_offset': 20,
                    'following_u32_raw': u32(observed, 24),
                    'extent_basis': 'Fixed 0x58-byte observation window; first DWORD also equals 0x58. No public payload schema asserted.',
                    'policy_bits_decoded': False}
            elif typ == 10:
                entry['opaque_address_observation'] = {**location(address, 8), 'raw': body[off:off + 8].hex(),
                    'semantics': 'UNKNOWN: entry version is 0x0100, whereas FIT Rev1.6 section4.12 uses special versions0/1/2. No disabled/enabled conclusion.'}
        entries.append(entry)
    assert [e['type'] for e in entries] == [0, 1, 1, 4, 10]

    volumes_path = BASE / 'release_review/checked_dxe_volumes.json'
    metadata = json.loads(volumes_path.read_text())['volumes']
    om = next(v for v in metadata if v['full_size'] == 0x630000)
    im = next(v for v in metadata if v['full_size'] == 0x1a42000)
    outer_at = 0x1841000
    outer = cap[outer_at:outer_at + om['full_size']]
    assert sha(outer) == om['full_sha256'] and outer[0x28:0x2c] == b'_FVH'
    assert u64(outer, 32) == len(outer)
    carrier = ffs(outer, om['files'][0]['offset'])
    assert sha(carrier) == om['files'][0]['sha256']
    assert str(uuid.UUID(bytes_le=carrier[:16])) == '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
    outer_plain = guided(carrier[24:])
    parts = sections(outer_plain)
    assert [p['type'] for p in parts] == [0x19, 0x17]
    volume_section = parts[1]
    inner = outer_plain[volume_section['offset'] + volume_section['header']:]
    assert len(inner) == im['full_size'] and sha(inner) == im['full_sha256']
    record = next(f for f in im['files'] if f['guid'] == TSE)
    tse_file = ffs(inner, record['offset'])
    assert sha(tse_file) == record['sha256']
    tse_plain = guided(tse_file[24:])
    parts = sections(tse_plain)
    assert [p['type'] for p in parts] == [0x10, 0x15]
    pe = tse_plain[parts[0]['header']:parts[0]['size']]
    profiled_pe = BASE / 'navigation/modules/AMITSE.efi'
    assert pe == profiled_pe.read_bytes()

    inventory_path = WORK / 'W890_SAGE_0603/inventory.json'
    inventory = json.loads(inventory_path.read_text())
    scanned = []
    sections_seen = set()
    section_hits = []
    for module in inventory['modules']:
        for sec in module['sections']:
            if sec['path'] in sections_seen:
                continue
            sections_seen.add(sec['path'])
            path = WORK / sec['path']
            raw = path.read_bytes()
            assert len(raw) == sec['size'] and sha(raw) == sec['sha256'], sec['path']
            scanned.append(bind(path))
            for sig in SIGNATURES:
                found = hits(raw, sig)
                if found:
                    section_hits.append({'module_guid': module['guid'], 'module_name': module.get('name'),
                        'section_type': sec['type'], 'path': str(path.relative_to(ROOT)),
                        'sha256': sha(raw), 'signature': sig.decode(), 'offsets': [hex(x) for x in found],
                        'interpretation': 'Literal occurrence only, not a validated manifest or referenced FIT.'})
    scan_report = {'scope': 'All indexed original module section bodies whose hashes match the existing inventory; no claim that unsupported/compressed opaque components were decoded.',
                   'file_count': len(scanned), 'total_bytes': sum(r['bytes'] for r in scanned),
                   'files': scanned, 'literal_hits': section_hits}
    (HERE / 'indexed_section_scan.json').write_text(json.dumps(scan_report, indent=2) + '\n')
    report = {'status': 'ORIGINAL_STATIC_BOOT_POLICY_IDENTIFICATION_WITH_UNRESOLVED_COVERAGE',
        'method': 'Bounded direct binary structure parsing and original LZMA extraction, cross-checked against original UEFIExtract inventory. No new REA native execution is asserted.',
        'original_capsule': bind(ORIGINAL), 'original_zip': bind(ZIP),
        'mapping': {'capsule_header_bytes': 4096, 'raw_image_bytes': len(body),
                    'image_physical_base': hex(physical_base), 'fit_pointer_physical': '0xffffffc0',
                    'fit_pointer_cap_offset': hex(len(cap) - 0x40)},
        'fit': {**location(fit_address, len(fit)), 'count': count, 'entries': entries,
                'header_checksum_enabled': bool(fit[14] & 128),
                'header_checksum_verdict': 'NOT_REQUIRED_BY_HEADER_C_V_FLAG',
                'raw_fit_literal_offsets': [hex(x) for x in hits(body, b'_FIT_   ')]},
        'raw_signature_search': {sig.decode(): [hex(x) for x in hits(body, sig)] for sig in SIGNATURES},
        'indexed_original_sections': {'report': bind(HERE / 'indexed_section_scan.json'),
                                      'files': len(scanned), 'literal_hit_records': len(section_hits)},
        'amitse_container': {'outer_fv_guid': '4f1c52d3-d824-4d2a-a2f0-ec40c23c5916',
            'outer': location(physical_base + outer_at - 0x1000, len(outer)),
            'outer_carrier_guid': '9e21fd93-9c72-4c15-8c4b-e77f1db2d792',
            'outer_carrier_relative_offset': om['files'][0]['offset'],
            'outer_carrier_bytes': len(carrier), 'outer_carrier_sha256': sha(carrier),
            'outer_lzma_uncompressed_bytes': len(outer_plain),
            'inner_fv_guid': '5c60f367-a505-419a-859e-2a4ff6ca6fe5',
            'inner_fv_bytes': len(inner), 'inner_fv_sha256': sha(inner),
            'ffs_guid': TSE, 'ffs_inner_relative_offset': record['offset'],
            'ffs_bytes': len(tse_file), 'ffs_sha256': sha(tse_file),
            'pe_bytes': len(pe), 'pe_sha256': sha(pe),
            'raw_flash_address_of_pe': None,
            'raw_flash_address_reason': 'AMITSE PE is inside its own LZMA section inside a compressed inner FV. Inner logical offset is not a raw physical SPI address.'},
        'measured_range_assessment': {'classic_type2_acm_references': 0,
            'classic_type11_km_references': 0, 'classic_type12_bpm_references': 0,
            'validated_ibb_segment_ranges': [], 'validated_ibb_segment_ranges_complete': False,
            'outer_dxe_fv_in_measured_range': None, 'amitse_pe_in_measured_range': None,
            'reason': 'No applicable validated IBB/OBB range manifest was decoded. The present OEM Type04 policy is not assigned a guessed legacy BPM layout. Absence of classic FIT records/signatures does not establish absence of modern protection.'},
        'unknown_runtime_state': ['Actual reset-time FIT selection and pre-reset service-processor changes',
            'CPU/platform fuses, CBnT/Boot Guard enforcement and key provisioning',
            'PFR or other controller enforcement and recovery policy',
            'Runtime measured/verified-boot registers and event log',
            'Vendor policy parser semantics and all IBB/OBB/DXE measurement ranges'],
        'sources': [bind(volumes_path), bind(inventory_path), bind(profiled_pe), bind(Path(__file__)),
                    bind(WORK / 'W890_SAGE_0603/uefiextract.log')],
        'original_inputs_unchanged': sha(ORIGINAL.read_bytes()) == CAP_SHA and bind(ZIP)['sha256'] == ZIP_SHA,
        'flash_ready': False, 'hardware_operations': False,
        'limits': ['This downloaded update image is not a full live SPI/fuse/status dump.',
            'No signature is bypassed, created, or changed; no key is generated or exported.',
            'Literal signatures in PE code/data do not prove presence of active KM/BPM/ACM objects.',
            'The OEM capsule signature and CPU/controller boot authentication are separate layers. This report does not relax either.']}
    (HERE / 'original_boot_policy.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'fit_types': [e['type'] for e in entries],
                      'indexed_section_count': len(scanned), 'section_hit_records': len(section_hits),
                      'outer_dxe_physical': report['amitse_container']['outer']['physical'],
                      'report': bind(HERE / 'original_boot_policy.json')}, indent=2))


if __name__ == '__main__':
    main()
