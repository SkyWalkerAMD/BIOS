"""Record primary local sources and verify the vendor variable name/GUID bytes."""
from pathlib import Path
import hashlib
import json
import struct
import uuid

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
BASE = 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/'


def fact(path):
    data = path.read_bytes()
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest())


def at_rva(pe, rva, length):
    assert pe[:2] == b'MZ'
    hdr = struct.unpack_from('<I', pe, 0x3c)[0]
    assert pe[hdr:hdr+4] == b'PE\0\0'
    count = struct.unpack_from('<H', pe, hdr+6)[0]
    opt_size = struct.unpack_from('<H', pe, hdr+20)[0]
    section = hdr + 24 + opt_size
    for i in range(count):
        off = section + i*40
        va, raw_size, ptr = struct.unpack_from('<III', pe, off+12)
        if va <= rva and rva + length <= va + raw_size:
            result = pe[ptr+rva-va:ptr+rva-va+length]
            assert len(result) == length
            return result
    raise AssertionError(f'RVA {rva:#x} not backed by raw bytes')


def main():
    references = []
    specs = [
        (OUT/'reference/VariableWrite.h', 'Protocol/VariableWrite.h',
         'GUID and required NULL interface marker; presence is tested by status.'),
        (OUT/'reference/HiiPackageList.h', 'Protocol/HiiPackageList.h',
         'Informational related GUID only; not present in live R2/P6 DEPEX.'),
        (OUT/'reference/PiDependency.h', 'Pi/PiDependency.h',
         'PI DEPEX opcode PUSH=2, AND=3, END=8.'),
        (ROOT/'analysis/hero_ipmi_init_b1/source/reference/PciEnumerationComplete.h',
         'Protocol/PciEnumerationComplete.h', 'PCI enumeration completion GUID.'),
        (ROOT/'analysis/hero_ipmi_setup_m1a/source/reference/HiiDatabase.h',
         'Protocol/HiiDatabase.h', 'HII database GUID.'),
        (ROOT/'analysis/hero_ipmi_setup_m1a/source/reference/HiiString.h',
         'Protocol/HiiString.h', 'HII string GUID, the actual second P6 operand.'),
    ]
    for path, suffix, use in specs:
        references.append(dict(**fact(path), url=BASE+suffix, use=use))
    origin_path = ROOT/'analysis/hero_inventory_publish_i3a_20261108/reference/origin.json'
    origin = json.loads(origin_path.read_text(encoding='utf-8'))
    snp = next(item for item in origin if item['name'] == 'SnpDxe')
    path = ROOT / snp['source']
    pe = path.read_bytes()
    assert hashlib.sha256(pe).hexdigest() == snp['sha256'] == 'b186518817547c71ab0818f1bc0872c2d21e7f78ec42028498fba4247a263474'
    assert at_rva(pe, 0x50a0, 32) == 'NetworkStackVar\0'.encode('utf-16-le')
    assert str(uuid.UUID(bytes_le=at_rva(pe, 0x4b90, 16))) == 'd1405d16-7afc-4695-bb12-41459d3695a2'
    assert at_rva(pe, 0x60b, 3) == b'\xff\x50\x48'  # call RT.GetVariable
    assert at_rva(pe, 0x5e0, 8) == bytes.fromhex('49c7431008000000')
    assert at_rva(pe, 0x613, 6) == bytes.fromhex('384424607462')
    report = dict(
        scope='Offline primary-source provenance; no external retrieval by this script.',
        official_headers=references,
        vendor_variable_evidence=dict(
            origin_manifest=fact(origin_path), pe=fact(path),
            disassembly=fact(ROOT/'analysis/hero_inventory_publish_i3a_20261108/reference/SnpDxe-entry.asm'),
            name='NetworkStackVar', guid='d1405d16-7afc-4695-bb12-41459d3695a2',
            name_rva='0x50a0', guid_rva='0x4b90', expected_buffer_bytes=8,
            instructions={hex(rva):at_rva(pe,rva,n).hex() for rva,n in [(0x5e0,8),(0x60b,3),(0x613,6)]},
            established='The stock SnpDxe asks GetVariable for 8 bytes and takes its unsupported exit if the call fails or byte 0 is zero.',
            boundary='Vendor binary evidence, not a public standardized variable schema; other bytes are exported raw and not interpreted. This probe never modifies this variable.'),
        abi_header=fact(ROOT/'analysis/hero_inventory_publish_i3a_20261108/source/efi_min.h'),
        source_files=[fact(OUT/name) for name in ('depex_probe.c','depex_probe.h','test_probe.py')],
    )
    (OUT/'provenance.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print('Verified six official header inputs and stock SnpDxe variable evidence; wrote provenance.json.')


if __name__ == '__main__':
    main()
