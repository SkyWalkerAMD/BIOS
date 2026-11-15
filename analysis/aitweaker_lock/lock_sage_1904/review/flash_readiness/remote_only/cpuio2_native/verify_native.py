"""Offline original-CAP extraction and exact CPU_IO2 read-path emulation.

Unicorn maps only synthetic memory; there is no device connection/passthrough.
"""
from pathlib import Path
import hashlib
import json
import lzma
import struct
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[6]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX

CAP = ROOT / 'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
CAP_SHA = 'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
RAW_SHA = '88067e05d84ed3157eb34964217a5baaba094ed2c1d7d67ab76583bee9a77a9b'
FFS_SHA = '52d56dd9dfeea0be800012f0cb08213eebf909ae5d8d36c3fbe59a2fa3030a6e'
EFI_SHA = '4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
GUID = uuid.UUID('ad61f191-ae5f-4c0e-b9fa-e869d288c64f').bytes_le
OFFSETS = [0, 4, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x84, 0x88, 0x8c, 0x90, 0x94]
sha = lambda b: hashlib.sha256(b).hexdigest()
q = lambda x: struct.pack('<Q', x)
ERR = lambda x: (1 << 63) | x

cap = CAP.read_bytes()
assert sha(cap) == CAP_SHA
section = 0x3181078 + 24
section_size = int.from_bytes(cap[section:section + 3], 'little')
raw = lzma.decompress(cap[section + 24:section + section_size], format=lzma.FORMAT_ALONE)
assert sha(raw) == RAW_SHA
ffs = raw[0x5cae0:0x5cae0 + 2370]
assert sha(ffs) == FFS_SHA
assert str(uuid.UUID(bytes_le=ffs[:16])) == 'a19b1fe7-c1bc-49f8-875f-54a5d542443f'
assert int.from_bytes(ffs[0x30:0x33], 'little') == 0x904 and ffs[0x33] == 0x10
efi = ffs[0x34:0x934]
assert sha(efi) == EFI_SHA
assert efi == (HERE / 'OriginalCpuIo2.efi').read_bytes()
(HERE / 'OriginalCpuIo2.ffs').write_bytes(ffs)
pe = pefile.PE(data=efi)
assert pe.OPTIONAL_HEADER.ImageBase == 0
assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x2d0
assert pe.get_data(0x720, 16) == GUID
methods = struct.unpack('<QQQQ', pe.get_data(0x730, 32))
assert methods == (0x3d4, 0x484, 0x534, 0x624)
md = Cs(CS_ARCH_X86, CS_MODE_64)
code = list(md.disasm(pe.get_data(0x3d4, 0x481 - 0x3d4), 0x3d4))
assert [i.op_str for i in code if i.mnemonic == 'call'] == ['0x30c']
assert not any(i.mnemonic in ['out', 'in', 'syscall', 'wrmsr'] for i in code)
assert pe.get_data(0x44c, 4).hex() == '8b038907'

IMAGE = 0x100000
STACK = 0x70000000
OUT = 0x71000000
ST = 0x72000000
BS = 0x73000000
MMIO = 0xfe010000
STOP = 0x60000000

def machine():
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    for addr, size in [(IMAGE, 0x10000), (STACK, 0x10000), (OUT, 0x1000), (ST, 0x1000), (BS, 0x1000), (MMIO, 0x1000), (STOP, 0x1000)]:
        u.mem_map(addr, size)
    data = bytearray(pe.get_memory_mapped_image())
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for ent in block.entries:
            if ent.type == 10:
                struct.pack_into('<Q', data, ent.rva, struct.unpack_from('<Q', data, ent.rva)[0] + IMAGE)
            else:
                assert ent.type == 0
    u.mem_write(IMAGE, bytes(data))
    sp = STACK + 0x8008
    u.reg_write(UC_X86_REG_RSP, sp)
    u.mem_write(sp, q(STOP))
    u.mem_write(OUT, b'\xcc' * 0x1000)
    page = bytearray(0x1000)
    for offset in OFFSETS:
        struct.pack_into('<I', page, offset, 0xa5000000 | offset)
    u.mem_write(MMIO, bytes(page))
    return u, sp, bytes(page)

def read_case(name, width=2, address=MMIO, count=1, buffer=OUT + 0x40, expected=0, offset=0, want_read=True):
    u, sp, page = machine()
    u.reg_write(UC_X86_REG_RCX, IMAGE + 0x730)
    u.reg_write(UC_X86_REG_RDX, width)
    u.reg_write(UC_X86_REG_R8, address)
    u.reg_write(UC_X86_REG_R9, count)
    u.mem_write(sp + 0x28, q(buffer))
    reads = []
    writes = []
    executed = []
    def rd(_u, _access, a, n, _value, _data):
        reads.append((a, n))
    def wr(_u, _access, a, n, _value, _data):
        assert STACK <= a and a + n <= STACK + 0x10000 or OUT <= a and a + n <= OUT + 0x1000, (name, hex(a), n)
        writes.append((a, n))
    def instruction(_u, a, _size, _data):
        if a == STOP:
            _u.emu_stop()
            return
        assert IMAGE + 0x30c <= a <= IMAGE + 0x480, (name, hex(a))
        executed.append(a - IMAGE)
    u.hook_add(UC_HOOK_MEM_READ, rd, begin=MMIO, end=MMIO + 0xfff)
    u.hook_add(UC_HOOK_MEM_WRITE, wr)
    u.hook_add(UC_HOOK_CODE, instruction)
    u.emu_start(IMAGE + 0x3d4, STOP + 1, count=1000)
    status = u.reg_read(UC_X86_REG_RAX)
    assert status == expected, (name, hex(status), hex(expected))
    assert u.reg_read(UC_X86_REG_RIP) == STOP
    assert reads == ([(address, 4)] if want_read else []), (name, reads)
    assert bytes(u.mem_read(MMIO, 0x1000)) == page
    if want_read:
        expected_out = bytearray(b'\xcc' * 0x1000)
        struct.pack_into('<I', expected_out, buffer - OUT, 0xa5000000 | offset)
        assert bytes(u.mem_read(OUT, 0x1000)) == bytes(expected_out)
        assert executed.count(0x44c) == executed.count(0x44e) == 1
    else:
        assert bytes(u.mem_read(OUT, 0x1000)) == b'\xcc' * 0x1000
    return {'name': name, 'status': f'0x{status:016X}', 'passed': True, 'synthetic_MMIO_reads': [{'address': hex(a), 'bytes': n} for a, n in reads], 'MMIO_writes': 0, 'other_writes': 'stack saves and caller output only', 'executed_instruction_count': len(executed)}

cases = [read_case(f'fixed_DWORD_{offset:02X}', address=MMIO + offset, offset=offset) for offset in OFFSETS]
cases += [
    read_case('invalid_width', width=12, expected=ERR(2), want_read=False),
    read_case('NULL_buffer', buffer=0, expected=ERR(2), want_read=False),
    read_case('unaligned_address', address=MMIO + 1, expected=ERR(3), want_read=False),
    read_case('unaligned_buffer', buffer=OUT + 0x41, expected=ERR(3), want_read=False),
    read_case('zero_count', count=0, want_read=False),
    read_case('count_overflow', count=(1 << 64) - 1, expected=ERR(3), want_read=False),
    read_case('address_plus_count_overflow', address=(1 << 64) - 4, count=2, expected=ERR(3), want_read=False),
]

u, sp, page = machine()
u.mem_write(ST + 0x60, q(BS))
u.mem_write(BS + 0x148, q(STOP + 0x100))
u.reg_write(UC_X86_REG_RCX, 0x1234)
u.reg_write(UC_X86_REG_RDX, ST)
registration = []
def entry_hook(_u, a, _size, _data):
    if a == STOP:
        _u.emu_stop()
    elif a == STOP + 0x100:
        rcx, rdx, r8, r9 = [_u.reg_read(r) for r in [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]]
        assert rcx == IMAGE + 0x790 and rdx == IMAGE + 0x720 and r8 == IMAGE + 0x730 and r9 == 0
        assert bytes(_u.mem_read(rdx, 16)) == GUID
        assert struct.unpack('<QQQQ', bytes(_u.mem_read(r8, 32))) == tuple(IMAGE + v for v in methods)
        registration.append({'boot_service_slot': '0x148 InstallMultipleProtocolInterfaces', 'protocol_guid': str(uuid.UUID(bytes_le=GUID)), 'interface_RVA': '0x730', 'methods_RVA': [hex(v) for v in methods]})
        rsp = _u.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(_u.mem_read(rsp, 8)))[0]
        _u.reg_write(UC_X86_REG_RAX, 0)
        _u.reg_write(UC_X86_REG_RSP, rsp + 8)
        _u.reg_write(UC_X86_REG_RIP, ret)
u.hook_add(UC_HOOK_CODE, entry_hook)
u.emu_start(IMAGE + 0x2d0, STOP + 1, count=1000)
assert len(registration) == 1 and u.reg_read(UC_X86_REG_RAX) == 0

report = {
    'status': 'PASS_ORIGINAL_CPU_IO2_STATIC_AND_SYNTHETIC_PATH_REVIEW',
    'reviewer': 'sage_original', 'hardware_access': False,
    'inputs': {'official_CAP': {'path': str(CAP), 'sha256': CAP_SHA}, 'decompressed_container': {'offset': '0x3181078', 'sha256': RAW_SHA}, 'FFS': {'raw_offset': '0x5CAE0', 'bytes': len(ffs), 'guid': 'a19b1fe7-c1bc-49f8-875f-54a5d542443f', 'sha256': FFS_SHA}, 'EFI': {'file': 'OriginalCpuIo2.efi', 'bytes': len(efi), 'sha256': EFI_SHA}, 'verification_source_sha256': sha(Path(__file__).read_bytes())},
    'registration': registration[0],
    'read_path': {'entry_RVA': '0x3D4', 'only_direct_call': '0x30C parameter check', 'DWORD_load_RVA': '0x44C', 'DWORD_load_bytes': '8B03', 'DWORD_store_to_caller_buffer_RVA': '0x44E', 'DWORD_store_bytes': '8907', 'success_return_RVA': '0x46A', 'separate_MemWrite_RVA': '0x484', 'finding': 'Width32/count1 reads one DWORD from the supplied address and writes it to the caller buffer. The path reaches no IO port operation, SPI-cycle start, selector/protection write or Mem.Write routine.'},
    'synthetic_execution': {'case_count': len(cases), 'cases': cases, 'registration_emulated': True, 'actual_machine_code': True, 'physical_MMIO_access': False, 'hardware_register_values': False},
    'limits': ['Static original producer registration and machine-code behavior do not establish that the live CPU_IO2 interface still points to this unmodified module.', 'CPU_IO2 performs general address/width/count/alignment checks, not a board/register allowlist or flash permission check. Candidate04 must enforce its independent exact PCI, map and fourteen-address gates.', 'Synthetic MMIO values are artificial and do not prove real hardware access, physical side effects of register reads, chip density, flash-read permissions, backup or recoverability.', 'EFI memory map attributes describe capabilities, not guaranteed active cache settings or access permission.'],
}
out = HERE / 'native_review.json'
out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': report['status'], 'case_count': len(cases), 'report_sha256': sha(out.read_bytes()), 'module_sha256': EFI_SHA}, indent=2))
