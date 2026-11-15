"""Execute the exact ACE inventory EFI with synthetic UEFI/PCI providers.

All unsupported services and every PCI write method trap. These are local
fault-injection tests, not evidence that a physical ACE exposes these devices.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import re
import struct
import sys
import uuid
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OUT = HERE/'build'
sys.path[:0] = [str(ROOT/'tools/pydeps'), str(ROOT/'tools/kvm-pydeps'), str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
import pefile
import unicorn as U
from unicorn import x86_const as R
from PIL import Image
from decode_captures import assemble, read_image

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
q = lambda v: struct.pack('<Q', v)
d = lambda v: struct.pack('<I', v)
BASE, HEAP, STACK, STOP = 0x140000000, 0x60000000, 0x70000000, 0x50000000
ERR = lambda n: 0x8000000000000000 | n
pe = pefile.PE(str(OUT/'BOOTX64.EFI'))
pe.relocate_image(BASE)
image = pe.get_memory_mapped_image()
symbols = {n: int(v, 16) for n, v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s', (OUT/'inventory.map').read_text(), re.M)}
OFFSETS = [0, 4, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x84, 0x88, 0x8c, 0x90, 0x94]
REGS = {0: 0x3fff3000, 4: 0xc000, 0x50: 0x0a0f0a0f, 0x54: 0, 0x58: 0x3fff3000, 0x5c: 0x06920001, 0x60: 0x7fff, 0x64: 0x7fff, 0x68: 0x7fff, 0x84: 0xbfff3000, 0x88: 0, 0x8c: 0, 0x90: 0, 0x94: 0}
CPU_BASE, MMIO = 0x61000000, 0xfe010000
cp = pefile.PE(str(HERE/'native/OriginalCpuIo2.efi')); cp.relocate_image(CPU_BASE); cpu_image = cp.get_memory_mapped_image()
CPU_GUID = uuid.UUID('ad61f191-ae5f-4c0e-b9fa-e869d288c64f').bytes_le
PCI_GUID = uuid.UUID('4cf5b200-68b8-4ca5-9eec-b23e3f50029a').bytes_le


def record(kind, length, strings):
    b = bytearray(length); b[0] = kind; b[1] = length
    if kind in (0, 2): b[5] = 1
    return bytes(b)+b'\0'.join(s.encode() for s in strings)+b'\0\0'


def execute(name, **opt):
    u = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
    for address, size in [(BASE, (len(image)+4095)&~4095), (HEAP, 0x20000), (STACK, 0x20000), (STOP, 0x1000), (CPU_BASE, 0x1000), (MMIO, 0x1000)]:
        u.mem_map(address, size)
    u.mem_write(BASE, image)
    u.mem_write(CPU_BASE, cpu_image)
    for offset, value in REGS.items():
        if offset == opt.get('all_ones'): value = 0xffffffff
        if offset == 4 and opt.get('busy'): value |= 0x20
        if offset == 4 and opt.get('invalid_fd'): value &= ~0x4000
        u.mem_write(MMIO+offset, d(value))
    if opt.get('cpu_corrupt') is not None:
        a=CPU_BASE+opt['cpu_corrupt']; u.mem_write(a,bytes([u.mem_read(a,1)[0]^1]))
    if opt.get('cpu_method') is not None: u.mem_write(CPU_BASE+0x730,q(opt['cpu_method']))
    if opt.get('cpu_other_method') is not None: u.mem_write(CPU_BASE+0x738,q(opt['cpu_other_method']))
    physical_reads=[]
    native_table_reads=[]
    map_calls=0
    cpu_get_calls=0
    cpu_handles=HEAP+0xb000
    u.mem_write(cpu_handles,q(CPU_BASE+0x730))

    st, bs, ct, eptr, table, handles = [HEAP+x for x in [0, 0x1000, 0x2000, 0x3000, 0x4000, 0x7000]]
    pcis = [HEAP+0x8000, HEAP+0x9000, HEAP+0xa000]
    board, version, sm = opt.get('board', 'Pro WS W790-ACE'), opt.get('version', '1904'), opt.get('sm', 3)
    raw = record(0, 24, [version])+record(2, 15, [board])+record(127, 4, [])
    damage = opt.get('damage')
    if damage == 'length': raw = raw[:1]+b'\xff'+raw[2:]
    if damage == 'unterminated': raw = raw[:24]+b'A'*64
    if damage == 'duplicate_bios': raw = record(0, 24, [version])+raw
    if damage == 'duplicate_board': raw = record(2, 15, [board])+raw
    if damage == 'missing_board': raw = record(0, 24, [version])+record(127, 4, [])
    if sm == 3:
        ep = bytearray(24); ep[:5] = b'_SM3_'; ep[6] = 24; ep[7:11] = bytes([3, 6, 0, 1])
        struct.pack_into('<IQ', ep, 12, opt.get('table_bytes', len(raw)), opt.get('table_address', table)); ep[5] = (-sum(ep))&255
        guid = 'f2fd1544-9794-4a2c-992e-e5bbcf20e394'
    else:
        ep = bytearray(31); ep[:4] = b'_SM_'; ep[5] = 31; ep[6:8] = bytes([2, 8]); ep[16:21] = b'_DMI_'
        struct.pack_into('<HIH', ep, 22, len(raw), table, 3); ep[21] = (-sum(ep[16:]))&255; ep[4] = (-sum(ep))&255
        guid = 'eb9d2d31-2d88-11d3-9a16-0090273fc14d'
    if damage == 'checksum': ep[5 if sm == 3 else 4] ^= 1
    if damage == 'intermediate_checksum': ep[21] ^= 1; ep[4] = 0; ep[4] = (-sum(ep))&255
    u.mem_write(table, raw); u.mem_write(eptr, bytes(ep)); u.mem_write(ct, uuid.UUID(guid).bytes_le+q(eptr))
    u.mem_write(st+0x58, q(STOP+0x900)+q(bs)+q(opt.get('table_count', 1))+q(opt.get('ct_pointer', ct)))
    for off in range(0x18, 0x178, 8): u.mem_write(bs+off, q(STOP+0x900))
    for off, value in {0x38: 0x100, 0x48: 0x130, 0x98: 0x120, 0x100: 0x170, 0x138: 0x110}.items():
        u.mem_write(bs+off, q(STOP+value))
    if opt.get('missing_map'): u.mem_write(bs+0x38, q(0))
    for pci in pcis:
        for off in range(0, 0xb0, 8): u.mem_write(pci+off, q(STOP+0x900))
        for off, key, method in [(0x10, 'mem_method', 0x160), (0x30, 'cfg_method', 0x140), (0x70, 'location_method', 0x150)]:
            u.mem_write(pci+off, q(opt.get(key, STOP+method)))
    u.mem_write(handles, b''.join(q(p) for p in pcis))
    ids = [0x7a8a8086, opt.get('id', 0x7aa48086), opt.get('third_id', 0xffffffff)]
    if opt.get('missing_lpc'): ids[0] = 0xffffffff
    cfg_calls, mem_calls, calls, observed, cpuid_calls = [], [], [], [], []
    snapshots = [0, 0, 0]
    external_reads = 0

    def reg(r): return u.reg_read(r)
    def readq(a): return struct.unpack('<Q', u.mem_read(a, 8))[0]
    def stackarg(n): return readq(reg(R.UC_X86_REG_RSP)+0x28+8*(n-5))
    def ret(value):
        sp = reg(R.UC_X86_REG_RSP); u.reg_write(R.UC_X86_REG_RAX, value)
        u.reg_write(R.UC_X86_REG_RIP, readq(sp)); u.reg_write(R.UC_X86_REG_RSP, sp+8)

    def hook(uc, address, size, data):
        nonlocal external_reads,map_calls,cpu_get_calls
        if address == STOP: uc.emu_stop(); return
        if address == symbols['kvm_present']:
            observed.append(bytes(u.mem_read(reg(R.UC_X86_REG_RDX), reg(R.UC_X86_REG_R8))))
            ret(0); return
        if address >= BASE and address < BASE+len(image):
            opcode = bytes(u.mem_read(address, min(size, 2)))
            if opcode == b'\x0f\xa2':
                leaf = reg(R.UC_X86_REG_EAX); sub = reg(R.UC_X86_REG_ECX); cpuid_calls.append([leaf, sub])
                vendor = opt.get('cpu_vendor', 'GenuineIntel').encode(); assert len(vendor) == 12
                if leaf == 0: values = [opt.get('max_leaf', 7), int.from_bytes(vendor[:4], 'little'), int.from_bytes(vendor[8:], 'little'), int.from_bytes(vendor[4:8], 'little')]
                elif leaf == 1: values = [opt.get('cpu_id', 0x806f8), 0, 0, 0]
                elif leaf == 7: assert sub == 0; values = [0, 0, 0, 0]
                else: raise AssertionError('Unenumerated CPUID leaf')
                for register, value in zip([R.UC_X86_REG_EAX, R.UC_X86_REG_EBX, R.UC_X86_REG_ECX, R.UC_X86_REG_EDX], values): uc.reg_write(register, value)
                uc.reg_write(R.UC_X86_REG_RIP, address+size)
            assert opcode not in [b'\x0f\x32', b'\x0f\x30', b'\x0f\x33'], 'MSR/PMC instruction attempted'
            return
        if CPU_BASE <= address < CPU_BASE+len(cpu_image):
            opcode=bytes(u.mem_read(address,min(size,2)))
            assert opcode not in [b'\x0f\x32',b'\x0f\x30',b'\x0f\x33']
            assert CPU_BASE+0x30c<=address<=CPU_BASE+0x480, 'Unexpected CPU_IO2 path'
            if address==CPU_BASE+0x3d4:
                assert reg(R.UC_X86_REG_RCX)==CPU_BASE+0x730 and reg(R.UC_X86_REG_RDX)==2 and reg(R.UC_X86_REG_R9)==1
                offset=reg(R.UC_X86_REG_R8)-MMIO;assert offset in OFFSETS
                mem_calls.append(offset); external_reads+=1
                if opt.get('smbios_changes_after_read')==len(mem_calls): u.mem_write(table+raw.index(board.encode()),b'X')
                if offset==opt.get('mmio_fail'): ret(opt.get('mmio_status',ERR(7)));return
            if address==CPU_BASE+0x480 and opt.get('cpu_changes_after_read')==len(mem_calls):
                u.mem_write(CPU_BASE+0x3d4,b'\x00')
            return
        assert STOP+0x100 <= address < STOP+0x180, f'Unapproved service/write method at {address:x}'
        a, b, c, e = map(reg, [R.UC_X86_REG_RCX, R.UC_X86_REG_RDX, R.UC_X86_REG_R8, R.UC_X86_REG_R9])
        if address == STOP+0x100:
            calls.append('GetMemoryMap');map_calls+=1
            if opt.get('map_fail'): ret(ERR(5)); return
            desc = struct.pack('<IIQQQQ', opt.get('heap_type', 4), 0, HEAP, 0, 0x20, 0)
            if not opt.get('no_code_map'):
                desc += struct.pack('<IIQQQQ', opt.get('code_type', 3), 0, STOP, 0, 1, opt.get('code_attributes', 0))
            desc += struct.pack('<IIQQQQ',opt.get('cpu_code_type',3),0,CPU_BASE,0,1,opt.get('cpu_code_attributes',0))
            if not opt.get('no_mmio_descriptor'):
                attrs=opt.get('mmio_attributes',0x8000000000000001)
                if opt.get('map_changes_after_read') is not None and len(mem_calls)>=opt['map_changes_after_read']: attrs ^= 0x2000
                desc += struct.pack('<IIQQQQ',opt.get('mmio_type',11),0,opt.get('mmio_base',MMIO),0,opt.get('mmio_pages',1),attrs)
                if opt.get('mmio_overlap'): desc+=struct.pack('<IIQQQQ',4,0,MMIO,0,1,0)
            if opt.get('ram_read_protect'):desc=struct.pack('<IIQQQQ',4,0,HEAP,0,0x20,0x2000)+desc[40:]
            invalid = opt.get('map_invalid')
            if invalid:
                desc += struct.pack('<IIQQQQ', 99 if invalid == 'type' else 4, 0, 0xfffffffffffff000 if invalid == 'overflow' else (0x80000001 if invalid == 'alignment' else 0x80000000), 0, 0 if invalid == 'zero' else 2, 0)
            u.mem_write(b, desc); u.mem_write(a, q(opt.get('map_size', len(desc)))); u.mem_write(c, q(1)); u.mem_write(e, q(opt.get('stride', 40))); u.mem_write(stackarg(5), d(opt.get('map_version', 1))); ret(0)
        elif address == STOP+0x110:
            assert a==2 and c==0
            guid=bytes(u.mem_read(b,16))
            if guid==CPU_GUID:
                calls.append('LocateCPUHandleBuffer');u.mem_write(e,q(opt.get('cpu_count',1)))
                u.mem_write(stackarg(5),q(opt.get('cpu_handles_pointer',cpu_handles)))
                ret(ERR(14) if opt.get('cpu_enum_fail') else 0);return
            calls.append('LocateHandleBuffer');assert guid==PCI_GUID
            u.mem_write(e, q(opt.get('count', 2))); u.mem_write(stackarg(5), q(opt.get('handles_pointer', handles)))
            ret(ERR(14) if opt.get('enum_fail') else 0)
        elif address == STOP+0x120:
            if bytes(u.mem_read(b,16))==CPU_GUID:
                calls.append('HandleCPUProtocol');cpu_get_calls+=1;assert a==CPU_BASE+0x730
                p=opt.get('cpu_pointer',CPU_BASE+0x730)
                if opt.get('cpu_owner_changes_after_read') is not None and len(mem_calls)>=opt['cpu_owner_changes_after_read']:p+=8
                u.mem_write(c,q(p));ret(ERR(3) if opt.get('cpu_handle_fail') else 0);return
            calls.append('HandleProtocol'); assert a in pcis and bytes(u.mem_read(b, 16)) == PCI_GUID
            if opt.get('protocol_fail'): ret(ERR(3)); return
            u.mem_write(c, q(opt.get('protocol_pointer', a))); ret(0)
        elif address == STOP+0x130:
            if a==cpu_handles:
                calls.append('CPU_FreePool');ret(ERR(7) if opt.get('cpu_free_fail') else 0);return
            calls.append('FreePool'); assert a == handles
            ret(ERR(7) if opt.get('free_fail') else 0)
        elif address == STOP+0x140:
            assert a in pcis and b == 2 and e == 1 and c in [0, 4, 8, 0x10, 0xdc]
            index = pcis.index(a); cfg_calls.append([index, c]); external_reads += 1
            if c == opt.get('cfg_fail'): ret(ERR(7)); return
            values = {0: ids[index], 4: opt.get('command', 0x402) if index else opt.get('lpc_command',0x547), 8: opt.get('revclass', 0x0c800011) if index else opt.get('lpc_revclass',0x06010011), 0x10: opt.get('bar', 0xfe010000) if index else opt.get('lpc_bar',0), 0xdc: opt.get('control',0x100008aa) if index else opt.get('lpc_control',0xa6)}
            if c == opt.get('mutation_offset') and index == opt.get('mutation_device',1) and snapshots[index] >= opt.get('mutation_snapshot', 2): values[c] ^= opt.get('mutation_mask', 0x10000)
            if opt.get('id_changes_during_selection') and c == 0 and snapshots[index] == 1: values[c] ^= 1
            u.mem_write(stackarg(5), d(values[c])); ret(0)
        elif address == STOP+0x150:
            assert a in pcis; index = pcis.index(a); snapshots[index] += 1
            if opt.get('location_fail'): ret(ERR(7)); return
            values = list(opt.get('location', [0, 0, 31, 5]))
            if index == 0: values[-1] = 0
            if opt.get('location_changes') and index == 1 and snapshots[index] >= 2: values[1] ^= 1
            for pointer, value in zip([b, c, e, stackarg(5)], values): u.mem_write(pointer, q(value))
            ret(0)
        elif address == STOP+0x160:
            raise AssertionError('PCI_IO Mem.Read must never run in06')
        elif address == STOP+0x170:
            calls.append('SetWatchdogTimer'); assert [a, b, c, e] == [0, 0, 0, 0]
            ret(ERR(7) if opt.get('watchdog_fail') else 0)

    def mmio_read(uc,access,address,size,value,data):
        assert reg(R.UC_X86_REG_RIP)==CPU_BASE+0x44c and size==4 and address-MMIO in OFFSETS
        physical_reads.append([address,size])
    def mmio_write(uc,access,address,size,value,data):
        raise AssertionError('MMIO write attempted')
    def native_data_read(uc,access,address,size,value,data):
        if CPU_BASE+0x30c<=reg(R.UC_X86_REG_RIP)<=CPU_BASE+0x480:
            assert address-CPU_BASE in [0x752,0x762] and size==1
            native_table_reads.append(address-CPU_BASE)
    u.hook_add(U.UC_HOOK_MEM_READ,mmio_read,begin=MMIO,end=MMIO+0xfff)
    u.hook_add(U.UC_HOOK_MEM_WRITE,mmio_write,begin=MMIO,end=MMIO+0xfff)
    u.hook_add(U.UC_HOOK_MEM_READ,native_data_read,begin=CPU_BASE+0x750,end=CPU_BASE+0x76f)
    u.hook_add(U.UC_HOOK_CODE, hook)
    sp = STACK+0x18000-8; u.mem_write(sp, q(STOP)); u.reg_write(R.UC_X86_REG_RSP, sp)
    u.reg_write(R.UC_X86_REG_RCX, 1); u.reg_write(R.UC_X86_REG_RDX, st)
    u.emu_start(symbols['efi_main'], STOP+1, count=8000000)
    assert len(observed) == 1, (name, 'did not present bounded log')
    log = observed[0]
    assert b'PROBE_COMPLETE\r\n' in log and b'LogOverflow=0x00000000' in log
    assert b'FLASH_BYTES_ACQUIRED=0' in log and b'FLASH_READ_CYCLES=0' in log
    assert b'LIVE_DESCRIPTOR_BYTES=NOT_READ' in log and b'LIVE_FIT_ACM_KM_BPM_BYTES=NOT_READ' in log
    assert b'BOOT_GUARD_FUSES_AND_PROVISIONING=UNKNOWN' in log
    positive = opt.get('expected_complete', False)
    assert (b'COLLECTION_STATUS=DEFINED_REGISTER_SNAPSHOT_COMPLETE' in log) == positive, (name, log)
    expected_reads = opt.get('expected_reads', 14 if positive else 0)
    assert mem_calls == OFFSETS[:expected_reads], (name, mem_calls, expected_reads, log)
    if opt.get('no_enum'): assert 'LocateHandleBuffer' not in calls
    if opt.get('no_free'): assert 'FreePool' not in calls
    assert len(log) < 16384
    expected_physical=expected_reads-(1 if opt.get('mmio_fail') in OFFSETS[:expected_reads] else 0)
    assert physical_reads==[[MMIO+x,4] for x in OFFSETS[:expected_physical]],(name,physical_reads)
    assert native_table_reads==[0x752,0x752,0x762]*expected_physical,(name,native_table_reads)

    return {'name': name, 'status': 'PASS', 'register_offsets_read': mem_calls, 'actual_original_CPU_IO2_DWORD_reads':physical_reads, 'actual_original_stride_table_reads':native_table_reads, 'memory_map_checks':map_calls, 'CPU_protocol_rechecks':cpu_get_calls, 'pci_config_read_count': len(cfg_calls), 'services': calls,
            'cpuid_leaves': cpuid_calls, 'complete_snapshot': positive, 'write_or_unapproved_method_calls': 0, 'log_sha256': hashlib.sha256(log).hexdigest()}, log


cases = []
def test(name, **opt):
    result, log = execute(name, **opt); cases.append(result); return log

positive = test('exact_observed_ACE_SMBIOS3_original_CPU_IO2', expected_complete=True)
test('exact_observed_ACE_SMBIOS2', sm=2, expected_complete=True)
test('other_BAR_and_BDF_refused',bar=0xfed10000,location=[2,7,4,2])
test('LoaderCode_provider', code_type=1, expected_complete=True)
test('RuntimeCode_provider', code_type=5, expected_complete=True)
test('CPUID_max1_no_leaf7', max_leaf=1, expected_complete=True)
for name, options in [
    ('SAGE_is_not_ACE', {'board': 'Pro WS W790E-SAGE SE'}), ('BIOS2003', {'version': '2003'}),
    ('CPU_AMD', {'cpu_vendor': 'AuthenticAMD'}), ('CPU_wrong_model', {'cpu_id': 0x906a0}), ('CPU_no_leaf1', {'max_leaf': 0}),
    ('SMBIOS_checksum', {'damage': 'checksum'}), ('SMBIOS2_intermediate', {'sm': 2, 'damage': 'intermediate_checksum'}),
    ('SMBIOS_length', {'damage': 'length'}), ('SMBIOS_unterminated', {'damage': 'unterminated'}),
    ('SMBIOS_duplicate_bios', {'damage': 'duplicate_bios'}), ('SMBIOS_duplicate_board', {'damage': 'duplicate_board'}),
    ('SMBIOS_missing_board', {'damage': 'missing_board'}), ('SMBIOS_outside_RAM', {'table_address': 0xfe020000}),
    ('SMBIOS_oversize', {'table_bytes': 0x200001}), ('SMBIOS_pointer_wrap', {'table_address': 0xfffffffffffffff0}),
    ('table_count_zero', {'table_count': 0}), ('table_count_oversize', {'table_count': 257}), ('config_outside_RAM', {'ct_pointer': 0xfe020000}),
    ('map_missing', {'missing_map': True}), ('map_error', {'map_fail': True}), ('map_small_stride', {'stride': 39}),
    ('map_oversize_stride', {'stride': 4097}), ('map_bad_version', {'map_version': 2}), ('map_oversize', {'map_size': 65537}),
    ('map_zero_size', {'map_size': 0}), ('map_unaligned_size', {'map_size': 79}), ('map_MMIO_for_RAM', {'heap_type': 11})]:
    test(name, no_enum=True, **options)
for kind in ['type', 'zero', 'overflow', 'alignment']: test('map_bad_'+kind, map_invalid=kind, no_enum=True)
for name, options in [
    ('enum_error', {'enum_fail': True, 'no_free': True}), ('enum_zero', {'count': 0}), ('enum_oversize', {'count': 2049}),
    ('handles_outside_RAM', {'handles_pointer': 0xfe020000, 'no_free': True}), ('protocol_error', {'protocol_fail': True}),
    ('protocol_outside_RAM', {'protocol_pointer': 0xfe020000}), ('no_W790_LPC', {'missing_lpc': True}),
    ('SPI_unknown', {'id': 0xdead8086}), ('two_SPI', {'count': 3, 'third_id': 0x7aa48086}), ('two_LPC', {'count': 3, 'third_id': 0x7a8a8086}),
    ('cfg_NULL', {'cfg_method': 0}), ('location_NULL', {'location_method': 0}), 
    ('cfg_method_in_data', {'cfg_method': HEAP+0x1f000}), 
    ('method_no_code_map', {'no_code_map': True}), ('method_noncode_type', {'code_type': 4}),
    ('method_RP', {'code_attributes': 0x2000}), ('method_XP', {'code_attributes': 0x4000}),
    ('wrong_class', {'revclass': 0x0c050011}), ('memory_decode_disabled', {'command': 0}), ('command_allones', {'command': 0xffffffff}),
    ('BAR_zero', {'bar': 0}), ('BAR_allones', {'bar': 0xffffffff}), ('BAR_IO', {'bar': 0xfe020001}),
    ('BAR_64bit', {'bar': 0xfe020004}), ('BAR_prefetch', {'bar': 0xfe020008}), ('location_error', {'location_fail': True}),
    ('location_overflow', {'location': [0, 256, 31, 5]}), ('location_changed', {'location_changes': True}),
    ('id_changes_during_selection', {'id_changes_during_selection': True})]:
    test(name, **options)
for offset in [0, 4, 8, 0x10, 0xdc]:
    test(f'configuration_error_{offset:02x}', cfg_fail=offset)
    test(f'snapshot_change_before_MMIO_{offset:02x}', mutation_offset=offset)
    test(f'snapshot_change_after_one_read_{offset:02x}', mutation_offset=offset, mutation_snapshot=3, expected_reads=1)
for offset in OFFSETS:
    test(f'first_MMIO_error_{offset:02x}', mmio_fail=offset, expected_reads=OFFSETS.index(offset)+1)
    test(f'allones_MMIO_{offset:02x}', all_ones=offset, expected_reads=OFFSETS.index(offset)+1)
test('unsupported_MMIO_no_fallback', mmio_fail=0, mmio_status=ERR(3), expected_reads=1)
test('HSFSTS_busy', busy=True, expected_reads=2)
test('HSFSTS_FDV_zero', invalid_fd=True, expected_reads=2)
test('SMBIOS_changes_after_last_read', smbios_changes_after_read=14, expected_reads=14)
test('free_pool_error_marks_partial', free_fail=True, expected_reads=14)
test('watchdog_error_marks_partial', watchdog_fail=True, expected_reads=14)

test('unused_PCI_IO_MemRead_NULL_still_safe',mem_method=0,expected_complete=True)
test('unused_PCI_IO_MemRead_data_still_safe',mem_method=HEAP+0x1f000,expected_complete=True)
for name,options in [
 ('same_model_other_CPU_stepping',{'cpu_id':0x806f9}),('7A24_is_not_observed_7AA4',{'id':0x7a248086}),
 ('SPI_control_not_observed',{'control':0xaa}),('SPI_command_extra_enable',{'command':0x406}),
 ('LPC_control_changed',{'lpc_control':0xa2}),('LPC_command_changed',{'lpc_command':0x543}),
 ('LPC_class_changed',{'lpc_revclass':0x06010012}),('LPC_bar_changed',{'lpc_bar':0xfe010000}),
 ('CPU_IO2_missing',{'cpu_enum_fail':True}),('CPU_IO2_zero',{'cpu_count':0}),('CPU_IO2_duplicate',{'cpu_count':2}),
 ('CPU_IO2_handle_failure',{'cpu_handle_fail':True}),('CPU_IO2_handle_array_not_RAM',{'cpu_handles_pointer':MMIO}),
 ('CPU_IO2_interface_not_RAM',{'cpu_pointer':MMIO}),('CPU_IO2_wrong_interface',{'cpu_pointer':CPU_BASE+0x738}),
 ('CPU_IO2_NULL_method',{'cpu_method':0}),('CPU_IO2_foreign_method',{'cpu_method':STOP+0x160}),
 ('CPU_IO2_changed_opaque_method',{'cpu_other_method':0}),('CPU_IO2_code_type_data',{'cpu_code_type':4}),
 ('CPU_IO2_code_read_protect',{'cpu_code_attributes':0x2000}),('CPU_IO2_code_execute_protect',{'cpu_code_attributes':0x4000}),
 ('CPU_IO2_handles_release_error',{'cpu_free_fail':True}),('MMIO_description_missing',{'no_mmio_descriptor':True}),
 ('MMIO_wrong_type',{'mmio_type':4}),('MMIO_broader_range',{'mmio_pages':2}),('MMIO_wrong_base',{'mmio_base':MMIO-4096}),
 ('MMIO_overlapping_RAM',{'mmio_overlap':True}),('MMIO_no_UC',{'mmio_attributes':0x8000000000000000}),
 ('MMIO_conflicting_WB',{'mmio_attributes':0x8000000000000009}),('MMIO_read_protect',{'mmio_attributes':0x8000000000002001}),
 ('MMIO_unknown_attribute',{'mmio_attributes':0x8000000100000001}),('RAM_read_protect',{'ram_read_protect':True})]:test(name,**options)
for offset in [0x30c,0x3d4,0x44c,0x480,0x720,0x750,0x752,0x760,0x762,0x76b]:test('original_CPU_code_table_corruption_'+hex(offset),cpu_corrupt=offset)
for n in [0,1,7,13,14]:
 test('MMIO_map_permissions_change_after_'+str(n),map_changes_after_read=n,expected_reads=n)
 test('CPU_provider_owner_change_after_'+str(n),cpu_owner_changes_after_read=n,expected_reads=n)
for n in [1,7,13,14]:test('original_CPU_code_changed_after_'+str(n),cpu_changes_after_read=n,expected_reads=n)
for off in [0,4,8,0x10,0xdc]:
 test('LPC_mutation_after_one_'+hex(off),mutation_offset=off,mutation_device=0,mutation_snapshot=3,expected_reads=1)
test('MMIO_XP_read_only_attributes',mmio_attributes=0x8000000000024001,expected_complete=True)

(OUT/'synthetic-positive-log.txt').write_bytes(positive)

# Round-trip the exact compiled QR encoder with the independent existing decoder.
dll = ctypes.CDLL(str(OUT/'qr_test.dll'))
dll.kvm_make_frame.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t]
dll.kvm_make_frame.restype = ctypes.c_size_t
dll.kvm_encode_frame.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
dll.kvm_encode_frame.restype = ctypes.c_int
dll.qrcodegen_getSize.argtypes = [ctypes.c_void_p]; dll.qrcodegen_getSize.restype = ctypes.c_int
dll.qrcodegen_getModule.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]; dll.qrcodegen_getModule.restype = ctypes.c_bool
qrdir = OUT/'synthetic-qr'; qrdir.mkdir(exist_ok=True); frames = []
for page in range((len(positive)+767)//768):
    buf = ctypes.create_string_buffer(1000); n = dll.kvm_make_frame(positive, len(positive), page, buf, 1000); expected = buf.raw[:n]
    qr = ctypes.create_string_buffer(2500); scratch = ctypes.create_string_buffer(2500)
    assert dll.kvm_encode_frame(positive, len(positive), page, qr, scratch) == 1
    side = dll.qrcodegen_getSize(qr); im = Image.new('L', ((side+8)*4,)*2, 255); pix = im.load()
    for y in range(side):
        for x in range(side):
            if dll.qrcodegen_getModule(qr, x, y):
                for dy in range(4):
                    for dx in range(4): pix[(x+4)*4+dx, (y+4)*4+dy] = 0
    path = qrdir/f'page-{page+1}.png'; im.save(path); frame = read_image(path); assert frame == expected; frames.append(frame)
restored, metadata = assemble(frames, require_inventory=False); assert restored == positive
bad = bytearray(frames[0]); bad[-1] ^= 1
for broken in [frames[:-1], [bytes(bad)]+frames[1:]]:
    try: assemble(broken, require_inventory=False)
    except ValueError: pass
    else: raise AssertionError('Incomplete or corrupt inventory accepted')
report = {'status': 'PASS_LOCAL_SIMULATION_ONLY', 'hardware_tested': False, 'efi_sha256': sha(OUT/'BOOTX64.EFI'),
          'iso_sha256': sha(OUT/'ACE1904-SPI-PROBE06.iso'), 'source_sha256': sha(HERE/'source/inventory.c'),
          'build_sha256': sha(OUT/'build.json'), 'map_sha256': sha(OUT/'inventory.map'), 'test_source_sha256': sha(Path(__file__)),
          'cases': cases, 'case_count': len(cases), 'qr_pages': len(frames), 'qr_log_bytes': len(positive),
          'qr_whole_crc32': f'{zlib.crc32(positive):08X}', 'qr_test_dll_sha256': sha(OUT/'qr_test.dll'),
          'qr_decoder_sha256': sha(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py'),
          'qr_roundtrip_byte_identical': True, 'missing_page_and_corrupt_crc_rejected': True,
          'limitations': ['UEFI/PCI/MMIO values are synthetic. Positive cases execute original ACE CPU_IO2 machine code; only provider error cases intercept that entry. No target-device access or physical success is claimed.',
                         'No flash contents acquired; no live descriptor/FIT/Boot Guard state, capacity, complete read permissions or recovery path established.',
                         'Display subsystem is stubbed here and separately exercised by OVMF.', 'Readiness rechecks do not create atomic exclusion against unrelated firmware/SMM activity.']}
(OUT/'local_verification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({k: report[k] for k in ['status', 'case_count', 'efi_sha256', 'qr_pages', 'qr_log_bytes']}, indent=2))
