"""Derive an isolated native-provider fixture; do not edit frozen inventory05."""
from pathlib import Path
import hashlib
import json

HERE=Path(__file__).resolve().parent
PREV=HERE.parent/'layout_recovery/probe'
src=(PREV/'verify_inventory.py').read_text(encoding='utf8')
def replace(old,new):
 global src
 assert old in src,old[:80]
 src=src.replace(old,new)
replace("PCI_GUID = uuid.UUID", "CPU_BASE, MMIO = 0x61000000, 0xfe010000\ncp = pefile.PE(str(HERE/'native/OriginalCpuIo2.efi')); cp.relocate_image(CPU_BASE); cpu_image = cp.get_memory_mapped_image()\nCPU_GUID = uuid.UUID('ad61f191-ae5f-4c0e-b9fa-e869d288c64f').bytes_le\nPCI_GUID = uuid.UUID")
replace("(STOP, 0x1000)]:", "(STOP, 0x1000), (CPU_BASE, 0x1000), (MMIO, 0x1000)]:")
replace("    u.mem_write(BASE, image)", """    u.mem_write(BASE, image)
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
""")
replace("ids = [0x7a8a8086, opt.get('id', 0x7a248086)","ids = [0x7a8a8086, opt.get('id', 0x7aa48086)")
replace("        nonlocal external_reads", "        nonlocal external_reads,map_calls,cpu_get_calls")
replace("        assert STOP+0x100 <= address", """        if CPU_BASE <= address < CPU_BASE+len(cpu_image):
            opcode=bytes(u.mem_read(address,min(size,2)))
            assert opcode not in [b'\\x0f\\x32',b'\\x0f\\x30',b'\\x0f\\x33']
            assert CPU_BASE+0x30c<=address<=CPU_BASE+0x480, 'Unexpected CPU_IO2 path'
            if address==CPU_BASE+0x3d4:
                assert reg(R.UC_X86_REG_RCX)==CPU_BASE+0x730 and reg(R.UC_X86_REG_RDX)==2 and reg(R.UC_X86_REG_R9)==1
                offset=reg(R.UC_X86_REG_R8)-MMIO;assert offset in OFFSETS
                mem_calls.append(offset); external_reads+=1
                if opt.get('smbios_changes_after_read')==len(mem_calls): u.mem_write(table+raw.index(board.encode()),b'X')
                if offset==opt.get('mmio_fail'): ret(opt.get('mmio_status',ERR(7)));return
            if address==CPU_BASE+0x480 and opt.get('cpu_changes_after_read')==len(mem_calls):
                u.mem_write(CPU_BASE+0x3d4,b'\\x00')
            return
        assert STOP+0x100 <= address""")
replace("            calls.append('GetMemoryMap')", "            calls.append('GetMemoryMap');map_calls+=1")
replace("            invalid = opt.get('map_invalid')", """            desc += struct.pack('<IIQQQQ',opt.get('cpu_code_type',3),0,CPU_BASE,0,1,opt.get('cpu_code_attributes',0))
            if not opt.get('no_mmio_descriptor'):
                attrs=opt.get('mmio_attributes',0x8000000000000001)
                if opt.get('map_changes_after_read') is not None and len(mem_calls)>=opt['map_changes_after_read']: attrs ^= 0x2000
                desc += struct.pack('<IIQQQQ',opt.get('mmio_type',11),0,opt.get('mmio_base',MMIO),0,opt.get('mmio_pages',1),attrs)
                if opt.get('mmio_overlap'): desc+=struct.pack('<IIQQQQ',4,0,MMIO,0,1,0)
            if opt.get('ram_read_protect'):desc=struct.pack('<IIQQQQ',4,0,HEAP,0,0x20,0x2000)+desc[40:]
            invalid = opt.get('map_invalid')""")
replace("            calls.append('LocateHandleBuffer'); assert a == 2 and c == 0 and bytes(u.mem_read(b, 16)) == PCI_GUID", """            assert a==2 and c==0
            guid=bytes(u.mem_read(b,16))
            if guid==CPU_GUID:
                calls.append('LocateCPUHandleBuffer');u.mem_write(e,q(opt.get('cpu_count',1)))
                u.mem_write(stackarg(5),q(opt.get('cpu_handles_pointer',cpu_handles)))
                ret(ERR(14) if opt.get('cpu_enum_fail') else 0);return
            calls.append('LocateHandleBuffer');assert guid==PCI_GUID""")
replace("            calls.append('HandleProtocol'); assert a in pcis and bytes(u.mem_read(b, 16)) == PCI_GUID", """            if bytes(u.mem_read(b,16))==CPU_GUID:
                calls.append('HandleCPUProtocol');cpu_get_calls+=1;assert a==CPU_BASE+0x730
                p=opt.get('cpu_pointer',CPU_BASE+0x730)
                if opt.get('cpu_owner_changes_after_read') is not None and len(mem_calls)>=opt['cpu_owner_changes_after_read']:p+=8
                u.mem_write(c,q(p));ret(ERR(3) if opt.get('cpu_handle_fail') else 0);return
            calls.append('HandleProtocol'); assert a in pcis and bytes(u.mem_read(b, 16)) == PCI_GUID""")
replace("            calls.append('FreePool'); assert a == handles", """            if a==cpu_handles:
                calls.append('CPU_FreePool');ret(ERR(7) if opt.get('cpu_free_fail') else 0);return
            calls.append('FreePool'); assert a == handles""")
replace("values = {0: ids[index], 4: opt.get('command', 2), 8: opt.get('revclass', 0x0c800011) if index != 0 else 0x06010011, 0x10: opt.get('bar', 0xfe020000), 0xdc: 0xa2}",
 "values = {0: ids[index], 4: opt.get('command', 0x402) if index else opt.get('lpc_command',0x547), 8: opt.get('revclass', 0x0c800011) if index else opt.get('lpc_revclass',0x06010011), 0x10: opt.get('bar', 0xfe010000) if index else opt.get('lpc_bar',0), 0xdc: opt.get('control',0x100008aa) if index else opt.get('lpc_control',0xa6)}")
replace("index == 1 and snapshots[index] >= opt.get('mutation_snapshot', 2)", "index == opt.get('mutation_device',1) and snapshots[index] >= opt.get('mutation_snapshot', 2)")
start=src.index('        elif address == STOP+0x160:')
end=src.index('        elif address == STOP+0x170:',start)
src=src[:start]+"        elif address == STOP+0x160:\n            raise AssertionError('PCI_IO Mem.Read must never run in06')\n"+src[end:]
replace("    u.hook_add(U.UC_HOOK_CODE, hook)", """    def mmio_read(uc,access,address,size,value,data):
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
    u.hook_add(U.UC_HOOK_CODE, hook)""")
replace("count=2000000)","count=8000000)")
replace("    assert len(log) < 16384", """    assert len(log) < 16384
    expected_physical=expected_reads-(1 if opt.get('mmio_fail') in OFFSETS[:expected_reads] else 0)
    assert physical_reads==[[MMIO+x,4] for x in OFFSETS[:expected_physical]],(name,physical_reads)
    assert native_table_reads==[0x752,0x752,0x762]*expected_physical,(name,native_table_reads)
""")
replace("'register_offsets_read': mem_calls,", "'register_offsets_read': mem_calls, 'actual_original_CPU_IO2_DWORD_reads':physical_reads, 'actual_original_stride_table_reads':native_table_reads, 'memory_map_checks':map_calls, 'CPU_protocol_rechecks':cpu_get_calls,")
replace("positive = test('SMBIOS3_7A24_positive', expected_complete=True)","positive = test('exact_observed_ACE_SMBIOS3_original_CPU_IO2', expected_complete=True)")
replace("test('SMBIOS2_7AA4_other_BAR_and_BDF', sm=2, id=0x7aa48086, bar=0xfed10000, location=[2, 7, 4, 2], expected_complete=True)", "test('exact_observed_ACE_SMBIOS2', sm=2, expected_complete=True)\ntest('other_BAR_and_BDF_refused',bar=0xfed10000,location=[2,7,4,2])")
replace("('mem_NULL', {'mem_method': 0}),", "")
replace("('mem_method_in_data', {'mem_method': HEAP+0x1f000}),", "")
insert="""
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
"""
replace("(OUT/'synthetic-positive-log.txt').write_bytes(positive)",insert+"\n(OUT/'synthetic-positive-log.txt').write_bytes(positive)")
replace('ACE1904-SPI-INVENTORY05.iso','ACE1904-SPI-PROBE06.iso')
replace("All UEFI/PCI values are synthetic. Does not prove physical ACE exposes EFI_PCI_IO for its SPI controller.","UEFI/PCI/MMIO values are synthetic. Positive cases execute original ACE CPU_IO2 machine code; only provider error cases intercept that entry. No target-device access or physical success is claimed.")
replace("'Display subsystem is stubbed here and separately exercised by OVMF.'", "'Display subsystem is stubbed here and separately exercised by OVMF.', 'Readiness rechecks do not create atomic exclusion against unrelated firmware/SMM activity.'")
(HERE/'verify_inventory.py').write_text(src,encoding='utf8')
report={'base_frozen05_test_sha256':hashlib.sha256((PREV/'verify_inventory.py').read_bytes()).hexdigest(),
 'derived_test_sha256':hashlib.sha256((HERE/'verify_inventory.py').read_bytes()).hexdigest(),
 'derivation_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'changes':'Use original ACE CPU_IO2 native code and exact physical identity gate; add CPU provider/map/identity mutation and no-fallback cases.'}
(HERE/'test_derivation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
