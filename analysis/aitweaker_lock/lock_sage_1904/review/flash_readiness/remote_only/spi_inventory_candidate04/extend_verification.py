"""Extend the exact INV03 harness with CPU_IO2 and refreshed-map failures."""
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=(HERE.with_name('spi_inventory_candidate03')/'verify_candidate.py').read_text(encoding='utf8')
s=s.replace("cfg_calls=[];mem_calls=[];root_calls=[];observed=[];calls=[]", "cfg_calls=[];mem_calls=[];root_calls=[];cpu_calls=[];observed=[];calls=[];map_calls=0;firmware_mutation=False")
anchor="    cfg_calls=[];mem_calls=[];root_calls=[];cpu_calls=[];observed=[];calls=[];map_calls=0;firmware_mutation=False"
extra='''
    cpu=HEAP+0xf000;cpu_handles=HEAP+0xf100
    for off in range(0,32,8):u.mem_write(cpu+off,q(STOP+0x900))
    method=0 if opt.get('cpu_null_method') else (HEAP+0x1f000 if opt.get('cpu_method_in_data') else STOP+0x1b0)
    u.mem_write(cpu,q(method));u.mem_write(cpu_handles,q(cpu)+q(cpu))
'''
assert anchor in s;s=s.replace(anchor,extra+anchor)
s=s.replace("descriptor(2,opt.get('root_bus_min',0),opt.get('root_bus_max',255),trans=", "descriptor(2,opt.get('root_bus_min',0),opt.get('root_bus_max',255),opt.get('bus_gran',0),trans=")
s=s.replace("def hook(uc,address,size,data):", "def hook(uc,address,size,data):\n        nonlocal map_calls,firmware_mutation")
s=s.replace("calls.append('GetMemoryMap')", "calls.append('GetMemoryMap');map_calls+=1")
old="""            desc=struct.pack('<IIQQQQ',kind,0,HEAP,0,0x20,0)
            if opt.get('bar_map_metadata'):desc+=struct.pack('<IIQQQQ',11,0,0xfe010000,0,1,1)"""
new="""            if map_calls==opt.get('cpu_map_fail_at'):ret(ERR(5));return
            desc=struct.pack('<IIQQQQ',kind,0,HEAP,0,0x20,0)
            if opt.get('cpu_support'):
                start=opt.get('cpu_page_start',0xfe010000);pages=opt.get('cpu_page_pages',1);mt=opt.get('cpu_page_type',11);attrs=opt.get('cpu_page_attributes',0x8000000000000001)
                if map_calls==3 and opt.get('cpu_map_changed_after_lookup'):attrs=0x8000000000002001
                if not opt.get('cpu_no_page'):desc+=struct.pack('<IIQQQQ',mt,0,start,0,pages,attrs)
                if not opt.get('cpu_no_code_map'):desc+=struct.pack('<IIQQQQ',opt.get('cpu_code_type',3),0,STOP,0,1,opt.get('cpu_code_attributes',0))
                if opt.get('cpu_overlap'):desc+=struct.pack('<IIQQQQ',11,0,0xfe010000,0,1,0x8000000000000001)
                if opt.get('cpu_partial_overlap'):desc+=struct.pack('<IIQQQQ',4,0,0xfe00f000,0,2,0)
                if map_calls>=2 and opt.get('cpu_bad_map'):
                    bad=opt['cpu_bad_map'];desc+=struct.pack('<IIQQQQ',99 if bad=='type' else 4,0,0xfffffffffffff000 if bad=='overflow' else (0x80000001 if bad=='alignment' else 0x80000000),0,0 if bad=='zero' else 2,0)
                if map_calls==3 and opt.get('cpu_identity_changes'):
                    token=raw.index(b'Pro WS W790E-SAGE SE');u.mem_write(table+token,b'X');firmware_mutation=True
            elif opt.get('bar_map_metadata'):desc+=struct.pack('<IIQQQQ',11,0,0xfe010000,0,1,1)"""
assert old in s;s=s.replace(old,new)
s=s.replace("u.mem_write(a,q(len(desc)))", "u.mem_write(a,q(65537 if map_calls==opt.get('cpu_map_oversize_at') else len(desc)))")
s=s.replace("q(opt.get('stride',40))", "q(39 if map_calls==opt.get('cpu_map_bad_stride_at') else opt.get('stride',40))")
s=s.replace("d(opt.get('map_version',1))", "d(2 if map_calls==opt.get('cpu_map_bad_version_at') else opt.get('map_version',1))")
anchor="""            if guid==uuid.UUID('2f707ebb-4a1a-11d4-9a38-0090273fc14d').bytes_le:"""
new="""            if guid==uuid.UUID('ad61f191-ae5f-4c0e-b9fa-e869d288c64f').bytes_le:
                calls.append('EnumerateCpuIo2')
                if not opt.get('cpu_support') or opt.get('cpu_enum_fail'):ret(ERR(14));return
                u.mem_write(e,q(opt.get('cpu_count',1)));u.mem_write(arg5(),q(0xfe010000 if opt.get('cpu_handles_outside_ram') else cpu_handles));ret(0)
            elif guid==uuid.UUID('2f707ebb-4a1a-11d4-9a38-0090273fc14d').bytes_le:"""
assert anchor in s;s=s.replace(anchor,new)
s=s.replace("assert a in pcis+roots\n            if a in roots:", "assert a in pcis+roots+[cpu]\n            if a==cpu:\n                if opt.get('cpu_protocol_fail'):ret(ERR(3));return\n                u.mem_write(c,q(0xfe010000 if opt.get('cpu_interface_outside_ram') else cpu));ret(0);return\n            if a in roots:")
s=s.replace("assert a in [handles,root_handles];ret(0)", "assert a in [handles,root_handles,cpu_handles];ret(ERR(7) if a==cpu_handles and opt.get('cpu_free_failure') else 0)")
s=s.replace("u.mem_write(arg5(),d(vals[c]));ret(0)","if 'EnumerateCpuIo2' in calls and c==opt.get('cpu_target_change_offset'):vals[c]=opt['cpu_target_change_value']\n            u.mem_write(arg5(),d(vals[c]));ret(0)")
s=s.replace("4 if opt.get('target_location_change') and 'LocateRootBridgeIo' in calls else opt.get('function',5)","4 if (opt.get('target_location_change') and 'LocateRootBridgeIo' in calls) or (opt.get('cpu_target_location_change') and 'EnumerateCpuIo2' in calls) else opt.get('function',5)")
s=s.replace("if opt.get('cpuio2_present'):u.mem_write(c,q(STOP+0x900));ret(0)", "if opt.get('cpuio2_present') or opt.get('cpu_support'):u.mem_write(c,q(cpu));ret(0)")
anchor="        else:raise AssertionError(f'Unapproved service {address:x}')"
extra='''        elif address==STOP+0x1b0:
            assert a==cpu and b==2 and e==1 and c in [0xfe010000+x for x in OFFSETS]
            offset=c-0xfe010000;cpu_calls.append(offset)
            if offset==opt.get('cpu_read_fail'):ret(opt.get('cpu_fail_status',ERR(7)));return
            value=REGS[offset]
            if offset==opt.get('cpu_all_ones'):value=0xffffffff
            if offset==4 and opt.get('cpu_busy'):value|=0x20
            if offset==4 and opt.get('cpu_invalid_fd'):value&=~0x4000
            u.mem_write(arg5(),d(value));ret(0)
'''
assert anchor in s;s=s.replace(anchor,extra+anchor)
s=s.replace('0x190,0x1a0,0x900','0x190,0x1a0,0x1b0,0x900')
s=s.replace("protected=[(root_handles,16)]", "protected=[(cpu,32),(cpu_handles,16),(root_handles,16)]")
s=s.replace("assert snapshots==[bytes(u.mem_read(a,n)) for a,n in protected],name+' modified protected inputs'", "for index,(a,n) in enumerate(protected):\n        current=bytes(u.mem_read(a,n))\n        if firmware_mutation and a==table:\n            expected_table=bytearray(snapshots[index]);expected_table[raw.index(b'Pro WS W790E-SAGE SE')]=ord('X');assert current==bytes(expected_table)\n        else:assert current==snapshots[index],name+' modified protected inputs'")
s=s.replace("assert root_calls==(OFFSETS if opt.get('root_read_expected') else []),name", "assert root_calls==(OFFSETS if opt.get('root_read_expected') else []),name\n    assert cpu_calls==OFFSETS[:opt.get('cpu_read_count',0)],(name,cpu_calls)\n    if opt.get('no_cpu_enum'):assert 'EnumerateCpuIo2' not in calls,name")
s=s.replace("'root_mmio_reads':len(root_calls)","'root_mmio_reads':len(root_calls),'cpu_mmio_reads':len(cpu_calls),'map_reads':map_calls")
anchor="(OUT/'synthetic-positive-log.txt').write_bytes(positive)"
extra='''
assert len(cases)==157
def ct(name,**kw):
    options={'id':0x7aa48086,'pci_all_unsupported':True,'no_mem_resource':True,'cpu_support':True,'expected':ERR(7)};options.update(kw);test(name,**options)
ct('CPU_exact_observed_resource_positive',expected=0,cpu_read_count=14)
_,positive=execute('CPU_QR_LOG',id=0x7aa48086,pci_all_unsupported=True,no_mem_resource=True,cpu_support=True,expected=0,cpu_read_count=14)
ct('CPU_root_nonzero_granularity_remains_rejected',bus_gran=32,expected=0,cpu_read_count=14)
ct('CPU_absent_root_interface_independent_gate',root_enum_fail=True,expected=0,cpu_read_count=14)
ct('CPU_RuntimeServicesCode_method_supported',cpu_code_type=5,expected=0,cpu_read_count=14)
for name,options in [
 ('no_target_page',{'cpu_no_page':True}),('wrong_page_start',{'cpu_page_start':0xfe020000}),('broader_page_range',{'cpu_page_start':0xfe00f000,'cpu_page_pages':2}),('multiple_pages',{'cpu_page_pages':2}),('wrong_memory_type',{'cpu_page_type':7}),
 ('UC_only_not_exact_observed',{'cpu_page_attributes':1}),('RP_reported',{'cpu_page_attributes':0x8000000000002001}),('WB_capability_not_exact',{'cpu_page_attributes':0x8000000000000009}),('reserved_attributes',{'cpu_page_attributes':0x8000000000400001}),
 ('duplicate_overlap',{'cpu_overlap':True}),('partial_overlap',{'cpu_partial_overlap':True}),('zero_page_descriptor',{'cpu_bad_map':'zero'}),('overflow_descriptor',{'cpu_bad_map':'overflow'}),('unaligned_descriptor',{'cpu_bad_map':'alignment'}),('unknown_type_descriptor',{'cpu_bad_map':'type'}),
 ('first_map_failure',{'cpu_map_fail_at':2}),('second_map_failure',{'cpu_map_fail_at':3}),('map_too_large',{'cpu_map_oversize_at':2}),('bad_map_stride',{'cpu_map_bad_stride_at':2}),('bad_map_version',{'cpu_map_bad_version_at':2}),('map_changed_after_lookup',{'cpu_map_changed_after_lookup':True}),
 ('no_interface',{'cpu_enum_fail':True}),('zero_interfaces',{'cpu_count':0}),('multiple_interfaces',{'cpu_count':2}),('unreadable_handles',{'cpu_handles_outside_ram':True}),('protocol_failure',{'cpu_protocol_fail':True}),('handle_release_failure',{'cpu_free_failure':True}),
 ('unreadable_interface',{'cpu_interface_outside_ram':True}),('NULL_method',{'cpu_null_method':True}),('method_in_data',{'cpu_method_in_data':True}),('method_no_code_mapping',{'cpu_no_code_map':True}),('method_wrong_type',{'cpu_code_type':4}),('method_RP',{'cpu_code_attributes':0x2000}),('method_XP',{'cpu_code_attributes':0x4000}),
 ('ID_changed_after_lookup',{'cpu_target_change_offset':0,'cpu_target_change_value':0x7a248086}),('revision_changed_after_lookup',{'cpu_target_change_offset':8,'cpu_target_change_value':0x0c800012}),('BAR_changed_after_lookup',{'cpu_target_change_offset':0x10,'cpu_target_change_value':0xfe020000}),('decode_disabled_after_lookup',{'cpu_target_change_offset':4,'cpu_target_change_value':0}),('BDF_changed_after_lookup',{'cpu_target_location_change':True}),('SMBIOS_changed_after_lookup',{'cpu_identity_changes':True})]:ct('CPU_reject_'+name,**options)
for offset in OFFSETS:ct(f'CPU_stop_first_error_{offset:02X}',cpu_read_fail=offset,cpu_read_count=OFFSETS.index(offset)+1)
ct('CPU_UNSUPPORTED_stops_no_raw_fallback',cpu_read_fail=0,cpu_fail_status=ERR(3),cpu_read_count=1)
ct('CPU_all_ones_stops',cpu_all_ones=0x50,cpu_read_count=3)
ct('CPU_busy_stops',cpu_busy=True,cpu_read_count=2)
ct('CPU_invalid_FD_stops',cpu_invalid_fd=True,cpu_read_count=2)
ct('CPU_not_attempted_after_RootRead_error',no_mem_resource=False,root_read_fail=4,root_read_expected=True,no_cpu_enum=True)
ct('CPU_not_attempted_when_Root_read_succeeds',no_mem_resource=False,root_read_expected=True,no_cpu_enum=True,expected=0)
ct('CPU_not_attempted_when_PCI_works',pci_all_unsupported=False,no_cpu_enum=True,expected=0)
ct('CPU_not_attempted_for_other_primary_error',primary_override_offset=0,primary_override_status=ERR(7),no_cpu_enum=True)
'''
assert anchor in s;s=s.replace(anchor,extra+'\n'+anchor)
s=s.replace("'inv03_additional_cases':len(cases)-89", "'inv03_additional_cases':68,'inv03_baseline_cases':157,'inv04_additional_cases':len(cases)-157")
(HERE/'verify_candidate.py').write_text(s,encoding='utf8')
print('INV04 CPU_IO2 native harness prepared')
