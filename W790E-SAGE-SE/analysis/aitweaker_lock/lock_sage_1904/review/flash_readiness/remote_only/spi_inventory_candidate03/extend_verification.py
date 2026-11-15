"""Add root-bridge fixtures to the copied INV02 native harness (local only)."""
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=(HERE.with_name('spi_inventory_candidate02')/'verify_candidate.py').read_text(encoding='utf8')
s=s.replace("cfg_calls=[];mem_calls=[];observed=[];calls=[]", "cfg_calls=[];mem_calls=[];root_calls=[];observed=[];calls=[]")
s=s.replace("0x140:0x900", "0x140:0x1a0")
anchor="    cfg_calls=[];mem_calls=[];root_calls=[];observed=[];calls=[]"
extra='''
    roots=[HEAP+0xa000,HEAP+0xb000];resources=[HEAP+0xc000,HEAP+0xd000];root_handles=HEAP+0xe000
    def descriptor(kind,lo,hi,gran=0,trans=0,length=None,gen=0,spec=0):
        return struct.pack('<BHBBBQQQQQ',0x8a,43,kind,gen,spec,gran,lo,hi,trans,hi-lo+1 if length is None else length)
    resource_bytes=[]
    for k,root in enumerate(roots):
        for off in range(0,0x98,8):u.mem_write(root+off,q(STOP+0x900))
        u.mem_write(root+0x18,q(0 if opt.get('root_no_read') else STOP+0x190))
        u.mem_write(root+0x88,q(0 if opt.get('root_no_config') else STOP+0x180))
        u.mem_write(root+0x90,d(opt.get('root_segment',0) if k==0 else opt.get('second_segment',0)))
        bus=descriptor(2,opt.get('root_bus_min',0),opt.get('root_bus_max',255),trans=opt.get('bus_translation',0),gen=opt.get('bus_gen',0),spec=opt.get('bus_spec',0))
        mem=descriptor(0,opt.get('root_mem_min',0xfe000000),opt.get('root_mem_max',0xfeffffff),opt.get('mem_gran',32),opt.get('mem_translation',0),opt.get('mem_length'),opt.get('mem_gen',0),opt.get('mem_spec',0))
        rb=(b'' if opt.get('no_bus_resource') else bus)+(b'' if opt.get('no_mem_resource') else mem)
        if opt.get('duplicate_bus'):rb+=bus
        if opt.get('duplicate_mem'):rb+=mem
        if opt.get('unknown_descriptor'):rb=b'\\x87'+rb[1:]
        if opt.get('bad_descriptor_length'):rb=rb[:1]+b'\\x2a\\0'+rb[3:]
        if opt.get('too_many_resources'):rb=mem*64
        else:rb+=bytes([0x79,0])
        if opt.get('bad_end_checksum'):
            bad=(1-sum(rb[:-1]))&255
            if not bad:bad=1
            assert (sum(rb[:-1])+bad)&255
            rb=rb[:-1]+bytes([bad])
        if opt.get('missing_end'):rb=rb[:-2]+b'\\0\\0'
        if opt.get('good_end_checksum'):rb=rb[:-1]+bytes([(-sum(rb[:-1]))&255])
        resource_bytes.append(rb);u.mem_write(resources[k],rb)
    u.mem_write(root_handles,q(roots[0])+q(roots[1]))
'''
assert anchor in s;s=s.replace(anchor,extra+anchor)
s=s.replace("desc=struct.pack('<IIQQQQ',kind,0,HEAP,0,0x20,0)","desc=struct.pack('<IIQQQQ',kind,0,HEAP,0,0x20,0)\n            if opt.get('bar_map_metadata'):desc+=struct.pack('<IIQQQQ',11,0,0xfe010000,0,1,1)")
old='''            calls.append('LocateHandleBuffer')
            if opt.get('enumeration_fail'):ret(ERR(14));return
            assert a==2 and bytes(u.mem_read(b,16))==uuid.UUID('4cf5b200-68b8-4ca5-9eec-b23e3f50029a').bytes_le
            u.mem_write(e,q(opt.get('count',1)));u.mem_write(arg5(),q(handles));ret(0)'''
new='''            assert a==2
            guid=bytes(u.mem_read(b,16))
            if guid==uuid.UUID('2f707ebb-4a1a-11d4-9a38-0090273fc14d').bytes_le:
                calls.append('LocateRootBridgeIo')
                if opt.get('root_enum_fail'):ret(ERR(14));return
                u.mem_write(e,q(opt.get('root_count',1)));u.mem_write(arg5(),q(root_handles));ret(0)
            else:
                calls.append('LocateHandleBuffer')
                if opt.get('enumeration_fail'):ret(ERR(14));return
                assert guid==uuid.UUID('4cf5b200-68b8-4ca5-9eec-b23e3f50029a').bytes_le
                u.mem_write(e,q(opt.get('count',1)));u.mem_write(arg5(),q(handles));ret(0)'''
assert old in s;s=s.replace(old,new)
old='''            assert a in pcis
            if opt.get('protocol_fail'):ret(ERR(3));return
            u.mem_write(c,q(a));ret(0)'''
new='''            assert a in pcis+roots
            if a in roots:
                if opt.get('root_protocol_fail'):ret(ERR(3));return
            elif opt.get('protocol_fail'):ret(ERR(3));return
            u.mem_write(c,q(a));ret(0)'''
assert old in s;s=s.replace(old,new)
s=s.replace("assert a==handles;ret(0)","assert a in [handles,root_handles];ret(0)")
s=s.replace("u.mem_write(arg5(),d(vals[c]));ret(0)","if 'LocateRootBridgeIo' in calls and c==opt.get('target_change_offset'):vals[c]=opt['target_change_value']\n            u.mem_write(arg5(),d(vals[c]));ret(0)")
s=s.replace("for dest,value in zip([b,c,e,arg5()],[opt.get('segment',0),opt.get('bus',0),opt.get('device',31),opt.get('function',5)]):", "for dest,value in zip([b,c,e,arg5()],[opt.get('segment',0),opt.get('bus',0),opt.get('device',31),4 if opt.get('target_location_change') and 'LocateRootBridgeIo' in calls else opt.get('function',5)]):")
s=s.replace("mem_calls.append(e)\n            if e==opt.get('mmio_fail')", "mem_calls.append(e)\n            if opt.get('pci_all_unsupported'):\n                ret(opt.get('primary_override_status',ERR(3)) if e==opt.get('primary_override_offset') else ERR(3));return\n            if e==opt.get('mmio_fail')")
anchor="        else:raise AssertionError(f'Unapproved service {address:x}')"
extra='''        elif address==STOP+0x180:
            assert a in roots
            if opt.get('root_config_fail') or (a==roots[1] and opt.get('second_config_fail')):ret(ERR(3));return
            ptr=resources[roots.index(a)]
            if opt.get('resource_null'):ptr=0
            if opt.get('resource_wrap'):ptr=0xfffffffffffffff0
            if opt.get('resource_outside_ram'):ptr=0xfe010000
            if opt.get('resource_truncated'):ptr=HEAP+0x1fff0
            u.mem_write(b,q(ptr));ret(0)
        elif address==STOP+0x190:
            assert a in roots and b==2 and e==1 and c in [0xfe010000+x for x in OFFSETS]
            offset=c-0xfe010000;root_calls.append(offset)
            if offset==opt.get('root_read_fail'):ret(opt.get('root_fail_status',ERR(7)));return
            value=REGS[offset]
            if offset==opt.get('root_all_ones'):value=0xffffffff
            if offset==4 and opt.get('root_busy'):value|=0x20
            u.mem_write(arg5(),d(value));ret(0)
        elif address==STOP+0x1a0:
            assert bytes(u.mem_read(a,16))==uuid.UUID('ad61f191-ae5f-4c0e-b9fa-e869d288c64f').bytes_le
            assert b==0
            calls.append('LocateCpuIo2Only')
            if opt.get('cpuio2_present'):u.mem_write(c,q(STOP+0x900));ret(0)
            else:ret(ERR(14))
'''
assert anchor in s;s=s.replace(anchor,extra+anchor)
s=s.replace('0x160,0x170,0x900','0x160,0x170,0x180,0x190,0x1a0,0x900')
s=s.replace("protected=[(st,0x100)","protected=[(root_handles,16)]+[(p,0x98) for p in roots]+[(p,len(raw)) for p,raw in zip(resources,resource_bytes)]+[(st,0x100)")
s=s.replace("else:assert mem_calls==OFFSETS,name", "else:assert mem_calls==OFFSETS,name\n    assert root_calls==(OFFSETS if opt.get('root_read_expected') else []),name\n    if opt.get('no_root_enum'):assert 'LocateRootBridgeIo' not in calls,name")
s=s.replace("'write_calls':0,", "'write_calls':0,'root_mmio_reads':len(root_calls),")
anchor="(OUT/'synthetic-positive-log.txt').write_bytes(positive)"
extra='''
assert len(cases)==89
def rt(name,**kw):
    options={'id':0x7aa48086,'pci_all_unsupported':True,'expected':ERR(7)};options.update(kw);test(name,**options)
rt('ROOT_exact_observed_binding_positive',root_read_expected=True,expected=0)
_,positive=execute('ROOT_QR_LOG',id=0x7aa48086,pci_all_unsupported=True,root_read_expected=True,expected=0,bar_map_metadata=True,cpuio2_present=True)
rt('ROOT_valid_nonzero_EndTag_checksum',good_end_checksum=True,root_read_expected=True,expected=0)
rt('ROOT_unique_among_other_segment',root_count=2,second_segment=1,root_read_expected=True,expected=0)
rt('ROOT_metadata_only_map_and_CPU_IO2',bar_map_metadata=True,cpuio2_present=True,root_read_expected=True,expected=0)
for name,options in [
 ('no_interface',{'root_enum_fail':True}),('empty_list',{'root_count':0}),('excess_list',{'root_count':33}),
 ('ambiguous_bus0',{'root_count':2}),('other_segment',{'root_segment':1}),('unknown_other_segment0_config',{'root_count':2,'second_config_fail':True}),
 ('protocol_failure',{'root_protocol_fail':True}),('no_mem_read_method',{'root_no_read':True}),('no_config_method',{'root_no_config':True}),('config_failure',{'root_config_fail':True}),
 ('missing_bus_resource',{'no_bus_resource':True}),('bus_does_not_cover0',{'root_bus_min':1}),('invalid_bus_limit',{'root_bus_max':256}),('duplicate_bus',{'duplicate_bus':True}),
 ('missing_memory_resource',{'no_mem_resource':True}),('memory_does_not_cover_BAR',{'root_mem_max':0xfe00ffff}),('memory_short_last_dword',{'root_mem_min':0xfe010000,'root_mem_max':0xfe010096}),('overlapping_memory_resources',{'duplicate_mem':True}),
 ('bus_translation',{'bus_translation':1}),('memory_translation',{'mem_translation':0x1000}),('consumer_resource',{'mem_gen':1}),('subtractive_decode',{'mem_gen':2}),('memory_to_IO_translation',{'mem_spec':0x20}),('reserved_general_flags',{'mem_gen':0x10}),('reserved_specific_flags',{'mem_spec':0x80}),('bus_specific_flags',{'bus_spec':1}),
 ('bad_memory_length',{'mem_length':1}),('bad_granularity',{'mem_gran':0}),('unknown_descriptor',{'unknown_descriptor':True}),('wrong_payload_length',{'bad_descriptor_length':True}),('missing_EndTag',{'missing_end':True}),('bad_EndTag_checksum',{'bad_end_checksum':True}),('too_many_resources',{'too_many_resources':True}),
 ('NULL_resources',{'resource_null':True}),('pointer_wrap',{'resource_wrap':True}),('descriptor_in_MMIO',{'resource_outside_ram':True}),('truncated_descriptor',{'resource_truncated':True}),
 ('ID_changed_after_selection',{'target_change_offset':0,'target_change_value':0x7a248086}),('revision_changed_after_selection',{'target_change_offset':8,'target_change_value':0x0c800012}),('BAR_changed_after_selection',{'target_change_offset':0x10,'target_change_value':0xfe020000}),('decode_disabled_after_selection',{'target_change_offset':4,'target_change_value':0}),('BDF_changed_after_selection',{'target_location_change':True}),
 ('CPU_IO2_presence_does_not_bypass_missing_window',{'no_mem_resource':True,'bar_map_metadata':True,'cpuio2_present':True})]:rt('ROOT_reject_'+name,**options)
rt('ROOT_7A24_not_eligible',id=0x7a248086,no_root_enum=True)
rt('ROOT_other_valid_BAR_not_eligible',bar=0xfe020000,no_root_enum=True)
rt('ROOT_mixed_primary_error_not_eligible',primary_override_offset=0x50,primary_override_status=ERR(7),no_root_enum=True)
rt('ROOT_partial_primary_support_not_eligible',primary_override_offset=0x50,primary_override_status=0,no_root_enum=True)
for offset in OFFSETS:rt(f'ROOT_read_failure_{offset:02X}',root_read_fail=offset,root_read_expected=True)
rt('ROOT_read_UNSUPPORTED_is_not_flash_protection',root_read_fail=4,root_fail_status=ERR(3),root_read_expected=True)
rt('ROOT_all_ones_is_untrusted',root_all_ones=0x50,root_read_expected=True)
rt('ROOT_busy_is_partial',root_busy=True,root_read_expected=True)
'''
assert anchor in s;s=s.replace(anchor,extra+'\n'+anchor)
s=s.replace("'inv02_additional_cases':len(cases)-62", "'inv02_additional_cases':27,'inv02_baseline_cases':89,'inv03_additional_cases':len(cases)-89")
(HERE/'verify_candidate.py').write_text(s,encoding='utf8')
print('Extended harness source prepared')
