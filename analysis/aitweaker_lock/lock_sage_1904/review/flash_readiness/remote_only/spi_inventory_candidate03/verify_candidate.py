"""Execute the exact candidate EFI in Unicorn with explicit UEFI/PCI stubs.

All register values are synthetic. Invalid write/service slots trap; no device
operation occurs. Positive cases validate callback ABI and read allowlists,
not the presence, permissions, or behaviour of a physical W790 controller.
"""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys,uuid,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps'),str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
import pefile,unicorn as U
from unicorn import x86_const as R
from PIL import Image
from decode_captures import assemble,read_image,parse_frame
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=lambda v:struct.pack('<Q',v)
d=lambda v:struct.pack('<I',v)
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
ERR=lambda n:0x8000000000000000|n
pe=pefile.PE(str(OUT/'BOOTX64.EFI'));pe.relocate_image(BASE);image=pe.get_memory_mapped_image()
symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(OUT/'inventory.map').read_text(),re.M)}
OFFSETS=[0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94]
REGS={0:0x3fff3000,4:0xc000,0x50:0x0a0f0a0f,0x54:0,0x58:0x3fff3000,0x5c:0x06920001,0x60:0x7fff,0x64:0x7fff,0x68:0x7fff,0x84:0xbfff3000,0x88:0,0x8c:0,0x90:0,0x94:0}

def record(kind,length,strings):
    b=bytearray(length);b[0]=kind;b[1]=length
    if kind in (0,2):b[5]=1
    return bytes(b)+b'\0'.join(s.encode() for s in strings)+b'\0\0'

def execute(name,**opt):
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,(len(image)+4095)&~4095),(HEAP,0x20000),(STACK,0x20000),(STOP,0x1000)]:u.mem_map(a,n)
    u.mem_write(BASE,image)
    st=HEAP;bs=HEAP+0x1000;ct=HEAP+0x2000;eptr=HEAP+0x3000;table=HEAP+0x4000
    pcis=[HEAP+0x8000,HEAP+0x9000];handles=HEAP+0x7000
    board=opt.get('board','Pro WS W790E-SAGE SE');version=opt.get('version','1904');sm=opt.get('sm',3)
    raw=record(0,24,[version])+record(2,15,[board])+record(127,4,[])
    damage=opt.get('damage')
    if damage=='length':raw=raw[:1]+b'\xff'+raw[2:]
    if damage=='unterminated':raw=raw[:24]+b'A'*64
    if damage=='duplicate':raw=record(0,24,[version])+raw
    if sm==3:
        ep=bytearray(24);ep[:5]=b'_SM3_';ep[6]=24;ep[7:11]=bytes([3,6,0,1]);struct.pack_into('<IQ',ep,12,len(raw),table);ep[5]=(-sum(ep))&255
        guid='f2fd1544-9794-4a2c-992e-e5bbcf20e394'
    else:
        ep=bytearray(31);ep[:4]=b'_SM_';ep[5]=31;ep[6:8]=bytes([2,8]);ep[16:21]=b'_DMI_'
        struct.pack_into('<HIH',ep,22,len(raw),table,3);ep[21]=(-sum(ep[16:]))&255;ep[4]=(-sum(ep))&255
        guid='eb9d2d31-2d88-11d3-9a16-0090273fc14d'
    if damage=='checksum':ep[5 if sm==3 else 4]^=1
    if damage=='intermediate_checksum':ep[21]^=1;ep[4]=0;ep[4]=(-sum(ep))&255
    u.mem_write(table,raw);u.mem_write(eptr,bytes(ep));u.mem_write(ct,uuid.UUID(guid).bytes_le+q(eptr))
    u.mem_write(st+0x58,q(STOP+0x900)+q(bs)+q(opt.get('table_count',1))+q(ct))
    # Every unsupported Boot/Runtime/PCI method is a trap, including all write slots.
    for off in range(0x18,0x178,8):u.mem_write(bs+off,q(STOP+0x900))
    for off,value in {0x38:0x100,0x40:0x900,0x48:0x130,0x98:0x120,0xf8:0x900,0x100:0x170,0x138:0x110,0x140:0x1a0}.items():u.mem_write(bs+off,q(STOP+value))
    for p in pcis:
        for off in range(0,0xb0,8):u.mem_write(p+off,q(STOP+0x900))
        u.mem_write(p+0x10,q(0 if opt.get('no_mem') else STOP+0x160))
        u.mem_write(p+0x30,q(STOP+0x140));u.mem_write(p+0x70,q(STOP+0x150))
    u.mem_write(handles,q(pcis[0])+q(pcis[1]))

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
        if opt.get('unknown_descriptor'):rb=b'\x87'+rb[1:]
        if opt.get('bad_descriptor_length'):rb=rb[:1]+b'\x2a\0'+rb[3:]
        if opt.get('too_many_resources'):rb=mem*64
        else:rb+=bytes([0x79,0])
        if opt.get('bad_end_checksum'):
            bad=(1-sum(rb[:-1]))&255
            if not bad:bad=1
            assert (sum(rb[:-1])+bad)&255
            rb=rb[:-1]+bytes([bad])
        if opt.get('missing_end'):rb=rb[:-2]+b'\0\0'
        if opt.get('good_end_checksum'):rb=rb[:-1]+bytes([(-sum(rb[:-1]))&255])
        resource_bytes.append(rb);u.mem_write(resources[k],rb)
    u.mem_write(root_handles,q(roots[0])+q(roots[1]))
    cfg_calls=[];mem_calls=[];root_calls=[];observed=[];calls=[]
    def reg(r):return u.reg_read(r)
    def readq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def arg5():return readq(reg(R.UC_X86_REG_RSP)+0x28)
    def ret(value):
        sp=reg(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,value);u.reg_write(R.UC_X86_REG_RIP,readq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def hook(uc,address,size,data):
        if address==STOP:uc.emu_stop();return
        if address==symbols['kvm_present']:
            observed.append(bytes(u.mem_read(reg(R.UC_X86_REG_RDX),reg(R.UC_X86_REG_R8))))
            ret(0);return
        assert STOP+0x100<=address<STOP+0x200,f'Unapproved service or instruction {address:x}'
        a,b,c,e=map(reg,[R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9])
        if address==STOP+0x100:
            calls.append('GetMemoryMap')
            if opt.get('map_fail'):ret(ERR(5));return
            kind=11 if opt.get('map_mmio') else 4
            desc=struct.pack('<IIQQQQ',kind,0,HEAP,0,0x20,0)
            if opt.get('bar_map_metadata'):desc+=struct.pack('<IIQQQQ',11,0,0xfe010000,0,1,1)
            u.mem_write(b,desc);u.mem_write(a,q(len(desc)));u.mem_write(c,q(1));u.mem_write(e,q(opt.get('stride',40)));u.mem_write(arg5(),d(opt.get('map_version',1)));ret(0)
        elif address==STOP+0x110:
            assert a==2
            guid=bytes(u.mem_read(b,16))
            if guid==uuid.UUID('2f707ebb-4a1a-11d4-9a38-0090273fc14d').bytes_le:
                calls.append('LocateRootBridgeIo')
                if opt.get('root_enum_fail'):ret(ERR(14));return
                u.mem_write(e,q(opt.get('root_count',1)));u.mem_write(arg5(),q(root_handles));ret(0)
            else:
                calls.append('LocateHandleBuffer')
                if opt.get('enumeration_fail'):ret(ERR(14));return
                assert guid==uuid.UUID('4cf5b200-68b8-4ca5-9eec-b23e3f50029a').bytes_le
                u.mem_write(e,q(opt.get('count',1)));u.mem_write(arg5(),q(handles));ret(0)
        elif address==STOP+0x120:
            assert a in pcis+roots
            if a in roots:
                if opt.get('root_protocol_fail'):ret(ERR(3));return
            elif opt.get('protocol_fail'):ret(ERR(3));return
            u.mem_write(c,q(a));ret(0)
        elif address==STOP+0x130:calls.append('FreePool');assert a in [handles,root_handles];ret(0)
        elif address==STOP+0x140:
            assert b==2 and e==1 and c in [0,4,8,0x10,0xdc]
            cfg_calls.append([a,c]);
            if c==opt.get('cfg_fail'):ret(ERR(7));return
            vals={0:opt.get('id',0x7a248086),4:opt.get('command',2),8:opt.get('revclass',0x0c800011),0x10:opt.get('bar',0xfe010000),0xdc:opt.get('bc',0xa2)}
            if opt.get('id_changes') and c==0 and sum(x[1]==0 for x in cfg_calls)>1:vals[0]=opt.get('changed_id',0x7aa48086)
            if 'LocateRootBridgeIo' in calls and c==opt.get('target_change_offset'):vals[c]=opt['target_change_value']
            u.mem_write(arg5(),d(vals[c]));ret(0)
        elif address==STOP+0x150:
            if opt.get('location_fail'):ret(ERR(7));return
            for dest,value in zip([b,c,e,arg5()],[opt.get('segment',0),opt.get('bus',0),opt.get('device',31),4 if opt.get('target_location_change') and 'LocateRootBridgeIo' in calls else opt.get('function',5)]):u.mem_write(dest,q(value))
            ret(0)
        elif address==STOP+0x160:
            assert a in pcis and b==2 and c==0 and e in OFFSETS and arg5()==1
            mem_calls.append(e)
            if opt.get('pci_all_unsupported'):
                ret(opt.get('primary_override_status',ERR(3)) if e==opt.get('primary_override_offset') else ERR(3));return
            if e==opt.get('mmio_fail'):ret(ERR(7));return
            value=REGS[e]
            if e==opt.get('all_ones'):value=0xffffffff
            if e==4 and opt.get('invalid_fd'):value&=~0x4000
            if e==4 and opt.get('busy'):value|=0x20
            if e==0x84 and opt.get('rpe'):value|=0x8000
            u.mem_write(readq(reg(R.UC_X86_REG_RSP)+0x30),d(value));ret(0)
        elif address==STOP+0x170:
            assert (a,b,c,e)==(0,0,0,0);calls.append('SetWatchdogTimer(0)');ret(ERR(3) if opt.get('watchdog_fail') else 0)
        elif address==STOP+0x180:
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
        else:raise AssertionError(f'Unapproved service {address:x}')
    for addr in [STOP]+[STOP+x for x in [0x100,0x110,0x120,0x130,0x140,0x150,0x160,0x170,0x180,0x190,0x1a0,0x900]]+[symbols['kvm_present']]:u.hook_add(U.UC_HOOK_CODE,hook,begin=addr,end=addr)
    protected=[(root_handles,16)]+[(p,0x98) for p in roots]+[(p,len(raw)) for p,raw in zip(resources,resource_bytes)]+[(st,0x100),(bs,0x180),(ct,24),(eptr,len(ep)),(table,len(raw)),(handles,16)]+[(p,0xb0) for p in pcis]
    snapshots=[bytes(u.mem_read(a,n)) for a,n in protected]
    sp=STACK+0x1ff08;u.mem_write(sp,q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp);u.reg_write(R.UC_X86_REG_CR4,0x600)
    u.reg_write(R.UC_X86_REG_RCX,0);u.reg_write(R.UC_X86_REG_RDX,st)
    u.emu_start(symbols['efi_main'],STOP+0x1000,count=3000000)
    assert reg(R.UC_X86_REG_RIP)==STOP and len(observed)==1,name
    assert snapshots==[bytes(u.mem_read(a,n)) for a,n in protected],name+' modified protected inputs'
    log=observed[0];result=reg(R.UC_X86_REG_RAX)
    assert b'actual_component_capacity=null' in log and b'Flash bytes read=0' in log
    assert f'INVENTORY_STATUS=0x{result:016X}'.encode() in log
    wanted=opt.get('expected',0);assert result==wanted,(name,hex(result),log.decode())
    if opt.get('no_pci'):assert not cfg_calls and 'LocateHandleBuffer' not in calls,name
    if opt.get('no_mmio'):assert not mem_calls,name
    else:assert mem_calls==OFFSETS,name
    assert root_calls==(OFFSETS if opt.get('root_read_expected') else []),name
    if opt.get('no_root_enum'):assert 'LocateRootBridgeIo' not in calls,name
    if result==0:
        assert b'BASE=0x03000000 LIMIT=0x03FFFFFF ENABLED' in log
        assert b'FREG3 OFFSET=0x60 RAW=0x00007FFF BASE=0x07FFF000 LIMIT=0x00000FFF DISABLED' in log
    return {'name':name,'passed':True,'return_status':f'0x{result:016X}','pci_reads':len(cfg_calls),'mmio_reads':len(mem_calls),'write_calls':0,'root_mmio_reads':len(root_calls),'log_sha256':hashlib.sha256(log).hexdigest()},log

cases=[];positive=None
def test(name,**kw):
    global positive
    case,log=execute(name,**kw);cases.append(case)
    if positive is None:positive=log
test('exact_sage1904_14_registers')
test('SMBIOS2_exact',sm=2)
test('read_protected_range_is_observed_not_bypassed',rpe=True)
test('busy_controller_only_observed_and_partial',busy=True,expected=ERR(7))
test('watchdog_failure_recorded_and_partial',watchdog_fail=True,expected=ERR(7))
test('BC_all_ones_is_untrusted_and_partial',bc=0xffffffff,expected=ERR(7))
for name,kw in [
 ('ACE_identity',{'board':'Pro WS W790-ACE'}),('W890_identity',{'board':'Pro WS W890E-SAGE SE'}),
 ('BIOS2003',{'version':'2003'}),('BIOS_suffix',{'version':'1904x'}),('board_suffix',{'board':'Pro WS W790E-SAGE SE X'}),
 ('SMBIOS3_checksum',{'damage':'checksum'}),('SMBIOS2_checksum',{'sm':2,'damage':'checksum'}),
 ('SMBIOS2_intermediate_checksum',{'sm':2,'damage':'intermediate_checksum'}),('malformed_record',{'damage':'length'}),
 ('unterminated_record',{'damage':'unterminated'}),('duplicate_type0',{'damage':'duplicate'}),
 ('memory_map_failure',{'map_fail':True}),('memory_map_MMIO',{'map_mmio':True}),
 ('bad_map_stride',{'stride':39}),('unknown_map_version',{'map_version':2}),('excess_CT_count',{'table_count':257})]:test(name,**kw,expected=ERR(3),no_pci=True,no_mmio=True)
for name,kw,status in [
 ('unsupported_SPI_7AA5',{'id':0x7aa58086},3),('unknown_SPI',{'id':0x12348086},3),('wrong_vendor',{'id':0x7a241234},3),
 ('wrong_segment',{'segment':1},3),('wrong_bus',{'bus':1},3),('wrong_device',{'device':30},3),('wrong_function',{'function':4},3),
 ('ambiguous_SPI',{'count':2},3),('no_handles',{'count':0},3),('too_many_handles',{'count':4097},3),
 ('enumeration_failed',{'enumeration_fail':True},14),('protocol_failed',{'protocol_fail':True},3),
 ('location_failed',{'location_fail':True},3),('missing_mem_read',{'no_mem':True},3),
 ('memory_decode_disabled',{'command':0},3),('command_all_ones',{'command':0xffffffff},3),
 ('zero_BAR',{'bar':0},3),('all_ones_BAR',{'bar':0xffffffff},3),('IO_BAR',{'bar':0xfe010001},3),
 ('64bit_BAR',{'bar':0xfe010004},3),('BAR_reserved_sizebits',{'bar':0xfe010010},3),
 ('ID_changed_between_enumeration_and_read',{'id_changes':True},7),
 ('BAR_config_read_failed',{'cfg_fail':0x10},7),('BC_config_read_failed',{'cfg_fail':0xdc},7)]:test(name,**kw,expected=ERR(status),no_mmio=True)
for offset in OFFSETS:test(f'MMIO_read_failed_{offset:02x}',mmio_fail=offset,expected=ERR(7))
test('MMIO_all_ones',all_ones=0x50,expected=ERR(7))
test('descriptor_invalid_flag',invalid_fd=True,expected=ERR(7))

# INV01 has 62 baseline cases. Its unsupported-ID example now uses 7AA5;
# 7AA4 is intentionally supported only under the new observed class/revision gate.
assert len(cases)==62
test('7AA4_actual_revision_class_positive',id=0x7aa48086)
_,positive=execute('7AA4_QR_log',id=0x7aa48086)
test('7AA4_SMBIOS2_positive',id=0x7aa48086,sm=2)
for name,kw,status in [
 ('7AA4_unknown_revision',{'revclass':0x0c800012},3),
 ('7AA4_wrong_class',{'revclass':0x06010011},3),
 ('7AA4_wrong_location',{'function':4},3),
 ('7AA4_decode_disabled',{'command':0},3),
 ('7AA4_zero_BAR',{'bar':0},3),
 ('7AA4_64bit_BAR',{'bar':0xfe010004},3),
 ('7AA4_ID_changed_to_allowed_7A24',{'id_changes':True,'changed_id':0x7a248086},7),
 ('7AA4_ambiguous_handles',{'count':2},3)]:
    test(name,id=0x7aa48086,**kw,expected=ERR(status),no_mmio=True)
test('7AA4_wrong_vendor',id=0x7aa41234,expected=ERR(3),no_mmio=True)
test('7AA4_wrong_board_identity',id=0x7aa48086,board='Pro WS W790-ACE',expected=ERR(3),no_pci=True,no_mmio=True)
test('7AA4_busy_is_partial',id=0x7aa48086,busy=True,expected=ERR(7))
for offset in OFFSETS:test(f'7AA4_MMIO_read_failed_{offset:02x}',id=0x7aa48086,mmio_fail=offset,expected=ERR(7))


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

(OUT/'synthetic-positive-log.txt').write_bytes(positive)

# Exact compiled QR code + unchanged existing P3 framing/decoder, on this log.
dll=ctypes.CDLL(str(OUT/'qr_test.dll'))
dll.kvm_make_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t];dll.kvm_make_frame.restype=ctypes.c_size_t
dll.kvm_encode_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p];dll.kvm_encode_frame.restype=ctypes.c_int
dll.qrcodegen_getSize.argtypes=[ctypes.c_void_p];dll.qrcodegen_getSize.restype=ctypes.c_int
dll.qrcodegen_getModule.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];dll.qrcodegen_getModule.restype=ctypes.c_bool
qrdir=OUT/'synthetic-qr';qrdir.mkdir(exist_ok=True);frames=[]
for page in range((len(positive)+767)//768):
    buf=ctypes.create_string_buffer(1000);n=dll.kvm_make_frame(positive,len(positive),page,buf,1000);expected=buf.raw[:n]
    qr=ctypes.create_string_buffer(2500);scratch=ctypes.create_string_buffer(2500);assert dll.kvm_encode_frame(positive,len(positive),page,qr,scratch)==1
    side=dll.qrcodegen_getSize(qr);im=Image.new('L',((side+8)*4,)*2,255);pix=im.load()
    for y in range(side):
        for x in range(side):
            if dll.qrcodegen_getModule(qr,x,y):
                for dy in range(4):
                    for dx in range(4):pix[(x+4)*4+dx,(y+4)*4+dy]=0
    path=qrdir/f'page-{page+1}.png';im.save(path);frame=read_image(path);assert frame==expected;frames.append(frame)
restored,metadata=assemble(frames,require_inventory=False);assert restored==positive
bad=bytearray(frames[0]);bad[-1]^=1
for broken in [frames[:-1],[bytes(bad)]+frames[1:]]:
    try:assemble(broken,require_inventory=False)
    except ValueError:pass
    else:raise AssertionError('Incomplete/corrupt inventory accepted')
report={'status':'PASS_LOCAL_SIMULATION_ONLY','hardware_tested':False,'efi_sha256':sha(OUT/'BOOTX64.EFI'),'source_sha256':sha(HERE/'source/inventory.c'),'build_sha256':sha(OUT/'build.json'),'test_source_sha256':sha(Path(__file__)),'cases':cases,'case_count':len(cases),'inv01_baseline_cases':62,'inv02_additional_cases':27,'inv02_baseline_cases':89,'inv03_additional_cases':len(cases)-89,'qr_pages':len(frames),'qr_log_bytes':len(positive),'qr_whole_crc32':f'{zlib.crc32(positive):08X}','qr_test_dll_sha256':sha(OUT/'qr_test.dll'),'qr_decoder_sha256':sha(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py'),'qr_roundtrip_byte_identical':True,'missing_page_and_corrupt_crc_rejected':True,'limitations':['All PCI/MMIO return values and UEFI inventory services are explicit synthetic stubs.','Test does not prove real SAGE exposes PCI_IO for SPI, that nominal 7A24 is its ID, or that any flash region is readable.','No flash READ cycle or real hardware operation was attempted.']}
(OUT/'local_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','case_count','efi_sha256','qr_pages','qr_log_bytes']},indent=2))
