"""Run the actual CAP02 EFI bytes with explicit UEFI providers in Unicorn.
Unknown services, raw USB, SCSI reset, pass-through, file and block methods trap.
Provider behavior is synthetic: this is not a USB controller or target test.
"""
from pathlib import Path
import copy,hashlib,json,re,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
E=lambda n:(1<<63)|n;Q=lambda n:struct.pack('<Q',n);D=lambda n:struct.pack('<I',n)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
PIN=bytes.fromhex('02010C00D041030A00000000010106000014030506000C000305060001007FFF0400')
GUIDS={uuid.UUID(v).bytes_le:k for k,v in {'usb':'2b2f68d6-0cd2-44cf-8e8b-bba20b1b5b75','bio':'964e5b21-6459-11d2-8e39-00a0c969723b','fs':'964e5b22-6459-11d2-8e39-00a0c969723b','dp':'09576e91-6d3f-11d2-8e39-00a0c969723b','scsi':'932f47e6-2362-4002-803e-3cd54b138f85','ext':'143b7632-b81b-4cb7-abd3-b625a5b9bffe','ata':'2e3ab8b6-ac9d-4d70-a675-54f52fb22d66'}.items()}
pe=pefile.PE(str(HERE/'build/BOOTX64.EFI'));pe.relocate_image(BASE);IMAGE=pe.get_memory_mapped_image()
SYMBOLS={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(HERE/'build/capacity.map').read_text(),re.M)}
def device(**kw):
    d=dict(usb=True,bio=True,fs=False,scsi=True,ext=False,ata=False,path='pinned',vid=0x046b,pid=0xff31,present=1,readonly=0,removable=1,partition=0,cache=0,block=1024,last=0x40000,id=7,align=0,scsi_align=0,class_=8,subclass=6,protocol=0x50,endpoints=2,interface=0,alternate=0)
    d.update(kw);return d
def controller(**kw):
    base=dict(usb=False,bio=False,scsi=False);base.update(kw);return device(**base)
def others():return [device(pid=0xff20,scsi=False,path='other',fs=True,block=2048,last=0x2038,readonly=1),controller(path='ancestor',ext=True),controller(path='internal',ata=True)]
def path_bytes(kind):
    paths={'pinned':PIN,'other':PIN[:-6]+b'\x02\x00'+PIN[-4:], 'ancestor':PIN[:18]+PIN[-4:],
      'internal':b'\x01\x01\x06\0\0\0\x7f\xff\x04\0','lun0':PIN[:-4]+b'\x03\x11\x05\x00\x00'+PIN[-4:],
      'lun1':PIN[:-4]+b'\x03\x11\x05\x00\x01'+PIN[-4:], 'descendant':PIN[:-4]+b'\x03\x05\x06\0\x02\0'+PIN[-4:],
      'malformed':b'\x03\x05\x03\0','multi':PIN[:-4]+b'\x7f\x01\x04\0'+PIN,
      'oversize':b'\x03\x05\xff\xff','many_nodes':b'\x01\x04\x04\0'*65,
      'long':b'\x03\x05\xfc\x07'+b'\x5a'*2040+b'\x7f\xff\x04\0','null':b'\0'*16}
    return paths[kind]
def execute(name,devices=None,**opt):
    devices=copy.deepcopy(devices if devices is not None else [device()]+others());u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,(len(IMAGE)+4095)&~4095),(HEAP,0x1000000),(STACK,0x30000),(STOP,0x2000)]:u.mem_map(a,n)
    u.mem_write(BASE,IMAGE);st=HEAP;bs=HEAP+0x1000;nextmem=HEAP+0x20000
    handles={};providers={};allocations=set();calls=[];logs=[];requests=[]
    def alloc(n=256):
        nonlocal nextmem
        a=nextmem;nextmem+=(n+255)&~255;assert nextmem<HEAP+0x1000000;return a
    def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(v):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,v);u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def guid(p):return GUIDS[bytes(u.mem_read(p,16))]
    for dev in devices:
        h=alloc();handles[h]=dev;dev['h']=h;dev['device_calls']=0;dev['scsi_lookups']=0
        for kind in ['dp','usb','bio','media','fs','scsi','ext','ata','target']:
            p=alloc(4096 if kind=='dp' else 256);dev[kind+'_ptr']=p;providers[p]=dev
        u.mem_write(dev['dp_ptr'],path_bytes(dev['path']))
        m=bytearray(32);struct.pack_into('<I',m,0,dev['id']);m[4:9]=bytes([dev[k] for k in ['removable','present','partition','readonly','cache']]);struct.pack_into('<II',m,12,dev['block'],dev['align']);struct.pack_into('<Q',m,24,dev['last']);u.mem_write(dev['media_ptr'],bytes(m))
        u.mem_write(dev['bio_ptr'],Q(0x2001f)+Q(0 if dev.get('media_null') else dev['media_ptr'])+Q(STOP+0x900)*4)
        u.mem_write(dev['usb_ptr'],Q(STOP+0x900)*6+Q(0 if dev.get('no_device_method') else STOP+0x140)+Q(STOP+0x900)+Q(0 if dev.get('no_interface_method') else STOP+0x150))
        u.mem_write(dev['fs_ptr'],Q(0x10000)+Q(STOP+0x900))
        u.mem_write(dev['scsi_ptr'],Q(0 if dev.get('no_type') else STOP+0x160)+Q(0 if dev.get('no_location') else STOP+0x170)+Q(STOP+0x900)*2+Q(0 if dev.get('no_execute') else STOP+0x180)+D(dev['scsi_align'])+D(0))
        u.mem_write(dev['ext_ptr'],Q(STOP+0x900)*12);u.mem_write(dev['ata_ptr'],Q(STOP+0x900)*12)
    u.mem_write(st+0x58,Q(STOP+0x900)+Q(bs))
    for off in range(0x18,0x178,8):u.mem_write(bs+off,Q(STOP+0x900))
    for off,fn in {0x48:0x110,0x98:0x120,0x100:0x100,0x138:0x130}.items():u.mem_write(bs+off,Q(STOP+fn))
    for field,off in [('no_watchdog',0x100),('no_locate',0x138),('no_handle_protocol',0x98),('no_free',0x48)]:
        if opt.get(field):u.mem_write(bs+off,Q(0))
    def hook(uc,a,n,unused):
        if a==STOP:uc.emu_stop();return
        if a==SYMBOLS['kvm_present']:
            x,y,z,w=[uc.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
            assert x==st and 0<z<32768;logs.append(bytes(uc.mem_read(y,z)));calls.append('QR_UI');ret(E(7) if opt.get('qr_fail') else 0);return
        if not STOP<=a<STOP+0x2000:return
        assert a in [STOP+n for n in range(0x100,0x190,0x10)],(name,'FORBIDDEN SERVICE',hex(a))
        x,y,z,w=[uc.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
        fifth=rq(uc.reg_read(R.UC_X86_REG_RSP)+0x28)
        if a==STOP+0x100:
            assert x==y==z==w==0;calls.append('disable_watchdog');ret(E(7) if opt.get('watchdog_fail') else 0)
        elif a==STOP+0x110:
            assert x in allocations;allocations.remove(x);calls.append('free_metadata_buffer');ret(E(7) if opt.get('free_fail') else 0)
        elif a==STOP+0x130:
            assert x==2 and z==0;g=guid(y);assert g in ['usb','scsi','ext','ata'];calls.append('locate_'+g)
            found=[h for h,d in handles.items() if d[g]]
            if opt.get('duplicate_list')==g and found:found.append(found[0])
            if opt.get('null_handle')==g:found.append(0)
            if opt.get('locate_error')==g:ret(E(7));return
            if opt.get('locate_oversize')==g:
                p=alloc(8);allocations.add(p);u.mem_write(w,Q(129));u.mem_write(fifth,Q(p));ret(0);return
            if not found:ret(E(14));return
            p=alloc(len(found)*8);allocations.add(p);u.mem_write(p,b''.join(Q(h) for h in found));u.mem_write(w,Q(len(found)));u.mem_write(fifth,Q(p));ret(E(7) if opt.get('locate_error_with_buffer')==g else 0)
        elif a==STOP+0x120:
            assert x in handles;dev=handles[x];g=guid(y);calls.append('metadata_protocol_'+g)
            if dev.get('protocol_error')==g:ret(E(7));return
            if dev.get('protocol_missing')==g:ret(E(3));return
            if g!='dp' and not dev[g]:ret(E(3));return
            pointer=dev[g+'_ptr']
            if (g=='dp' and dev['path']=='null') or dev.get('protocol_null')==g:pointer=0
            if g=='scsi':
                dev['scsi_lookups']+=1
                if opt.get('owner_changes') and dev['scsi_lookups']>1:pointer=dev['ext_ptr']
            if opt.get('after_media_error') and g=='bio' and requests:ret(E(7));return
            u.mem_write(z,Q(pointer));ret(0)
        elif a in (STOP+0x140,STOP+0x150):
            assert x in providers;dev=providers[x];isdev=a==STOP+0x140;calls.append('cached_device_descriptor' if isdev else 'cached_interface_descriptor')
            if dev.get('device_error' if isdev else 'interface_error'):ret(E(7));return
            if isdev:
                dev['device_calls']+=1
                b=bytearray(18);b[:2]=b'\x12\x01';b[4:7]=bytes([0,0,0]);struct.pack_into('<HH',b,8,dev['vid'],dev['pid']);b[17]=1
                if dev.get('bad_device'):b[0]=17
                if opt.get('device_changes') and dev['device_calls']>1:b[8]^=1
                if opt.get('path_changes') and dev['device_calls']>1:u.mem_write(dev['dp_ptr'],path_bytes('other'))
                if opt.get('media_changes_before') and dev['device_calls']>1:u.mem_write(dev['media_ptr']+12,D(4096))
            else:
                b=bytearray([9,4,dev['interface'],dev['alternate'],dev['endpoints'],dev['class_'],dev['subclass'],dev['protocol'],0])
                if dev.get('bad_interface'):b[1]=5
            u.mem_write(y,bytes(b));ret(0)
        elif a==STOP+0x160:
            assert x in providers;calls.append('scsi_get_type');u.mem_write(y,bytes([opt.get('device_type',0)]));ret(E(7) if opt.get('type_error') else 0)
        elif a==STOP+0x170:
            assert x in providers;calls.append('scsi_get_location');dev=providers[x];u.mem_write(y,Q(0 if opt.get('null_target') else dev['target_ptr']));u.mem_write(z,Q(opt.get('lun',0)));ret(E(7) if opt.get('location_error') else 0)
        elif a==STOP+0x180:
            assert x in providers and z==0 and len(requests)==0;dev=providers[x];p=bytes(u.mem_read(y,56))
            timeout,indata,outdata,sense,cdb,inlen,outlen=struct.unpack_from('<QQQQQII',p)
            assert timeout==20000000 and inlen==8 and outlen==0 and outdata==sense==0 and p[48:53]==bytes([10,0,255,255,0])
            assert bytes(u.mem_read(cdb,10))==bytes.fromhex('25000000000000000000') and indata%4096==0
            assert dev['scsi_align']<=1 or indata%dev['scsi_align']==0
            calls.append('scsi_RC10_only');requests.append({'cdb_hex':'25000000000000000000','input_bytes':inlen,'output_bytes':0,'timeout_100ns':timeout,'event_null':True,'via_existing_scsi_io':True})
            answer=bytes.fromhex(opt.get('answer','00007fff00000200'));assert len(answer)==8
            u.mem_write(indata,answer);u.mem_write(y+40,D(opt.get('returned_length',8)));u.mem_write(y+50,bytes([opt.get('host_status',0),opt.get('target_status',0),opt.get('sense_length',0)]))
            if 'corrupt_guard' in opt:
                addr={'before_data':indata-1,'after_data':indata+8,'before_cdb':cdb-1,'after_cdb':cdb+10}[opt['corrupt_guard']];u.mem_write(addr,b'\0')
            if opt.get('mutate_cdb'):u.mem_write(cdb+1,b'\x01')
            if 'packet_offset' in opt:
                off=opt['packet_offset'];u.mem_write(y+off,bytes([u.mem_read(y+off,1)[0]^1]))
            if opt.get('media_changes_after'):u.mem_write(dev['media_ptr']+12,D(512));u.mem_write(dev['media_ptr']+24,Q(32767))
            ret(opt.get('command_status',0))
    u.hook_add(U.UC_HOOK_CODE,hook)
    sp=STACK+0x28000;u.mem_write(sp,Q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp);u.reg_write(R.UC_X86_REG_RCX,0x1234);u.reg_write(R.UC_X86_REG_RDX,st)
    u.emu_start(BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint,STOP+1,count=20000000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP and not allocations
    log=b''.join(logs);result=u.reg_read(R.UC_X86_REG_RAX)
    if log:
        assert log.startswith(b'MEDIA-CAPACITY-02 ') and log.endswith(b'PROBE_COMPLETE\r\n') and len(log)<32768
        assert b'RAW_USB_OPS=0 CONNECT_OPS=0' in log and b'SCSI_WRITE_OPS=0 SCSI_RESET_OPS=0 PASSTHRU_COMMANDS=0 RUNTIME_OPS=0' in log
    dest=HERE/'review/native_logs';dest.mkdir(parents=True,exist_ok=True);(dest/(name+'.txt')).write_bytes(log)
    return {'name':name,'return':f'{result:016X}','log_bytes':len(log),'log_sha256':hashlib.sha256(log).hexdigest(),'calls':calls,'requests':requests,'log':log}
def main():
    rows=[]
    def check(name,devices=None,good=False,commands=0,contains=(),**opt):
        r=execute(name,devices,**opt);assert (r['return']=='0000000000000000')==good,(name,r['return'])
        assert len(r['requests'])==commands,(name,len(r['requests']))
        for text in contains:assert text in r['log'],(name,text)
        if good:assert b'INVENTORY_COMPLETE=1\r\n' in r['log'] and b'RC10_VALID=1\r\n' in r['log']
        r.pop('log');rows.append(r)
    check('positive_cached_mismatch',good=True,commands=1,contains=[b'RC10_MATCHES_CACHED_BEFORE=0',b'MEDIA_BLOCK_BYTES=00000400',b'RC10_BLOCK_BYTES=00000200'])
    check('positive_cached_match',[device(block=512,last=32767)],good=True,commands=1,contains=[b'RC10_MATCHES_CACHED_BEFORE=1'])
    check('positive_lun0_child',[device(scsi=False),controller(path='lun0',scsi=True)],good=True,commands=1,contains=[b'ASSOCIATION_KIND=2'])
    for al in [1,2,512,4096]:check('alignment_'+str(al),[device(scsi_align=al)],good=True,commands=1)
    check('positive_readonly',[device(readonly=1)],good=True,commands=1)
    check('positive_no_bio',[device(bio=False)],good=True,commands=1,contains=[b'CACHED_MEDIA_COMPARISON=UNAVAILABLE'])
    check('media_refresh_observed',good=True,commands=1,media_changes_after=True,contains=[b'CACHED_MEDIA_UNCHANGED=0',b'RC10_MATCHES_CACHED_AFTER=1'])
    check('raw_geometry_observed',good=True,commands=1,answer='0004000000000400',contains=[b'RC10_MATCHES_CACHED_BEFORE=1',b'RC10_CAPACITY_BYTES=0000000010000400'])
    check('no_protocols',[],contains=[b'TARGET_ID_COUNT=0000',b'INVENTORY_COMPLETE=1',b'RC10_BLOCKED=TARGET_ABSENT'])
    check('no_scsi',[device(scsi=False)]+others(),contains=[b'RC10_BLOCKED=NO_STANDARD_SCSI_IO',b'INVENTORY_COMPLETE=1'])
    check('ext_same_path_inventory_only',[device(scsi=False,ext=True)],contains=[b'ASSOCIATED_EXT_SCSI=1',b'RC10_BLOCKED=NO_STANDARD_SCSI_IO'])
    check('ata_same_path_inventory_only',[device(scsi=False,ata=True)],contains=[b'ASSOCIATED_ATA=1',b'RC10_BLOCKED=NO_STANDARD_SCSI_IO'])
    check('ambiguous_target',[device(),device(scsi=False,path='other')],contains=[b'TARGET_ID_COUNT=0002',b'RC10_BLOCKED=TARGET_AMBIGUOUS'])
    check('ambiguous_owner',[device(),controller(path='lun0',scsi=True)],contains=[b'SCSI_EXECUTABLE_OWNER_COUNT=0002',b'RC10_BLOCKED=SCSI_OWNER_AMBIGUOUS'])
    for path in ['internal','ancestor','descendant','lun1']:
        check('scsi_unrelated_'+path,[device(scsi=False),controller(path=path,scsi=True)],contains=[b'RC10_BLOCKED=NO_STANDARD_SCSI_IO'])
    for path in ['other','multi','long']:
        check('unpinned_'+path,[device(path=path)],contains=[b'RC10_BLOCKED='+ (b'INVENTORY_INCOMPLETE' if path=='multi' else b'TARGET_PATH_NOT_PINNED')])
    check('unknown_scsi_path',[device(),controller(path='internal',scsi=True,protocol_missing='dp')],contains=[b'SCSI_ASSOCIATION_UNCERTAIN=1',b'RC10_COMMANDS=0'])
    for path in ['null','malformed','oversize','many_nodes']:check('path_'+path,[device(path=path)])
    for k,v in [('vid',0x1234),('pid',0xff20),('class_',3),('subclass',5),('protocol',0x62)]:check('identity_'+k,[device(**{k:v})],contains=[b'TARGET_ID_COUNT=0000'])
    for k,v in [('interface',1),('alternate',1),('endpoints',3)]:check('interface_'+k,[device(**{k:v})],contains=[b'RC10_BLOCKED=TARGET_INTERFACE_NOT_PINNED'])
    for al in [3,8192,0xffffffff]:check('bad_alignment_'+str(al),[device(scsi_align=al)],contains=[b'RC10_BLOCKED=SCSI_ALIGNMENT'])
    for flag in ['no_type','no_location','no_execute']:check(flag,[device(**{flag:True})])
    for flag in ['type_error','location_error','null_target','device_changes','path_changes','owner_changes','media_changes_before']:
        check(flag,**{flag:True})
    check('wrong_type',device_type=5);check('wrong_lun',lun=1)
    for flag in ['media_null','no_device_method','no_interface_method','device_error','interface_error','bad_device','bad_interface']:
        check(flag,[device(**{flag:True})])
    for g in ['dp','usb','bio','fs','scsi','ext','ata']:
        check('protocol_error_'+g,[device(fs=True,ext=True,ata=True,protocol_error=g)])
        check('protocol_null_'+g,[device(fs=True,ext=True,ata=True,protocol_null=g)])
    for g in ['usb','scsi','ext','ata']:
        for flag in ['locate_error','locate_error_with_buffer','locate_oversize','null_handle']:
            check(flag+'_'+g,[device(ext=True,ata=True)],**{flag:g})
    for flag in ['free_fail','watchdog_fail','no_watchdog','no_locate','no_handle_protocol','no_free']:check(flag,**{flag:True})
    check('qr_failure_after_success',commands=1,qr_fail=True,contains=[b'RC10_VALID=1'])
    for g in ['usb','scsi']:check('duplicate_list_'+g,good=True,commands=1,duplicate_list=g)
    check('log_overflow',[device(path='long') for _ in range(20)],contains=[b'LOG_OVERFLOW=1',b'RC10_COMMANDS=0',b'INVENTORY_COMPLETE=0'])
    check('log_overflow_small',[device(bio=False) for _ in range(70)],contains=[b'LOG_OVERFLOW=1',b'RC10_COMMANDS=0',b'INVENTORY_COMPLETE=0'])
    check('union_limit',[device(scsi=False) for _ in range(65)]+[controller(path='internal',scsi=True) for _ in range(65)],contains=[b'HANDLE_UNION_LIMIT_EXCEEDED=1'])
    for status in [E(7),E(18),E(6),E(3),1]:check('command_status_'+hex(status),commands=1,command_status=status,contains=[b'RC10_VALID=0'])
    for n in [0,7,9,0xffffffff]:check('short_or_excess_'+str(n),commands=1,returned_length=n)
    for k,v in [('host_status',1),('target_status',2),('sense_length',1)]:check('response_'+k,commands=1,**{k:v})
    for side in ['before_data','after_data','before_cdb','after_cdb']:check('guard_'+side,commands=1,corrupt_guard=side,contains=[b'RC10_GUARDS_OK=0'])
    check('mutated_cdb',commands=1,mutate_cdb=True)
    for off in [0,8,16,24,32,44,48,49]:check('mutated_packet_'+str(off),commands=1,packet_offset=off)
    check('zero_block',commands=1,answer='00007fff00000000',contains=[b'RC10_VALID=0'])
    check('rc16_sentinel',commands=1,answer='ffffffff00000200',contains=[b'RC10_VALID=0'])
    check('after_media_error',commands=1,after_media_error=True,contains=[b'RC10_VALID=1',b'CACHED_AFTER_VALID=0'])
    report={'status':'PASS','case_count':len(rows),'efi_sha256':sha(HERE/'build/BOOTX64.EFI'),'test_sha256':sha(Path(__file__)),
        'scope':__doc__,'all_forbidden_service_pointers_trap':True,'max_commands_per_run':1,'cases':rows}
    (HERE/'build/native_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({'status':'PASS','cases':len(rows)}))
if __name__=='__main__':main()
