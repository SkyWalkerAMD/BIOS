"""Run the shipped x64 EFI bytes against explicit synthetic UEFI services.

This script has no socket, device-path, disk-backend or firmware access. It does
not replace the application gates with Python logic: the actual efi_main,
ConnectController selection, unique-volume selection and file transaction run
in Unicorn. Only UEFI protocol services and QR rendering are modeled. OVMF is
the separate real UEFI filesystem/USB-driver integration check.
"""
from pathlib import Path
import copy, hashlib, json, re, struct, sys, uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[6]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
import unicorn as U
from unicorn import x86_const as R

BASE, HEAP, STACK, STOP = 0x140000000, 0x60000000, 0x70000000, 0x50000000
ERR = lambda n: (1 << 63) | n
Q = lambda n: struct.pack('<Q', n)
D = lambda n: struct.pack('<I', n)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
MARKER = b'AI TWEAKER LOCAL WRITEBACK TEST 02\r\nMARKER 39F4B65F-613F-475A-A93F-FA6CB211B002\r\n'
RESULT = (HERE / 'expected-result.bin').read_bytes()
assert len(RESULT) == 120 and hashlib.sha256(RESULT).hexdigest() == '2c5d83822598f60d991e5720e918afd47e68b7580eb0a86c357392d55b8988cf'
GUIDS = {uuid.UUID(v).bytes_le:k for k,v in {
    'fs':'964e5b22-6459-11d2-8e39-00a0c969723b',
    'bio':'964e5b21-6459-11d2-8e39-00a0c969723b',
    'usb':'2b2f68d6-0cd2-44cf-8e8b-bba20b1b5b75',
    'dp':'09576e91-6d3f-11d2-8e39-00a0c969723b',
    'fsinfo':'09576e93-6d3f-11d2-8e39-00a0c969723b',
    'fileinfo':'09576e92-6d3f-11d2-8e39-00a0c969723b',
}.items()}
EFI = HERE / 'build/BOOTX64.EFI'
pe = pefile.PE(str(EFI)); pe.relocate_image(BASE)
IMAGE = pe.get_memory_mapped_image()
SYMBOLS = {n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s', (HERE/'build/inventory.map').read_text(), re.M)}

def target(**kw):
    d = dict(name='test-image', usb=True, bio=True, fs=True, path='usb',
             block=512, last=32767, present=True, readonly=False, partition=0,
             class_=8, subclass=6, protocol=0x50, endpoints=2, marker=MARKER,
             label='WBTEST02', volume=16726016, fsblock=2048, free=16723968,
             result=None, media_id=17, fs_readonly=False)
    d.update(kw); return d

def ancillary():
    return [target(name='boot-cd', block=2048, last=8191, readonly=True),
            target(name='internal', usb=False, path='internal'),
            target(name='keyboard', bio=False, fs=False, class_=3, subclass=1, protocol=1, endpoints=1),
            target(name='hub', bio=False, fs=False, class_=9, endpoints=1)]

def execute(name, devices=None, **opt):
    devices = copy.deepcopy(devices if devices is not None else [target()] + ancillary())
    u = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
    for addr,size in [(BASE,(len(IMAGE)+4095)&~4095),(HEAP,0x400000),(STACK,0x20000),(STOP,0x1000)]:
        u.mem_map(addr,size)
    u.mem_write(BASE,IMAGE)
    st,bs = HEAP,HEAP+0x1000
    nextmem = HEAP+0x20000
    fds,ptrdev,handles,allocations = {},{},{},set()
    calls,connects,opens,writes,logs = [],[],[],[],[]
    counters = {}
    def count(key):
        counters[key] = counters.get(key,0)+1
        return counters[key]
    def alloc(n=256):
        nonlocal nextmem
        addr=nextmem; nextmem+=(n+255)&~255
        assert nextmem < HEAP+0x400000
        return addr
    def rq(addr): return struct.unpack('<Q',u.mem_read(addr,8))[0]
    def ret(value):
        sp=u.reg_read(R.UC_X86_REG_RSP)
        u.reg_write(R.UC_X86_REG_RAX,value)
        u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def text16(addr):
        out=bytearray()
        for i in range(128):
            b=bytes(u.mem_read(addr+i*2,2))
            if b==b'\0\0': return out.decode('utf-16le')
            out.extend(b)
        raise AssertionError('unbounded filename')
    def get_guid(addr):
        raw=bytes(u.mem_read(addr,16));assert raw in GUIDS
        return GUIDS[raw]
    def filehandle(dev,role):
        p=alloc(); fds[p]={'device':dev,'role':role,'pos':0,'closed':False}
        u.mem_write(p,Q(0x10000))
        for off in range(8,88,8):u.mem_write(p+off,Q(STOP+0x900))
        for off,fn in [(8,0x300),(16,0x310),(32,0x320),(40,0x330),(64,0x340),(80,0x350)]:
            u.mem_write(p+off,Q(STOP+fn))
        if opt.get('missing_file_method')==role:u.mem_write(p+32,Q(0))
        if role=='created' and opt.get('missing_write'):u.mem_write(p+40,Q(0))
        if role=='created' and opt.get('missing_flush'):u.mem_write(p+80,Q(0))
        return p
    def install(dev):
        for k in ('handle','dp_ptr','bio_ptr','media_ptr','usb_ptr','fs_ptr'):
            dev[k]=alloc();ptrdev[dev[k]]=dev
        handles[dev['handle']]=dev
        dp={'usb':b'\x03\x05\x06\x00\x00\x00\x7f\xff\x04\x00',
            'internal':b'\x01\x01\x06\x00\x00\x00\x7f\xff\x04\x00',
            'malformed':b'\x03\x05\x03\x00\x7f\xff\x04\x00',
            'instance':b'\x03\x05\x06\x00\x00\x00\x7f\x01\x04\x00',
            'null':b'\0'*16}[dev['path']]
        u.mem_write(dev['dp_ptr'],dp)
        m=bytearray(32);struct.pack_into('<I',m,0,dev['media_id'])
        m[4:9]=bytes([1,int(dev['present']),dev['partition'],int(dev['readonly']),0])
        struct.pack_into('<IIQ',m,12,dev['block'],0,0)
        struct.pack_into('<Q',m,24,dev['last'])
        u.mem_write(dev['media_ptr'],bytes(m))
        u.mem_write(dev['bio_ptr'],Q(0x10000)+Q(dev['media_ptr'])+Q(STOP+0x900)*4)
        u.mem_write(dev['usb_ptr'],Q(STOP+0x900)*8+Q(STOP+0x150))
        u.mem_write(dev['fs_ptr'],Q(0x10000)+Q(STOP+0x200))
        if opt.get('missing_interface'):u.mem_write(dev['usb_ptr']+64,Q(0))
    for dev in devices:install(dev)
    u.mem_write(st+0x58,Q(STOP+0x900)+Q(bs))
    for off in range(0x18,0x178,8):u.mem_write(bs+off,Q(STOP+0x900))
    for off,fn in {0x40:0x900,0x48:0x110,0x98:0x120,0x100:0x100,0x108:0x140,0x138:0x130,0x140:0x900}.items():
        u.mem_write(bs+off,Q(STOP+fn))
    if opt.get('no_connect_service'):u.mem_write(bs+0x108,Q(0))
    if opt.get('no_watchdog'):u.mem_write(bs+0x100,Q(0))
    if opt.get('no_free_service'):u.mem_write(bs+0x48,Q(0))
    def callback(uc,a,n,_):
        if a==STOP:uc.emu_stop();return
        if a==SYMBOLS['kvm_present']:
            x,y,z,w=[u.reg_read(reg) for reg in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
            assert x==st and z<4096
            logs.append(bytes(u.mem_read(y,z)));ret(0);return
        assert STOP+0x100<=a<=STOP+0x350,(name,'forbidden service',hex(a))
        x,y,z,w=[u.reg_read(reg) for reg in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
        fifth=rq(u.reg_read(R.UC_X86_REG_RSP)+0x28)
        if a==STOP+0x100:
            assert x==y==z==w==0;calls.append('watchdog');ret(ERR(7) if opt.get('watchdog_fail') else 0)
        elif a==STOP+0x110:
            assert x in allocations;allocations.remove(x);calls.append('free')
            ret(ERR(7) if count('free')==opt.get('free_fail_at') else 0)
        elif a==STOP+0x130:
            assert x==2 and z==0;g=get_guid(y);assert g in ('usb','bio','fs');calls.append('enumerate_'+g)
            if opt.get('locate_fail')==g:ret(ERR(7));return
            found=[d['handle'] for d in devices if d[g]]
            if opt.get('locate_overflow')==g:
                p=alloc(8);allocations.add(p);u.mem_write(w,Q(129));u.mem_write(fifth,Q(p));ret(0);return
            if not found:ret(ERR(14));return
            p=alloc(len(found)*8);allocations.add(p);u.mem_write(p,b''.join(Q(h) for h in found))
            u.mem_write(w,Q(len(found)));u.mem_write(fifth,Q(p));ret(0)
        elif a==STOP+0x120:
            assert x in handles;dev=handles[x];g=get_guid(y);calls.append('protocol_'+g)
            if dev.get('protocol_error')==g:ret(ERR(7));return
            if g=='dp':
                u.mem_write(z,Q(0 if dev['path']=='null' else dev['dp_ptr']));ret(0);return
            assert g in ('usb','bio','fs')
            if not dev[g]:ret(ERR(3));return
            if g=='bio':
                c=count(dev['name']+'_bio')
                # 1=USB_IO pass; 2=BlockIO pass; 3=selection; 4=pre-mutation recheck.
                if c==opt.get('media_change_at'):
                    u.mem_write(dev['media_ptr'],D(dev['media_id']+1))
                if c==opt.get('readonly_change_at'):u.mem_write(dev['media_ptr']+7,b'\1')
                if c==opt.get('path_change_at'):u.mem_write(dev['dp_ptr'],b'\x01\x01\x06\0\0\0\x7f\xff\4\0')
            u.mem_write(z,Q(dev[g+'_ptr']));ret(0)
        elif a==STOP+0x140:
            assert x in handles and y==z==0 and w in (0,1)
            dev=handles[x];assert dev['path']=='usb' and not dev['fs']
            if not w:assert dev['usb'] and not dev['bio'] and (dev['class_'],dev['subclass'],dev['protocol'],dev['endpoints'])==(8,6,0x50,2)
            else:assert dev['bio'] and dev['block']==512 and dev['last']==32767 and dev['present'] and not dev['readonly']
            connects.append([dev['name'],w])
            if opt.get('connect_fail'):ret(ERR(7));return
            if not opt.get('connect_no_progress'):
                if w or opt.get('one_connect_full'):dev['fs']=True
                dev['bio']=True
            ret(0)
        elif a==STOP+0x150:
            assert x in ptrdev;dev=ptrdev[x];calls.append('interface_'+dev['name'])
            if opt.get('interface_fail'):ret(ERR(7));return
            desc=bytes([opt.get('descriptor_length',9),opt.get('descriptor_type',4),0,0,dev['endpoints'],dev['class_'],dev['subclass'],dev['protocol'],0])
            u.mem_write(y,desc);ret(0)
        elif a==STOP+0x200:
            assert x in ptrdev;dev=ptrdev[x];calls.append('volume_'+dev['name'])
            assert dev['path']=='usb' and dev['block']==512 and dev['last']==32767 and not dev['readonly']
            if dev.get('open_volume_fail') or opt.get('open_volume_fail'):ret(ERR(7));return
            p=filehandle(dev,'root');u.mem_write(y,Q(p));ret(ERR(7) if opt.get('open_volume_fail_with_handle') else 0)
        elif a==STOP+0x300:
            assert x in fds and not fds[x]['closed'] and fds[x]['role']=='root'
            dev=fds[x]['device'];filename=text16(z);assert fifth==0
            assert filename in ('\\IDENTIFY.TXT','\\WRBACK.TXT') and w in (1,0x8000000000000003)
            opens.append([dev['name'],filename,hex(w)])
            if filename=='\\IDENTIFY.TXT':
                assert w==1
                if opt.get('marker_open_fail'):ret(ERR(7));return
                if dev['marker'] is None:ret(ERR(14));return
                p=filehandle(dev,'marker');u.mem_write(y,Q(p));ret(0);return
            if w==1:
                role='readback' if dev.get('written') else 'existing'
                if role=='readback' and opt.get('reopen_fail'):
                    if opt.get('error_with_handle'):u.mem_write(y,Q(filehandle(dev,role)))
                    ret(ERR(7));return
                if dev['result'] is None:
                    if opt.get('absence_nonnull'):u.mem_write(y,Q(filehandle(dev,role)))
                    ret(ERR(7) if opt.get('absence_error') else ERR(14));return
                u.mem_write(y,Q(filehandle(dev,role)));ret(0);return
            count('create');assert counters['create']==1
            if opt.get('create_fail'):
                if opt.get('error_with_handle'):u.mem_write(y,Q(filehandle(dev,'created')))
                ret(ERR(7));return
            dev['result']=b'pre-existing-race' if opt.get('raced_content') else b''
            u.mem_write(y,Q(filehandle(dev,'created')));ret(0)
        elif a==STOP+0x310:
            assert x in fds and not fds[x]['closed'];fd=fds[x];fd['closed']=True
            calls.append('close_'+fd['role']);c=count('close_'+fd['role'])
            ret(ERR(7) if opt.get('close_fail')==fd['role'] and c==opt.get('close_fail_at',1) else 0)
        elif a==STOP+0x320:
            assert x in fds and not fds[x]['closed'];fd=fds[x];role=fd['role'];dev=fd['device']
            assert role in ('marker','readback')
            data=dev['marker'] if role=='marker' else dev['result']
            requested=rq(y);assert requested in (len(MARKER),len(RESULT),1)
            if opt.get(role+'_read_error'):ret(ERR(7));return
            if role=='marker' and opt.get('marker_change_second') and counters.get('info_marker',0)>=2:data=b'X'+data[1:]
            if opt.get(role+'_bad'):data=b'X'+data[1:]
            if opt.get(role+'_extra'):data+=b'!'
            if fd['pos']>=len(data) and opt.get(role+'_eof_error'):ret(ERR(7));return
            value=data[fd['pos']:fd['pos']+requested]
            if opt.get(role+'_short') and requested>1:value=value[:-1]
            if value:u.mem_write(z,value)
            u.mem_write(y,Q(len(value)));fd['pos']+=len(value);ret(0)
        elif a==STOP+0x330:
            assert x in fds and not fds[x]['closed'] and fds[x]['role']=='created'
            dev=fds[x]['device'];assert rq(y)==120 and bytes(u.mem_read(z,120))==RESULT
            assert not writes and dev['path']=='usb' and dev['label']=='WBTEST02' and dev['marker']==MARKER and dev['result']==b''
            writes.append([dev['name'],120]);dev['written']=True
            n=119 if opt.get('short_write') else 120
            dev['result']=RESULT[:n];u.mem_write(y,Q(n));ret(ERR(7) if opt.get('write_fail') else 0)
        elif a==STOP+0x340:
            assert x in fds and not fds[x]['closed'];fd=fds[x];role=fd['role'];dev=fd['device']
            g=get_guid(y);assert rq(z)==512;count('info_'+role)
            if opt.get('info_fail')==role:ret(ERR(7));return
            blob=bytearray(512)
            if role=='root':
                assert g=='fsinfo';size=54;blob[8]=int(dev['fs_readonly'])
                struct.pack_into('<QQI',blob,16,dev['volume'],dev['free'],dev['fsblock'])
                label=dev['label']
                if opt.get('label_change_second') and counters['info_root']>=2:label='CHANGED!'
                blob[36:54]=(label+'\0').encode('utf-16le')
            else:
                assert g=='fileinfo';size=106;data=dev['marker'] if role=='marker' else dev['result']
                struct.pack_into('<Q',blob,8,len(data)+(1 if opt.get(role+'_wrong_size') else 0))
                struct.pack_into('<Q',blob,72,opt.get(role+'_attr',0))
            struct.pack_into('<Q',blob,0,opt.get(role+'_internal_size',size))
            u.mem_write(w,bytes(blob));u.mem_write(z,Q(opt.get(role+'_reported_size',size)));ret(0)
        elif a==STOP+0x350:
            assert x in fds and not fds[x]['closed'] and fds[x]['role']=='created'
            calls.append('flush');ret(ERR(7) if opt.get('flush_fail') else 0)
        else:raise AssertionError((name,'unmodeled service',hex(a)))
    u.hook_add(U.UC_HOOK_CODE,callback,begin=STOP,end=STOP+0xfff)
    u.hook_add(U.UC_HOOK_CODE,callback,begin=SYMBOLS['kvm_present'],end=SYMBOLS['kvm_present'])
    def forbidden_io(*args):raise AssertionError((name,'forbidden port I/O'))
    u.hook_add(U.UC_HOOK_INSN,forbidden_io,None,1,0,R.UC_X86_INS_IN)
    u.hook_add(U.UC_HOOK_INSN,forbidden_io,None,1,0,R.UC_X86_INS_OUT)
    sp=STACK+0x1ff00-8;u.mem_write(sp,Q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
    u.reg_write(R.UC_X86_REG_RCX,0x1234);u.reg_write(R.UC_X86_REG_RDX,st)
    u.emu_start(BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint,STOP+0xfff,count=4000000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP,(name,'instruction bound')
    status=u.reg_read(R.UC_X86_REG_RAX)
    assert len(writes)<=1 and counters.get('create',0)<=1
    assert not allocations,(name,'handle-array leak')
    assert all(fd['closed'] for fd in fds.values()),(name,'file handle leak')
    log=b''.join(logs)
    if logs:assert b'PROBE_COMPLETE' in log and len(log)<4096
    return dict(name=name,status=f'0x{status:016X}',success=status==0,
                connect_calls=connects,create_calls=counters.get('create',0),
                file_write_calls=len(writes),flush_calls=calls.count('flush'),
                file_readback_reported=b'UEFI_FILE_READBACK_STATUS=0x0000000000000000' in log,
                log_sha256=hashlib.sha256(log).hexdigest(),
                root_opens=[s[7:] for s in calls if s.startswith('volume_')],
                only_allowlisted_services=True,all_file_handles_closed=True,
                files=[dict(device=d['name'],result_sha256=hashlib.sha256(d['result']).hexdigest() if d['result'] is not None else None) for d in devices])

def main():
    cases=[]
    def check(name,success=False,writes=0,creates=0,connects=None,devices=None,**opt):
        r=execute(name,devices,**opt)
        assert r['success']==success,(name,r)
        assert r['file_write_calls']==writes and r['create_calls']==creates,(name,r)
        if connects is not None:assert r['connect_calls']==connects,(name,r)
        if success:assert r['file_readback_reported'] and r['flush_calls']==1
        r['assertions']='PASS';cases.append(r)
    check('already_bound_only_marked_usb_written',True,1,1,[])
    check('USB_interface_then_exact_BlockIO_subtree',True,1,1,[['test-image',0],['test-image',1]],devices=[target(bio=False,fs=False)]+ancillary())
    check('firmware_connect_installs_SFS_in_one_call',True,1,1,[['test-image',0]],devices=[target(bio=False,fs=False)],one_connect_full=True)
    check('BlockIO_only_scoped_recursion',True,1,1,[['test-image',1]],devices=[target(usb=False,fs=False)])
    check('no_devices',devices=[])
    check('only_CD_keyboard_hub_internal_ignored',devices=ancillary(),connects=[])
    check('no_watchdog',no_watchdog=True)
    check('watchdog_error',watchdog_fail=True)
    check('no_ConnectController',no_connect_service=True)
    check('no_FreePool',no_free_service=True)
    for g in ['usb','bio','fs']:
        check('enumeration_error_'+g,locate_fail=g)
        check('enumeration_overflow_'+g,locate_overflow=g)
    for p in ['malformed','instance','null']:
        check('bad_device_path_'+p,devices=[target(path=p)])
    for desc_opt in [dict(interface_fail=True),dict(missing_interface=True),dict(descriptor_length=8),dict(descriptor_type=5)]:
        check('descriptor_'+next(iter(desc_opt)),**desc_opt)
    for change in [dict(class_=3),dict(subclass=5),dict(protocol=0x62),dict(endpoints=1)]:
        check('unbound_not_BOT_'+next(iter(change)),devices=[target(bio=False,fs=False,**change)],connects=[])
    check('interface_connection_failure_no_retry',devices=[target(bio=False,fs=False)],connect_fail=True,connects=[['test-image',0]])
    check('block_connection_failure_no_retry',devices=[target(fs=False)],connect_fail=True,connects=[['test-image',1]])
    check('connection_success_no_progress_no_retry',devices=[target(bio=False,fs=False)],connect_no_progress=True,connects=[['test-image',0]])
    many=[target(name='usb-'+str(i),bio=False,fs=False) for i in range(33)]
    check('connection_cap32',devices=many,connects=[['usb-'+str(i),0] for i in range(32)])
    for i in [1,2,3]:check('free_failure_'+str(i),free_fail_at=i)
    for change in [dict(block=2048),dict(last=32766),dict(present=False),dict(readonly=True),dict(partition=2)]:
        check('geometry_'+next(iter(change)),devices=[target(**change)],connects=[])
    check('logical_partition1_with_exact_geometry',True,1,1,[],devices=[target(partition=1)])
    check('duplicate_exact_images',devices=[target(),target(name='duplicate')])
    for change in [dict(label='OTHER123'),dict(volume=16777216),dict(fsblock=512),dict(free=0),dict(free=16726017),dict(fs_readonly=True),dict(marker=None)]:
        check('known_nonmatch_'+next(iter(change))+'_'+str(next(iter(change.values()))),devices=[target(**change)])
    check('bad_marker',devices=[target(marker=b'X'+MARKER[1:])])
    check('other_USB_volume_open_error_blocks_unique_selection',devices=[target(),target(name='unknown',open_volume_fail=True)])
    for role in ['root','marker']:check('GetInfo_failure_'+role,info_fail=role)
    for opt in ['marker_read_error','marker_short','marker_extra','marker_eof_error','marker_wrong_size','marker_open_fail','open_volume_fail','open_volume_fail_with_handle']:
        check(opt,**{opt:True})
    for role in ['root','marker']:
        check('missing_read_method_'+role,missing_file_method=role)
        check('metadata_small_'+role,**{role+'_reported_size':8})
        check('metadata_internal_large_'+role,**{role+'_internal_size':513})
    check('marker_close_error',close_fail='marker')
    check('media_ID_changes_before_mutation',media_change_at=4)
    check('media_readonly_before_mutation',readonly_change_at=4)
    check('device_path_changes_before_mutation',path_change_at=4)
    check('marker_changes_before_mutation',marker_change_second=True)
    check('label_changes_before_mutation',label_change_second=True)
    check('existing_nonempty_result_never_overwritten',devices=[target(result=b'PRESERVE THIS')])
    check('existing_empty_result_never_overwritten',devices=[target(result=b'')])
    check('result_absence_check_error',absence_error=True)
    check('NOT_FOUND_with_nonnull_handle',absence_nonnull=True)
    check('create_error',creates=1,create_fail=True)
    check('create_error_with_handle_closed',creates=1,create_fail=True,error_with_handle=True)
    check('raced_existing_content_refused',creates=1,raced_content=True)
    for opt in ['missing_write','missing_flush']:
        check(opt,creates=1,**{opt:True})
    check('created_missing_read_method',creates=1,missing_file_method='created')
    check('created_GetInfo_error',creates=1,info_fail='created')
    for attr in [1,16]:check('created_invalid_attributes_'+str(attr),creates=1,created_attr=attr)
    check('created_metadata_small',creates=1,created_reported_size=8)
    for opt in ['short_write','write_fail','flush_fail']:
        check(opt,writes=1,creates=1,**{opt:True})
    check('created_close_failure',writes=1,creates=1,close_fail='created')
    check('reopen_failure',writes=1,creates=1,reopen_fail=True)
    check('reopen_failure_with_handle_closed',writes=1,creates=1,reopen_fail=True,error_with_handle=True)
    for opt in ['readback_bad','readback_short','readback_extra','readback_read_error','readback_eof_error','readback_wrong_size']:
        check(opt,writes=1,creates=1,**{opt:True})
    check('readback_GetInfo_error',writes=1,creates=1,info_fail='readback')
    check('readback_close_error',writes=1,creates=1,close_fail='readback')
    check('root_close_error_after_write_is_failure',writes=1,creates=1,close_fail='root')
    check('readback_missing_read_method',writes=1,creates=1,missing_file_method='readback')
    report=dict(status='PASS_SYNTHETIC_UEFI_NATIVE_CODE_ONLY',cases_count=len(cases),
                efi_sha256=sha(EFI),source_sha256=sha(HERE/'source/writeback.c'),
                test_sha256=sha(Path(__file__)),cases=cases,
                limitations=['Protocol services and media changes are synthetic; this is not ASUS or BMC HDMEDIA hardware acceptance.',
                             'Only QR rendering is skipped; application decisions and file transaction run from actual EFI bytes.',
                             'Failure after CREATE may leave a new empty or partial disposable file; there is no retry, truncate or delete.',
                             'UEFI lacks exclusive CREATE. A separately created empty file cannot be distinguished after the absence check.',
                             'ConnectController invokes existing firmware drivers below selected USB storage; their low-level I/O is covered separately by OVMF, not modeled here.'])
    (HERE/'build/native_verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['status','cases_count','efi_sha256','test_sha256']},indent=2))

if __name__=='__main__':main()
