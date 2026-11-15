"""Execute actual compiled EFI in Unicorn with explicit metadata fixtures.
Every file,ConnectController,raw USB/BlockIO,RuntimeServices or unknown service
pointer traps. No network,device or target firmware operation is possible.
"""
from pathlib import Path
import copy,hashlib,json,re,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
E=lambda n:(1<<63)|n;Q=lambda n:struct.pack('<Q',n);D=lambda n:struct.pack('<I',n)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
GUIDS={uuid.UUID(v).bytes_le:k for k,v in {'usb':'2b2f68d6-0cd2-44cf-8e8b-bba20b1b5b75','bio':'964e5b21-6459-11d2-8e39-00a0c969723b','fs':'964e5b22-6459-11d2-8e39-00a0c969723b','dp':'09576e91-6d3f-11d2-8e39-00a0c969723b'}.items()}
pe=pefile.PE(str(HERE/'build/BOOTX64.EFI'));pe.relocate_image(BASE);IMAGE=pe.get_memory_mapped_image()
SYMBOLS={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(HERE/'build/inventory.map').read_text(),re.M)}
def device(**kw):
    d=dict(usb=True,bio=True,fs=False,path='usb',vid=0x046b,pid=0xff31,present=1,readonly=0,removable=1,partition=0,cache=0,block=512,last=32767,id=7,align=0,class_=8,subclass=6,protocol=0x50,endpoints=2)
    d.update(kw);return d
def others():return [device(pid=0xff20,fs=True,block=2048,last=0x2038,readonly=1),device(usb=False,path='internal'),device(bio=False,class_=3,subclass=1,protocol=1,endpoints=1),device(bio=False,class_=9,subclass=0,protocol=0,endpoints=1)]
def execute(name,devices=None,**opt):
    devices=copy.deepcopy(devices if devices is not None else [device()]+others());u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,(len(IMAGE)+4095)&~4095),(HEAP,0x1000000),(STACK,0x20000),(STOP,0x2000)]:u.mem_map(a,n)
    u.mem_write(BASE,IMAGE);st=HEAP;bs=HEAP+0x1000;nextmem=HEAP+0x20000
    handles={};providers={};allocations=set();calls=[];logs=[]
    def alloc(n=256):
        nonlocal nextmem
        a=nextmem;nextmem+=(n+255)&~255;assert nextmem<HEAP+0x1000000;return a
    def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(v):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,v);u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def guid(p):return GUIDS[bytes(u.mem_read(p,16))]
    for dev in devices:
        h=alloc();handles[h]=dev;dev['h']=h
        for kind in ['dp','usb','bio','media','fs']:
            p=alloc(4096 if kind=='dp' else 256);dev[kind+'_ptr']=p;providers[p]=dev
        dp={'usb':b'\x03\x05\x06\0\0\0\x7f\xff\x04\0','internal':b'\x01\x01\x06\0\0\0\x7f\xff\x04\0',
            'malformed':b'\x03\x05\x03\0','multi':b'\x03\x05\x06\0\0\0\x7f\x01\x04\0\x03\x05\x06\0\1\0\x7f\xff\x04\0',
            'oversize':b'\x03\x05\xff\xff','many_nodes':b'\x01\x04\x04\0'*65,
            'long':b'\x03\x05\xfc\x07'+b'\x5a'*2040+b'\x7f\xff\x04\0','null':b'\0'*16}[dev['path']]
        u.mem_write(dev['dp_ptr'],dp)
        m=bytearray(32);struct.pack_into('<I',m,0,dev['id']);m[4:9]=bytes([dev[k] for k in ['removable','present','partition','readonly','cache']]);struct.pack_into('<II',m,12,dev['block'],dev['align']);struct.pack_into('<Q',m,24,dev['last']);u.mem_write(dev['media_ptr'],bytes(m))
        u.mem_write(dev['bio_ptr'],Q(0x20001)+Q(0 if dev.get('media_null') else dev['media_ptr'])+Q(STOP+0x900)*4)
        u.mem_write(dev['usb_ptr'],Q(STOP+0x900)*6+Q(0 if dev.get('no_device_method') else STOP+0x140)+Q(STOP+0x900)+Q(0 if dev.get('no_interface_method') else STOP+0x150))
        u.mem_write(dev['fs_ptr'],Q(0x10000)+Q(STOP+0x900))
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
        assert STOP+0x100<=a<=STOP+0x150,(name,'forbidden service',hex(a))
        x,y,z,w=[uc.reg_read(r) for r in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9]]
        fifth=rq(uc.reg_read(R.UC_X86_REG_RSP)+0x28)
        if a==STOP+0x100:
            assert x==y==z==w==0;calls.append('disable_watchdog');ret(E(7) if opt.get('watchdog_fail') else 0)
        elif a==STOP+0x110:
            assert x in allocations;allocations.remove(x);calls.append('free_metadata_buffer');ret(E(7) if opt.get('free_fail') else 0)
        elif a==STOP+0x130:
            assert x==2 and z==0;g=guid(y);assert g in ['usb','bio','fs'];calls.append('locate_'+g)
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
            if g!='dp' and not dev[g]:ret(E(3));return
            pointer=dev[g+'_ptr']
            if (g=='dp' and dev['path']=='null') or dev.get('protocol_null')==g:pointer=0
            u.mem_write(z,Q(pointer));ret(0)
        elif a in (STOP+0x140,STOP+0x150):
            assert x in providers;dev=providers[x];isdev=a==STOP+0x140;calls.append('cached_device_descriptor' if isdev else 'cached_interface_descriptor')
            if dev.get('device_error' if isdev else 'interface_error'):ret(E(7));return
            if isdev:
                b=bytearray(18);b[:2]=b'\x12\x01';b[4:7]=bytes([0,0,0]);struct.pack_into('<HH',b,8,dev['vid'],dev['pid']);b[17]=1
                if dev.get('bad_device'):b[0]=17
            else:
                b=bytearray([9,4,0,0,dev['endpoints'],dev['class_'],dev['subclass'],dev['protocol'],0])
                if dev.get('bad_interface'):b[1]=5
            u.mem_write(y,bytes(b));ret(0)
    u.hook_add(U.UC_HOOK_CODE,hook)
    sp=STACK+0x18000;u.mem_write(sp,Q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp);u.reg_write(R.UC_X86_REG_RCX,0x1234);u.reg_write(R.UC_X86_REG_RDX,st)
    u.emu_start(BASE+pe.OPTIONAL_HEADER.AddressOfEntryPoint,STOP+1,count=15000000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP and not allocations
    log=b''.join(logs);result=u.reg_read(R.UC_X86_REG_RAX)
    assert b'FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0' in log or opt.get('no_locate') or opt.get('no_handle_protocol') or opt.get('no_free')
    dest=HERE/'review/native_logs';dest.mkdir(parents=True,exist_ok=True);(dest/(name+'.txt')).write_bytes(log)
    return {'name':name,'return':f'{result:016X}','log_bytes':len(log),'log_sha256':hashlib.sha256(log).hexdigest(),'calls':calls,'expected':opt.get('expected',''),'log':log}

def main():
    rows=[]
    def check(name,devices=None,good=True,contains=(),**opt):
        r=execute(name,devices,**opt);assert (r['return']=='0000000000000000')==good,(name,r['return'])
        for text in contains:assert text in r['log'],(name,text)
        if r['log']:
            assert r['log'].endswith(b'PROBE_COMPLETE\r\n')
            if good:assert b'INVENTORY_COMPLETE=1\r\n' in r['log']
        r.pop('log');rows.append(r)
    check('mixed_devices',contains=[b'USB_VID=046B',b'USB_PID=FF31',b'MEDIA_BLOCK_BYTES=00000200',b'MEDIA_BLOCK_BYTES=00000800',b'HANDLES_REPORTED=0005'])
    check('no_devices',[])
    check('readonly',[device(readonly=1)],contains=[b'MEDIA_READ_ONLY=01'])
    check('no_media',[device(present=0)],contains=[b'MEDIA_PRESENT=00'])
    check('usb_no_blockio',[device(bio=False)],contains=[b'VENDOR_HD_ID_MATCH=1',b'BLOCK_IO_STATUS=8000000000000003'])
    check('blockio_no_sfs',[device()],contains=[b'SFS_PUBLISHED=0'])
    check('usb_with_sfs',[device(fs=True)],contains=[b'SFS_PUBLISHED=1'])
    check('non_usb',[device(usb=False,path='internal')],contains=[b'DP_USB_NODE=0',b'MEDIA_BLOCK_BYTES=00000200'])
    check('nonmatching_geometry',[device(block=4096,last=9)],contains=[b'MEDIA_BLOCK_BYTES=00001000',b'MEDIA_LAST_BLOCK=0000000000000009'])
    check('multi_instance_path',[device(path='multi')],contains=[b'DP_VALID=1',b'DP_EXTRA_INSTANCES=01'])
    check('long_valid_path',[device(path='long')],contains=[b'DP_BYTES=0800',b'DP_VALID=1'])
    check('duplicate_handles',[device()],duplicate_list='usb',contains=[b'HANDLE_UNION_COUNT=0001'])
    for path in ['null','malformed','oversize','many_nodes']:check('path_'+path,[device(path=path)],good=False)
    for flag in ['media_null','no_device_method','no_interface_method','device_error','interface_error','bad_device','bad_interface']:
        check(flag,[device(**{flag:True})],good=False)
    for g in ['dp','usb','bio','fs']:
        check('protocol_error_'+g,[device(protocol_error=g)],good=False)
        check('protocol_null_'+g,[device(fs=True,protocol_null=g)],good=False)
    for g in ['usb','bio','fs']:
        check('locate_error_'+g,[device(fs=True)],locate_error=g,good=False)
        check('locate_error_with_buffer_'+g,[device(fs=True)],locate_error_with_buffer=g,good=False)
        check('locate_oversize_'+g,[device(fs=True)],locate_oversize=g,good=False)
        check('null_handle_'+g,[device(fs=True)],null_handle=g,good=False)
    for flag in ['free_fail','watchdog_fail','no_watchdog','no_locate','no_handle_protocol','no_free','qr_fail']:
        check(flag,good=False,**{flag:True})
    check('log_overflow',[device(path='long') for _ in range(20)],good=False,contains=[b'LOG_OVERFLOW=1',b'INVENTORY_PARTIAL=1',b'INVENTORY_COMPLETE=0'])
    check('union_limit',[device(bio=False) for _ in range(65)]+[device(usb=False,path='internal') for _ in range(65)],good=False,contains=[b'HANDLE_UNION_LIMIT_EXCEEDED=1'])
    report={'status':'PASS','case_count':len(rows),'efi_sha256':sha(HERE/'build/BOOTX64.EFI'),'test_sha256':sha(Path(__file__)),
        'scope':__doc__,'all_forbidden_service_pointers_trap':True,'cases':rows}
    (HERE/'build/native_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({'status':'PASS','cases':len(rows)}))
if __name__=='__main__':main()
