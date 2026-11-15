"""Bounded original ARM replay. All OS/device/network calls are scalar stubs.

Capacity cases start after an assumed complete decoded WebSocket packet; they
do not simulate authentication/framing or prove any live BMC state. Gadget
commands are captured as strings and are NEVER executed.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE=Path(__file__).resolve().parent
BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
spec=importlib.util.spec_from_file_location('elf_reader',BASE/'update_chain_review05/inspect_chain.py')
E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
import unicorn as U
from unicorn import arm_const as R
IMAGE=BASE/'media_geometry_review06/official_inputs/5308416/usr/local/lib/mod_websocket.so.13.12.6'
EXPECTED='793260a1ade29a6775776dbae84455d51417db1d68a7df9826c616904dba6605'
HEAP=0x70000000;STACK=0x71000000;STOP=0x60000000
FRAME=HEAP;CTX=HEAP+0x1000;CELL=HEAP+0x2000;GOT=HEAP+0x3000;ALLOC=HEAP+0x4000
P=lambda x:struct.pack('<I',x&0xffffffff)

def new_vm():
    e=E.Elf32(IMAGE);assert hashlib.sha256(e.data).hexdigest()==EXPECTED
    u=U.Uc(U.UC_ARCH_ARM,U.UC_MODE_ARM|U.UC_MODE_LITTLE_ENDIAN)
    for a,n in [(0,0x40000),(HEAP,0x40000),(STACK,0x20000),(STOP,0x1000)]:u.mem_map(a,n)
    off=struct.unpack_from('<I',e.data,28)[0];sz,num=struct.unpack_from('<HH',e.data,42)
    for i in range(num):
        typ,fo,va,pa,fs,ms,fl,al=struct.unpack_from('<8I',e.data,off+i*sz)
        if typ==1:u.mem_write(va,e.data[fo:fo+fs])
    for va,r in e.relocations.items():
        if r['type']==2 and r['symbol_defined']:
            a=struct.unpack('<I',u.mem_read(va,4))[0];u.mem_write(va,P(a+r['symbol_va']))
        elif r['type'] in (21,22) and r['symbol_defined']:u.mem_write(va,P(r['symbol_va']))
        elif r['type']==23:pass # load bias zero; RELATIVE addend unchanged
    u.reg_write(R.UC_ARM_REG_SP,STACK+0x18000);u.reg_write(R.UC_ARM_REG_LR,STOP)
    return u,e

def word(u,p):return struct.unpack('<I',u.mem_read(p,4))[0]
def cstr(u,p):return bytes(u.mem_read(p,1024)).split(b'\0',1)[0].decode('ascii')
def ret(u,v):u.reg_write(R.UC_ARM_REG_R0,v&0xffffffff);u.reg_write(R.UC_ARM_REG_PC,u.reg_read(R.UC_ARM_REG_LR))

def capacity(name,nbd_rc=0,thread_rc=0):
    u,e=new_vm();calls=[];pc_end=[]
    frame=bytearray(69);frame[41]=0x25;frame[61:69]=bytes.fromhex('0000201f00000800')
    u.mem_write(FRAME,bytes(frame));u.mem_write(CELL,P(CTX));u.mem_write(CTX,P(9))
    u.mem_write(GOT+0x2f8,P(0x6b80));u.mem_write(GOT+0x2f4,P(CELL+4));u.mem_write(CELL+4,P(0))
    u.mem_write(STACK+0x18000+0x24,P(GOT))
    for reg,v in [(R.UC_ARM_REG_R7,FRAME),(R.UC_ARM_REG_R8,CTX),(R.UC_ARM_REG_R10,CELL)]:u.reg_write(reg,v)
    def hook(uc,a,size,user):
        if a in (0x77f4,0x75e0):pc_end.append(hex(a));uc.emu_stop();return
        if a not in e.plt:return
        n=e.plt[a]
        if n=='nbd_init':
            p=uc.reg_read(R.UC_ARM_REG_R0)
            calls.append({'call':n,'pointer':hex(p),'block_size':word(u,p+24),'block_size_high':word(u,p+28),
                          'blocks':word(u,p+32),'blocks_high':word(u,p+36),'readonly':word(u,p+68)&65535,'synthetic_return':nbd_rc})
            ret(u,nbd_rc)
        elif n=='pthread_create':
            calls.append({'call':n,'start_rva':hex(uc.reg_read(R.UC_ARM_REG_R2)),'synthetic_return':thread_rc});ret(u,thread_rc)
        elif n=='nbd_disconnect':calls.append({'call':n});ret(u,0)
        elif n=='sendCmdToCdserver':
            calls.append({'call':n,'opcode':uc.reg_read(R.UC_ARM_REG_R1),'instance':uc.reg_read(R.UC_ARM_REG_R2)});ret(u,0)
        else:raise AssertionError('Unapproved imported operation: '+n)
    u.hook_add(U.UC_HOOK_CODE,hook);u.emu_start(0x771c,STOP,count=1000)
    assert len(pc_end)==1
    first=calls[0];assert first['block_size']==2048 and first['blocks']==8224 and first['readonly']==1
    assert first['block_size_high']==first['blocks_high']==0
    if nbd_rc==-1:assert len(calls)==1 and pc_end==['0x75e0']
    elif thread_rc:assert [c['call'] for c in calls]==['nbd_init','pthread_create','nbd_disconnect','sendCmdToCdserver'] and calls[-1]['opcode']==247 and pc_end==['0x75e0']
    else:assert len(calls)==2 and calls[1]['start_rva']=='0x6b80' and pc_end==['0x77f4']
    return {'name':name,'entry_rva':'0x771c','stop_rva':pc_end[0],'wire_capacity_hex':'0000201f00000800','capacity_bytes':8224*2048,'calls':calls}

def worker():
    u,e=new_vm();calls=[];packet=[]
    u.mem_write(0x24300,P(CELL));u.mem_write(CELL,P(CTX))
    u.mem_write(0x242f0,P(GOT));u.mem_write(GOT,P(ALLOC));u.mem_write(ALLOC,b'/dev/nbd0\0')
    for off,v in [(0x34,1),(0x48,0),(0x4c,2048),(0x50,0),(0x64,0),(0x68,0),(0x74,2048)]:u.mem_write(CTX+off,P(v))
    def hook(uc,a,size,user):
        if a==0x5bc8:
            p=uc.reg_read(R.UC_ARM_REG_R0);packet.append(bytes(uc.mem_read(p,62)));uc.emu_stop();return
        if a not in e.plt:return
        n=e.plt[a]
        if n=='cdrom_start':calls.append({'call':n,'path':cstr(u,uc.reg_read(R.UC_ARM_REG_R0)),'synthetic_return':0});ret(u,0)
        elif n=='nbd_read_req':calls.append({'call':n,'synthetic_return':0,'synthetic_offset':0,'synthetic_length':2048});ret(u,0)
        elif n=='memset':
            p,v,c=[uc.reg_read(r) for r in (R.UC_ARM_REG_R0,R.UC_ARM_REG_R1,R.UC_ARM_REG_R2)];uc.mem_write(p,bytes([v&255])*c);ret(u,p)
        else:raise AssertionError('Unapproved imported operation: '+n)
    u.hook_add(U.UC_HOOK_CODE,hook);u.emu_start(0x6b80,STOP,count=10000)
    assert len(packet)==1 and packet[0][41]==0xa8 and [c['call'] for c in calls]==['cdrom_start','nbd_read_req']
    assert packet[0][43:47]==bytes(4) and int.from_bytes(packet[0][47:51],'little')==1
    return {'name':'worker_builds_READ12_after_synthetic_NBD_request','entry_rva':'0x6b80','stop_before_transport_rva':'0x5bc8','calls':calls,'request_opcode':'0xa8','request_lba':0,'request_sectors_native_field':1,'request_62_bytes_hex':packet[0].hex()}

def gadget(name,system_rcs=(0,0),thread_rc=0):
    u,e=new_vm();calls=[];returns=[];system_index=0
    u.mem_write(ALLOC+0x1000,b'/dev/nbd0\0');u.reg_write(R.UC_ARM_REG_R0,ALLOC+0x1000)
    def hook(uc,a,size,user):
        nonlocal system_index
        if a==STOP:returns.append(uc.reg_read(R.UC_ARM_REG_R0));uc.emu_stop();return
        if a==0xdd40:calls.append({'call':'marker_cleanup_boundary','slot':uc.reg_read(R.UC_ARM_REG_R0)});ret(u,0);return
        if a not in e.plt:return
        n=e.plt[a]
        if n=='__xstat':calls.append({'call':n,'path':cstr(u,uc.reg_read(R.UC_ARM_REG_R1)),'synthetic_return':-1});ret(u,-1)
        elif n=='touch':calls.append({'call':n,'path':cstr(u,uc.reg_read(R.UC_ARM_REG_R0)),'executed':False});ret(u,0)
        elif n=='calloc':ret(u,ALLOC)
        elif n=='snprintf':
            p=uc.reg_read(R.UC_ARM_REG_R0);fmt=cstr(u,uc.reg_read(R.UC_ARM_REG_R2));path=cstr(u,uc.reg_read(R.UC_ARM_REG_R3));slot=word(u,uc.reg_read(R.UC_ARM_REG_SP))
            s=fmt%(path,slot);uc.mem_write(p,s.encode()+b'\0');ret(u,len(s))
        elif n=='safe_system':
            value=system_rcs[system_index];system_index+=1
            calls.append({'call':n,'captured_only_command':cstr(u,uc.reg_read(R.UC_ARM_REG_R0)),'synthetic_return':value,'executed':False});ret(u,value)
        elif n=='pthread_create':calls.append({'call':n,'synthetic_return':thread_rc});ret(u,thread_rc)
        elif n=='free' or n.startswith('IDBG_'):ret(u,0)
        else:raise AssertionError('Unapproved imported operation: '+n)
    u.hook_add(U.UC_HOOK_CODE,hook);u.emu_start(0xe340,STOP+4,count=5000)
    assert len(returns)==1
    if system_rcs[0]<0:assert returns==[0xffffffff] and system_index==1
    else:assert returns==[0] and system_index==2
    cmds=[c for c in calls if c['call']=='safe_system']
    assert cmds[0]['captured_only_command'].endswith('/lun.0/file &')
    if len(cmds)==2:assert '1e6a0000.usb-vhub:p1 >UDC' in cmds[1]['captured_only_command']
    return {'name':name,'entry_rva':'0xe340','returned_slot_u32':returns[0],'calls':calls}

def main():
    cases=[capacity('valid_P04_capacity_success'),capacity('nbd_init_negative_stops_worker',-1),capacity('worker_create_failure_disconnects',0,11),worker(),
           gadget('gadget_zero_status'),gadget('gadget_positive_wait_status_256_accepted',(256,256)),gadget('gadget_negative_status_rejected',(-1,)),gadget('eject_monitor_creation_failure_returns_slot',(0,0),11)]
    out={'status':'PASS','cases':len(cases),'source_path':str(IMAGE.relative_to(ROOT)),'source_sha256':EXPECTED,
         'test_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'address_convention':'ELF link-time VA, load bias zero; Ghidra generated addresses add0x10000',
         'scope':'original ARM local branches with synthetic state and trapped import boundaries, no process/network/device/kernel I/O',
         'results':cases,'limitations':['Capacity replay begins after complete decoded WebSocket payload; framing/authentication and observed live execution are not established.',
         'NBD initialization, configfs, gadget attach, pthreads and operating-system effects are stubs; positive256 is a synthetic nonnegative wait-status counterexample, not an observed live error.',
         'Worker actual compiler integer division executes; its transport call is stopped before sending.',
         'Public official1.1.57 backend ELF has not been read back from the running BMC.']}
    (HERE/'native_capacity_replay.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':'PASS','cases':len(cases),'output':str(HERE/'native_capacity_replay.json')}))
if __name__=='__main__':main()
