"""Original ARM geometry/cache and attach code, all external effects modeled.

Never invokes an OS ioctl, shell command, socket, thread, or hardware interface.
Actual ARM is executed only in Unicorn with explicit boundary allowlists.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
PRIOR=BASE/'media_attach_review02';KDIR=BASE/'media_geometry_review03'
sys.path.insert(0,str(KDIR))
def load(name,p):
    spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
K=load('kernel_cache_original',KDIR/'replay_kernel_geometry.py')
HD=load('hd_original',PRIOR/'replay_capacity.py')
N=load('nbd_original',KDIR/'replay_nbd_client.py')
U=K.U;R=K.R;P=K.P;Q=K.Q
sha=lambda b:hashlib.sha256(b).hexdigest()

class CacheVM(K.VM):
    def hook(self,u,addr,size,data):
        if self.symbols.get(addr)=='fsg_lun_close' and not any(a<=addr<b for a,b in self.active_ranges):
            args=[u.reg_read(r) for r in K.REGS]
            assert args[0]==K.LUN
            self.calls.append({'function':'fsg_lun_close_BOUNDARY','r0_r3':args,'scope':'Only synthetic prior file handle cleared; no actual close/fsync occurs.'})
            u.mem_write(K.LUN,P(0));self.ret();return
        return super().hook(u,addr,size,data)
    def prepare(self,block_size,total_bytes):
        self.setup()
        for p,n in [(K.FILE+0x10,K.INODE),(K.FILE+0x28,0x60002),(K.INODE+0x20,K.MAPPING),(K.MAPPING,K.INODE),
                    (K.INODE+0x160,K.BDEV),(K.QUEUE+0x370,block_size)]:self.u.mem_write(p,P(n))
        self.u.mem_write(K.INODE,struct.pack('<H',0x6000));self.u.mem_write(K.INODE+0x30,Q(total_bytes))
        self.u.mem_write(K.H+0xa000,b'/synthetic/only\0')
        assert self.call(0x807385b0,0x80738984,[K.LUN,K.H+0xa000])==0
    def cache(self):
        return {'total_blocks':self.quad(K.LUN+0x10),'block_size':self.word(K.LUN+0x2c),
                'capacity_hex':self.capacity_fragment().hex(),'current_inode_bytes':self.quad(K.INODE+0x30),
                'current_queue_block_size':self.word(K.QUEUE+0x370)}

def cache_case(name,old_bs,old_bytes,new_bs,new_blocks):
    v=CacheVM();v.prepare(old_bs,old_bytes);initial=v.cache()
    # Execute original ioctl branches and size-update, with only kernel APIs
    # modeled exactly as listed by the frozen base harness.
    assert v.call(0x8066c890,0x8066c918,[])==K.CFG
    assert v.call(0x8066d2a8,0x8066d680,[K.BDEV,0,0xab01,new_bs])==0
    assert v.call(0x8066d2a8,0x8066d680,[K.BDEV,0,0xab07,new_blocks])==0
    v.call(0x80669b08,0x80669c14,[K.NBD,0])
    after_update=v.cache()
    assert after_update['current_inode_bytes']==new_bs*new_blocks
    assert after_update['current_queue_block_size']==new_bs
    assert after_update['capacity_hex']==initial['capacity_hex']
    assert v.call(0x807385b0,0x80738984,[K.LUN,K.H+0xa000])==0
    after_reopen=v.cache()
    assert after_reopen['capacity_hex']==struct.pack('>II',new_blocks-1,new_bs).hex()
    return {'name':name,'synthetic_old_backing_bytes':old_bytes,'synthetic_old_block_size':old_bs,
            'requested_new_blocks':new_blocks,'requested_new_block_size':new_bs,'initial':initial,
            'after_actual_nbd_geometry_update_without_lun_reopen':after_update,
            'after_actual_lun_reopen':after_reopen,'steps':v.steps,'boundaries':v.calls,
            'limit':'Old geometry is a deliberate synthetic initial condition, not evidence identifying its live source.'}

def attach_case(name,system_result=0,thread_result=0):
    u=HD.new_vm();calls=[];steps=0
    inv=json.loads((PRIOR/'hdserver_decompile/function_inventory.json').read_text())
    thunks={int(x['address'],16):x['name'] for x in inv['functions'] if x['thunk']}
    buf=HD.HEAP+0x10000;path=HD.HEAP+0x20000
    u.mem_write(path,b'/dev/nbd0\0');u.mem_write(0x2e248,P(1)+P(0))
    def cs(p):return bytes(u.mem_read(p,4096)).split(b'\0',1)[0].decode('ascii')
    def ret(n=0):u.reg_write(R.UC_ARM_REG_R0,n&0xffffffff);u.reg_write(R.UC_ARM_REG_PC,u.reg_read(R.UC_ARM_REG_LR))
    def hook(uc,addr,size,unused):
        nonlocal steps
        if addr==HD.STOP:uc.emu_stop();return
        steps+=1
        if 0x17dec<=addr<0x18054:return
        if addr==0x177c8:
            calls.append({'call':'hdisk_release_boundary','slot':uc.reg_read(R.UC_ARM_REG_R0)});ret();return
        n=thunks.get(addr)
        args=[uc.reg_read(r) for r in K.REGS]
        if n=='__xstat':calls.append({'call':'synthetic_stat','path':cs(args[1]),'return':-1});ret(-1);return
        if n=='touch':calls.append({'call':'synthetic_touch','path':cs(args[0])});ret();return
        if n=='calloc':assert args[:2]==[0x400,1];uc.mem_write(buf,bytes(0x400));ret(buf);return
        if n=='memset':uc.mem_write(args[0],bytes([args[1]&255])*args[2]);ret(args[0]);return
        if n=='snprintf':
            fmt=cs(args[2]);values=[args[3]]+[struct.unpack('<I',uc.mem_read(uc.reg_read(R.UC_ARM_REG_SP)+k*4,4))[0] for k in range(3)]
            tokens=[];i=0;cur=0
            while i<len(fmt):
                if fmt[i]=='%':
                    typ=fmt[i+1];assert typ in ('s','d')
                    value=values[cur];cur+=1
                    tokens.append(cs(value) if typ=='s' else str(value if value<0x80000000 else value-0x100000000));i+=2
                else:tokens.append(fmt[i]);i+=1
            text=''.join(tokens).encode('ascii');assert len(text)+1<=args[1]
            uc.mem_write(args[0],text+b'\0');ret(len(text));return
        if n=='safe_system':
            cmd=cs(args[0]);calls.append({'call':'synthetic_safe_system_NOT_EXECUTED','command':cmd,'return':system_result})
            ret(system_result);return
        if n=='free':ret();return
        if n=='pthread_create':calls.append({'call':'synthetic_pthread_create_NOT_STARTED','entry':hex(args[2]),'arg':args[3],'return':thread_result});ret(thread_result);return
        if n and n.startswith('IDBG_'):ret();return
        raise AssertionError('Unapproved native boundary '+str(n)+' '+hex(addr))
    u.hook_add(U.UC_HOOK_CODE,hook)
    u.reg_write(R.UC_ARM_REG_SP,HD.STACK+0x18000);u.reg_write(R.UC_ARM_REG_LR,HD.STOP);u.reg_write(R.UC_ARM_REG_R0,path)
    u.emu_start(0x17dec,HD.STOP+4,count=50000);assert u.reg_read(R.UC_ARM_REG_PC)==HD.STOP
    rc=u.reg_read(R.UC_ARM_REG_R0)
    commands=[x['command'] for x in calls if x['call']=='synthetic_safe_system_NOT_EXECUTED']
    if system_result<0:
        assert rc==0xffffffff and len(commands)==1
    else:
        assert rc==0 and len(commands)==4
        assert commands[2]=="cd /sys/kernel/config/usb_gadget/hddisk && echo '/dev/nbd0' >functions/mass_storage.usb0/lun.0/file &"
        assert commands[3]=='cd /sys/kernel/config/usb_gadget/hddisk && echo 1e6a0000.usb-vhub:p2 >UDC'
        assert not any(x.get('call') in ('geometry_query','wait_for_file_write') for x in calls)
    return {'name':name,'synthetic_safe_system_result':system_result,'synthetic_thread_result':thread_result,
            'native_result':rc,'steps':steps,'calls':calls,
            'limit':'No shell command, file write, USB bind, thread, syscall or external I/O executed. This proves status checks/call order, not live failure/race.'}

def wire_case():
    b=bytearray(HD.make_frame('legacy'));b[61:69]=bytes.fromhex('0004000000000400');b[11]=0;b[11]=(-sum(b))&255
    r=HD.run('synthetic_observed_geometry_is_accepted',bytes(b))
    call=next(x for x in r['calls'] if x['call']=='nbd_init_boundary')
    assert call['block_size']==1024 and call['blocks']==262145 and r['final_state']==1
    r['limit']='Deliberate synthetic alternate input; no evidence the real client sent these bytes.'
    return r

def main():
    cases=[cache_case('cached_observed_to_expected',1024,268436480,512,32768),
           cache_case('cached_expected_to_observed',512,16777216,1024,262145),
           cache_case('cached_round_256MiB_is_not_observed',1024,268435456,512,32768)]
    cases.extend([attach_case('shell_zero'),attach_case('shell_exit_one_encoded_256',256),
                  attach_case('negative_wrapper_error',-1),attach_case('monitor_thread_create_failure',0,11),wire_case()])
    assert cases[0]['initial']['capacity_hex']=='0004000000000400'
    assert cases[0]['after_actual_lun_reopen']['capacity_hex']=='00007fff00000200'
    assert cases[2]['initial']['capacity_hex']=='0003ffff00000400'
    out={'status':'PASS','case_count':len(cases),'cases':cases,'inputs':[
        {'path':str(p),'sha256':sha(p.read_bytes())} for p in [HD.IMAGE,K.KERNEL,PRIOR/'replay_capacity.py',KDIR/'replay_kernel_geometry.py',KDIR/'kernel_targets.py',KDIR/'trace_nbd.py',KDIR/'kernel_symbols.json']],
        'scope':'Actual original pinned ARM functions with synthetic state and explicit scalar/file/OS service stubs. No target daemon/kernel execution, no BMC session, no device or network.'}
    (HERE/'native_cache_attach_replay.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({'status':'PASS','cases':len(cases),'cache_transitions':[{k:r[k] for k in ['name','initial','after_actual_nbd_geometry_update_without_lun_reopen','after_actual_lun_reopen']} for r in cases[:3]]},indent=2))
if __name__=='__main__':main()
