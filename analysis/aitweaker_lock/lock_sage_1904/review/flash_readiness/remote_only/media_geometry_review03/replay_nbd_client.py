"""Execute original libnbd ARM bytes with all OS/device operations trapped.

No host ioctl is performed. Each ioctl callback merely records r0..r3 and
returns a synthetic result, isolating the userspace argument/error boundary.
"""
from pathlib import Path
import hashlib,json,struct,sys
from trace_nbd import HERE,PRIOR,ROOT,SOURCE,EXPECTED,elf_parts
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import unicorn as U
from unicorn import arm_const as R

STOP=0x60000000;STATE=0x70000000;STACK=0x71000000
P=lambda x:struct.pack('<I',x&0xffffffff)
NAMES={0xab01:'NBD_SET_BLKSIZE',0xab07:'NBD_SET_SIZE_BLOCKS',0xab04:'NBD_CLEAR_SOCK',
       0x125d:'BLKROSET',0xab09:'NBD_SET_TIMEOUT',0xab00:'NBD_SET_SOCK',0xab03:'NBD_DO_IT'}

def run(name,block_size=512,blocks=32768,failed=(),socket_result=19):
    raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    u=U.Uc(U.UC_ARCH_ARM,U.UC_MODE_ARM|U.UC_MODE_LITTLE_ENDIAN)
    u.mem_map(0,0x30000);u.mem_map(STATE,0x10000);u.mem_map(STACK,0x10000);u.mem_map(STOP,0x1000)
    for typ,off,va,pa,fs,ms,flags,align in elf_parts(raw):
        if typ==1:u.mem_write(va,raw[off:off+fs])
    # Load at ELF base zero. Text is original, no patching. All invoked PLT
    # calls are intercepted before any GOT resolution/OS execution.
    thunks={int(x['address'],16)-0x10000:x['name'] for x in json.loads((PRIOR/'nbd_decompile/function_inventory.json').read_text())['functions'] if x['thunk']}
    u.mem_write(STATE+0x10,P(23)+P(0)+struct.pack('<QQ',block_size,blocks))
    calls=[];executed=[]
    def ret(v):u.reg_write(R.UC_ARM_REG_R0,v&0xffffffff);u.reg_write(R.UC_ARM_REG_PC,u.reg_read(R.UC_ARM_REG_LR))
    def hook(uc,addr,size,data):
        if addr==STOP:uc.emu_stop();return
        executed.append(addr)
        if addr==0x125c:
            calls.append({'call':'local_socket_setup_boundary','server_mode':uc.reg_read(R.UC_ARM_REG_R0),
                          'slot':uc.reg_read(R.UC_ARM_REG_R1),'result':socket_result})
            ret(socket_result);return
        if addr not in thunks:return
        n=thunks[addr]
        if n=='ioctl':
            args=[uc.reg_read(r) for r in [R.UC_ARM_REG_R0,R.UC_ARM_REG_R1,R.UC_ARM_REG_R2,R.UC_ARM_REG_R3]]
            rc=-1 if args[1] in failed else 0
            calls.append({'call':'synthetic_ioctl','callsite_return':hex(uc.reg_read(R.UC_ARM_REG_LR)),
                          'fd':args[0],'request':hex(args[1]),'name':NAMES.get(args[1],'UNKNOWN'),
                          'r2':args[2],'r3':args[3],'synthetic_result':rc})
            assert args[1] in NAMES
            ret(rc);return
        if n.startswith('IDBG_'):ret(0);return
        raise AssertionError('Unapproved imported operation '+n+' at '+hex(addr))
    u.hook_add(U.UC_HOOK_CODE,hook)
    u.reg_write(R.UC_ARM_REG_SP,STACK+0xf000);u.reg_write(R.UC_ARM_REG_LR,STOP);u.reg_write(R.UC_ARM_REG_R0,STATE)
    u.emu_start(0x163c,STOP+4,count=20000)
    assert u.reg_read(R.UC_ARM_REG_PC)==STOP
    return {'name':name,'input_block_size':block_size,'input_blocks':blocks,'synthetic_failed_requests':[hex(x) for x in failed],
            'return':u.reg_read(R.UC_ARM_REG_R0),'calls':calls,'original_instruction_entries':len(executed),
            'final_geometry':list(struct.unpack('<QQ',u.mem_read(STATE+0x18,16)))}

def main():
    cases=[]
    for name,failed in [('success',()),('set_blocksize_fails',(0xab01,)),('set_size_blocks_fails',(0xab07,)),
                        ('all_ioctl_fail',tuple(NAMES))]:
        r=run(name,failed=failed)
        ios=[x for x in r['calls'] if x['call']=='synthetic_ioctl']
        assert len(ios)==7 and r['return']==0 and r['final_geometry']==[512,32768]
        assert ios[0]['name']=='NBD_SET_BLKSIZE' and ios[0]['r2']==512
        assert ios[1]['name']=='NBD_SET_SIZE_BLOCKS' and ios[1]['r2']==32768
        cases.append(r)
    r=run('socket_failure',socket_result=-1);assert r['return']==0xffffffff and len(r['calls'])==1;cases.append(r)
    r=run('distinct_geometry_is_forwarded',1024,262145)
    ios=[x for x in r['calls'] if x['call']=='synthetic_ioctl']
    assert ios[0]['r2']==1024 and ios[1]['r2']==262145;cases.append(r)
    out={'status':'PASS','scope':'Actual original ARM userspace function with synthetic socket/ioctl. No kernel or device operation.',
         'source':str(SOURCE.relative_to(ROOT)),'sha256':EXPECTED,'function_elf_rva':'0x163c','ghidra_address':'0x1163c',
         'cases':cases,'case_count':len(cases),
         'conclusions':['For input 512/32768 the original code sends those exact integer values to NBD_SET_BLKSIZE/NBD_SET_SIZE_BLOCKS.',
                        'Every ioctl result, including both geometry operations, is ignored and the function returns success after the synthetic NBD_DO_IT returns.',
                        'These tests prove userspace forwarding and ignored errors; they do not establish any actual kernel ioctl failure or fallback geometry.']}
    (HERE/'nbd_client_replay.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({'status':out['status'],'cases':len(cases),'first_ioctl_trace':cases[0]['calls']}))

if __name__=='__main__':main()
