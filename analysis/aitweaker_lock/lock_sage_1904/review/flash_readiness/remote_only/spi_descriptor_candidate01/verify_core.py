"""Run compiled FD01 core in synthetic MMIO, including ambiguous-I/O failures.

The SPI model comes from Intel 743845-001. No target access or privileged host
execution occurs; the model is not proof of physical controller behavior.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
q=lambda n:struct.pack('<Q',n)
d=lambda n:struct.pack('<I',n)
ERR=lambda n:(1<<63)|n
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
pe=pefile.PE(str(HERE/'build/BOOTX64.EFI'));pe.relocate_image(BASE);image=pe.get_memory_mapped_image()
symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(HERE/'build/inventory.map').read_text(),re.M)}
REGS={0x0c:0,0x50:0x4acf,0x54:0,0x84:0,0x88:0,0x8c:0,0x90:0,0x94:0,0x98:0}
FLASH=bytearray(((i*17+0x29)^(i>>5))&255 for i in range(4096));struct.pack_into('<I',FLASH,0x10,0x0ff0a55a)

def execute(name,**opt):
    u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
    for a,n in [(BASE,(len(image)+4095)&~4095),(HEAP,0x10000),(STACK,0x20000),(STOP,0x1000)]:u.mem_map(a,n)
    u.mem_write(BASE,image);u.mem_write(HEAP,b'\xcc'*0x10000)
    io=HEAP;first=HEAP+0x1000;second=HEAP+0x3000;result=HEAP+0x5000
    u.mem_write(io,q(0xabc)+q(STOP+0x100)+q(STOP+0x110)+q(STOP+0x120)+q(STOP+0x130))
    state={'status':opt.get('status',0x0010e800),'address':opt.get('address',0x03ffffc0),
           'reads':0,'writes':0,'binding':0,'go':0,'poll':0,'waiting':False,'stalls':0,'fault':False}
    original_status=state['status'];original_address=state['address'];regs=dict(REGS);regs.update(opt.get('registers',{}))
    protected=dict(regs);trace=[];data=bytearray(FLASH)
    if opt.get('bad_signature'):data[0x10]^=1
    def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
    def ret(v):
        sp=u.reg_read(R.UC_X86_REG_RSP);u.reg_write(R.UC_X86_REG_RAX,v);u.reg_write(R.UC_X86_REG_RIP,rq(sp));u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def step(uc,a,n,_):
        if a==STOP:uc.emu_stop();return
        assert STOP+0x100<=a<=STOP+0x130,(name,hex(a))
        ctx,off,value=[u.reg_read(x) for x in [R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8]]
        assert ctx==0xabc
        if a==STOP+0x130:
            state['binding']+=1;ret(0 if state['binding']==opt.get('binding_fail') else 1);return
        if a==STOP+0x120:
            assert off==10;state['stalls']+=1
            failed=state['stalls']==opt.get('stall_fail');state['fault']|=failed;ret(ERR(7) if failed else 0);return
        if a==STOP+0x100:
            state['reads']+=1
            assert off in REGS or off in [4,8] or (0x10<=off<=0x4c and off%4==0),(name,off)
            if state['reads']==opt.get('read_fail'):
                state['fault']=True;trace.append(['read-error',off]);ret(ERR(7));return
            if off==4:
                if state['waiting']:
                    state['poll']+=1
                    if state['poll']>=opt.get('polls',2):state['waiting']=False;state['status']=0x3f00e801
                val=state['status']
                if state['go']==opt.get('poll_corrupt_at') and state['poll']==1:val^=opt['poll_xor']
                if state['go']==opt.get('end_corrupt_at') and not state['waiting'] and trace and trace[-1][0]=='data':val^=opt['end_xor']
            elif off==8:
                val=state['address']
                if opt.get('address_mismatch')=='pre' and state['writes']==1:val^=64
                if opt.get('address_mismatch')=='post' and state['go']==1 and not state['waiting']:val^=64
            elif off in REGS:
                val=regs[off]
                if off==0x0c and state['go']==opt.get('changed_protection_after_go'):val^=1
            else:
                assert state['go'] and not state['waiting'] and state['status']&1
                pos=state['address']+off-0x10;assert 0<=pos<=4092
                block=bytearray(data[pos:pos+4])
                if state['go']>64 and 'mismatch' in opt and pos<=opt['mismatch']<pos+4:block[opt['mismatch']-pos]^=1
                val=struct.unpack('<I',block)[0]
            u.mem_write(value,d(val));trace.append(['data' if 0x10<=off<=0x4c else 'read',off,val]);ret(0);return
        assert a==STOP+0x110
        assert not state['fault'],'Controller write after ambiguous failure'
        assert off in [4,8],(name,off);value&=0xffffffff
        state['writes']+=1;trace.append(['write',off,value])
        failed=state['writes']==opt.get('write_fail')
        if not failed or opt.get('error_after_apply'):
            if off==8:
                assert not state['waiting'];assert value==original_address or (value<4096 and value%64==0)
                state['address']=value
            elif value&0x10000:
                assert value==0x3f01e800 and not state['waiting'] and not state['status']&7
                assert 0<=state['address']<4096 and state['address']%64==0
                state['go']+=1;state['poll']=0;state['waiting']=True;state['status']=0x3f00e820
            else:
                assert not state['waiting'];assert value&0xf800==state['status']&0xf800==0xe800
                assert value&0xc0e00000==0 and ((value>>17)&15)<=8
                state['status']=(value&0xffff0000)|(state['status']&0xfff8)|((state['status']&7)&~(value&7))
        if failed:state['fault']=True;ret(ERR(7))
        else:ret(0)
    u.hook_add(U.UC_HOOK_CODE,step,begin=STOP,end=STOP+0xfff)
    written=[]
    def memwrite(uc,access,a,n,value,_):
        assert STACK<=a and a+n<=STACK+0x20000 or first<=a and a+n<=first+4096 or second<=a and a+n<=second+4096 or result<=a and a+n<=result+56,(name,hex(a),n)
        written.append((a,n))
    u.hook_add(U.UC_HOOK_MEM_WRITE,memwrite)
    sp=STACK+0x10008;u.mem_write(sp,q(STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
    for reg,val in zip([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9],[io,first,second,result]):u.reg_write(reg,val)
    u.emu_start(symbols['fd_capture'],STOP+1,count=12000000)
    assert u.reg_read(R.UC_X86_REG_RIP)==STOP,name
    status=u.reg_read(R.UC_X86_REG_RAX);raw=struct.unpack('<12IQ',u.mem_read(result,56))
    keys=['reads','writes','go_attempts','blocks','passes','failure_stage','failure_offset','final_transients_restored','protection_unchanged','initial_hsfc','initial_faddr','last_status','failure_status']
    record=dict(zip(keys,raw));expect=opt.get('expected_stage',0)
    assert record['failure_stage']==expect,(name,record,expect)
    assert bool(status)==bool(expect),(name,hex(status))
    assert record['reads']==state['reads'] and record['writes']==state['writes']
    assert regs==protected
    assert bytes(u.mem_read(first-16,16))==b'\xcc'*16 and bytes(u.mem_read(first+4096,16))==b'\xcc'*16
    assert bytes(u.mem_read(second-16,16))==b'\xcc'*16 and bytes(u.mem_read(second+4096,16))==b'\xcc'*16
    if not expect:
        assert state['go']==128 and record['blocks']==128 and record['passes']==2
        assert record['final_transients_restored']==record['protection_unchanged']==1
        assert bytes(u.mem_read(first,4096))==bytes(u.mem_read(second,4096))==data
        assert state['address']==original_address and state['status']==original_status&~1
    if opt.get('no_go'):assert state['go']==0
    if expect in [11,12,13,14,15]:assert state['go']==1 and record['final_transients_restored']==0
    return {'name':name,'passed':True,'efi_return':hex(status),'result':record,
            'controller_writes_to_offsets':[4,8] if state['writes'] else [],'successful_go_count':state['go'],
            'trace_sha256':hashlib.sha256(json.dumps(trace,separators=(',',':')).encode()).hexdigest()}

def main():
    started=time.monotonic();cases=[]
    def add(name,**kw):
        cases.append(execute(name,**kw))
        if len(cases)%20==0:print(json.dumps({'completed_cases':len(cases),'seconds':round(time.monotonic()-started,1)}),flush=True)
    add('normal_128_READ64_two_matching_passes')
    add('preexisting_done_acknowledged',status=0x0010e801)
    add('immediate_done',polls=1,address=0)
    add('slower_done',polls=9)
    for off,val in [(0x0c,0xffffffff),(0x50,0x4ace),(0x50,0xffffffff),(0x54,0x10000)]+[(o,1) for o in [0x84,0x88,0x8c,0x90,0x94,0x98]]:
        add(f'refuse_protection_{off:02x}_{val:x}',registers={off:val},expected_stage=3,no_go=True)
    for bit in [1,2,3,4,5,6,10,11,12,13,14,15,16,21,22,23,30,31]:
        add(f'refuse_initial_status_bit_{bit}',status=0x0010e800^(1<<bit),expected_stage=5,no_go=True)
    add('reserved_cycle_15',status=0x001ee800,expected_stage=5,no_go=True)
    add('reserved_address_bits',address=0x80000000,expected_stage=8,no_go=True)
    for n in [1,2,65,129,130]:add(f'binding_lost_{n}',binding_fail=n,expected_stage=7)
    for n in [1,2,3,10,11,12,24,40,100,500,6000]:
        if n<=cases[0]['result']['reads']:add(f'read_error_{n}',read_fail=n,expected_stage=1)
    for n in [1,2,3,4,100,192,384,385,386]:
        if n<=cases[0]['result']['writes']:
            for applied in [False,True]:add(f'write_error_{n}_applied_{applied}',write_fail=n,error_after_apply=applied,expected_stage=2)
    add('pre_GO_address_readback_mismatch',address_mismatch='pre',expected_stage=9,no_go=True)
    add('post_GO_address_change',address_mismatch='post',expected_stage=14)
    for bit in [1,2,11,12,14,15,16,17,21,31]:add(f'poll_changed_bit_{bit}',poll_corrupt_at=1,poll_xor=1<<bit,expected_stage=11)
    add('completion_removed_after_data',end_corrupt_at=1,end_xor=1,expected_stage=15)
    add('busy_after_data',end_corrupt_at=1,end_xor=0x20,expected_stage=5)
    add('stall_failure_after_GO',stall_fail=1,expected_stage=12)
    add('completion_timeout_no_second_command',polls=10001,expected_stage=13)
    for n in [1,64,128]:add(f'protection_changed_after_GO_{n}',changed_protection_after_go=n,expected_stage=4)
    for n in [0,16,4095]:add(f'two_pass_mismatch_at_{n}',mismatch=n,expected_stage=18)
    add('matching_but_invalid_descriptor_signature',bad_signature=True,expected_stage=19)
    report={'status':'PASS_COMPILED_DESCRIPTOR_CORE_SYNTHETIC_ONLY','case_count':len(cases),'cases':cases,
            'efi_sha256':sha(HERE/'build/BOOTX64.EFI'),'source_sha256':sha(HERE/'source/fd_core.c'),
            'verification_source_sha256':sha(Path(__file__)),'seconds':round(time.monotonic()-started,2),
            'physical_access':False,'tested_scope':'Exact linked EFI fd_capture function; modeled register/W1C/FGO semantics and explicit firmware I/O stubs.',
            'limits':['No actual SPI controller or descriptor data.','Identity/map/native-protocol binding and KVM transport are separate frontend checks.',
                      'Each captured state is a time-local observation; no claim of exclusive control against SMM or another firmware component.']}
    (HERE/'core_regression.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ['status','case_count','seconds','efi_sha256']}))
if __name__=='__main__':main()
