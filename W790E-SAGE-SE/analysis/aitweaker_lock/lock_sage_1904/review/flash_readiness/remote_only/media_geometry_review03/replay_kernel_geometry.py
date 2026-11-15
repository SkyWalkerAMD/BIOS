"""Pinned ARM kernel geometry arithmetic in synthetic memory only.

Only named functions/fragments run. Allocation, file-open, locks and kernel
services are audited pure stubs. Never imports or executes host ioctls/files.
"""
import hashlib,json,struct,sys
from kernel_targets import HERE,KERNEL,EXPECTED
from trace_nbd import ROOT
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import unicorn as U
from unicorn import arm_const as R

BASE=0x80008000;STOP=0x60000000;H=0x70000000;STACK=0x71000000
BDEV=H;DISK=H+0x1000;NBD=H+0x2000;CFG=H+0x3000;QUEUE=H+0x4000
LUN=H+0x5000;FILE=H+0x6000;INODE=H+0x7000;MAPPING=H+0x8000;OUTPUT=H+0x9000
P=lambda x:struct.pack('<I',x&0xffffffff)
Q=lambda x:struct.pack('<Q',x&0xffffffffffffffff)
REGS=(R.UC_ARM_REG_R0,R.UC_ARM_REG_R1,R.UC_ARM_REG_R2,R.UC_ARM_REG_R3)

class VM:
    def __init__(self):
        raw=KERNEL.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
        self.u=U.Uc(U.UC_ARCH_ARM,U.UC_MODE_ARM|U.UC_MODE_LITTLE_ENDIAN)
        self.u.mem_map(BASE,(len(raw)+4095)&~4095);self.u.mem_write(BASE,raw)
        self.u.mem_map(H,0x20000);self.u.mem_map(STACK,0x10000);self.u.mem_map(STOP,4096)
        self.symbols={int(x['address'],16):x['name'] for x in json.loads((HERE/'kernel_symbols.json').read_text())['symbols']}
        self.addresses={v:k for k,v in self.symbols.items()}
        self.calls=[];self.active_ranges=[];self.until=STOP;self.steps=0
        self.u.hook_add(U.UC_HOOK_CODE,self.hook)
    def word(self,p):return struct.unpack('<I',self.u.mem_read(p,4))[0]
    def quad(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
    def ret(self,v=0):self.u.reg_write(R.UC_ARM_REG_R0,v&0xffffffff);self.u.reg_write(R.UC_ARM_REG_PC,self.u.reg_read(R.UC_ARM_REG_LR))
    def hook(self,u,addr,size,data):
        if addr==self.until:u.emu_stop();return
        self.steps+=1
        if any(a<=addr<b for a,b in self.active_ranges):return
        name=self.symbols.get(addr)
        args=[u.reg_read(r) for r in REGS]
        self.calls.append({'function':name or hex(addr),'r0_r3':args})
        if name=='__gnu_mcount_nc':
            u.reg_write(R.UC_ARM_REG_SP,u.reg_read(R.UC_ARM_REG_SP)+4);self.ret(args[0]);return
        if name=='capable':self.ret(1);return
        if name in ['mutex_lock','mutex_unlock','__init_waitqueue_head','try_module_get','kobject_uevent','bdput']:
            self.ret(0);return
        if name=='kmem_cache_alloc_trace':
            assert args[2]==0x50;u.mem_write(CFG,bytes(0x50));self.ret(CFG);return
        if name=='div_s64_rem':
            value=args[0]|(args[1]<<32)
            if value>>63:value-=1<<64
            div=args[2];assert div>0
            quotient=abs(value)//div*(1 if value>=0 else -1);rem=value-quotient*div
            u.mem_write(args[3],P(rem));u.reg_write(R.UC_ARM_REG_R1,(quotient>>32)&0xffffffff);self.ret(quotient);return
        if name=='bdget_disk':self.ret(BDEV);return
        if name=='blk_queue_logical_block_size':
            assert args[0]==QUEUE;u.mem_write(QUEUE+0x370,P(args[1]));self.ret();return
        if name=='blk_queue_physical_block_size':self.ret();return
        if name=='bd_set_size':
            assert args[0]==BDEV;u.mem_write(INODE+0x30,struct.pack('<II',args[2],args[3]));self.ret();return
        if name=='filp_open':
            # This is a synthetic kernel object pointer; no host path is opened.
            assert args[0]==H+0xa000;self.ret(FILE);return
        raise AssertionError('Unapproved kernel boundary '+str(name)+' at '+hex(addr))
    def call(self,start,end,args):
        self.active_ranges=[(start,end)];self.until=STOP
        self.u.reg_write(R.UC_ARM_REG_SP,STACK+0xf000);self.u.reg_write(R.UC_ARM_REG_LR,STOP)
        for r,v in zip(REGS,args):self.u.reg_write(r,v)
        self.u.emu_start(start,STOP+4,count=50000)
        assert self.u.reg_read(R.UC_ARM_REG_PC)==STOP
        return self.u.reg_read(R.UC_ARM_REG_R0)
    def setup(self):
        for p,v in [(BDEV+0x54,DISK),(DISK+0x278,NBD),(DISK+0x274,QUEUE),(NBD+0x78,CFG),(NBD+0x90,DISK)]:self.u.mem_write(p,P(v))
        self.u.mem_write(BDEV+4,P(2))
    def capacity_fragment(self):
        self.active_ranges=[(0x8073743c,0x80737484)];self.until=0x80737484
        self.u.reg_write(R.UC_ARM_REG_R1,LUN);self.u.reg_write(R.UC_ARM_REG_R2,OUTPUT);self.u.reg_write(R.UC_ARM_REG_R7,8)
        self.u.emu_start(0x8073743c,0x80737488,count=1000)
        assert self.u.reg_read(R.UC_ARM_REG_PC)==0x80737484
        return bytes(self.u.mem_read(OUTPUT,8))

def nbd_case(name,block_size=512,blocks=32768):
    v=VM();v.setup()
    rc=v.call(0x8066c890,0x8066c918,[]);assert rc==CFG
    default=v.quad(CFG+0x38);assert default==1024
    setblock=v.call(0x8066d2a8,0x8066d680,[BDEV,0,0xab01,block_size])
    setsize=v.call(0x8066d2a8,0x8066d680,[BDEV,0,0xab07,blocks])
    assert setblock==setsize==0
    expected_bs=block_size or 1024
    assert v.quad(CFG+0x38)==expected_bs and v.quad(CFG+0x40)==expected_bs*blocks
    v.call(0x80669b08,0x80669c14,[NBD,0])
    assert v.word(QUEUE+0x370)==expected_bs and v.quad(DISK+0x40)==expected_bs*blocks//512
    return {'name':name,'initial_default_block_size':default,'requested_block_size':block_size,'requested_blocks':blocks,
            'final_config_block_size':v.quad(CFG+0x38),'final_config_bytes':v.quad(CFG+0x40),
            'queue_logical_block_size':v.word(QUEUE+0x370),'gendisk_512_byte_sectors':v.quad(DISK+0x40),
            'synthetic_inode_bytes':v.quad(INODE+0x30),'instruction_count':v.steps,'stub_calls':v.calls}

def gadget_case(name,block_size,backing_bytes):
    v=VM();v.setup()
    for p,n in [(FILE+0x10,INODE),(FILE+0x28,0x60002),(INODE+0x20,MAPPING),(MAPPING,INODE),
                (INODE+0x160,BDEV),(QUEUE+0x370,block_size)]:v.u.mem_write(p,P(n))
    v.u.mem_write(INODE,struct.pack('<H',0x6000));v.u.mem_write(INODE+0x30,Q(backing_bytes))
    v.u.mem_write(H+0xa000,b'/synthetic/only\0')
    rc=v.call(0x807385b0,0x80738984,[LUN,H+0xa000]);assert rc==0
    result=v.capacity_fragment();last,bs=struct.unpack('>II',result)
    assert bs==block_size and last==backing_bytes//bs-1
    return {'name':name,'synthetic_queue_block_size':block_size,'synthetic_backing_bytes':backing_bytes,
            'lun_block_size':v.word(LUN+0x2c),'lun_block_shift':v.word(LUN+0x28),'lun_blocks':v.quad(LUN+0x10),
            'read_capacity_bytes':result.hex(),'last_lba':last,'block_size':bs,
            'instruction_count':v.steps,'stub_calls':v.calls}

def main():
    cases=[nbd_case('normal_512_32768'),nbd_case('explicit_zero_requests_default_1024',0),nbd_case('explicit_1024',1024)]
    cases.extend([gadget_case('normal_16MiB_512',512,16777216),gadget_case('16MiB_with_1024_only',1024,16777216),
                  gadget_case('256MiB_1024',1024,268435456),gadget_case('geometry_matching_observed_fields_requires_extra_1KiB',1024,268436480)])
    out={'status':'PASS','kernel_sha256':EXPECTED,'scope':'Actual pinned ARM allocation/ioctl/size-update/LUN-open and READ CAPACITY output instructions with fully synthetic kernel objects and trapped boundaries.',
         'case_count':len(cases),'cases':cases,
         'limits':['Not a kernel boot or actual NBD/gadget execution. No live object, scheduling, locking, transport or USB state is observed.',
                   'The last case constructs the observed geometry mathematically; it does not identify why hardware reported that geometry.']}
    (HERE/'kernel_geometry_replay.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps({'status':out['status'],'cases':len(cases),'results':[{k:v for k,v in c.items() if k not in ['stub_calls']} for c in cases]},indent=2))
if __name__=='__main__':main()
