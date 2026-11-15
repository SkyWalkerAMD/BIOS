"""Bounded execution of original SHA-pinned W890 AMITSE instructions.

UEFI services/pages are fixtures. No firmware executes on the host or hardware.
"""
from map_w890 import *
import struct
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
BASE=0x2000000;STUB=0x3001000;END=0x3000000;STACK=0x4000000;DATA=0x5000000
DENY=0x800000000000000f
ARGS=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
NONVOL=[UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
class Machine:
    def __init__(self):
        self.original_sha=sha((NEW/'AMITSE.efi').read_bytes())
        assert self.original_sha=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
        p=pefile.PE(str(NEW/'AMITSE.efi'));p.relocate_image(BASE);b=p.get_memory_mapped_image()
        self.uc=Uc(UC_ARCH_X86,UC_MODE_64);self.uc.mem_map(BASE,(len(b)+4095)&~4095);self.uc.mem_write(BASE,b)
        for addr,n in [(END,0x10000),(STACK,0x200000),(DATA,0x20000)]:self.uc.mem_map(addr,n)
        self.uc.mem_write(STUB,b'\xc3'*0x1000);self.trace=[];self.callbacks={};self.stops=set()
        self.uc.hook_add(UC_HOOK_CODE,self.hook);self.uc.reg_write(UC_X86_REG_CR4,0x600)
    def hook(self,uc,addr,size,_):
        if BASE<=addr<BASE+0x100000:self.trace.append(addr-BASE)
        if addr in self.stops:uc.emu_stop()
        if addr in self.callbacks:self.callbacks[addr]()
    def w64(self,a,v):self.uc.mem_write(a,struct.pack('<Q',v))
    def w32(self,a,v):self.uc.mem_write(a,struct.pack('<I',v))
    def w16(self,a,v):self.uc.mem_write(a,struct.pack('<H',v))
    def r64(self,a):return struct.unpack('<Q',self.uc.mem_read(a,8))[0]
    def r32(self,a):return struct.unpack('<I',self.uc.mem_read(a,4))[0]
    def reg(self,r,v=None):
        if v is not None:self.uc.reg_write(r,v)
        return self.uc.reg_read(r)
    def setup(self):
        sp=STACK+0x1fe008;self.w64(sp,END);self.reg(UC_X86_REG_RSP,sp)
        for i,r in enumerate(NONVOL):self.reg(r,0x11110000+i)
        for i,r in enumerate(ARGS):self.reg(r,DATA+i*0x100)
        self.uc.mem_write(sp+40,b'CANARY-ABOVE-SHADOW-SPACE!');return sp
    def run(self,rva,stop=END):
        self.uc.emu_start(BASE+rva,stop,count=200000)
        assert self.reg(UC_X86_REG_RIP)==stop or self.reg(UC_X86_REG_RIP) in self.stops,'instruction bound'
def dispatch(status):
    m=Machine();sp=m.setup();calls=[];m.w64(BASE+0xa9d08,STUB)
    def cb():calls.append([m.reg(r) for r in ARGS]);m.reg(UC_X86_REG_RAX,status)
    m.callbacks[STUB]=cb;m.run(0x10594)
    assert m.reg(UC_X86_REG_RAX)==status and len(calls)==1
    assert calls[0]==[DATA+i*0x100 for i in range(4)]
    assert [m.reg(r) for r in NONVOL]==[0x11110000+i for i in range(len(NONVOL))]
    assert m.reg(UC_X86_REG_RSP)==sp+8
    assert bytes(m.uc.mem_read(sp+40,26))==b'CANARY-ABOVE-SHADOW-SPACE!'
    return {'name':'dispatch_'+hex(status),'passed':True,'status':hex(status),'native_rva':hex(0x10594),'instructions':len(m.trace)}
def caller(status,initial):
    m=Machine();m.setup();m.reg(UC_X86_REG_RSP,STACK+0x1fe000);m.reg(UC_X86_REG_R15,2)
    m.w64(BASE+0xafdd0,DATA+0x2000);m.w32(DATA+0x2028,9);m.w64(BASE+0xa9d08,STUB)
    m.callbacks[STUB]=lambda:m.reg(UC_X86_REG_RAX,status)
    if initial:entry=0x1968a;m.stops={BASE+0x19693}
    else:entry=0x23a55;m.stops={BASE+0x23c9c,BASE+0x23e71}
    m.run(entry);page=m.r32(DATA+0x2028);stop=m.reg(UC_X86_REG_RIP)-BASE
    assert page==(2 if status==DENY and not initial else 9)
    if initial:assert stop==0x19693 and m.reg(UC_X86_REG_RAX)==m.reg(UC_X86_REG_RBP)-0x39
    else:assert stop==(0x23e71 if status==DENY else 0x23c9c)
    return {'name':('initial_ignores_' if initial else 'pageinput_checks_')+hex(status),'passed':True,'start':hex(entry),'stop':hex(stop),'result_page':page,'instructions':len(m.trace)}
def menu(cookie_kind,history):
    m=Machine();sp=m.setup();app=DATA+0x2000;cookie=DATA+0x3000;bs=DATA+0x4000;h=DATA+0x5000;frees=[]
    m.w64(BASE+0xafdd0,app);m.w32(app+0x28,2);m.w64(BASE+0xafbc8,bs);m.w64(bs+0x48,STUB)
    m.w64(BASE+0xafde8,h if history else 0);m.w32(BASE+0xafe00,3);m.w32(BASE+0xafddc,2)
    m.w32(cookie,cookie_kind or 0);m.w16(cookie+8,4);m.reg(UC_X86_REG_R8,cookie if cookie_kind is not None else 0)
    def free():frees.append(m.reg(UC_X86_REG_RCX));m.reg(UC_X86_REG_RAX,0)
    m.callbacks[STUB]=free;m.run(0x22818)
    if cookie_kind==8:
        assert m.r32(app+0x28)==4 and bytes(m.uc.mem_read(app+0x58,1))==b'\1' and m.r32(app+0x5c)==1
        assert m.r64(BASE+0xafde8)==0 and m.r32(BASE+0xafe00)==0 and m.r32(BASE+0xafddc)==0
        assert frees==([h] if history else [])
    else:
        assert m.r32(app+0x28)==2 and m.r64(BASE+0xafde8)==(h if history else 0) and not frees
        assert m.r32(BASE+0xafe00)==3 and m.r32(BASE+0xafddc)==2
    assert m.reg(UC_X86_REG_RSP)==sp+8
    return {'name':'menu_kind_'+str(cookie_kind)+'_history_'+str(history),'passed':True,'history_frees':len(frees),'new_page':m.r32(app+0x28),'native_rva':'0x22818','instructions':len(m.trace)}
def main():
    cases=[dispatch(x) for x in [0,DENY,0x8000000000000007]]
    cases +=[caller(x,i)for i in [False,True]for x in [0,DENY,0x8000000000000007]]
    cases +=[menu(kind,h)for kind in [None,7,8]for h in [False,True]]
    result={'status':'PASS','scope':__doc__,'cases':cases,'case_count':len(cases),'module_sha256':sha((NEW/'AMITSE.efi').read_bytes()),'source_sha256':sha(Path(__file__).read_bytes()),'conclusions':['Initial browser navigation ignores EFI_ACCESS_DENIED, so its callback alone cannot enforce first entry.','Page input restores only the page index when navigation returns EFI_ACCESS_DENIED.','The menu callback updates page, redraw and menu state and destroys history before that late navigation check.'],'hardware_validation':False}
    (HERE/'native_replay.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
