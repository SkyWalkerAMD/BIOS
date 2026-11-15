"""Bounded Unicorn executions of original, SHA-pinned AMITSE x64 code.

Firmware data/services/callbacks are controlled fixtures. This is neither whole
ASUS firmware emulation nor proof that an installed hardware hook is reached.
"""
from pathlib import Path
import hashlib,json,struct,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
MODULE=OUT.parent.parent/'hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi'
SHA='99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5'
BASE=0x2000000;STUB=0x3001000;END=0x3000000;STACK=0x4000000;DATA=0x5000000;DENY=0x800000000000000f
ARGS=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
NONVOL=[UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
class Machine:
    def __init__(self):
        assert hashlib.sha256(MODULE.read_bytes()).hexdigest()==SHA
        pe=pefile.PE(str(MODULE));pe.relocate_image(BASE);image=pe.get_memory_mapped_image()
        self.uc=Uc(UC_ARCH_X86,UC_MODE_64);self.uc.mem_map(BASE,(len(image)+4095)&~4095);self.uc.mem_write(BASE,image)
        for addr,size in [(END,0x10000),(STACK,0x200000),(DATA,0x20000)]:self.uc.mem_map(addr,size)
        self.uc.mem_write(STUB,b'\xc3');self.uc.mem_write(STUB+0x100,b'\xc3');self.trace=[];self.callbacks={};self.stops=set()
        self.uc.hook_add(UC_HOOK_CODE,self.hook)
    def hook(self,uc,addr,size,_):
        if BASE<=addr<BASE+0x100000:self.trace.append(addr-BASE)
        if addr in self.stops:uc.emu_stop()
        if addr in self.callbacks:self.callbacks[addr]()
    def w64(self,a,v):self.uc.mem_write(a,struct.pack('<Q',v))
    def w32(self,a,v):self.uc.mem_write(a,struct.pack('<I',v))
    def r64(self,a):return struct.unpack('<Q',self.uc.mem_read(a,8))[0]
    def r32(self,a):return struct.unpack('<I',self.uc.mem_read(a,4))[0]
    def reg(self,r,v=None):
        if v is not None:self.uc.reg_write(r,v)
        return self.uc.reg_read(r)
    def setup(self,entry):
        sp=STACK+0x1fe008;self.w64(sp,END);self.reg(UC_X86_REG_RSP,sp)
        for i,r in enumerate(NONVOL):self.reg(r,0x11110000+i)
        for i,r in enumerate(ARGS):self.reg(r,DATA+0x100*i)
        self.uc.mem_write(sp+40,b'CANARY-ABOVE-SHADOW-SPACE!')
        return sp
    def run(self,rva,stop=END):
        self.uc.emu_start(BASE+rva,stop,count=200000)
        assert self.reg(UC_X86_REG_RIP)==stop or self.reg(UC_X86_REG_RIP) in self.stops,'instruction limit'
def original_dispatch(status=None):
    m=Machine();sp=m.setup(0x62bc);calls=[]
    if status is not None:
        m.w64(BASE+0x7cb30,STUB)
        def callback():
            assert m.reg(UC_X86_REG_RSP)%16==8
            calls.append([m.reg(r) for r in ARGS]);m.reg(UC_X86_REG_RAX,status)
        m.callbacks[STUB]=callback
    m.run(0x62bc)
    assert m.reg(UC_X86_REG_RAX)==(status or 0)
    assert all(m.reg(r)==0x11110000+i for i,r in enumerate(NONVOL))
    assert m.reg(UC_X86_REG_RSP)==sp+8
    assert bytes(m.uc.mem_read(sp+40,26))==b'CANARY-ABOVE-SHADOW-SPACE!'
    if status is not None:assert calls==[[DATA+0x100*i for i in range(4)]]
    return {'name':'default_dispatch' if status is None else 'controlled_dispatch_'+hex(status),'passed':True,'return_status':hex(m.reg(UC_X86_REG_RAX)),'callback_count':len(calls),'nonvolatile_registers_preserved':True,'stack_canary_preserved':True,'instruction_count':len(m.trace),'native_rva_start':'0x62bc'}
def caller(status,initial=False):
    m=Machine();m.setup(0);m.reg(UC_X86_REG_RSP,STACK+0x1fe000);m.reg(UC_X86_REG_R15,2);m.reg(UC_X86_REG_R14,0);m.reg(UC_X86_REG_R13,0)
    m.w64(BASE+0x82748,DATA+0x2000);m.w32(DATA+0x2028,9);m.w64(BASE+0x7cb30,STUB)
    def cb():m.reg(UC_X86_REG_RAX,status)
    m.callbacks[STUB]=cb
    if initial:entry=0xe6f4;m.stops={BASE+0xe70d}
    else:entry=0x1701c;m.stops={BASE+0x17040,BASE+0x17206}
    m.run(entry);page=m.r32(DATA+0x2028);end=m.reg(UC_X86_REG_RIP)-BASE
    if initial:assert page==9 and end==0xe70d and m.reg(UC_X86_REG_RAX)==DATA+0x2000
    elif status==DENY:assert page==2 and end==0x17206
    else:assert page==9 and end==0x17040
    return {'name':('initial_ignores_' if initial else 'page_input_checks_')+hex(status),'passed':True,'native_rva_start':hex(entry),'native_rva_stop':hex(end),'resulting_page_index':page,'fixture_callback_status':hex(status),'instruction_count':len(m.trace)}
def loop_proxy(cached=True):
    m=Machine();m.setup(0);m.w64(BASE+0x82748,DATA+0x2000);m.w32(DATA+0x2028,9)
    m.w64(BASE+0x82998,DATA+0x4000 if cached else 0);m.w64(DATA+0x4000,STUB);m.w64(BASE+0x824c8,DATA+0x5000);m.w64(DATA+0x5140,STUB+0x100)
    calls=[]
    def proxy():
        assert m.reg(UC_X86_REG_RSP)%16==8;calls.append('proxy');m.w32(DATA+0x2028,0);m.reg(UC_X86_REG_RAX,0)
    def locate():
        assert bytes(m.uc.mem_read(m.reg(UC_X86_REG_RCX),16)).hex()=='a847a0c7b182db488e6a7b27cc7c561f'
        assert m.reg(UC_X86_REG_RDX)==0 and m.reg(UC_X86_REG_R8)==BASE+0x82998
        calls.append('locate');m.w64(m.reg(UC_X86_REG_R8),DATA+0x4000);m.reg(UC_X86_REG_RAX,0)
    m.callbacks[STUB]=proxy;m.callbacks[STUB+0x100]=locate;m.run(0x34b7c)
    assert calls==(['proxy'] if cached else ['locate','proxy']) and m.r32(DATA+0x2028)==0
    return {'name':'loop_helper_'+('cached' if cached else 'LocateProtocol'),'passed':True,'calls':calls,'native_rva_start':'0x34b7c','cached_interface_global':'0x82998','instruction_count':len(m.trace),'resulting_page_index':0}
def prologue_equivalence():
    original=bytes(Machine().uc.mem_read(BASE+0xe208,18))
    assert original.hex()=='40555356574154415541564157488d6c24e1'
    snapshots=[]
    for detour in [False,True]:
        m=Machine();sp=m.setup(0);m.reg(UC_X86_REG_RAX,0x8877665544332211)
        if detour:
            trampoline=STUB+0x2000
            absolute=lambda addr:b'\xff\x25\0\0\0\0'+struct.pack('<Q',addr)
            m.uc.mem_write(trampoline,original+absolute(BASE+0xe21a))
            m.uc.mem_write(BASE+0xe208,absolute(trampoline)+b'\x90'*4)
        m.stops={BASE+0xe21a};m.run(0xe208)
        snapshots.append({'registers':[m.reg(r) for r in NONVOL+ARGS+[UC_X86_REG_RSP,UC_X86_REG_RAX]],'stack':bytes(m.uc.mem_read(sp-128,192)).hex()})
    assert snapshots[0]==snapshots[1]
    return {'name':'browser_loop_18_byte_prologue_trampoline_equivalence','passed':True,'entry_rva':'0xe208','resume_rva':'0xe21a','copied_bytes':original.hex(),'replacement':'FF25 indirect absolute branch (14 bytes) + 4 NOP','comparison':'RSP, RAX, integer arguments, all x64 nonvolatile integer registers, 192 stack bytes','limitation':'Only detour/prologue equivalence. No full wrapper lifecycle or browser-body return claim.'}
def main():
    cases=[original_dispatch(),original_dispatch(0),original_dispatch(DENY),original_dispatch(0x8000000000000007)]
    cases += [caller(s,i) for i in [False,True] for s in [0,DENY,0x8000000000000007]]
    cases += [loop_proxy(True),loop_proxy(False),prologue_equivalence()]
    report={'module_sha256':SHA,'cases':cases,'all_passed':all(c['passed'] for c in cases),'limitation':'Native bounded routines with synthetic data/callbacks only. No claim of full ASUS browser, lock integration, timer, SMM, hardware, or physical firmware validation.'}
    (OUT/'native_hooks_result.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
