"""Inherited independently reviewed VM, used only against full TX09 PE bytes.
No carrier compile, no native host execution and no hardware methods.
"""
from pathlib import Path
from datetime import datetime,timezone
import hashlib, json, os, re, struct, subprocess, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
D04=HERE.parent
TX=D04/'ram_transaction09'
ROOT=next(path for path in HERE.parents if (path/'tools/zig-x86_64-windows-0.14.1/zig.exe').exists())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
q=lambda value:struct.pack('<Q',value)
ERR=lambda value:(1<<63)|value
BASE=0x140000000
DATA=0x50000000
ST=DATA;BS=DATA+0x1000;RT=DATA+0x2000;OUT=DATA+0x3000;IN=DATA+0x4000
STACK=0x70000000;STOP=DATA+0x10000;TRAMP=STOP+0x1000
FUNCTIONS={name:STOP+0x100+16*i for i,name in enumerate(['create','create_ex','watchdog','attribute','clear','output','input','stall'])}


class VM:
    def __init__(self,efi,symbols,ending=None,failed=None,missing=None,failure_handle=False):
        self.symbols=symbols;self.ending=ending;self.failed=failed;self.calls=[];self.after_end=[];self.callback=0
        self.failure_handle=failure_handle;self.result=None;self.end_fired=False
        self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
        pe=pefile.PE(str(efi));pe.relocate_image(BASE);raw=pe.get_memory_mapped_image()
        self.u.mem_map(BASE,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.u.mem_write(BASE,raw)
        self.u.mem_map(DATA,0x20000);self.u.mem_map(STACK,0x20000)
        for offset,value in [(0x60,BS),(0x58,RT),(0x40,OUT),(0x30,IN)]:self.u.mem_write(ST+offset,q(value))
        for name,offset in [('create',0x50),('create_ex',0x170),('watchdog',0x100),('stall',0xf8)]:self.u.mem_write(BS+offset,q(0 if name==missing else FUNCTIONS[name]))
        for name,offset in [('attribute',0x28),('clear',0x30),('output',8)]:self.u.mem_write(OUT+offset,q(FUNCTIONS[name]))
        self.u.mem_write(IN+8,q(FUNCTIONS['input']))
        self.u.hook_add(U.UC_HOOK_CODE,self.code)
        self.u.hook_add(U.UC_HOOK_MEM_INVALID,self.invalid)
    def invalid(self,u,access,address,size,value,context):
        raise AssertionError(('fixture mapping failure',self.ending,self.failed,hex(u.reg_read(R.UC_X86_REG_RIP)),hex(address),size,self.calls))
    def getq(self,address):return struct.unpack('<Q',self.u.mem_read(address,8))[0]
    def arg(self,index):
        if index<4:return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][index])
        return self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+0x28+(index-4)*8)
    def ret(self,value):
        sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,value)
        self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
    def end_then_return(self,status):
        assert self.callback
        self.end_fired=True
        code=b'\x48\x83\xec\x28\x48\xb9'+q(0xdead0000)+b'\x31\xd2\x48\xb8'+q(self.callback)+b'\xff\xd0\x48\xb8'+q(status)+b'\x48\x83\xc4\x28\xc3'
        self.u.mem_write(TRAMP,code);self.u.reg_write(R.UC_X86_REG_RIP,TRAMP)
    def code(self,u,address,size,context):
        reason=struct.unpack('<I',u.mem_read(self.symbols['app_hold_reason'],4))[0]
        if reason:self.result=('resident_hold',reason);u.emu_stop();return
        if address==STOP:self.result=('returned',u.reg_read(R.UC_X86_REG_RAX));u.emu_stop();return
        name=next((key for key,value in FUNCTIONS.items() if value==address),None)
        if name is None:return
        self.calls.append(name)
        if self.end_fired:self.after_end.append(name)
        status=ERR(7) if name==self.failed else 0
        if name in ['create','create_ex']:
            self.callback=self.arg(2)
            self.u.mem_write(self.arg(4 if name=='create'else 5),q(0 if status and not self.failure_handle else 0xdead0000))
        if name==self.ending:self.end_then_return(status);return
        if name=='input':self.result=('menu_reached',0);u.emu_stop();return
        self.ret(status)
    def run(self):
        sp=STACK+0x1fe08;self.u.mem_write(sp,q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
        self.u.reg_write(R.UC_X86_REG_RCX,0x12345000);self.u.reg_write(R.UC_X86_REG_RDX,ST)
        self.u.emu_start(self.symbols['app_main'],0,count=2000000)
        assert self.result is not None
        return self.result

