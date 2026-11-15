"""Run original AMITSE variable get/save machine code under Unicorn.

EFI services are memory-only mocks. This exercises the original 0x1a908,
0x130c and 0x1ab7c functions with appended index119 and the actual P6
serialized variable metadata. No target device or real NVRAM is accessed.
"""
from pathlib import Path
import hashlib, json, struct, sys, uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_INVALID
from unicorn.x86_const import *

IMAGE=ROOT/'analysis/hero_remote_bios_r3/reference/HERO-3107-AMITSE.efi'
EXPECTED_SHA='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
ERR=0x8000000000000000
REG=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
def u(b):return int.from_bytes(b,'little')
def pack(v,n=8):return v.to_bytes(n,'little')

class Machine:
    def __init__(self,record,data,*,present=True,save_status=0):
        self.mu=Uc(UC_ARCH_X86,UC_MODE_64);self.calls=[];self.writes=[];self.present=present
        self.data=bytes(data);self.save_status=save_status;self.alloc=0x5008000
        raw=IMAGE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED_SHA
        pe=pefile.PE(data=raw);assert pe.OPTIONAL_HEADER.ImageBase==0
        self.mu.mem_map(0,(pe.OPTIONAL_HEADER.SizeOfImage+0xfff)&~0xfff)
        self.mu.mem_write(0,pe.get_memory_mapped_image())
        for addr,size in [(0x3000000,0x10000),(0x4000000,0x10000),(0x5000000,0x20000)]:self.mu.mem_map(addr,size)
        self.end=0x3000f00;self.get=0x3000100;self.set=0x3000200;self.v=0x5000000
        self.mu.mem_write(0x1937f0,pack(self.v));self.mu.mem_write(self.v,pack(120,4))
        self.mu.mem_write(0x193658,pack(self.v));self.mu.mem_write(0x193670,pack(self.v))
        self.mu.mem_write(0x1936d0,pack(0x5003100))
        self.mu.mem_write(0x5003100,struct.pack('<IHHQQ',0x3f00,119,0,0x8888,0))
        self.mu.mem_write(self.v+4+119*4,pack(0x1000,4));self.mu.mem_write(self.v+0x1000,record+bytes(128-len(record)))
        self.mu.mem_write(0x180198,pack(0x3001000));self.mu.mem_write(0x3001000+0x48,pack(self.get));self.mu.mem_write(0x3001000+0x58,pack(self.set))
        self.mu.hook_add(UC_HOOK_CODE,self.code);self.mu.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
        self.names=[];self.routed=False
    def read(self,p,n):return bytes(self.mu.mem_read(p,n))
    def write(self,p,b):self.mu.mem_write(p,bytes(b))
    def value(self,p,n=8):return u(self.read(p,n))
    def ret(self,value):
        sp=self.mu.reg_read(UC_X86_REG_RSP);dest=self.value(sp)
        self.mu.reg_write(UC_X86_REG_RAX,value);self.mu.reg_write(UC_X86_REG_RSP,sp+8);self.mu.reg_write(UC_X86_REG_RIP,dest)
    def arg5(self):return self.value(self.mu.reg_read(UC_X86_REG_RSP)+0x28)
    def identity(self,name,guid):
        chars=[]
        for k in range(40):
            n=self.value(name+2*k,2)
            if not n:break
            chars.append(chr(n))
        result=(''.join(chars),str(uuid.UUID(bytes_le=self.read(guid,16))))
        assert result==('HeroIpmiSettings','bef09fe1-8540-4be1-9082-e6624328f435')
        return result
    def code(self,mu,address,size,user):
        a=[mu.reg_read(r) for r in REG]
        if address==self.end:mu.emu_stop();return
        if address==self.get:
            self.identity(a[0],a[1]);self.calls.append('GetVariable')
            if not self.present:self.ret(ERR|14);return
            if a[2]:self.write(a[2],pack(3,4))
            capacity=self.value(a[3]);self.write(a[3],pack(len(self.data)))
            if not self.arg5() or capacity<len(self.data):self.ret(ERR|5);return
            self.write(self.arg5(),self.data);self.ret(0);return
        if address==self.set:
            ident=self.identity(a[0],a[1]);assert a[2]==3 and a[3]==32
            payload=self.read(self.arg5(),a[3]);self.calls.append('SetVariable')
            self.writes.append(dict(name=ident[0],guid=ident[1],attributes=a[2],size=a[3],data_hex=payload.hex(),status=self.save_status))
            if self.save_status==0:self.data=payload
            self.ret(self.save_status);return
        if address==0x14c8:
            assert 0<a[0]<=256
            p=self.alloc;self.alloc+=0x200;self.write(p,bytes(a[0]));self.ret(p);return
        if address==0x1b74c:self.calls.append('InvalidateVariableCache:'+str(a[0]));assert a[0]==119;self.ret(0);return
        if address==0x2785c:self.routed=True;self.calls.append('RouteConfig');self.ret(ERR|3);return
        if address==0x484c8:self.ret(0);return # EFI varstore name is already present.
        if address==0x10749e:self.write(a[0],bytes([a[2]&255])*a[1]);self.ret(a[0]);return
        if address==0x1073e0:self.write(a[0],self.read(a[1],a[2]));self.ret(a[0]);return
        if address==0x13d0:
            self.write(a[0],pack(0));self.ret(0);return
    def invalid(self,mu,access,address,size,value,user):
        raise AssertionError(('invalid emulated access',hex(address),size,hex(mu.reg_read(UC_X86_REG_RIP))))
    def call(self,address,args):
        sp=0x400f008;self.write(sp,pack(self.end))
        self.mu.reg_write(UC_X86_REG_RSP,sp)
        for reg,val in zip(REG,args):self.mu.reg_write(reg,val)
        for i,val in enumerate(args[4:]):self.write(sp+0x28+i*8,pack(val))
        self.mu.emu_start(address,self.end,count=100000)
        assert self.mu.reg_read(UC_X86_REG_RIP)==self.end
        return self.mu.reg_read(UC_X86_REG_RAX)

def main():
    spf=(HERE/'AMITSESetupData-P6.bin').read_bytes();vs=u(spf[0x34:0x38]);start=vs+u(spf[vs+4+119*4:vs+8+119*4]);record=spf[start:start+128]
    assert u(record[0x68:0x6c])==0x1000
    initial=(HERE/'HeroIpmiSettings-default.bin').read_bytes();results=[]
    # Read the same 32 bytes through AMITSE's real EFI-variable branch.
    m=Machine(record,initial);length=0x5007000
    pointer=m.call(0x1a908,[119,length]);assert pointer and m.value(length)==32 and m.read(pointer,32)==initial
    assert m.calls==['GetVariable','GetVariable'] and not m.writes and not m.routed
    results.append(dict(name='native_read_existing_32_byte_variable',pass_=True,calls=m.calls))
    # Save a changed network/timeout value through the original save function.
    changed=bytearray(initial);changed[0]=2;changed[3]=12;changed[8:12]=bytes([192,0,2,5])
    m=Machine(record,initial);buffer=0x5006000;m.write(buffer,changed)
    status=m.call(0x1ab7c,[119,buffer,32]);assert status==0 and m.data==changed and not m.routed
    assert len(m.writes)==1 and m.calls==['SetVariable','InvalidateVariableCache:119']
    results.append(dict(name='native_save_index119_attrs3_exact_bytes',pass_=True,calls=m.calls,write=m.writes[0]))
    # EFI write failure is returned, with no success-path cache invalidation.
    m=Machine(record,initial,save_status=ERR|8);m.write(buffer,changed)
    status=m.call(0x1ab7c,[119,buffer,32]);assert status==ERR|8 and m.data==initial and m.calls==['SetVariable']
    results.append(dict(name='native_write_protected_status_propagates',pass_=True,status=hex(status),calls=m.calls))
    # Missing variable produces a missing result: backend creation is necessary.
    m=Machine(record,initial,present=False);pointer=m.call(0x1a908,[119,length])
    assert pointer==0 and m.value(length)==0 and m.calls==['GetVariable'] and not m.writes
    results.append(dict(name='native_missing_variable_is_not_synthesized',pass_=True,calls=m.calls))
    # A wrong variable class takes RouteConfig, proving flags1000 is material.
    wrong=bytearray(record);wrong[0x68:0x6c]=bytes(4)
    m=Machine(bytes(wrong),initial);m.write(buffer,changed)
    status=m.call(0x1ab7c,[119,buffer,32]);assert status==ERR|3 and m.routed and not m.writes
    results.append(dict(name='negative_wrong_variable_class_reaches_routing',pass_=True,calls=m.calls))
    # Index outside declared table does not issue any variable operation.
    m=Machine(record,initial);m.write(buffer,changed)
    status=m.call(0x1ab7c,[120,buffer,32]);assert status==ERR|2 and not m.calls
    results.append(dict(name='negative_index120_rejected',pass_=True,status=hex(status)))
    # Execute the stock control/default parser for every new question. This
    # verifies that the generated IFR selects the same u8 standard and
    # manufacturing defaults as the precompiled CONTROL_INFO tails.
    forms=(HERE/'Setup-forms-P6.bin').read_bytes();meta=json.loads((HERE/'native-payload.json').read_text())
    fields={f['name']:f for f in meta['settings']['fields']};parsed=[]
    for c in meta['spf_metadata']['controls']:
        if c['name']=='config_status':continue
        f=fields[c['name']];at=c['offset'];pos=at;depth=0
        while True:
            n=forms[pos+1]&127
            if forms[pos]==0x29:depth-=1
            elif forms[pos+1]&128:depth+=1
            pos+=n
            if depth==0:break
        m=Machine(record,initial);m.write(0x5004000,forms[at:pos]);m.write(0x5003028,pack(1,4))
        count=m.call(0x2dabc,[0x8888,0x5004000,0x5003000,0x5003010,0x5003018,0x5003020,0x5003028,0])&255
        width=m.value(0x5003000,2);manufacturing=m.read(m.value(0x5003010),width);standard=m.read(m.value(0x5003018),width)
        assert width==1 and manufacturing==standard==bytes([f['default']])
        assert count==(2 if f['control']=='numeric' else 0)
        ext=[];p=m.value(0x5003020)
        while p:
            ext.append((m.value(p,2),m.value(p+8,1)));p=m.value(p+16)
            assert len(ext)<=2
        assert ext==([(0,f['default']),(1,f['default'])] if f['control']=='numeric' else [])
        assert not m.writes and not m.calls
        parsed.append(dict(name=f['name'],width=width,standard_default=standard.hex(),manufacturing_default=manufacturing.hex(),explicit_defaults=ext))
    results.append(dict(name='native_parser_all21_u8_defaults_match_spf',pass_=True,controls=parsed))
    report=dict(result='PASS',image_sha256=EXPECTED_SHA,functions=['0x1a908','0x130c','0x1ab7c','0x2d160','0x2dabc','0x2ce68'],
        artifact_spf_sha256=hashlib.sha256(spf).hexdigest(),cases=results,
        limitations=['Original native get/save functions executed with EFI services mocked in RAM.',
                     'Does not execute the entire F10 UI flow or prove platform variable policy acceptance.'])
    (HERE/'native-variable-emulation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
