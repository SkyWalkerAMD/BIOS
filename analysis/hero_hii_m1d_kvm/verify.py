"""Run final EFI bytes against bounded EFI doubles; all file/PCI/RT I/O forbidden."""
from pathlib import Path
import sys,struct,re,uuid,json,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'));sys.path.insert(0,str(ROOT/'analysis'))
import verify_hero_ipmi_fan_b2c as base
import pefile
from unicorn.x86_const import *
ERR=base.ERR
DP='09576e91-6d3f-11d2-8e39-00a0c969723b';DB='ef9fc172-a1b2-4693-b327-6d32fc416042';BROWSER='b9d4c360-bcfb-4f9b-9298-53c136982258';GOP='9042a9de-23dc-4a38-96fb-7aded080516a'
class Hang(Exception):pass
class Machine(base.Machine):
    def __init__(self,keys='qq',fault=None,stage=None):
        super().__init__('real_3107');self.keys=list(keys);self.fault=fault;self.stage=stage
        self.shows=0;self.adds=0;self.removes=0;self.path_installed=False;self.hii_live=False
        self.u.mem_write(0x100000,bytes(0x100000));pe=pefile.PE(str(OUT/'payload/EFI/BOOT/BOOTX64.EFI'));pe.relocate_image(0x100000);self.u.mem_write(0x100000,pe.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'diag.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+(\w+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        for off,name in ((0x40,'Allocate'),(0x80,'Install'),(0x90,'Uninstall')):self.stub(self.bs+off,name)
        self.stub(self.textout+0x28,'Attribute');self.w64(self.textin+16,0x1234)
        self.db=self.alloc(bytes(16));self.stub(self.db,'AddPackages');self.stub(self.db+8,'RemovePackages')
        self.browser=self.alloc(bytes(16));self.stub(self.browser,'SendForm')
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e,f,g=[self.r64(rsp+0x28+i*8) for i in range(3)];result=0;self.calls.append(name)
        if self.fault=='hang' and name==self.stage:raise Hang(name)
        if name=='Output':
            value=self.wide(b);self.output+=value
            if self.fault=='output' and (not self.stage or self.stage in value):result=ERR(7)
        elif name=='Attribute':assert b in (7,15)
        elif name=='Watchdog':assert a==b==c==d==0
        elif name=='ReadKey':
            if self.fault=='input_error':result=ERR(7)
            else:
                assert self.keys,('unbounded input',self.output[-400:]);k=self.keys.pop(0)
                u.mem_write(b,struct.pack('<HH',0x17 if k=='!' else 0,0 if k=='!' else ord(k)))
        elif name=='Stall':assert a==5000000
        elif name=='HandleProtocol':
            assert str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==GOP;result=ERR(14)
        elif name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))))
            assert guid in (DB,BROWSER,GOP)
            if guid==GOP or self.fault=='missing_db' and guid==DB or self.fault=='missing_browser' and guid==BROWSER:result=ERR(14)
            else:self.w64(c,self.db if guid==DB else self.browser)
        elif name=='Allocate':
            assert a==4 and b==24
            if self.fault=='allocate':result=ERR(9)
            else:self.path=self.alloc(bytes(b));self.w64(c,self.path)
        elif name=='FreePool':
            assert not self.path_installed and not self.hii_live;self.freed.append(a)
        elif name=='Install':
            assert str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==DP
            path=bytes(u.mem_read(d,24));assert path[:4]==b'\x01\x04\x14\x00' and path[-4:]==b'\x7f\xff\x04\x00'
            if self.fault=='install':result=ERR(7)
            else:self.w64(a,0xdddd);self.path_installed=True
        elif name=='AddPackages':
            assert self.path_installed and c==0xdddd and 'NEW_PACKAGES_BEFORE' in self.output
            self.adds+=1
            if self.fault=='packages':result=ERR(7)
            else:self.w64(d,0xeeee);self.hii_live=True
        elif name=='RemovePackages':
            assert self.hii_live;self.removes+=1
            if self.fault=='remove':result=ERR(7)
            else:self.hii_live=False
        elif name=='Uninstall':
            assert not self.hii_live and self.path_installed
            if self.fault=='uninstall':result=ERR(7)
            else:self.path_installed=False
        elif name=='SendForm':
            assert self.hii_live and self.r64(b)==0xeeee and c==1 and e==1 and f==0
            assert str(uuid.UUID(bytes_le=bytes(u.mem_read(d,16))))=='33f07484-7ced-4094-9adf-c219535d9acc'
            assert 'ENTER_SEND_FORM' in self.output and 'CAPTURE NOW' in self.output
            self.shows+=1;self.w64(g,0)
            if self.fault=='send':result=ERR(3)
        else:raise AssertionError(('forbidden/unexpected service',name))
        u.reg_write(UC_X86_REG_RAX,result)
        for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
    def run(self):
        rsp=0xef0000-8;stop=0x8f0000;self.w64(rsp,stop);self.u.reg_write(UC_X86_REG_RSP,rsp)
        self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
        self.u.emu_start(self.functions['efi_main'],stop,count=30000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,'instruction limit'
        for a,n in self.guard:assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16 and bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        assert not self.pci_writes and not self.opened and not self.log
        return self.u.reg_read(UC_X86_REG_RAX)

def main():
    rows=[]
    def passed(name):rows.append(dict(case=name,passed=True));print(name,'PASS',flush=True)
    for label,keys in [('quit','qq'),('esc','!!'),('register','pqq'),('show','ps\rq\r'),('repeat_P','PPs\rq\r'),('text_pages','pvnnb!qq'),('legacy_L','lpqq')]:
        m=Machine(keys);assert m.run()==0 and m.calls[0]=='Output' and not m.path_installed and not m.hii_live
        passed(label)
    m=Machine('sq\r');assert m.run()!=0 and m.shows==0;passed('S_requires_P')
    for keys in ('ps!qq','psqqq'):
        m=Machine(keys);assert m.run()==0 and m.shows==0 and 'SHOW_CANCELLED' in m.output;passed('cancel_'+repr(keys))
    m=Machine('ps!s\rqq');assert m.run()==0 and m.shows==1;passed('cancel_then_show')
    m=Machine('ps\rsqq');assert m.run()!=0 and m.shows==1;passed('SendForm_once')
    for fault in ('missing_db','missing_browser','allocate','install','packages','send','remove','uninstall'):
        keys='ps\rqq' if fault in ('send','remove','uninstall') else 'pqq'
        m=Machine(keys,fault);assert m.run()!=0
        if fault in ('remove','uninstall'):assert m.path not in m.freed and m.path_installed
        else:assert not m.path_installed and not m.hii_live
        passed('fault_'+fault)
    for service,checkpoint in [('AddPackages','NEW_PACKAGES_BEFORE'),('SendForm','ENTER_SEND_FORM')]:
        m=Machine('ps\rqq','hang',service)
        try:m.run();raise AssertionError('expected hang')
        except Hang:pass
        assert checkpoint in m.output;passed('visible_before_hang_'+service)
    m=Machine('ps\rqq','output','CAPTURE NOW');assert m.run()!=0 and m.shows==0;passed('display_error_blocks_SendForm')
    m=Machine('qq','input_error');assert m.run()!=0 and m.calls.count('Stall')==1;passed('input_error_bounded')
    m=Machine('psc!\rqc!\r');assert m.run()==0 and m.shows==1 and 'HERO-HII-M1D-KVM' in m.output and 'TEXT PAGE' in m.output;passed('QR_no_GOP_text_fallback_and_final_snapshot')
    report=dict(image_sha256=hashlib.sha256((OUT/'payload/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),all_passed=True,count=len(rows),cases=rows,
                limitations=['Synthetic service faults do not establish HERO root cause.','QR graphics is separately verified on a read-only virtual CD.'])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL PASS',len(rows),flush=True)
if __name__=='__main__':main()
