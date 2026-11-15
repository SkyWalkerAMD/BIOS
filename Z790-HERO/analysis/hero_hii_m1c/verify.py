"""Execute final M1c machine code with stateful files and HII fault doubles."""
from pathlib import Path
import sys,struct,re,uuid,json,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'));sys.path.insert(0,str(ROOT/'analysis'))
import verify_hero_ipmi_fan_b2c as base
import pefile
from unicorn.x86_const import *
ERR=base.ERR
LOADED='5b1b31a1-9562-11d2-8e3f-00a0c969723b';FS='964e5b22-6459-11d2-8e39-00a0c969723b';DP='09576e91-6d3f-11d2-8e39-00a0c969723b'
DB='ef9fc172-a1b2-4693-b327-6d32fc416042';BROWSER='b9d4c360-bcfb-4f9b-9298-53c136982258'
class Hang(Exception):pass
class Machine(base.Machine):
    def __init__(self,keys='q',fault=None,stage=None):
        super().__init__('real_3107');self.keys=list(keys);self.fault=fault;self.stage=stage
        self.disk={};self.openfiles={};self.created=[];self.shows=0;self.adds=0;self.removes=0;self.path_installed=False;self.hii_live=False;self.mutations=[]
        if fault=='existing':self.disk['\\M1C000.TXT']=b'CANARY'
        self.u.mem_write(0x100000,bytes(0x100000));pe=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'));pe.relocate_image(0x100000);self.u.mem_write(0x100000,pe.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'diag.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+(\w+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        for off,name in ((0x40,'Allocate'),(0x80,'Install'),(0x90,'Uninstall')):self.stub(self.bs+off,name)
        self.stub(self.textout+0x28,'Attribute');self.w64(self.textin+16,0x1234)
        self.stub(self.file+0x20,'ReadLog');self.stub(self.file+0x38,'Position')
        self.db=self.alloc(bytes(16));self.stub(self.db,'AddPackages');self.stub(self.db+8,'RemovePackages')
        self.browser=self.alloc(bytes(16));self.stub(self.browser,'SendForm')
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e,f,g=[self.r64(rsp+0x28+i*8) for i in range(3)];result=0;self.calls.append(name)
        if self.fault=='hang' and name==self.stage:raise Hang(name)
        if name=='Output':self.output+=self.wide(b)
        elif name=='Attribute':assert b==15
        elif name=='Watchdog':assert a==b==c==d==0
        elif name=='ReadKey':
            if self.fault=='input_error':result=ERR(7)
            else:
                assert self.keys,'unbounded input';k=self.keys.pop(0);u.mem_write(b,struct.pack('<HH',0x17 if k=='!' else 0,0 if k=='!' else ord(k)))
        elif name=='Stall':assert a==5000000
        elif name=='HandleProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            assert guid in (LOADED,FS)
            if guid==FS and self.fault=='no_fs':result=ERR(14)
            else:self.w64(c,self.loaded if guid==LOADED else self.fs)
        elif name=='OpenVolume':
            assert self.root not in self.openfiles
            if self.fault=='null_root':self.w64(b,0)
            else:self.w64(b,self.root);self.openfiles[self.root]=dict(role='root')
        elif name=='OpenFile':
            assert a==self.root and self.root in self.openfiles
            path=self.wide(c);self.opened.append(path)
            if path=='\\HERO-IPMI-M1C.TAG':
                if self.fault=='missing_marker':result=ERR(14)
                else:self.w64(b,self.tag);self.openfiles[self.tag]=dict(role='tag')
            else:
                assert re.fullmatch(r'\\M1C\d{3}\.TXT',path)
                if self.fault=='full' and d==1:self.w64(b,self.existing);self.openfiles[self.existing]=dict(role='existing')
                elif d==0x8000000000000003:
                    assert path not in self.disk
                    if self.fault=='readonly':result=ERR(8)
                    else:
                        self.created.append(path);self.w64(b,self.file);self.openfiles[self.file]=dict(role='log',path=path,data=b'',position=0,writable=True)
                elif path not in self.disk:result=ERR(14)
                else:self.w64(b,self.file);self.openfiles[self.file]=dict(role='log',path=path,data=self.disk[path],position=0,writable=d==3)
        elif name=='ReadFile':
            assert self.tag in self.openfiles
            data=b'wrong' if self.fault=='wrong_marker' else b'HERO-HII-M1C\r\n'
            u.mem_write(c,data);self.w64(b,len(data))
        elif name=='ReadLog':
            file=self.openfiles[a];assert not file['writable']
            if self.fault=='readback_error':result=ERR(7)
            else:
                data=file['data'][:self.r64(b)]
                if self.fault=='corrupt_readback':data=b'!'+data[1:]
                if self.fault=='short_readback':data=data[:-1]
                u.mem_write(c,data);self.w64(b,len(data))
        elif name=='Position':self.openfiles[a]['position']=b
        elif name=='WriteFile':
            file=self.openfiles[a];assert file['writable'];data=bytes(u.mem_read(c,self.r64(b)))
            if self.fault=='write' and (not self.stage or self.stage.encode() in data):result=ERR(7)
            else:
                if self.fault=='short_write':data=data[:-1];self.w64(b,len(data))
                pos=file['position'];file['data']=file['data'][:pos]+data+file['data'][pos+len(data):];file['position']+=len(data)
        elif name=='FlushFile':
            file=self.openfiles[a]
            if self.fault=='flush' and (not self.stage or self.stage.encode() in file['data']):result=ERR(7)
            elif self.fault!='lost_write':self.disk[file['path']]=file['data']
        elif name=='CloseFile':
            file=self.openfiles.pop(a)
            if self.fault=='close' and file['role']=='log':result=ERR(7)
        elif name=='Allocate':
            assert b==24 and not self.openfiles
            self.path=self.alloc(bytes(b));self.w64(c,self.path)
        elif name=='FreePool':
            assert not self.path_installed and not self.hii_live;self.freed.append(a)
        elif name=='LocateProtocol':
            assert not self.openfiles
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))))
            assert guid in (DB,BROWSER)
            if self.fault=='missing_db' and guid==DB or self.fault=='missing_browser' and guid==BROWSER:result=ERR(14)
            else:self.w64(c,self.db if guid==DB else self.browser)
        elif name=='Install':
            assert not self.openfiles and str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==DP
            if self.fault=='install':result=ERR(7)
            else:self.w64(a,0xdddd);self.path_installed=True
        elif name=='AddPackages':
            assert not self.openfiles and self.path_installed and c==0xdddd
            assert any(b'NEW_PACKAGES_BEFORE' in data for data in self.disk.values())
            self.adds+=1
            if self.fault=='packages':result=ERR(7)
            else:self.w64(d,0xeeee);self.hii_live=True
        elif name=='RemovePackages':
            assert not self.openfiles and self.hii_live;self.removes+=1
            if self.fault=='remove':result=ERR(7)
            else:self.hii_live=False
        elif name=='Uninstall':
            assert not self.openfiles and not self.hii_live and self.path_installed
            if self.fault=='uninstall':result=ERR(7)
            else:self.path_installed=False
        elif name=='SendForm':
            assert not self.openfiles and self.hii_live and b and c==1 and e==1 and f==0
            assert any(b'ENTER_SEND_FORM' in data for data in self.disk.values())
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
        assert not self.openfiles
        for a,n in self.guard:assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16 and bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        return self.u.reg_read(UC_X86_REG_RAX)
def run():
    rows=[]
    def passed(name):rows.append(dict(case=name,passed=True));print(name,'PASS',flush=True)
    for keys in ('q','!','lq','lpq','lpsq','LLPPSQ'):
        m=Machine(keys);assert m.run()==0 and m.calls[0]=='Output'
        if keys in ('q','!'):assert not m.opened and not m.disk
        if keys=='lpq':assert m.adds==1 and m.shows==0
        if keys=='lpsq':assert m.shows==1 and m.removes==1
        assert not m.path_installed and not m.hii_live
        passed('normal_'+keys)
    for keys in ('pq','sq','lsq'):
        m=Machine(keys);assert m.run()!=0 and m.shows==0 and m.adds==0;passed('stage_gate_'+keys)
    m=Machine('lpq','existing');assert m.run()==0 and m.disk['\\M1C000.TXT']==b'CANARY' and m.created==['\\M1C001.TXT'];passed('existing_log_preserved')
    for fault in ('no_fs','null_root','missing_marker','wrong_marker','readonly','full','write','short_write','flush','close','lost_write','readback_error','corrupt_readback','short_readback'):
        m=Machine('lpq',fault);assert m.run()!=0 and m.adds==0 and not m.path_installed
        assert 'L complete' not in m.output
        passed('log_failure_blocks_HII_'+fault)
    for fault in ('missing_db','missing_browser','install','packages'):
        m=Machine('lpsq',fault);assert m.run()!=0 and m.shows==0 and not m.path_installed and not m.hii_live
        passed('registration_error_'+fault)
    for fault in ('send','remove','uninstall'):
        m=Machine('lpsq',fault);assert m.run()!=0
        if fault in ('remove','uninstall'):assert m.path not in m.freed and m.path_installed
        passed('show_or_cleanup_error_'+fault)
    for service,checkpoint in [('AddPackages',b'NEW_PACKAGES_BEFORE'),('SendForm',b'ENTER_SEND_FORM')]:
        m=Machine('lpsq','hang',service)
        try:m.run();raise AssertionError('expected hang')
        except Hang:pass
        assert not m.openfiles and any(checkpoint in data for data in m.disk.values())
        passed('closed_log_before_hang_'+service)
    m=Machine('lpsq','write','ENTER_SEND_FORM');assert m.run()!=0 and m.shows==0;passed('last_commit_failure_blocks_browser')
    m=Machine('q','input_error');assert m.run()!=0 and m.calls.count('Stall')==1;passed('keyboard_failure_visible_delay')
    report=dict(image_sha256=hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),all_passed=True,count=len(rows),cases=rows,limitations=['Synthetic file persistence and service faults, not observed target behavior.','Readback cannot prove survival of arbitrary device/firmware cache loss.'])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL PASS',len(rows),flush=True)
if __name__=='__main__':run()
