"""Exercise final S0 machine code with EFI service/failure doubles.
Checks first-output ordering and key-gated access; no target hardware evidence.
"""
from pathlib import Path
import sys,struct,re,json,hashlib,uuid
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'));sys.path.insert(0,str(ROOT/'analysis'))
import verify_hero_ipmi_fan_b2c as base
import pefile
from unicorn.x86_const import *
ERR=base.ERR
LOADED='5b1b31a1-9562-11d2-8e3f-00a0c969723b'
FS='964e5b22-6459-11d2-8e39-00a0c969723b'
GOP='9042a9de-23dc-4a38-96fb-7aded080516a'
class Hang(Exception):pass
class Machine(base.Machine):
    def __init__(self,keys='q',fault=None):
        super().__init__('real_3107');self.fault=fault;self.keys=list(keys);self.durable=b'';self.pending=b'';self.created=[];self.traces=[];self.blt=[]
        self.u.mem_write(0x100000,bytes(0x100000));p=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'));p.relocate_image(0x100000);self.u.mem_write(0x100000,p.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'probe.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+(\w+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        for off,name in ((0x20,'TextMode'),(0x28,'TextAttribute')):self.stub(self.textout+off,name)
        self.gop=self.alloc(bytes(32));self.stub(self.gop+16,'GopBlt')
        info=self.alloc(struct.pack('<9I',0,1280,800,1,0,0,0,0,1280))
        mode=self.alloc(struct.pack('<IIQQQQ',1,0,info,36,0,0));self.w64(self.gop+24,mode)
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8,(name,'alignment')
        args=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]+[self.r64(rsp+0x28+i*8) for i in range(6)]
        a,b,c,d,e,f,g,h,i,j=args;result=0;self.calls.append(name)
        if self.fault=='hang_filesystem' and name=='OpenVolume':raise Hang(name)
        if self.fault=='hang_first_output' and name=='Output':raise Hang(name)
        if name=='Output':
            line=self.wide(b);self.output+=line
            if self.fault=='hidden_text':result=ERR(3)
        elif name=='TextAttribute':assert b==15
        elif name=='TextMode':assert b==0 and 'TEXT_MODE0_BEFORE' in self.output
        elif name=='Watchdog':assert a==b==c==d==0
        elif name=='ReadKey':
            if self.fault=='input_error':result=ERR(7)
            else:
                assert self.keys,'unbounded input loop';k=self.keys.pop(0)
                u.mem_write(b,struct.pack('<HH',0x17 if k=='!' else 0,0 if k=='!' else ord(k)))
        elif name=='Stall':assert a==5000000 and self.fault=='input_error'
        elif name=='HandleProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            if guid==LOADED:self.w64(c,self.loaded)
            elif guid==FS:
                if self.fault=='no_filesystem':result=ERR(14)
                else:self.w64(c,self.fs)
            elif guid==GOP:self.w64(c,self.gop)
            else:raise AssertionError(('unexpected protocol',guid))
        elif name=='OpenVolume':self.w64(b,self.root)
        elif name=='OpenFile':
            path=self.wide(c);self.opened.append(path)
            if path=='\\HERO-BOOT-S0.TAG':
                if self.fault=='missing_marker':result=ERR(14)
                else:self.w64(b,self.tag)
            else:
                assert re.fullmatch(r'\\HERO-S0-\d{3}\.TXT',path),path
                if d==1:
                    if self.fault=='existing_log' and path.endswith('000.TXT'):self.w64(b,self.existing)
                    elif self.fault=='names_exhausted':self.w64(b,self.existing)
                    elif self.fault=='unreadable_name':result=ERR(7)
                    else:result=ERR(14)
                else:
                    assert d==0x8000000000000003
                    if self.fault=='readonly':result=ERR(8)
                    else:self.created.append(path);self.w64(b,self.file)
        elif name=='ReadFile':
            data=b'WRONG\r\n' if self.fault=='wrong_marker' else b'HERO-BOOT-S0\r\n'
            if self.fault=='marker_read_failure':result=ERR(7)
            else:self.w64(b,len(data));u.mem_write(c,data)
        elif name=='WriteFile':
            data=bytes(u.mem_read(c,self.r64(b)))
            if self.fault=='write_failure':result=ERR(7)
            elif self.fault=='partial_write':self.w64(b,len(data)-1);self.pending+=data[:-1]
            else:self.pending+=data
        elif name=='FlushFile':
            if self.fault=='flush_failure':result=ERR(7)
            else:self.durable=self.pending
        elif name=='CloseFile':
            if a==self.tag and self.fault=='marker_close_failure':result=ERR(7)
        elif name=='LocateHandles':
            assert a==2 and str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==GOP
            if self.fault=='missing_gop':result=ERR(14)
            else:self.w64(d,1);self.w64(e,self.alloc(struct.pack('<Q',0x8877)))
        elif name=='GopBlt':
            assert a==self.gop and c==0 and d==e==j==0
            assert f+h<=1280 and g+i<=800 and h==i==64
            self.blt.append(bytes(u.mem_read(b,4)).hex())
            if self.fault=='blt_failure':result=ERR(7)
        elif name=='FreePool':self.freed.append(a)
        else:raise AssertionError(('forbidden/unexpected EFI service',name))
        u.reg_write(UC_X86_REG_RAX,result)
        for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
    def execute(self):
        rsp=0xef0000-8;stop=0x8f0000;self.w64(rsp,stop);self.u.reg_write(UC_X86_REG_RSP,rsp)
        self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
        self.u.emu_start(self.functions['efi_main'],stop,count=30000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,'instruction limit'
        for a,n in self.guard:assert bytes(self.u.mem_read(a-16,16))==b'\xa5'*16 and bytes(self.u.mem_read(a+n,16))==b'\xa5'*16
        return self.u.reg_read(UC_X86_REG_RAX)
def run():
    rows=[]
    def passed(name):rows.append(dict(case=name,passed=True));print(name,'PASS',flush=True)
    for keys in ('q','!','dshq'):
        m=Machine(keys);assert m.execute()==0
        assert m.calls[0]=='Output' and not m.opened and not m.created and not m.blt
        assert 'HandleProtocol' not in m.calls and 'LocateHandles' not in m.calls and 'TextMode' not in m.calls
        passed('startup_no_filesystem_hii_pci_or_mode_switch_'+keys)
    for keys in ('lq','LQ','llq'):
        m=Machine(keys);assert m.execute()==0 and m.created==['\\HERO-S0-000.TXT']
        assert m.calls[0]=='Output' and m.calls.index('ReadKey')<m.calls.index('HandleProtocol')
        assert b'FIRST_OUTPUT' in m.durable and b'24_USB_LOG_READY' in m.durable and b'SESSION_END' in m.durable
        passed('explicit_log_complete_'+keys)
    m=Machine('lq','existing_log');assert m.execute()==0 and m.created==['\\HERO-S0-001.TXT'];passed('existing_log_preserved')
    for fault in ('missing_marker','wrong_marker','no_filesystem','marker_read_failure','marker_close_failure','unreadable_name','names_exhausted','readonly','write_failure','partial_write','flush_failure'):
        m=Machine('lq',fault);assert m.execute()!=0
        assert m.calls[0]=='Output' and 'ENTRY REACHED' in m.output
        if fault not in ('write_failure','partial_write','flush_failure'):assert not m.created
        assert not m.durable and not m.blt
        passed('visible_log_failure_'+fault)
    m=Machine('gq');assert m.execute()==0 and m.blt==['0000ff00','00ff0000','ff000000'] and not m.opened and m.freed;passed('graphics_explicit_no_filesystem_or_mode_switch')
    m=Machine('gq','hidden_text');assert m.execute()==0 and len(m.blt)==3;passed('graphics_key_works_if_text_service_returns_unsupported')
    for fault in ('missing_gop','blt_failure'):
        m=Machine('gq',fault);assert m.execute()==0 and not m.opened
        if fault=='blt_failure':assert m.freed
        passed('graphics_error_returns_to_key_loop_'+fault)
    m=Machine('tq');assert m.execute()==0 and m.calls.count('TextMode')==1 and not m.opened;passed('text_mode_switch_only_after_T')
    m=Machine(fault='input_error');assert m.execute()==ERR(7) and m.calls.count('Stall')==1 and not m.opened;passed('input_error_visible_five_seconds_before_exit')
    for fault in ('hang_first_output','hang_filesystem'):
        m=Machine('lq',fault)
        try:m.execute();raise AssertionError('expected synthetic hang')
        except Hang:pass
        if fault=='hang_first_output':assert not m.opened and not m.blt and not m.durable
        else:assert '14_OPEN_VOLUME_BEFORE' in m.output and '15_OPEN_VOLUME_AFTER' not in m.output
        passed('failure_boundary_'+fault)
    report=dict(image_sha256=hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),all_passed=True,count=len(rows),cases=rows,limitations=['Actual final x64 code with synthetic EFI doubles.','Text OutputString itself hanging remains a possible early failure; no software log can precede the first output in this variant.','No HERO/ASUS target validation.'])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print('ALL PASS',len(rows))
if __name__=='__main__':run()
