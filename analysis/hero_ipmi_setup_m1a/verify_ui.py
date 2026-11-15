"""Execute actual M1a driver/launcher machine code with EFI fault doubles.

Checks durable stage ordering, no work after a failed checkpoint, callback
string-update reentrancy, and scoped trace pointers. Not an AMI hardware test.
"""
from pathlib import Path
import sys,struct,re,json,hashlib,uuid
sys.dont_write_bytecode=True
import verify as core
from unicorn.x86_const import *
import pefile
OUT=Path(__file__).resolve().parent
ERR=core.ERR
API='be5c8a51-65bc-4f1d-92a2-0b399f8e1215'
LEGACY='40823e46-8089-43f6-aa64-a6334212bb12'
DB='ef9fc172-a1b2-4693-b327-6d32fc416042'
STRING='0fd96974-23aa-4cdc-b9cb-98d17750322a'
ROUTING='587e72d7-cc50-4f79-8209-ca291fc1a10f'
BROWSER='b9d4c360-bcfb-4f9b-9298-53c136982258'
class Hang(Exception):pass
def returns(m,value):
    m.u.reg_write(UC_X86_REG_RAX,value)
    for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):m.u.reg_write(reg,0xcccccccccccccccc)
class Driver(core.Machine):
    def __init__(self,fault=None,stage=None):
        super().__init__();self.fault=fault;self.stage=stage;self.saved=b'';self.installed={};self.hii=[];self.show_calls=0
        self.trace=self.alloc(struct.pack('<QIIQQ',0x414d50494845524f,1,32,0,0x1234))
        self.stub(self.trace+16,'TraceSink')
        self.u.mem_write(self.loaded+0x30,struct.pack('<I',32));self.w64(self.loaded+0x38,self.trace)
        self.database=self.alloc(bytes(16));self.stub(self.database,'NewPackages');self.stub(self.database+8,'RemovePackages')
        self.routing=self.alloc(bytes(40));self.browser=self.alloc(bytes(16));self.stub(self.browser,'SendForm')
        self.stub(self.bs+0x80,'InstallProtocol');self.stub(self.bs+0x90,'UninstallProtocol')
        self.w64(self.functions['strings'],0) # M1 base fixture prebinds this; real entry does not.
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        result=0
        if name=='TraceSink':
            assert a==0x1234 and c<=131072
            data=bytes(u.mem_read(b,c))
            if self.fault=='sink' and (not self.stage or self.stage.encode() in data):result=ERR(7)
            else:self.saved+=data
        elif name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))))
            p={DB:self.database,STRING:self.hstr,ROUTING:self.routing,BROWSER:self.browser}.get(guid)
            if self.fault=='missing_browser' and guid==BROWSER:result=ERR(14)
            elif self.fault=='legacy' and guid==LEGACY:self.w64(c,0x1234)
            elif p:self.w64(c,p)
            elif guid in self.installed:self.w64(c,self.installed[guid])
            else:return super().hook(u,addr,size,user)
        elif name=='InstallProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            assert guid not in self.installed
            if not self.r64(a):self.w64(a,0x555500)
            self.installed[guid]=d
        elif name=='UninstallProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            assert self.installed.pop(guid)==c
        elif name=='NewPackages':
            assert self.saved.endswith(b'status=0000000000000000\r\n')
            if self.fault=='new_packages':result=ERR(7)
            else:
                p=0x444400+len(self.hii)*16;self.hii.append(p);self.w64(d,p)
        elif name=='RemovePackages':self.hii.remove(b)
        elif name=='SendForm':
            self.show_calls+=1
            assert b'SEND_FORM_BEFORE' in self.saved
            if self.fault=='hang_browser':raise Hang('SendForm')
            if self.fault=='send_error':result=ERR(3)
        elif name=='HiiSetString':
            assert not self.r64(self.functions['showing'])&0xffffffff, 'HiiSetString inside SendForm/callback'
            return super().hook(u,addr,size,user)
        else:return super().hook(u,addr,size,user)
        self.calls.append(name);returns(self,result)
    def run_entry(self):return self.call('efi_main',0x3333,self.st)
    def clear_trace(self):assert self.r64(self.functions['active']+16)==0 and self.r64(self.functions['active']+24)==0
class Launcher(core.Machine):
    def __init__(self,keys='q',fault=None,stage=None):
        super().__init__();self.fault=fault;self.stage=stage;self.keys=list(keys);self.durable=b'';self.pending=b'';self.api_ready=False;self.operations=[]
        self.u.mem_map(0xa00000,0x200000) # Keep 1 MiB image buffer away from EFI tables at 0x700000.
        p=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'));p.relocate_image(0x100000)
        self.u.mem_write(0x100000,bytes(0x100000));self.u.mem_write(0x100000,p.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'launcher.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        for off,name in ((0x18,'RaiseTpl'),(0x20,'RestoreTpl'),(0x40,'AllocatePool'),(0xc8,'LoadImage'),(0xd0,'StartImage'),(0xe0,'UnloadImage')):self.stub(self.bs+off,name)
        self.mode=self.alloc(struct.pack('<iiiiiB3x',1,0,7,0,0,1));self.w64(self.textout+0x48,self.mode)
        for off,name in ((0x20,'TextMode'),(0x28,'Attribute'),(0x40,'Cursor')):self.stub(self.textout+off,name)
        self.device_path=self.alloc(b'\x7f\xff\x04\0');self.driver_file=self.alloc(bytes(88));self.stub(self.driver_file+0x20,'ReadDriver');self.stub(self.driver_file+0x10,'CloseFile')
        self.api=self.alloc(struct.pack('<IIQQQ',2,32,0,0,0));self.stub(self.api+8,'ApiShow');self.stub(self.api+16,'ApiQuery');self.stub(self.api+24,'ApiLog')
        self.child_loaded=self.alloc(bytes(96));self.log_data=self.alloc(b'RESULT: MOCK read\r\n\0')
        self.created=[];self.driver_payload=(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi').read_bytes()
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        e,f=[self.r64(rsp+x) for x in (0x28,0x30)]
        result=0
        if self.fault=='hang' and name==self.stage:raise Hang(name)
        if name=='RaiseTpl':assert a==31;result=8 if self.fault=='high_tpl' else 4
        elif name=='RestoreTpl':pass
        elif name in ('TextMode','Attribute','Cursor'):assert self.durable
        elif name=='Output':assert self.durable or self.fault in ('flush','write','high_tpl');self.output+=self.wide(b)
        elif name=='AllocatePool':
            if b==1048576:
                p=0xa00010;u.mem_write(p-16,b'\xa5'*16+bytes(b)+b'\xa5'*16);self.guard.append((p,b));self.w64(c,p)
            else:self.w64(c,self.alloc(bytes(b)))
        elif name=='HandleProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            if guid=='09576e91-6d3f-11d2-8e39-00a0c969723b':self.w64(c,self.device_path)
            elif guid=='5b1b31a1-9562-11d2-8e3f-00a0c969723b' and a==0x9999:self.w64(c,self.child_loaded)
            else:return super().hook(u,addr,size,user)
        elif name=='OpenFile':
            path=self.wide(c);self.opened.append(path)
            if path=='\\HERO-IPMI-M1A.TAG':self.w64(b,self.tag)
            elif path=='\\EFI\\HERO\\HeroIpmiM1a.efi':self.w64(b,self.driver_file)
            elif path.startswith('\\HERO-M1A-'):
                if d==1:
                    if self.fault=='existing_log' and path.endswith('000.TXT'):self.w64(b,self.existing)
                    else:result=ERR(14)
                else:assert d==0x8000000000000003;self.created.append(path);self.w64(b,self.file)
            else:raise AssertionError(path)
        elif name=='ReadFile':u.mem_write(c,b'HERO-IPMI-SETUP-M1A\r\n');self.w64(b,21)
        elif name=='ReadDriver':u.mem_write(c,self.driver_payload);self.w64(b,len(self.driver_payload))
        elif name=='WriteFile':
            data=bytes(u.mem_read(c,self.r64(b)))
            if self.fault=='write' and (not self.stage or self.stage.encode() in data):result=ERR(7)
            else:self.pending+=data
        elif name=='FlushFile':
            if self.fault=='flush' and (not self.stage or self.stage.encode() in self.pending[len(self.durable):]):result=ERR(7)
            else:self.durable=self.pending
        elif name=='LoadImage':
            assert c and d and e==len(self.driver_payload), 'Full file device path + source buffer required'
            assert b'LOAD_IMAGE_BEFORE' in self.durable;self.w64(f,0x9999)
        elif name=='StartImage':
            assert b'START_IMAGE_BEFORE' in self.durable
            t=self.r64(self.child_loaded+0x38);assert self.r64(t)==0x414d50494845524f
            self.u.mem_write(self.child_loaded+0x30,bytes(4));self.w64(self.child_loaded+0x38,0);self.api_ready=True
        elif name=='UnloadImage':self.api_ready=False
        elif name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))))
            if guid==API and self.api_ready:self.w64(c,self.api)
            else:result=ERR(14)
        elif name in ('ApiShow','ApiQuery'):
            self.operations.append((name,a if name=='ApiShow' else None))
            assert b'KEY_' in self.durable
        elif name=='ApiLog':self.w64(a,19);result=self.log_data
        else:return super().hook(u,addr,size,user)
        self.calls.append(name);returns(self,result)
    def run_entry(self):return self.call('efi_main',0x3333,self.st)
def run():
    rows=[]
    def passed(name):rows.append(dict(case=name,passed=True));print(name,'PASS',flush=True)
    m=Driver();assert m.run_entry()==0;m.clear_trace()
    assert not m.dev.packets and not m.nv_writes and not m.hii and not m.show_calls
    assert 'CreateEventEx' not in m.calls and API in m.installed
    assert m.r64(m.loaded+0x38)==0 and bytes(m.u.mem_read(m.loaded+0x30,4))==bytes(4)
    passed('driver_entry_hii_deferred_auto_suppressed_even_saved_enabled')
    for minimal in (1,0):
        m=Driver();assert m.run_entry()==0;assert m.call('show',minimal,m.trace)==0;m.clear_trace()
        assert m.show_calls==1 and not m.nv_writes and not m.dev.packets
        assert m.call('unload',0x3333)==0 and not m.installed and not m.hii
        passed('explicit_show_and_cleanup_'+('minimal' if minimal else 'full'))
    for fault in ('legacy','sink'):
        m=Driver(fault);assert m.run_entry()!=0;m.clear_trace();assert not m.hii and not m.installed and not m.dev.packets
        passed('entry_stops_'+fault)
    for fault,stage in [('missing_browser',None),('new_packages',None),('send_error',None),('sink','FULL_SEND_FORM_BEFORE'),('sink','INSTALL_DEVICE_PATH_AFTER'),('sink','INSTALL_CONFIG_ACCESS_AFTER')]:
        m=Driver();assert m.run_entry()==0;m.fault=fault;m.stage=stage
        assert m.call('show',0,m.trace)!=0;m.clear_trace()
        if fault=='sink':assert m.show_calls==0
        assert m.call('unload',0x3333)==0 and not m.installed and not m.hii
        passed('show_stops_and_cleans_'+fault+'_'+str(stage))
    m=Driver();assert m.run_entry()==0;m.fault='hang_browser'
    try:m.call('show',1,m.trace);raise AssertionError('expected simulated hang')
    except Hang:pass
    assert b'MINIMAL_SEND_FORM_BEFORE' in m.saved and b'MINIMAL_SEND_FORM_AFTER' not in m.saved
    passed('browser_hang_leaves_flushed_pre_call_checkpoint')
    m=Driver();assert m.run_entry()==0
    before=len(m.calls);request=m.alloc(bytes(8))
    for action in (3,4,5):assert m.call('callback',0,action,0,0,0,request)==0
    assert 'HiiSetString' not in m.calls[before:] and not m.nv_writes and not m.dev.packets
    passed('form_open_close_submitted_no_hii_string_reentry')
    for keys in ('q','dq','dshq','drq'):
        m=Launcher(keys);assert m.run_entry()==0
        assert b'TEXT_READY_NO_DRIVER_NO_HII' in m.durable and b'SESSION_END status=0x0000000000000000' in m.durable
        assert not m.nv_writes and not m.dev.packets
        if keys=='q':assert 'LoadImage' not in m.calls
        if keys=='dq':assert not m.operations
        if keys=='dshq':assert m.operations==[('ApiShow',1),('ApiShow',0)]
        if keys=='drq':assert m.operations==[('ApiQuery',None)]
        passed('launcher_explicit_keys_'+keys)
    m=Launcher('q','existing_log');assert m.run_entry()==0 and m.created==['\\HERO-M1A-001.TXT'];passed('preserves_existing_usb_logs')
    for name,checkpoint in [('TextMode','CONSOLE_MODE0_BEFORE'),('LoadImage','LOAD_IMAGE_BEFORE'),('StartImage','START_IMAGE_BEFORE'),('ApiShow','KEY_S_MINIMAL')]:
        m=Launcher('dsq','hang',name)
        try:m.run_entry();raise AssertionError('expected simulated hang')
        except Hang:pass
        assert checkpoint.encode() in m.durable
        passed('flushed_before_simulated_hang_'+name)
    for fault,stage,forbidden in [('write',None,'TextMode'),('flush',None,'TextMode'),('high_tpl',None,'TextMode'),('flush','LOAD_IMAGE_BEFORE','LoadImage'),('write','START_IMAGE_BEFORE','StartImage'),('flush','KEY_S_MINIMAL','ApiShow')]:
        m=Launcher('dsq',fault,stage);assert m.run_entry()!=0
        assert forbidden not in m.calls
        passed('log_failure_stops_'+fault+'_'+str(stage))
    report=dict(driver_sha256=core.hashlib.sha256((OUT/'USB/EFI/HERO/HeroIpmiM1a.efi').read_bytes()).hexdigest(),launcher_sha256=core.hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),all_passed=True,count=len(rows),cases=rows,limits='Actual x64 code, synthetic EFI doubles and hangs; not target AMI firmware.')
    (OUT/'ui-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('ALL PASS',len(rows))
if __name__=='__main__':run()
