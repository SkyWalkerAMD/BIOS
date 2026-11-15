"""Run final M1b x64 code against EFI fault doubles, and reproduce M1a gaps.
No physical PCI/BMC/disk access. Simulated hangs are not a HERO diagnosis.
"""
from pathlib import Path
import sys,struct,re,json,hashlib,uuid
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(OUT.parent/'hero_ipmi_setup_m1a'))
import verify_ui as old
from unicorn.x86_const import *
from unicorn import UcError
import pefile
ERR=old.ERR
LOADED='5b1b31a1-9562-11d2-8e3f-00a0c969723b';FS='964e5b22-6459-11d2-8e39-00a0c969723b'
DP='09576e91-6d3f-11d2-8e39-00a0c969723b';GOP='9042a9de-23dc-4a38-96fb-7aded080516a'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Machine(old.Launcher):
    def __init__(self,keys='q',fault=None,stage=None):
        super().__init__(keys,fault,stage)
        pe=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'));pe.relocate_image(0x100000)
        self.u.mem_write(0x100000,bytes(0x100000));self.u.mem_write(0x100000,pe.get_memory_mapped_image())
        self.functions={}
        for line in (OUT/'launcher.map').read_text().splitlines():
            m=re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})',line,re.I)
            if m:self.functions[m[1]]=int(m[2],16)-0x140000000+0x100000
        self.child_live=False;self.blt=[];self.closed=[];self.key_count=0
        self.w64(self.textin+16,0x123456)
        self.gop=self.alloc(bytes(32));self.stub(self.gop+16,'GopBlt')
        info=self.alloc(struct.pack('<9I',0,1280,800,1,0,0,0,0,1280))
        mode=self.alloc(struct.pack('<IIQQQQ',1,0,info,36,0,0));self.w64(self.gop+24,mode)
        if fault=='no_wait':self.w64(self.textin+16,0)
        if fault=='no_console':self.w64(self.st+0x40,0)
        if fault=='bad_api':self.w64(self.api+8,0)
        if fault=='unterminated_result':
            self.u.mem_map(0x2000000,0x1000);self.log_data=0x2000ff8;self.u.mem_write(self.log_data,b'RESULT: ')
        if fault=='long_path':
            self.device_path=0x2100000;self.u.mem_map(self.device_path,0x1000)
            self.u.mem_write(self.device_path,b'\x01\x01\xfe\x0f'+bytes(4092))
    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8,(name,'alignment')
        args=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]+[self.r64(rsp+0x28+i*8) for i in range(6)]
        a,b,c,d,e,f,g,h,i,j=args;result=0;self.calls.append(name)
        if self.fault=='hang' and name==self.stage:raise old.Hang(name)
        if name=='Output':
            self.output+=self.wide(b)
            if self.fault=='hidden_text':result=ERR(3)
        elif name=='Attribute':assert b==15
        elif name in ('TextMode','Cursor'):raise AssertionError('unexpected mode/cursor change')
        elif name=='Watchdog':assert a==b==c==d==0
        elif name=='ReadKey':
            self.key_count+=1
            if self.fault=='input_error':result=ERR(7)
            elif self.fault in ('no_wait','wait_error') and self.key_count==1:result=ERR(6)
            else:
                assert self.keys,'unbounded key loop';k=self.keys.pop(0);u.mem_write(b,struct.pack('<HH',0x17 if k=='!' else 0,0 if k=='!' else ord(k)))
        elif name=='WaitEvent':assert self.fault=='wait_error';result=ERR(7)
        elif name=='Stall':assert a==5000000
        elif name=='RaiseTpl':assert a==31;result=8 if self.fault=='high_tpl' else 4
        elif name=='RestoreTpl':assert a in (4,8)
        elif name=='HandleProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
            if guid==LOADED:
                if a==0x9999:
                    if not self.child_live:result=ERR(2)
                    else:self.w64(c,self.child_loaded)
                elif self.fault=='null_loaded':self.w64(c,0)
                else:self.w64(c,self.loaded)
            elif guid==FS:
                if self.fault=='no_fs':result=ERR(14)
                else:self.w64(c,0 if self.fault=='null_fs' else self.fs)
            elif guid==DP:self.w64(c,self.device_path)
            elif guid==GOP:self.w64(c,self.gop)
            else:raise AssertionError(guid)
        elif name=='OpenVolume':self.w64(b,0 if self.fault=='null_root' else self.root)
        elif name=='OpenFile':
            path=self.wide(c);self.opened.append(path)
            if path=='\\HERO-IPMI-M1B.TAG':
                if self.fault=='missing_marker':result=ERR(14)
                else:self.w64(b,0 if self.fault=='null_tag' else self.tag)
            elif path=='\\EFI\\HERO\\HeroIpmiM1a.efi':
                if self.fault=='driver_missing':result=ERR(14)
                else:self.w64(b,self.driver_file)
            else:
                assert re.fullmatch(r'\\HERO-M1B-\d{3}\.TXT',path)
                if d==1:
                    if self.fault=='existing_log' and path.endswith('000.TXT') or self.fault=='names_full':self.w64(b,self.existing)
                    elif self.fault=='unreadable_name':result=ERR(7)
                    else:result=ERR(14)
                else:
                    assert d==0x8000000000000003
                    if self.fault=='readonly':result=ERR(8)
                    elif self.fault=='null_journal':self.w64(b,0)
                    else:self.created.append(path);self.w64(b,self.file)
        elif name=='ReadFile':
            data=b'WRONG\r\n' if self.fault=='wrong_marker' else b'HERO-IPMI-SETUP-M1B\r\n'
            if self.fault=='marker_read':result=ERR(7)
            else:u.mem_write(c,data);self.w64(b,len(data))
        elif name=='ReadDriver':
            if self.fault=='driver_read':result=ERR(7)
            else:u.mem_write(c,self.driver_payload);self.w64(b,len(self.driver_payload))
        elif name=='CloseFile':
            self.closed.append(a)
            if a==self.tag and self.fault=='marker_close':result=ERR(7)
            if a==self.driver_file and self.fault=='driver_close':result=ERR(7)
            if a==self.file and self.fault=='log_close':result=ERR(7)
        elif name=='WriteFile':
            data=bytes(u.mem_read(c,self.r64(b)))
            if self.fault=='write' and (not self.stage or self.stage.encode() in data):result=ERR(7)
            elif self.fault=='short_write':self.w64(b,len(data)-1);self.pending+=data[:-1]
            else:self.pending+=data
        elif name=='FlushFile':
            if self.fault=='flush' and (not self.stage or self.stage.encode() in self.pending[len(self.durable):]):result=ERR(7)
            else:self.durable=self.pending
        elif name=='AllocatePool':
            if self.fault=='allocate_null':self.w64(c,0)
            elif b==1048576:
                p=0xa00010;u.mem_write(p-16,b'\xa5'*16+bytes(b)+b'\xa5'*16);self.guard.append((p,b));self.w64(c,p)
            else:self.w64(c,self.alloc(bytes(b)))
        elif name=='FreePool':self.freed.append(a)
        elif name=='LocateProtocol':
            guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))))
            if guid==old.API and self.api_ready:self.w64(c,self.api)
            elif guid==old.LEGACY and self.fault=='resident':self.w64(c,0x1234)
            else:result=ERR(14)
        elif name=='LoadImage':
            assert b'LOAD_IMAGE_BEFORE' in self.durable and c and d and e==len(self.driver_payload)
            if self.fault=='load_error':result=ERR(1)
            elif self.fault=='null_child':self.w64(f,0)
            else:
                self.child_live=True;self.w64(f,0x9999)
                if self.fault=='security':result=ERR(26)
        elif name=='StartImage':
            assert b'START_IMAGE_BEFORE' in self.durable and self.child_live
            trace=self.r64(self.child_loaded+0x38);assert self.r64(trace)==0x414d50494845524f
            if self.fault=='start_frees':self.child_live=False;result=ERR(7)
            elif self.fault=='start_retains':result=ERR(26)
            else:
                self.api_ready=True;u.mem_write(self.child_loaded+0x30,bytes(4));self.w64(self.child_loaded+0x38,0)
        elif name=='UnloadImage':
            assert self.child_live,'double unload';assert self.r64(self.child_loaded+0x38)==0,'dangling LoadOptions'
            if self.fault=='unload':result=ERR(7)
            else:self.child_live=False;self.api_ready=False
        elif name in ('ApiShow','ApiQuery'):
            assert b'KEY_' in self.durable
            self.operations.append((name,a if name=='ApiShow' else None))
            if self.fault=='api_error':result=ERR(3)
        elif name=='ApiLog':self.w64(a,8 if self.fault=='unterminated_result' else 19);result=self.log_data
        elif name=='LocateHandles':
            assert a==2 and str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==GOP
            if self.fault=='missing_gop':result=ERR(14)
            else:self.w64(d,1);self.w64(e,self.alloc(struct.pack('<Q',0x8877)))
        elif name=='GopBlt':
            assert c==0 and d==e==j==0 and f+h<=1280 and g+i<=800
            self.blt.append(bytes(u.mem_read(b,4)).hex())
            if self.fault=='blt_error':result=ERR(7)
        else:raise AssertionError(('unexpected hardware or EFI call',name))
        old.returns(self,result)
def audit_original():
    rows=[]
    for target in ('OpenVolume','RaiseTpl','TextMode'):
        m=old.Launcher('q','hang',target)
        try:m.run_entry();raise AssertionError('expected injected hang')
        except old.Hang:pass
        rows.append(dict(case='original_hang_'+target,console_visible=bool(m.output),log_durable=bool(m.durable)))
        if target=='TextMode':assert m.durable and not m.output
        else:assert not m.output and not m.durable
    class OriginalNullFs(old.Launcher):
        def hook(self,u,addr,size,user):
            name=self.stubs.get(addr)
            if name=='HandleProtocol':
                b=u.reg_read(UC_X86_REG_RDX);c=u.reg_read(UC_X86_REG_R8)
                if str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==FS:
                    self.w64(c,0);old.returns(self,0);return
            if name=='Output':self.output+=self.wide(u.reg_read(UC_X86_REG_RDX));old.returns(self,0);return
            return super().hook(u,addr,size,user)
    m=OriginalNullFs('q');assert m.run_entry()==0 and not m.created
    rows.append(dict(case='original_null_filesystem_falsely_returns_success',reproduced=True))
    class OriginalBound(old.Launcher):
        def hook(self,u,addr,size,user):
            if self.stubs.get(addr)=='ApiLog':self.w64(u.reg_read(UC_X86_REG_RCX),8);old.returns(self,0x2000ff8);return
            return super().hook(u,addr,size,user)
    m=OriginalBound('drq');m.u.mem_map(0x2000000,4096);m.u.mem_write(0x2000ff8,b'RESULT: ')
    try:m.run_entry();raise AssertionError('expected out-of-bounds read')
    except UcError:pass
    rows.append(dict(case='original_result_print_reads_past_reported_length',reproduced=True,reachability='Only after D and R, not initial boot.'))
    report=dict(original_launcher_sha256=sha(OUT.parent/'hero_ipmi_setup_m1a/USB/EFI/BOOT/BOOTX64.EFI'),observations=rows,limitations='Fault injection proves code paths, not that these faults occurred on HERO.')
    (OUT/'original-audit.json').write_text(json.dumps(report,indent=2)+'\n')
    print('M1a original behavior audit PASS',len(rows),flush=True)
def run():
    audit_original();rows=[]
    def passed(name):rows.append(dict(case=name,passed=True));print(name,'PASS',flush=True)
    for keys in ('q','!','dshrqt','LQ'):
        m=Machine(keys);assert m.run_entry()==0
        assert m.calls[0]=='Output' and 'TextMode' not in m.calls and not m.operations
        if keys!='LQ':assert not m.opened and not m.created and 'RaiseTpl' not in m.calls
        passed('entry_and_key_gates_'+keys)
    for keys in ('lq','llq','ldq','ldshq','ldrq','lddsq'):
        m=Machine(keys);assert m.run_entry()==0
        assert b'FIRST_OUTPUT' in m.durable and b'SESSION_END status=0x0000000000000000' in m.durable
        assert m.calls.index('ReadKey')<m.calls.index('HandleProtocol') and len(m.created)==1
        assert not m.child_live and not m.nv_writes and not m.dev.packets
        if keys in ('lq','llq'):assert 'RaiseTpl' not in m.calls and 'LoadImage' not in m.calls
        if keys=='ldshq':assert m.operations==[('ApiShow',1),('ApiShow',0)]
        passed('explicit_complete_flow_'+keys)
    m=Machine('lq','existing_log');assert m.run_entry()==0 and m.created==['\\HERO-M1B-001.TXT'];passed('existing_logs_not_overwritten')
    for fault in ('null_loaded','null_fs','null_root','null_tag','null_journal','no_fs','missing_marker','wrong_marker','marker_read','marker_close','unreadable_name','names_full','readonly','write','short_write','flush'):
        m=Machine('ldshq',fault);assert m.run_entry()!=0
        assert 'ENTRY REACHED' in m.output and 'LoadImage' not in m.calls and not m.operations
        passed('filesystem_error_visible_blocks_driver_'+fault)
    for fault in ('driver_missing','driver_read','driver_close','allocate_null','long_path','resident','load_error','null_child','security','start_frees','start_retains','bad_api','unload'):
        m=Machine('ldshq',fault);assert m.run_entry()!=0
        if fault!='unload':assert not m.operations and not m.child_live
        if fault=='security':assert 'StartImage' not in m.calls and 'UnloadImage' in m.calls
        if fault=='start_frees':assert 'UnloadImage' not in m.calls
        passed('driver_error_cleanup_'+fault)
    m=Machine('ldshq','api_error');assert m.run_entry()!=0 and len(m.operations)==1;passed('api_error_stops_later_operations')
    m=Machine('ldrq','unterminated_result');assert m.run_entry()==0 and 'RESULT: ' in m.output;passed('result_respects_reported_length_at_unmapped_page')
    for fault,stage,forbidden in [('write','LOAD_IMAGE_BEFORE','LoadImage'),('flush','START_IMAGE_BEFORE','StartImage'),('flush','KEY_S_MINIMAL','ApiShow')]:
        m=Machine('ldsq',fault,stage);assert m.run_entry()!=0 and forbidden not in m.calls;passed('durable_checkpoint_gates_'+forbidden)
    for stage,success in [('LOG_TEST_RETURN','L complete: USB_LOG_READY'),('DRIVER_LOAD_RETURN','D complete: DRIVER_READY')]:
        m=Machine('ldsq','flush',stage);assert m.run_entry()!=0 and success not in m.output and not m.operations
        passed('late_log_failure_no_false_success_'+stage)
    for stage in ('OpenVolume','ReadFile','WriteFile','LoadImage','StartImage','ApiShow'):
        m=Machine('ldsq','hang',stage)
        try:m.run_entry();raise AssertionError('expected injected hang')
        except old.Hang:pass
        assert 'ENTRY REACHED' in m.output
        if stage in ('LoadImage','StartImage','ApiShow'):assert m.durable
        passed('visible_checkpoint_before_hang_'+stage)
    for fault in ('input_error','no_wait','wait_error'):
        m=Machine('q',fault);assert m.run_entry()!=0 and m.calls.count('Stall')==1 and not m.opened
        passed('input_error_visible_delay_'+fault)
    for fault in (None,'hidden_text','no_console','missing_gop','blt_error'):
        m=Machine('gq',fault);assert m.run_entry()==0 and not m.opened
        if fault in (None,'hidden_text','no_console'):assert m.blt==['0000ff00','00ff0000','ff000000']
        passed('explicit_graphics_'+str(fault))
    for fault in (None,'high_tpl','write'):
        m=Machine(fault=fault);m.w64(m.functions['gST'],m.st);m.w64(m.functions['journal'],m.file)
        m.u.mem_write(m.functions['log_ready'],struct.pack('<I',1));data=m.alloc(b'DRIVER TRACE\r\n')
        status=m.call('emit',m.functions['journal'],data,14)
        assert status==(0 if fault is None else ERR(3) if fault=='high_tpl' else ERR(7))
        if fault=='high_tpl':assert 'WriteFile' not in m.calls
        passed('scoped_driver_trace_'+str(fault))
    for fault,stage in [('log_close',None),('flush','SESSION_END')]:
        m=Machine('lq',fault,stage);assert m.run_entry()!=0;passed('exit_preserves_error_'+fault)
    report=dict(launcher_sha256=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI'),driver_sha256=sha(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi'),all_passed=True,count=len(rows),cases=rows,limitations=['Final x64 code with synthetic EFI services.','Does not reproduce target firmware behavior or prove the black-screen root cause.'])
    (OUT/'verification.json').write_text(json.dumps(report,indent=2)+'\n');print('ALL PASS',len(rows),flush=True)
if __name__=='__main__':run()
