"""Independent final-R2-machine-code entry/lifecycle and config regressions.

Only synthetic UEFI service doubles are used. No real device or firmware is run.
The shared engine fixture remains in verify.py; this file owns entry/cleanup
fault injection and checks that failed publication cannot leave auto-init armed.
"""
from pathlib import Path
import hashlib,json,struct,sys,traceback,uuid
OUT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
import verify as core
from unicorn.x86_const import *

ERR=lambda n:0x8000000000000000|n
API3='61f3761c-a3a6-4fb5-98f9-4636c331bc39'
API='7e575405-66a3-420d-88da-8ad70fd9e59b'
OLD='40823e46-8089-43f6-aa64-a6334212bb12'
LOADED='5b1b31a1-9562-11d2-8e3f-00a0c969723b'
READY='7ce88fb3-4bd7-4679-87a8-a8d8dee50d2b'
ON=struct.pack('<IBBBB',0x31495048,1,1,0,0)
OFF=ON[:4]+b'\0'+ON[5:]
MANUAL=struct.pack('<II',0x324d5048,8)
IMAGE=0x9090
EVENT=0x51515151
DRIVER_HANDLE=0x52525252

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

class EntryMachine(core.Machine):
    def __init__(self,fault='',mode='firmware',config='missing',engine_case='success'):
        super().__init__(engine_case,full=True)
        self.u.mem_write(self.functions['installed'],bytes(4)) # Fresh entry, before publication.
        self.entry_fault=fault;self.entry_calls=[];self.protocol_queries=[]
        self.created=False;self.closed=False;self.published=False;self.published3=False
        self.callback_address=0;self.api_address=0;self.close_count=0;self.uninstall_count=0
        if config=='missing':self.vars={}
        elif config=='off':self.vars={'HeroIpmiCfg':(3,OFF)}
        elif config=='on':self.vars={'HeroIpmiCfg':(3,ON)}
        elif config=='bad_attrs':self.vars={'HeroIpmiCfg':(7,ON)}
        elif config=='bad_magic':self.vars={'HeroIpmiCfg':(3,b'BAD!'+ON[4:])}
        elif config=='bad_version':self.vars={'HeroIpmiCfg':(3,ON[:5]+b'\x02'+ON[6:])}
        elif config=='bad_enabled':self.vars={'HeroIpmiCfg':(3,ON[:4]+b'\x02'+ON[5:])}
        elif config=='bad_reserved':self.vars={'HeroIpmiCfg':(3,ON[:-1]+b'\x01')}
        elif config=='short':self.vars={'HeroIpmiCfg':(3,ON[:-1])}
        elif config=='long':self.vars={'HeroIpmiCfg':(3,ON+b'\0')}
        else:raise ValueError(config)
        self.entry_loaded=self.alloc(bytes(96))
        if mode!='firmware':
            options=MANUAL
            if mode=='bad_magic':options=b'BAD!'+MANUAL[4:]
            if mode=='bad_inner_size':options=MANUAL[:4]+struct.pack('<I',16)
            size=4 if mode=='bad_outer_size' else 8
            pointer=0 if mode=='null_options' else self.alloc(options)
            self.u.mem_write(self.entry_loaded+0x30,struct.pack('<I',size))
            self.w64(self.entry_loaded+0x38,pointer)
        for offset,name in ((0x170,'EntryCreateEvent'),(0x70,'EntryCloseEvent'),
                            (0x80,'EntryInstallProtocol'),(0x90,'EntryUninstallProtocol')):
            self.stub(self.bs+offset,name)

    def guid(self,p):return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(p,16))))
    def u32(self,p):return struct.unpack('<I',self.u.mem_read(p,4))[0]
    def _return(self,u,name,value):
        self.calls.append(name);self.entry_calls.append(name)
        u.reg_write(UC_X86_REG_RAX,value)
        for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):
            u.reg_write(reg,0xcccccccccccccccc)

    def hook(self,u,addr,size,user):
        name=self.stubs.get(addr)
        if name is None:return
        rsp=u.reg_read(UC_X86_REG_RSP)
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        result=0;handled=True;fault=self.entry_fault
        if name=='LocateProtocol' and self.guid(a) in (API,OLD,API3):
            guid=self.guid(a);self.protocol_queries.append(guid)
            existing=(guid==API3 and fault=='existing_r3') or (guid==API and fault=='existing_r2') or (guid==OLD and fault=='existing_m1')
            error=(guid==API3 and fault=='r3_lookup_error') or (guid==API and fault=='r2_lookup_error') or (guid==OLD and fault=='m1_lookup_error')
            if existing:self.w64(c,0x52520000);result=0
            elif error:result=ERR(7)
            else:result=ERR(14)
        elif name=='HandleProtocol' and a==IMAGE and self.guid(b)==LOADED:
            if fault=='loaded_error':result=ERR(14)
            else:self.w64(c,0 if fault=='loaded_null' else self.entry_loaded)
        elif name=='EntryCreateEvent':
            assert rsp%16==8 and a==0x200 and b==8 and d==0
            group=self.r64(rsp+0x28);out=self.r64(rsp+0x30)
            assert self.guid(group)==READY and c==self.functions['ready_callback']
            if fault=='event_create_error':result=ERR(9)
            else:self.w64(out,EVENT);self.created=True;self.callback_address=c
        elif name=='EntryCloseEvent':
            assert a==EVENT and self.created and not self.closed
            self.close_count+=1
            if fault in ('install_close_error','unload_close_error'):result=ERR(7)
            else:self.closed=True
        elif name=='EntryInstallProtocol':
            guid=self.guid(b);assert guid in (API,API3) and c==0
            assert self.u32(d)==(2 if guid==API else 3) and self.u32(d+4)==(64 if guid==API else 48)
            if fault in ('install_error','install_close_error') or (fault=='compat_install_error' and guid==API):result=ERR(7)
            else:
                self.w64(a,DRIVER_HANDLE)
                if guid==API:self.api_address=d;self.published=True
                else:self.api3_address=d;self.published3=True
        elif name=='EntryUninstallProtocol':
            guid=self.guid(b);assert a==DRIVER_HANDLE and guid in (API,API3)
            assert c==(self.api_address if guid==API else self.api3_address)
            self.uninstall_count+=1
            if fault=='uninstall_error' or (fault=='uninstall_r3_error' and guid==API3):result=ERR(7)
            elif guid==API:self.published=False
            else:self.published3=False
        elif name=='GetVariable' and self.wide(a)=='HeroIpmiCfg' and fault=='config_read_error':result=ERR(7)
        elif name=='SetVariable' and self.wide(a)=='HeroIpmiCfg' and fault in ('config_false_success','config_write_error','config_bad_readback'):
            pointer=self.r64(rsp+0x28);data=bytes(u.mem_read(pointer,d))
            assert self.guid(b)=='c2614243-a877-4acf-a458-ce2904ec3e10' and c==3 and d==8
            self.nv_writes.append(('HeroIpmiCfg',c,data.hex(),len(self.dev.oem_packets)))
            if fault=='config_write_error':result=ERR(7)
            elif fault=='config_bad_readback':self.vars['HeroIpmiCfg']=(3,OFF if data==ON else ON)
        else:handled=False
        if not handled:return super().hook(u,addr,size,user)
        assert rsp%16==8,name
        self._return(u,name,result)

    def enter(self):
        status=self.call('efi_main',IMAGE,self.st)
        assert not self.dev.packets and not self.dev.writes and not self.pci_writes and not self.nv_writes,'entry performed hardware/config writes'
        assert all(g in (API,OLD,API3) for g in self.protocol_queries)
        return status

    def signal(self):
        assert self.created and self.callback_address==self.functions['ready_callback']
        self.call('ready_callback',EVENT,0)

    def read_config(self):
        p=self.alloc(bytes(8));s=self.alloc(bytes(4));status=self.call('api_config',p,s)
        return status,bytes(self.u.mem_read(p,8)),self.u32(s)

def run():
    rows=[]
    def case(name,test):
        try:
            details=test() or {};rows.append(dict(case=name,passed=True,**details));print(name,'PASS',flush=True)
        except Exception as ex:
            rows.append(dict(case=name,passed=False,error=str(ex),traceback=traceback.format_exc()))
            print(name,'FAIL',str(ex),flush=True)

    def enter_firmware():
        m=EntryMachine();assert m.enter()==0 and m.created and m.published
        assert m.u32(m.api_address+8)==0
        assert m.r64(m.entry_loaded+0x58)==m.functions['unload']
        assert m.call('unload',IMAGE)==0 and m.closed and not m.published
    case('firmware_entry_is_io_free_registers_event_and_api',enter_firmware)

    def manual():
        m=EntryMachine(mode='manual');assert m.enter()==0 and not m.created and m.published
        assert m.u32(m.api_address+8)==1
        m.call('ready_callback',EVENT,0);m.call('ready_callback',EVENT,0)
        assert not m.dev.packets and not m.nv_writes
        assert m.call('unload',IMAGE)==0 and not m.published and not m.close_count
    case('manual_options_no_event_and_callback_cannot_auto_run',manual)

    def auto_once():
        m=EntryMachine();assert m.enter()==0;m.signal()
        assert len(m.dev.oem_packets)==4 and 'HeroIpmiCfg' not in m.vars and 'HeroIpmiAttempt' not in m.vars
        before=(len(m.dev.packets),len(m.dev.writes),len(m.nv_writes));m.signal()
        assert before==(len(m.dev.packets),len(m.dev.writes),len(m.nv_writes))
        assert not(m.config[4]&2)
        return {'oem_packets':4,'event_count':2,'configuration_remains_missing':True}
    case('missing_configuration_ready_to_boot_runs_once',auto_once)

    def disabled_once():
        m=EntryMachine(config='off');assert m.enter()==0;m.signal();assert not m.dev.packets
        assert m.call('api_enable',1)==0;m.signal();assert not m.dev.packets
        assert 'READY_TO_BOOT_AUTO_DISABLED' in m.audit()
    case('explicit_disabled_preserved_and_later_event_does_not_retry',disabled_once)

    def auto_failure_once():
        m=EntryMachine(engine_case='startup_c1');assert m.enter()==0;m.signal()
        assert not m.dev.packets and not m.dev.writes
        before=(len(m.calls),len(m.nv_writes),len(m.pci_writes));m.signal()
        assert before==(len(m.calls),len(m.nv_writes),len(m.pci_writes))
    case('c1_auto_skip_no_abort_and_no_second_event_retry',auto_failure_once)

    def prior_lock():
        m=EntryMachine();m.vars['HeroIpmiAttempt']=(3,b'\x01');assert m.enter()==0;m.signal()
        assert not m.dev.packets and not m.pci_writes and not m.nv_writes
    case('missing_config_default_on_does_not_override_prior_lock',prior_lock)

    for fault in ('existing_r3','existing_r2','existing_m1','r3_lookup_error','r2_lookup_error','m1_lookup_error','loaded_error','loaded_null'):
        def check(fault=fault):
            m=EntryMachine(fault=fault);s=m.enter();assert s==ERR(20 if fault.startswith('existing_') else 14 if fault.startswith('loaded_') else 7)
            assert not m.created and not m.published
        case('entry_'+fault,check)
    for mode in ('bad_magic','bad_outer_size','bad_inner_size','null_options'):
        def check(mode=mode):
            m=EntryMachine(mode=mode);assert m.enter()==ERR(2) and not m.created and not m.published
        case('invalid_load_options_'+mode,check)

    def event_error():
        m=EntryMachine(fault='event_create_error');assert m.enter()==ERR(9) and not m.created and not m.published
    case('event_creation_failure_does_not_publish_api',event_error)
    def install_error():
        m=EntryMachine(fault='install_error');assert m.enter()==ERR(7) and m.closed and not m.published
        m.call('ready_callback',EVENT,0);assert not m.dev.packets
    case('api_install_failure_closes_event_and_disarms_auto',install_error)
    def install_close_error():
        m=EntryMachine(fault='install_close_error');assert m.enter()==0 and m.created and not m.closed and not m.published
        m.signal();m.signal();assert not m.dev.packets and not m.dev.writes and not m.nv_writes
        assert m.call('unload',IMAGE)==ERR(7);m.signal();assert not m.dev.packets
    case('failed_install_and_failed_close_resident_but_auto_disarmed',install_close_error)
    def unload_close_error():
        m=EntryMachine(fault='unload_close_error');assert m.enter()==0
        assert m.call('unload',IMAGE)==ERR(7) and not m.closed and m.published
        m.signal();assert not m.dev.packets and not m.nv_writes
    case('failed_unload_close_preserves_code_and_disarms_auto',unload_close_error)
    def uninstall_error():
        m=EntryMachine(fault='uninstall_error');assert m.enter()==0
        assert m.call('unload',IMAGE)==ERR(7) and m.closed and m.published
        m.call('ready_callback',EVENT,0);assert not m.dev.packets and not m.nv_writes
    case('failed_uninstall_keeps_api_code_resident_without_auto',uninstall_error)

    def default_config():
        m=EntryMachine();s,c,source=m.read_config();assert s==0 and c==ON and source==0 and not m.nv_writes
    case('not_found_configuration_reports_default_enabled_without_write',default_config)
    for config in ('bad_attrs','bad_magic','bad_version','bad_enabled','bad_reserved','short','long'):
        def check(config=config):
            m=EntryMachine(config=config);s,_,source=m.read_config();assert s&ERR(0) and source==2
            assert m.enter()==0;m.signal();assert not m.dev.packets and not m.nv_writes
        case('configuration_'+config+'_blocks_auto',check)
    def config_read_error():
        m=EntryMachine(fault='config_read_error');s,_,source=m.read_config();assert s==ERR(7) and source==2
        assert m.enter()==0;m.signal();assert not m.dev.packets and not m.nv_writes
    case('configuration_read_error_is_not_default_enabled',config_read_error)
    for enabled in (0,1):
        def check(enabled=enabled):
            m=EntryMachine();assert m.enter()==0;assert m.call('api_enable',enabled)==0
            expect=ON if enabled else OFF
            assert m.vars['HeroIpmiCfg']==(3,expect) and len(m.nv_writes)==1
            assert m.read_config()==(0,expect,1)
            assert m.call('api_enable',enabled)==0 and len(m.nv_writes)==1
            # A fresh driver session reads persisted bytes, rather than relying on cached state.
            other=EntryMachine();other.vars=dict(m.vars);assert other.read_config()==(0,expect,1)
            assert not m.dev.packets and not other.dev.packets
        case('explicit_save_'+str(enabled)+'_persists_missing_config_and_no_redundant_write',check)
    for fault in ('config_false_success','config_write_error','config_bad_readback'):
        for enabled in (0,1):
            def check(fault=fault,enabled=enabled):
                m=EntryMachine(fault=fault);assert m.enter()==0;assert m.call('api_enable',enabled)!=0
                assert not m.dev.packets
            case(fault+'_enabled_'+str(enabled),check)

    def compat_install_error():
        m=EntryMachine(fault='compat_install_error');assert m.enter()==ERR(7)
        assert m.closed and not m.published and not m.published3
        m.call('ready_callback',EVENT,0);assert not m.dev.packets
    case('second_protocol_install_failure_removes_first',compat_install_error)
    def partial_unload():
        m=EntryMachine(fault='uninstall_r3_error');assert m.enter()==0
        assert m.call('unload',IMAGE)==ERR(7) and not m.published and m.published3
        assert m.call('r3_run',0x103)==ERR(6) and not m.dev.packets
    case('partial_unload_keeps_inert_extended_api',partial_unload)
    driver=OUT/'USB/EFI/HERO/HeroIpmiR5.efi' 
    report=dict(driver_sha256=sha(driver),map_sha256=sha(OUT/'driver.map'),count=len(rows),all_passed=all(r['passed'] for r in rows),cases=rows,
        limits=['Synthetic UEFI and recorded/synthetic BMC responses; no target HERO execution.',
                'Tests call registered callback machine code; they do not establish ASUS firmware dispatch from the CAP.',
                'Empty LoadOptions is the implementation contract for firmware mode; this does not authenticate the image origin.'])
    (OUT/'entry-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('ENTRY',sum(r['passed'] for r in rows),'/',len(rows),'PASS',flush=True)
    if not report['all_passed']:raise SystemExit(1)

if __name__=='__main__':run()
