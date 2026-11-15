"""Execute the linked EFI bytes in Unicorn, with explicit modeled hosts.

No native AMITSE/UEFI hardware execution is implied. Prompt authentication is
modeled here; the exact AP_CORE crypto was executed separately in the host DLL.
"""
from pathlib import Path
import ctypes as C
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;PASSWORD=HERE.parent;ROOT=PASSWORD.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'));sys.path.insert(0,str(PASSWORD/'core'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
import verify_core as core
OUT=HERE/'build';BUILD=json.loads((OUT/'build.json').read_text());EFI=OUT/BUILD['file']
assert hashlib.sha256(EFI.read_bytes()).hexdigest()==BUILD['sha256']
PE=pefile.PE(str(EFI));BASE=PE.OPTIONAL_HEADER.ImageBase;SYMBOLS={n:BASE+r for n,r in BUILD['symbols'].items()}
STACK=0x40000000;HEAP=0x50000000;HOOK=0x60000000;STOP=HOOK+0xf000;TAIL=HOOK+0xe000
DENIED=0x800000000000000f;UNSUPPORTED=0x8000000000000003;ARG=0x8000000000000002
REGISTER_ARGS=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
PROFILE=json.loads((PASSWORD/'profile_0603.json').read_text(encoding='utf8'))
ENABLED=core.signed_record();DISABLED=core.signed_record(disabled=True)
CASES=[]
def q(n):return struct.pack('<Q',n)
class VM:
    def __init__(self,record=ENABLED):
        self.u=Uc(UC_ARCH_X86,UC_MODE_64);size=(PE.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
        self.u.mem_map(BASE,size);self.u.mem_write(BASE,PE.get_memory_mapped_image())
        self.u.mem_map(STACK,0x200000);self.u.mem_map(HEAP,0x20000);self.u.mem_map(HOOK,0x10000)
        self.record=record;self.calls=[];self.outputs=[];self.profile=True;self.tpl=True;self.caller=True;self.active=True;self.writable=True;self.authorized=True
        self.prompt='deny';self.depth_args=[];self.end_on=None;self.pending=None;self.subcall_on=None;self.subcall_results=[]
        self.names=['read','persist','entropy','clock','profile','tpl','caller','active','writable','prompt','authorized']
        self.addresses={name:HOOK+0x100*i for i,name in enumerate(self.names)}
        for a in self.addresses.values():self.u.mem_write(a,b'\xc3')
        self.u.mem_write(STOP,b'\xf4');self.u.mem_write(TAIL,b'\xc3')
        self.u.hook_add(UC_HOOK_CODE,self.hook)
        self.env=HEAP;self.host=HEAP+0x100;self.out=HEAP+0x200;self.sd=HEAP+0x300;self.td=HEAP+0x340;self.request=HEAP+0x400
        self.w(self.env,q(0)+b''.join(q(self.addresses[x])for x in ['read','persist','entropy','clock']))
        self.w(self.host,struct.pack('<II',1,64)+b''.join(q(self.addresses[x])for x in ['profile','tpl','caller','active','writable','prompt','authorized']))
        self.w(self.sd,bytes.fromhex(PROFILE['sources']['Setup']['sha256']));self.w(self.td,bytes.fromhex(PROFILE['sources']['AMITSE']['sha256']))
        self.cp=SYMBOLS['w890_password_core'];self.p=SYMBOLS['w890_provider'];self.cfg=SYMBOLS['w890_management_config']
    def w(self,a,b):self.u.mem_write(a,bytes(b))
    def r(self,a,n):return bytes(self.u.mem_read(a,n))
    def Q(self,a):return struct.unpack('<Q',self.r(a,8))[0]
    def arg(self,i):return self.u.reg_read(REGISTER_ARGS[i])if i<4 else self.Q(self.u.reg_read(UC_X86_REG_RSP)+8+32+8*(i-4))
    def ret(self,v):
        sp=self.u.reg_read(UC_X86_REG_RSP);self.u.reg_write(UC_X86_REG_RAX,v&((1<<64)-1));self.u.reg_write(UC_X86_REG_RIP,self.Q(sp));self.u.reg_write(UC_X86_REG_RSP,sp+8)
    def nested_call_then_ret(self,name,args,v):
        original=self.u.reg_read(UC_X86_REG_RSP);self.pending=(original,v)
        # A synthetic callback CALL with x64 shadow space and standard alignment.
        sp=original-40;self.w(sp,q(TAIL));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i in range(4):self.u.reg_write(REGISTER_ARGS[i],args[i]if i<len(args)else 0)
        self.u.reg_write(UC_X86_REG_RIP,SYMBOLS[name])
    def hook(self,u,address,size,data):
        if address==STOP:u.emu_stop();return
        if address==TAIL:
            original,value=self.pending;self.pending=None;self.subcall_results.append(u.reg_read(UC_X86_REG_RAX));u.reg_write(UC_X86_REG_RSP,original);self.ret(value);return
        name=next((n for n,a in self.addresses.items()if a==address),None)
        if name is None:return
        self.calls.append(name)
        if name=='read':
            if self.record is None:self.w(self.arg(3),q(0));value=1
            else:self.w(self.arg(1),self.record[:self.arg(2)]);self.w(self.arg(3),q(len(self.record)));value=0
        elif name=='persist':raise AssertionError('This provider lifetime suite must not persist any credential')
        elif name=='entropy':raise AssertionError('This provider lifetime suite must not enroll credentials')
        elif name=='clock':self.w(self.arg(1),q(100000));value=0
        elif name=='profile':value=int(self.profile)
        elif name=='tpl':value=int(self.tpl)
        elif name=='caller':
            self.depth_args.append((self.arg(1),self.arg(3),self.arg(4)));value=int(self.caller and self.arg(0)==STOP)
        elif name=='active':value=int(self.active)
        elif name=='writable':value=int(self.writable and HEAP<=self.arg(0)<HEAP+0x20000 and self.arg(1)<=0x20000-(self.arg(0)-HEAP))
        elif name=='authorized':value=int(self.authorized and self.arg(0)==STOP)
        elif name=='prompt':
            operation=self.arg(0)&0xffffffff;self.outputs.append(operation)
            if self.prompt=='grant':self.w(self.cp+core.Core.unlocked.offset,b'\1');value=1
            elif self.prompt=='success_without_unlock':value=1
            elif self.prompt=='owner_lost':self.active=False;value=1
            elif self.prompt=='profile_lost':self.profile=False;value=1
            else:value=0
        else:raise AssertionError(name)
        if self.end_on==name:self.end_on=None;self.nested_call_then_ret('w890_provider_end_boot',[],value)
        elif self.subcall_on and self.subcall_on[0]==name:
            _,function,args=self.subcall_on;self.subcall_on=None;self.nested_call_then_ret(function,args,value)
        else:self.ret(value)
    def call(self,name,*args):
        address=BASE+PE.OPTIONAL_HEADER.AddressOfEntryPoint if name=='entry' else SYMBOLS[name]
        sp=STACK+0x1ff008
        self.w(sp,bytes(0x200));self.w(sp,q(STOP));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i in range(4):self.u.reg_write(REGISTER_ARGS[i],args[i]if i<len(args)else 0)
        for i in range(4,len(args)):self.w(sp+40+8*(i-4),q(args[i]))
        self.u.emu_start(address,STOP+1,count=4000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==STOP,'execution did not return'
        return self.u.reg_read(UC_X86_REG_RAX)
    def init(self):return self.call('w890_provider_initialize',self.env,self.host,self.sd,self.td)
    def begin(self):return self.call('w890_provider_begin',self.p,self.out)
    def query(self):return self.call('w890_provider_query',self.p)
    def end(self,token=None):return self.call('w890_provider_end',self.p,self.Q(self.out)if token is None else token)
    def request_call(self):return self.call('w890_provider_request',self.p)
    def manage(self,op=0):return self.call('w890_provider_manage',self.p,op)
def check(name,fn):
    v=VM();assert fn(v),name;CASES.append({'name':name,'status':'PASS'})
check('unbound_efi_entry_refuses_without_services',lambda v:v.call('entry',1,2)==UNSUPPORTED and not v.calls)
check('correct_profile_initializes_locked',lambda v:v.init()==0 and v.query()==1)
check('repeat_initialize_refused',lambda v:v.init()==0 and v.init()==11)
for which,offset in [('setup',0),('tse',31)]:
    def wrong(v,which=which,offset=offset):
        target=v.sd if which=='setup'else v.td;v.w(target+offset,bytes([v.r(target+offset,1)[0]^1]))
        return v.init()==2 and 'read'not in v.calls and v.begin()==DENIED
    check('wrong_'+which+'_digest_refused_before_read',wrong)
check('unbound_native_profile_refused_before_read',lambda v:(setattr(v,'profile',False),v.init()==5 and 'read'not in v.calls)[1])
check('before_begin_prompt_denied',lambda v:v.init()==0 and v.request_call()==DENIED and v.manage()==DENIED and not v.outputs)
check('outer_begin_sets_owned_not_granted',lambda v:v.init()==0 and v.begin()==0 and v.Q(v.out)==1 and v.query()==3)
for field in ['tpl','caller','writable']:
    def reject(v,field=field):
        assert v.init()==0;setattr(v,field,False);return v.begin()==DENIED and not v.outputs
    check(field+'_invalid_begin_refused',reject)
check('invalid_provider_pointer_refused',lambda v:v.init()==0 and v.call('w890_provider_begin',v.p+8,v.out)==DENIED and v.call('w890_provider_query',0)==0)
check('valid_request_denied_on_cancel',lambda v:v.init()==0 and v.begin()==0 and v.request_call()==DENIED and v.outputs==[0xffffffff]and v.query()==3)
check('prompt_success_without_core_unlock_is_not_grant',lambda v:(setattr(v,'prompt','success_without_unlock'),v.init()==0 and v.begin()==0 and v.request_call()==DENIED and v.query()==3)[1])
check('grant_requires_owned_core_state',lambda v:(setattr(v,'prompt','grant'),v.init()==0 and v.begin()==0 and v.request_call()==0 and v.query()==7)[1])
def already(v):
    assert v.init()==0 and v.begin()==0;v.prompt='grant';assert v.request_call()==0
    return v.request_call()==0 and len(v.outputs)==1
check('already_unlocked_does_not_reprompt',already)
for field in ['active','authorized','tpl']:
    def reject(v,field=field):
        assert v.init()==0 and v.begin()==0;setattr(v,field,False);return v.request_call()==DENIED and not v.outputs
    check(field+'_invalid_request_refused',reject)
for mode in ['owner_lost','profile_lost']:
    check(mode+'_after_prompt_revokes',lambda v,mode=mode:(setattr(v,'prompt',mode),v.init()==0 and v.begin()==0 and v.request_call()==DENIED and v.query()&32)[1])
def nested(v):
    assert v.init()==0 and v.begin()==0;v.prompt='grant';assert v.request_call()==0
    assert v.begin()==0 and v.Q(v.out)==1 and v.end()==0 and v.query()==7
    assert v.end()==0 and v.query()==1 and v.begin()==0
    return v.Q(v.out)==2 and v.query()==3
check('nested_same_session_and_outer_exit_relocks',nested)
check('wrong_end_token_faults',lambda v:v.init()==0 and v.begin()==0 and v.end(2)==DENIED and v.query()&32)
check('invalid_management_operation_refused',lambda v:v.init()==0 and v.begin()==0 and v.manage(2)==ARG and not v.outputs)
def callback(v):
    assert v.init()==0 and v.begin()==0;v.prompt='success_without_unlock';v.w(v.request,bytes([0xa5])*24)
    s=v.call('w890_config_callback',v.cfg,0,0xffd0,0,0,v.request+8)
    return s==0 and v.r(v.request,24)==bytes([0xa5])*8+bytes(8)+bytes([0xa5])*8 and v.outputs==[0]
check('hii_action_request_is_exact_UINTN_no_overwrite',callback)
for action in [2,3,4,5,6,7,8,9,10]:
    check('nonchanging_hii_action_'+str(action)+'_does_not_manage',lambda v,action=action:v.init()==0 and v.begin()==0 and v.call('w890_config_callback',v.cfg,action,0xffd0,0,0,0)==UNSUPPORTED and not v.outputs)
check('changed_hii_action_acknowledges_without_prompt',lambda v:v.init()==0 and v.begin()==0 and v.call('w890_config_callback',v.cfg,1,0xffd0,0,0,0)==0 and not v.outputs)
check('unknown_question_refused',lambda v:v.init()==0 and v.begin()==0 and v.call('w890_config_callback',v.cfg,0,0xffe0,0,0,0)==UNSUPPORTED and not v.outputs)
check('wrong_ConfigAccess_object_refused',lambda v:v.init()==0 and v.begin()==0 and v.call('w890_config_callback',v.cfg+8,0,0xffd0,0,0,0)==DENIED and not v.outputs)
def endboot(v):
    assert v.init()==0 and v.begin()==0;v.call('w890_provider_end_boot');count=len(v.calls)
    return v.query()==64 and v.begin()==DENIED and v.request_call()==DENIED and v.manage()==DENIED and len(v.calls)==count and v.r(v.cp+core.Core.record.offset,128)==bytes(128)
check('end_boot_revokes_and_calls_no_further_host_services',endboot)
for callback_name in ['profile','tpl','caller','writable']:
    def asynchronous(v,callback_name=callback_name):
        assert v.init()==0;v.end_on=callback_name
        return v.begin()==DENIED and v.query()==64 and not v.outputs
    check('end_boot_during_begin_'+callback_name,asynchronous)
def during_prompt(v):
    assert v.init()==0 and v.begin()==0;v.prompt='grant';v.end_on='prompt'
    return v.request_call()==DENIED and v.query()==64 and v.r(v.cp+core.Core.record.offset,128)==bytes(128)
check('end_boot_during_prompt_cannot_grant',during_prompt)
for callback_name in ['profile','read']:
    check('end_boot_during_initialize_'+callback_name,lambda v,callback_name=callback_name:(setattr(v,'end_on',callback_name),v.init()!=0 and v.query()==64 and not v.outputs)[1])
def nested_limit(v):
    assert v.init()==0
    for _ in range(32):assert v.begin()==0
    return v.begin()==DENIED and v.query()&32
check('nested_depth_overflow_faults_without_wrap',nested_limit)
def busy_query(v):
    assert v.init()==0 and v.begin()==0;v.prompt='grant';v.subcall_on=('prompt','w890_provider_query',[v.p])
    return v.request_call()==0 and v.subcall_results==[19] and v.query()==7
check('query_during_prompt_reports_busy_without_grant',busy_query)
def begin_reentry(v):
    assert v.init()==0;v.subcall_on=('profile','w890_provider_begin',[v.p,v.out+8])
    return v.begin()==0 and v.subcall_results==[DENIED] and v.Q(v.out)==1
check('begin_callback_reentry_cannot_create_second_session',begin_reentry)
def session_exit(v):
    assert v.init()==0 and v.begin()==0;v.prompt='grant';v.subcall_on=('prompt','ap_session_end',[v.cp])
    return v.request_call()==DENIED and v.query()&32
check('session_exit_during_prompt_cannot_grant',session_exit)
for offset,name in [(8,'profile'),(48,'prompt'),(56,'authorize_operation')]:
    def absent(v,offset=offset):
        v.w(v.host+offset,q(0));return v.init()==2 and 'read'not in v.calls
    check('missing_host_'+name+'_refused',absent)
check('wrong_host_revision_refused',lambda v:(v.w(v.host,struct.pack('<I',2)),v.init()==2 and 'read'not in v.calls)[1])
check('wrong_host_size_refused',lambda v:(v.w(v.host+4,struct.pack('<I',56)),v.init()==2 and 'read'not in v.calls)[1])
for rec,name,mode,want in [(None,'absent',0,1),(DISABLED,'disabled',2,9),(b'bad','malformed',3,33)]:
    v=VM(rec);s=v.init();flags=v.query()
    assert s==({0:6,2:0,3:5}[mode]) and flags==want,name
    if mode==0:assert v.begin()==0 and v.request_call()==DENIED
    if mode==2:assert v.begin()==0 and v.query()==15 and v.request_call()==0 and not v.outputs
    if mode==3:assert v.begin()==DENIED
    CASES.append({'name':name+'_credential_mode_never_confused','status':'PASS'})
report={'status':'PASS_ACTUAL_W890_PROVIDER_EFI_BYTES_SYNTHETIC_HOST','cases':CASES,'case_count':len(CASES),
        'efi_sha256':BUILD['sha256'],'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'native_owner_modeled':True,'prompt_authentication_modeled':True,'AP_CORE_crypto_separately_host_executed':True,
        'hardware_or_firmware_writes':0,'scope':'Actual linked PE x64 provider/session/ConfigAccess code in Unicorn; explicit synthetic host boundaries. EFI entry refusal tested. No native observer binding or UI publication, no ASUS runtime acceptance.'}
(OUT/'provider_pe_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'case_count':len(CASES),'efi_sha256':BUILD['sha256']}))
