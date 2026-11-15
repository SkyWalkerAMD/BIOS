"""Actual compiled provider and PBKDF2, mocked storage/UI/caller/TPL boundaries."""
from pathlib import Path
import ctypes as C,hashlib,json,shutil,struct,time
HERE=Path(__file__).resolve().parent;OUT=HERE/'build';DLL=OUT/'provider_state.dll'
U64=C.c_uint64;U32=C.c_uint32;P=C.c_void_p;SZ=C.c_size_t;I=C.c_int
READ=C.WINFUNCTYPE(I,P,P,SZ,C.POINTER(SZ));PERSIST=C.WINFUNCTYPE(I,P,P,SZ)
ENTROPY=C.WINFUNCTYPE(I,P,P,SZ);NOW=C.WINFUNCTYPE(I,P,C.POINTER(U64))
TPL=C.WINFUNCTYPE(I);CALLER=C.WINFUNCTYPE(I,P,U32,P,U64,U32);ACTIVE=C.WINFUNCTYPE(I,U64,U32);WRITE=C.WINFUNCTYPE(I,P,U64);PROMPT=C.WINFUNCTYPE(I,I)
class Env(C.Structure):_fields_=[('opaque',P),('read',READ),('persist',PERSIST),('entropy',ENTROPY),('now',NOW)]
class Host(C.Structure):_fields_=[('tpl',TPL),('caller',CALLER),('active',ACTIVE),('write',WRITE),('prompt',PROMPT)]
class Core(C.Structure):_fields_=[('env',Env),('record',C.c_ubyte*128),('token',U64),('last',U64),('retry',U64),('failed',U32),('mode',U32),('active',C.c_ubyte),('unlocked',C.c_ubyte),('busy',C.c_ubyte),('clock',C.c_ubyte)]
assert C.sizeof(Core)==208
ERR=lambda n:0x8000000000000000|n
PW=b'unit-test-only-password';WRONG=b'unit-test-only-wrong';NEW=b'unit-test-only-replacement'
def record(enabled=True):
    raw=bytearray(128);raw[:8]=b'AITWKP01';raw[8]=1;raw[10]=128
    struct.pack_into('<IIIQ',raw,12,int(enabled),1 if enabled else 0,600000 if enabled else 0,1)
    if enabled:
        raw[32:64]=bytes(range(1,33));raw[64:96]=hashlib.pbkdf2_hmac('sha256',PW,raw[32:64],600000)
    raw[96:]=hashlib.sha256(raw[:96]).digest();return bytes(raw)
ENABLED=record();DISABLED=record(False);results=[];counter=0
class Case:
 def __init__(self,name,stored=None,init=True):
    global counter
    counter+=1;self.name=name;self.record=stored;self.tpl=True;self.caller=True;self.write=True;self.now=10000
    self.prompts=[];self.writes=0;self.read_error=False;self.entropy_error=False;self.clock_error=False;self.persist_error=False
    self.effect=None;self.prompt_action=None;self.nonce=0;self.outer_permitted=True;self.active_context=True;self.caller_ops=[]
    folder=OUT/'state_cases';folder.mkdir(exist_ok=True);path=folder/f'{counter:02d}-{name}.dll';shutil.copyfile(DLL,path)
    self.lib=C.WinDLL(str(path));L=self.lib
    for fn,args,restype in [('provider_initialize',[C.POINTER(Env),C.POINTER(Host)],I),('provider_begin',[P,C.POINTER(U64)],U64),
      ('provider_end',[P,U64],U64),('provider_query',[P],U32),('provider_request',[P],U64),('provider_manage',[P,I],U64),
      ('provider_end_boot',[],None),('provider_fault',[],None),('platform_session_owned',[],I),('platform_can_enter',[],I),
      ('ap_unlock',[P,U64,P,SZ],I),('ap_set_password',[P,U64,P,SZ,P,SZ],I),('ap_clear_password',[P,U64,P,SZ],I)]:
        f=getattr(L,fn);f.argtypes=args;f.restype=restype
    self.core=Core.in_dll(L,'password_core');self.cp=C.addressof(self.core)
    self.protocol=(C.c_ubyte*56).in_dll(L,'native_provider');self.pp=C.addressof(self.protocol)
    def read(_,p,n,out):
        if self.read_error:out[0]=0;return 2
        if self.record is None:out[0]=0;return 1
        out[0]=len(self.record)
        if len(self.record)>n:return 2
        C.memmove(p,self.record,len(self.record));return 0
    def persist(_,p,n):
        if self.persist_error:return 1
        self.record=C.string_at(p,n);self.writes+=1
        if self.effect:self.effect('persist')
        return 0
    def entropy(_,p,n):
        if self.entropy_error:return 1
        self.nonce+=1;C.memmove(p,bytes((i+self.nonce*3)%256 for i in range(n)),n)
        if self.effect:self.effect('entropy')
        return 0
    def now(_,out):out[0]=self.now;return int(self.clock_error)
    def caller(p,op,out,token,depth):self.caller_ops.append(op);return int(self.caller and (op!=1 or self.outer_permitted))
    def prompt(op):
        self.prompts.append(op)
        if self.prompt_action:return int(self.prompt_action(op))
        if op==-1:return L.ap_unlock(self.cp,self.core.token,PW,len(PW))==0
        if op==0:return L.ap_set_password(self.cp,self.core.token,PW if self.core.mode==1 else None,len(PW) if self.core.mode==1 else 0,NEW,len(NEW))==0
        return L.ap_clear_password(self.cp,self.core.token,PW,len(PW))==0
    self.callbacks=[READ(read),PERSIST(persist),ENTROPY(entropy),NOW(now),TPL(lambda:int(self.tpl)),CALLER(caller),ACTIVE(lambda t,d:int(self.active_context)),WRITE(lambda p,n:int(bool(p)and self.write)),PROMPT(prompt)]
    self.env=Env(None,*self.callbacks[:4]);self.host=Host(*self.callbacks[4:])
    self.initial=L.provider_initialize(C.byref(self.env),C.byref(self.host)) if init else None
 def q(self):return self.lib.provider_query(self.pp)
 def begin(self,expected=0):
    token=U64(0xdeadbeef);r=self.lib.provider_begin(self.pp,C.byref(token));assert r==expected,(self.name,hex(r));return token.value
 def end(self,t,expected=0):assert self.lib.provider_end(self.pp,t)==expected
 def request(self,expected=0):assert self.lib.provider_request(self.pp)==expected,(self.name,self.q())
 def check(self,condition,label):assert condition,(self.name,label);results.append({'case':self.name,'check':label,'passed':True})

c=Case('uninitialized',init=False);c.check(c.q()==0,'not ready');c.begin(ERR(15));c.request(ERR(15));c.check(not c.prompts,'no prompt')
c=Case('unconfigured');c.check(c.initial==6 and c.q()==1,'absent remains locked');c.request(ERR(15));t=c.begin();c.check(t!=0 and c.q()==3,'explicit owner established');c.request(ERR(15));c.check(c.record is None,'unlock cannot enroll');c.check(c.lib.provider_manage(c.pp,0)==0,'explicit enrollment');c.check(c.writes==1 and c.core.mode==1 and c.q()==3,'enrollment does not grant');c.end(t);c.check(c.q()==1,'outer end revokes')
c=Case('unlock_nested',ENABLED);t=c.begin();c.request();c.check(c.q()==7,'correct password grants');nested=c.begin();c.check(nested==t and c.q()==7,'nested entry retains owner grant');c.end(nested);c.check(c.q()==7,'inner end retains grant');c.end(t);c.check(c.q()==1,'outer end clears grant');second=c.begin();c.check(second!=t and c.q()==3,'new session locked');c.check(c.caller_ops==[1,3,2,2,1],'outer and nested caller hooks differ')
c=Case('disabled',DISABLED);c.check(c.q()==9,'explicit disabled visible without owner');t=c.begin();c.check(c.q()==15,'disabled owner may enter');c.request();c.check(not c.prompts,'disabled requires no unlock prompt');c.end(t);c.check(c.q()==9,'end preserves explicit policy')
c=Case('clear_authentication',ENABLED);t=c.begin();c.check(c.lib.provider_manage(c.pp,1)==0,'authenticated clear');c.check(c.q()==15 and c.record[12]==0,'clear persists disabled record');c.end(t);c.check(c.q()==9,'disabled persists across outer end')
c=Case('invalid_modes');c.check(c.lib.provider_manage(c.pp,2)==ERR(2),'invalid management operation');c.check(c.lib.provider_query(c.pp+8)==0,'wrong This query');c.check(c.lib.provider_request(c.pp+8)==ERR(15),'wrong This request');c.check(c.lib.provider_end(c.pp+8,1)==ERR(15),'wrong This end')
for name,setting in [('wrong_caller','caller'),('wrong_tpl','tpl'),('unwritable_token','write'),('late_provider_outer_rejected','outer_permitted')]:
    c=Case(name,ENABLED);setattr(c,setting,False);t=c.begin(ERR(15));c.check(t==(0xdeadbeef if setting=='write' else 0),'output contract');c.check(c.q()==1 and not c.core.active,'cannot manufacture owner')
c=Case('wrong_end_caller',ENABLED);t=c.begin();c.request();c.caller=False;c.end(t,ERR(15));c.check(c.q()==7,'untrusted end cannot alter valid owner');c.caller=True;c.end(t);c.check(c.q()==1,'verified owner can end')
c=Case('wrong_end_token',ENABLED);t=c.begin();c.end(t+1,ERR(15));c.check(c.q()==33 and not c.core.active,'token mismatch fails closed');c.begin(ERR(15));c.request(ERR(15))
c=Case('depth_bound',ENABLED);tokens=[c.begin()for _ in range(32)];c.check(len(set(tokens))==1,'bounded nesting same token');c.begin(ERR(15));c.check(c.q()==33,'depth overflow faults')
c=Case('counter_exhausted',ENABLED);c.core.token=2**64-1;c.begin(ERR(15));c.check(c.q()==33,'token exhaustion faults')
c=Case('foreign_active_core',ENABLED);c.core.active=1;c.begin(ERR(15));c.check(c.q()==33,'unexpected active core rejected')
c=Case('malformed_record',b'X'*128);c.check(c.initial==5 and c.q()==33,'malformed does not disable');c.begin(ERR(15));c.request(ERR(15))
c=Case('callback_reentry',ENABLED);t=c.begin()
def reentry(op):
    c.check(c.q()==19,'busy visible during prompt');c.begin(ERR(15));c.request(ERR(15));c.check(c.lib.provider_manage(c.pp,1)==ERR(15),'reentrant manage rejected');return c.lib.ap_unlock(c.cp,t,PW,len(PW))==0
c.prompt_action=reentry;c.request();c.check(c.q()==7 and c.prompts==[-1],'single prompt and valid postcheck')
c=Case('end_during_prompt',ENABLED);t=c.begin()
def ended_prompt(op):c.end(t);return True
c.prompt_action=ended_prompt;c.request(ERR(15));c.check(c.q()==33 and not c.lib.platform_can_enter(),'owner end cannot be revived')
c=Case('partial_depth_end_during_prompt',ENABLED);t=c.begin();c.begin()
def inner_end(op):c.end(t);c.core.unlocked=1;return True
c.prompt_action=inner_end;c.request(ERR(15));c.check(c.q()==33 and not c.core.active,'unexpected depth mutation revokes even forged success')
c=Case('ebs_during_prompt',ENABLED);c.begin()
def ebs_prompt(op):c.lib.provider_end_boot();return True
c.prompt_action=ebs_prompt;c.request(ERR(15));c.check(c.q()==64 and not any(c.core.record),'EBS permanently revokes and wipes');c.begin(ERR(15));c.check(c.lib.provider_manage(c.pp,0)==ERR(15),'EBS blocks management')
c=Case('ebs_during_persist');c.begin();c.effect=lambda where:c.lib.provider_end_boot()if where=='persist'else None
c.check(c.lib.provider_manage(c.pp,0)==ERR(15),'persist callback cannot grant after EBS');c.check(c.writes==1 and c.q()==64 and not any(c.core.record),'committed NVRAM retained while memory wiped')
c=Case('end_during_entropy');t=c.begin();c.effect=lambda where:c.end(t)if where=='entropy'else None
c.check(c.lib.provider_manage(c.pp,0)==ERR(15),'lost owner before PBKDF commit rejected');c.check(c.writes==0 and c.q()==33,'no credential write after owner loss')
c=Case('storage_clean_failure');c.persist_error=True;t=c.begin();c.check(c.lib.provider_manage(c.pp,0)==ERR(15),'clean persistence failure denied');c.check(c.writes==0 and c.q()==3 and c.record is None,'unchanged storage and unconfigured mode')
c=Case('entropy_failure');c.entropy_error=True;c.begin();c.check(c.lib.provider_manage(c.pp,0)==ERR(15),'entropy failure denied');c.check(c.writes==0 and c.q()==3,'no weak salt fallback')
c=Case('rate_across_session',ENABLED);t=c.begin();c.prompt_action=lambda op:c.lib.ap_unlock(c.cp,c.core.token,WRONG,len(WRONG))==0;c.request(ERR(15));c.check(c.core.failed==1 and c.core.retry==15000,'failed password delays');c.end(t);c.begin();c.prompt_action=None;c.request(ERR(15));c.check(c.core.failed==1 and c.q()==3,'session cycling cannot reset delay');c.now=15000;c.request();c.check(c.q()==7,'correct password after delay grants')
c=Case('clock_failure',ENABLED);c.begin();c.clock_error=True;c.request(ERR(15));c.check(c.q()==3 and not c.core.unlocked,'clock failure cannot authorize')
c=Case('reinitialize',ENABLED);c.check(c.lib.provider_initialize(C.byref(c.env),C.byref(c.host))==11,'reinitialization refused');c.check(c.q()==1,'existing core not reset')
c=Case('invalid_initializer',init=False);bad=Host();c.check(c.lib.provider_initialize(C.byref(c.env),C.byref(bad))==2,'missing host hook fails');c.check(c.q()==32,'no READY when adapter incomplete');c.begin(ERR(15))
c=Case('idempotent_ebs',DISABLED);c.begin();c.lib.provider_end_boot();c.lib.provider_end_boot();c.check(c.q()==64 and not c.core.active,'idempotent permanent EBS state');c.check(c.lib.provider_initialize(C.byref(c.env),C.byref(c.host))==11,'EBS cannot be reset by init')
c=Case('missing_native_frame',ENABLED);c.begin();c.request();c.active_context=False;c.check(c.q()==1,'lost native frame suppresses grant');c.request(ERR(15));c.check(c.lib.provider_manage(c.pp,0)==ERR(15),'missing frame blocks management');c.active_context=True;c.check(c.q()==7,'temporarily denied nested frame cannot erase outer grant')
def caller_ebs(p,op,out,token,depth):c.lib.provider_end_boot();return 1
ending_caller=CALLER(caller_ebs)
# Hooks were copied at initialization, so use an isolated uninitialized instance.
c=Case('ebs_during_caller_verification',ENABLED,init=False);c.host.caller=ending_caller
c.lib.provider_initialize(C.byref(c.env),C.byref(c.host));c.begin(ERR(15));c.check(c.q()==64 and not c.core.active and not any(c.core.record),'caller callback EBS cannot reactivate core')
c=Case('ebs_during_initial_read',ENABLED,init=False)
def initial_ebs(_,p,n,out):c.lib.provider_end_boot();C.memmove(p,ENABLED,128);out[0]=128;return 0
ending_read=READ(initial_ebs);c.env.read=ending_read
c.check(c.lib.provider_initialize(C.byref(c.env),C.byref(c.host))==3,'EBS interrupts initialization');c.check(c.q()==64 and not any(c.core.record),'post-callback credential copy wiped')
report={'status':'PASS_ACTUAL_NATIVE_PROVIDER_CORE_MOCKED_IO','scenario_count':counter,'check_count':len(results),'checks':results,
 'dll_sha256':hashlib.sha256(DLL.read_bytes()).hexdigest(),'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'crypto':'Actual unchanged PBKDF2-SHA256 core,600000 iterations; Python hashlib independently constructs stored fixtures.',
 'limitations':['Caller/TPL/memory/storage/UI are injected callbacks, not ASUS firmware.','Late outer-entry predicate must still be proven by native guard integration.',
                'Synthetic test passwords only; no target hardware, real firmware variables, sockets or BMC access.']}
(OUT/'state_verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'scenarios':counter,'checks':len(results)}))
