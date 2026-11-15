"""Actual optimized UI PE under Unicorn; all firmware interactions are explicit mocks."""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid,traceback
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;TX=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
PE=HERE/'build/UI-EMULATION-FIXTURE-NOT-FOR-BOOT.EFI';p=pefile.PE(str(PE))
BASE=p.OPTIONAL_HEADER.ImageBase;SIZE=(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
EXPORT={s.name.decode():BASE+s.address for s in p.DIRECTORY_ENTRY_EXPORT.symbols}
STACK=0x50000000;STOP=0x60000000
ERR=lambda n:(1<<63)|n
PRIVATE='AiTweakerPassword1904';OC='VARSTORE_OCMR_SETTINGS_NAME';MEM='SocketMemoryConfig'
GUIDS={PRIVATE:uuid.UUID('750e9d9d-f2d8-4e14-9b53-8923a7190461').bytes_le,
       OC:uuid.UUID('a3a3b874-7636-4182-ba1e-f52c584494e3').bytes_le,
       MEM:uuid.UUID('98cf19ed-4109-4681-b79d-9196757c7824').bytes_le}
PACK=bytes(int(x,16)for x in re.findall(r'0x([0-9a-f]{2})', (TX/'source/ui_bindings.h').read_text()))
assert len(PACK)==991

def record(gen=1,enabled=True,tag=0):
    a=bytearray(128);a[:8]=b'AITWKP01';struct.pack_into('<HH',a,8,1,128)
    struct.pack_into('<IIIQ',a,12,int(enabled),int(enabled),600000 if enabled else 0,gen)
    if enabled:a[32:64]=bytes((i+tag)%256 for i in range(32));a[64:96]=bytes(range(1,33))
    a[96:]=hashlib.sha256(a[:96]).digest();return bytes(a)

class Model:
    def __init__(self):
        self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.u.mem_map(BASE,SIZE)
        self.u.mem_write(BASE,p.get_memory_mapped_image());self.u.mem_map(STACK,0x20000);self.u.mem_map(STOP,4096)
        self.vars={OC:(3,bytes((i*7)%256 for i in range(26681))),MEM:(7,bytes((i*11)%256 for i in range(1392)))}
        self.logs=[];self.calls=[];self.writes=[];self.sent=[];self.hold=None;self.error=None
        self.tpl=4;self.abort_at=None;self.service_index=0;self.hii_case=None;self.send_status=0;self.send_action=0
        self.on_send=None;self.delete_status=0;self.delete_effect=True;self.read_error=None;self.after_delete_error=None
        self.after_send_condition=None;self.calls_before_run=0
        self.handlers={EXPORT[name]:getattr(self,name)for name in
            ['fixture_get','fixture_set','fixture_raise','fixture_restore','fixture_locate','fixture_list','fixture_export','fixture_send']}
        for address in set(self.handlers)|{STOP,EXPORT['app_hold'],EXPORT['app_log'],EXPORT['app_number'],EXPORT['app_result']}:
            self.u.hook_add(UC_HOOK_CODE,self.hook,begin=address,end=address)
        assert self.call('test_setup')[0]=='RETURN'
        self.session=self.call('test_session')[1]
    def q(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
    def putq(self,a,n):self.u.mem_write(a,struct.pack('<Q',n))
    def putd(self,a,n):self.u.mem_write(a,struct.pack('<I',n))
    def arg(self,n):
        if n<=4:return self.u.reg_read([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9][n-1])
        return self.q(self.u.reg_read(UC_X86_REG_RSP)+0x28+8*(n-5))
    def text(self,a,wide=False):
        out=bytearray();size=2 if wide else 1
        for i in range(4096):
            b=bytes(self.u.mem_read(a+i*size,size))
            if b==b'\0'*size:return out.decode('utf-16-le'if wide else'ascii')
            out+=b
        raise AssertionError('Unbounded text')
    def ret(self,n=0):
        sp=self.u.reg_read(UC_X86_REG_RSP);self.u.reg_write(UC_X86_REG_RAX,n&((1<<64)-1))
        self.u.reg_write(UC_X86_REG_RIP,self.q(sp));self.u.reg_write(UC_X86_REG_RSP,sp+8)
    def boundary(self,name):
        self.calls.append(name);self.service_index+=1
        if self.abort_at==self.service_index:self.putd(EXPORT['app_ended'],1)
    def hook(self,u,address,size,unused):
        try:
            if address==STOP:u.emu_stop();return
            if address==EXPORT['app_hold']:
                self.hold=self.arg(1);u.emu_stop();return
            if address in (EXPORT['app_log'],EXPORT['app_number'],EXPORT['app_result']):
                label=self.text(self.arg(1));self.logs.append((label,self.arg(2) if address!=EXPORT['app_log'] else None));self.ret();return
            if address in self.handlers:
                self.handlers[address]();return
        except Exception:self.error=traceback.format_exc();u.emu_stop()
    def call(self,name,*args):
        self.hold=None;self.error=None;sp=STACK+0x1ef88
        self.u.mem_write(sp,b'\0'*256);self.putq(sp,STOP)
        self.u.reg_write(UC_X86_REG_RSP,sp);self.u.reg_write(UC_X86_REG_EFLAGS,0x202)
        for i,n in enumerate(args,1):
            if i<=4:self.u.reg_write([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9][i-1],n)
            else:self.putq(sp+0x28+8*(i-5),n)
        self.u.emu_start(EXPORT[name],STOP,count=20000000)
        assert self.error is None,self.error
        if self.hold is not None:return ('HOLD',self.hold)
        assert self.u.reg_read(UC_X86_REG_RIP)==STOP,'Instruction bound exhausted'
        return ('RETURN',self.u.reg_read(UC_X86_REG_RAX))
    def fixture_raise(self):
        assert self.arg(1)==31;self.boundary('RaiseTPL');self.ret(self.tpl)
    def fixture_restore(self):
        assert self.arg(1)==self.tpl;self.boundary('RestoreTPL');self.ret()
    def fixture_get(self):
        name=self.text(self.arg(1),True);assert name in GUIDS
        assert bytes(self.u.mem_read(self.arg(2),16))==GUIDS[name]
        attr,sz,buf=self.arg(3),self.arg(4),self.arg(5);capacity=self.q(sz)
        self.boundary('GetVariable:'+name)
        if self.read_error and self.read_error[0]==name:self.ret(self.read_error[1]);return
        if name not in self.vars:self.ret(ERR(14));return
        attributes,data=self.vars[name]
        if attr:self.putd(attr,attributes)
        self.putq(sz,len(data))
        if capacity<len(data):self.ret(ERR(5));return
        assert buf and capacity>=len(data);self.u.mem_write(buf,data);self.ret()
    def fixture_set(self):
        name=self.text(self.arg(1),True)
        assert name==PRIVATE and bytes(self.u.mem_read(self.arg(2),16))==GUIDS[PRIVATE]
        assert self.arg(3)==0 and self.arg(4)==0 and self.arg(5)==0
        self.boundary('SetVariable:fixed-private-delete-only');self.writes.append('DELETE_FIXED_PRIVATE')
        if self.delete_effect:self.vars.pop(PRIVATE,None)
        if self.after_delete_error:self.read_error=(PRIVATE,self.after_delete_error)
        self.ret(self.delete_status)
    def fixture_locate(self):
        assert bytes(self.u.mem_read(self.arg(1),16))==uuid.UUID('ef9fc172-a1b2-4693-b327-6d32fc416042').bytes_le
        self.boundary('LocateHiiDatabase')
        if self.hii_case=='locate_error':self.ret(ERR(14));return
        self.putq(self.arg(3),EXPORT['fixture_hii']);self.ret()
    def fixture_list(self):
        self.boundary('ListHiiHandles');assert self.arg(1)==EXPORT['fixture_hii'] and self.arg(2)==0 and self.arg(3)==0
        n,buf=self.arg(4),self.arg(5);assert self.q(n)==4096
        if self.hii_case=='list_too_many':self.putq(n,4104);self.ret(ERR(5));return
        if self.hii_case=='list_misaligned':self.putq(n,15);self.ret();return
        handles=[0x7777,0x8888]+([0x9999]if self.hii_case=='duplicate'else[])
        if self.hii_case=='missing':handles=[0x7777]
        self.u.mem_write(buf,b''.join(struct.pack('<Q',a)for a in handles));self.putq(n,len(handles)*8);self.ret()
    def fixture_export(self):
        handle,n,buf=self.arg(2),self.arg(3),self.arg(4);self.boundary('ExportHii:copy'if buf else'ExportHii:size')
        data=PACK if handle in [0x8888,0x9999]else bytes(range(16))+struct.pack('<I',20)
        if self.hii_case=='malformed'and handle==0x8888:data=PACK[:-1]+bytes([PACK[-1]^1])
        if self.hii_case=='wrong_length'and handle==0x8888:data=PACK+b'X'
        if self.hii_case=='oversize':self.putq(n,4*1024*1024+1);self.ret(ERR(5));return
        if not buf:self.putq(n,len(data));self.ret(ERR(5));return
        assert self.q(n)==len(data)
        if self.hii_case=='copy_error':self.ret(ERR(7));return
        self.u.mem_write(buf,data);self.putq(n,len(data)+(1 if self.hii_case=='copy_changed_size' else 0));self.ret()
    def fixture_send(self):
        handle=self.q(self.arg(2));guid=bytes(self.u.mem_read(self.arg(4),16));form=self.arg(5)
        assert self.arg(3)==1 and self.arg(6)==0
        if handle==0x8888:assert guid==uuid.UUID('b16b94e6-99f4-4f60-8f7b-b6d234e4a513').bytes_le and form==1
        else:assert handle==0x7777 and guid==uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le and form==0
        self.boundary('OriginalSendForm');self.sent.append({'management':handle==0x8888,'form':form})
        if self.on_send:self.on_send(self)
        if self.after_send_condition:
            state=EXPORT['fixture_state']
            if self.after_send_condition=='ui_head':self.putq(state,1)
            elif self.after_send_condition=='save_head':self.putq(state+8,1)
            elif self.after_send_condition=='bad_magic':self.putq(state+16,0)
        self.putq(self.arg(7),self.send_action);self.ret(self.send_status)
    def prepare(self):assert self.call('ui_capture_initial')==('RETURN',1)
    def enroll(self,rec=None):
        self.on_send=lambda m:m.vars.__setitem__(PRIVATE,(3,rec or record()))
        assert self.call('ui_open_management',self.session)==('RETURN',1)
        self.on_send=None
    def owned_locations(self,rec):
        raw=bytes(self.u.mem_read(BASE,SIZE));return [BASE+m.start()for m in re.finditer(re.escape(rec),raw)]
    def clean_logs(self):
        for label,value in self.logs:
            assert PRIVATE not in label and 'AITWKP01'not in label
            assert not re.search(r'[a-f0-9]{64}',label,re.I)

results=[]
def case(name,fn):
    fn();results.append({'name':name,'status':'PASS'});print('PASS '+name,flush=True)

def basic():
    m=Model();m.prepare();assert m.call('ui_capture_initial')==('RETURN',0);m.enroll();rec=record()
    found=m.owned_locations(rec);assert len(found)==1
    assert m.call('ui_open_original_setup',m.session)==('RETURN',1)
    assert m.call('ui_restore_credential',m.session)==('RETURN',1)
    assert PRIVATE not in m.vars and m.writes==['DELETE_FIXED_PRIVATE']
    assert bytes(m.u.mem_read(found[0],128))==b'\0'*128
    assert m.call('ui_restore_credential',m.session)==('RETURN',1)and len(m.writes)==1
    assert m.call('ui_open_management',m.session)==('RETURN',0);m.clean_logs()
case('M exact independent form + B exact OEM form + one exact delete + zeroized owned RAM',basic)

for label,data in [('existing valid',record()),('existing malformed',b'bad'),('existing oversized',bytes(200))]:
    def check(data=data):
        m=Model();m.vars[PRIVATE]=(3,data);assert m.call('ui_capture_initial')==('RETURN',0)
        assert m.call('ui_open_management',m.session)==('RETURN',0)
        assert m.call('ui_restore_credential',m.session)==('RETURN',0)
        assert not m.writes and m.vars[PRIVATE][1]==data
        assert m.calls.count('GetVariable:'+PRIVATE)==1;m.clean_logs()
    case('initial '+label+' preserved without reading content',check)
for code in [ERR(7),ERR(5),0]:
    def check(code=code):
        m=Model();m.read_error=(PRIVATE,code);assert m.call('ui_capture_initial')==('RETURN',0);assert not m.writes
    case('initial private status '+hex(code)+' fails closed',check)
for var in [OC,MEM]:
    for kind in ['absent','wrong_size','wrong_attributes','read_error']:
        def check(var=var,kind=kind):
            m=Model()
            if kind=='absent':m.vars.pop(var)
            if kind=='wrong_size':m.vars[var]=(3,b'X')
            if kind=='wrong_attributes':m.vars[var]=(0,m.vars[var][1])
            if kind=='read_error':m.read_error=(var,ERR(7))
            assert m.call('ui_capture_initial')==('RETURN',0)and not m.writes
        case('baseline '+var+' '+kind+' refuses UI',check)
for tpl in [8,16,31]:
    def check(tpl=tpl):
        m=Model();m.tpl=tpl;assert m.call('ui_capture_initial')==('HOLD',0x55350003)
        assert m.calls==['RaiseTPL']
    case('unexpected TPL '+str(tpl)+' CPU-holds without restoring or returning to app',check)
for condition in [1,2,3,9,12]:
    def check(condition=condition):
        m=Model();m.prepare();m.call('test_condition',condition)
        assert m.call('ui_open_management',m.session)==('RETURN',0)and not m.sent and not m.writes
    case('UI session/interface precondition '+str(condition)+' rejects',check)
for condition in [5,6,7,8,10,11,13,14]:
    def check(condition=condition):
        m=Model();m.prepare();m.call('test_condition',condition);before=len(m.calls)
        assert m.call('ui_open_original_setup',m.session)[0]=='HOLD'
        assert len(m.calls)==before and not m.sent and not m.writes
    case('corrupt/ended/held context '+str(condition)+' holds before service',check)
for kind in ['locate_error','list_too_many','list_misaligned','missing','duplicate','malformed','wrong_length','oversize','copy_error','copy_changed_size']:
    def check(kind=kind):
        m=Model();m.prepare();m.hii_case=kind
        assert m.call('ui_open_management',m.session)==('RETURN',0)and not m.sent and not m.writes
    case('HII '+kind+' rejects before SendForm',check)
for flags in [0,3,7,16,32,64,0x80]:
    def check(flags=flags):
        m=Model();m.prepare();m.putd(EXPORT['fixture_provider_flags'],flags)
        assert m.call('ui_open_management',m.session)==('RETURN',0)and not m.sent
    case('provider flags '+hex(flags)+' refuses outside ready idle',check)
def unseen():
    m=Model();m.prepare();m.vars[PRIVATE]=(3,record());assert m.call('ui_open_management',m.session)==('RETURN',0)
    assert m.call('ui_restore_credential',m.session)==('RETURN',0)and not m.writes and PRIVATE in m.vars
case('new unobserved private record between capture and UI is never adopted/deleted',unseen)
for kind in ['invalid','oversize','wrong_attrs','same_generation_changed','lower_generation','unexpected_absence']:
    def check(kind=kind):
        m=Model();m.prepare();m.enroll(record(2))
        def mutate(x):
            if kind=='unexpected_absence':x.vars.pop(PRIVATE);return
            data={'invalid':b'bad','oversize':bytes(200),'wrong_attrs':record(3),
                  'same_generation_changed':record(2,tag=1),'lower_generation':record(1)}[kind]
            x.vars[PRIVATE]=(7 if kind=='wrong_attrs' else 3,data)
        m.on_send=mutate
        assert m.call('ui_open_original_setup',m.session)==('RETURN',0)
        assert m.call('ui_restore_credential',m.session)==('RETURN',0)and not m.writes
    case('post-UI '+kind+' sticky unknown; no blind delete',check)
def forward():
    m=Model();m.prepare();m.enroll();m.on_send=lambda x:x.vars.__setitem__(PRIVATE,(3,record(5,False)))
    assert m.call('ui_open_management',m.session)==('RETURN',1)
    assert m.call('ui_restore_credential',m.session)==('RETURN',1)and len(m.writes)==1
case('multiple legitimate generations and explicit disabled record remain cleanable',forward)
for kind in ['byte_change','attributes','absent','read_error','oversize']:
    def check(kind=kind):
        m=Model();m.prepare();m.enroll();old=m.owned_locations(record());assert len(old)==1
        if kind=='byte_change':m.vars[PRIVATE]=(3,record(2))
        if kind=='attributes':m.vars[PRIVATE]=(7,record())
        if kind=='absent':m.vars.pop(PRIVATE)
        if kind=='read_error':m.read_error=(PRIVATE,ERR(7))
        if kind=='oversize':m.vars[PRIVATE]=(3,bytes(200))
        assert m.call('ui_restore_credential',m.session)==('RETURN',0)and not m.writes
        assert bytes(m.u.mem_read(old[0],128))==b'\0'*128
    case('cleanup mismatch '+kind+' refuses write and wipes owned copy',check)
for kind in ['set_error_retains','set_error_but_absent','set_success_but_present','readback_error']:
    def check(kind=kind):
        m=Model();m.prepare();m.enroll();old=m.owned_locations(record());assert len(old)==1
        m.delete_status=ERR(7) if kind.startswith('set_error') else 0
        m.delete_effect=kind in ['set_error_but_absent','readback_error']
        if kind=='readback_error':m.after_delete_error=ERR(7)
        assert m.call('ui_restore_credential',m.session)==('RETURN',0)
        assert len(m.writes)==1 and bytes(m.u.mem_read(old[0],128))==b'\0'*128
        m.call('ui_restore_credential',m.session);assert len(m.writes)==1
    case('cleanup '+kind+' reports failure without retrying deletion',check)
for field in ['ui_head','save_head','bad_magic']:
    def check(field=field):
        m=Model();m.prepare();m.after_send_condition=field
        assert m.call('ui_open_original_setup',m.session)[0]=='HOLD'
        assert m.calls[-1]=='OriginalSendForm'and not m.writes
    case('SendForm dangling '+field+' holds without further firmware call',check)
for mode in ['error','action']:
    def check(mode=mode):
        m=Model();m.prepare();m.on_send=lambda x:x.vars.__setitem__(PRIVATE,(3,record()))
        if mode=='error':m.send_status=ERR(7)
        else:m.send_action=1
        assert m.call('ui_open_original_setup',m.session)==('RETURN',0)
        assert m.call('ui_restore_credential',m.session)==('RETURN',1)
        assert len(m.writes)==1
    case('SendForm '+mode+' reports failure but valid observed record safely cleaned',check)
for var in [OC,MEM]:
    def check(var=var):
        m=Model();m.prepare();m.on_send=lambda x:x.vars.__setitem__(var,(x.vars[var][0],bytes(len(x.vars[var][1]))))
        assert m.call('ui_open_original_setup',m.session)==('RETURN',0)and not m.writes
        assert m.call('ui_compare_original_stores')==('RETURN',0)
    case('OEM '+var+' change detected without repair write',check)
def cleanup_failed_attach():
    m=Model();m.prepare();m.call('test_condition',3)
    assert m.call('ui_restore_credential',m.session)==('RETURN',1)and not m.writes
case('failed provider attach permits absence-only cleanup with zero writes',cleanup_failed_attach)
def cleanup_faulted_provider():
    m=Model();m.prepare();m.enroll();m.putd(EXPORT['fixture_provider_flags'],32)
    assert m.call('ui_restore_credential',m.session)==('RETURN',1)and len(m.writes)==1
case('faulted provider does not prevent exact-owned cleanup after chains empty',cleanup_faulted_provider)
def cleanup_retired():
    m=Model();m.prepare();m.enroll();m.call('test_condition',4)
    assert m.call('ui_restore_credential',m.session)==('RETURN',1)and len(m.writes)==1
case('retired transaction retains owned state long enough for exact cleanup',cleanup_retired)

# Insert an actual app_ended transition at every mocked firmware boundary and
# verify actual compiled app_require_services prevents the next service call.
for stage in ['capture','management','cleanup']:
    baseline=Model()
    if stage!='capture':baseline.prepare()
    if stage=='cleanup':baseline.enroll()
    baseline.service_index=0
    function={'capture':'ui_capture_initial','management':'ui_open_management','cleanup':'ui_restore_credential'}[stage]
    args=()if stage=='capture'else(baseline.session,)
    assert baseline.call(function,*args)==('RETURN',1)
    boundaries=baseline.service_index
    for index in range(1,boundaries+1):
        def check(stage=stage,function=function,index=index):
            m=Model()
            if stage!='capture':m.prepare()
            if stage=='cleanup':m.enroll()
            m.service_index=0;m.abort_at=index
            assert m.call(function,*(()if stage=='capture'else(m.session,)))[0]=='HOLD'
            assert m.service_index==index
        case('EBS '+stage+' boundary '+str(index)+' has no subsequent service',check)

source=(TX/'source/session_ui.c').read_text()
assert source.count('initial_set(credential_name,&credential_guid,0,0,0)')==1
assert 'SetVariable call' in source and 'get_variable=' not in source and 'set_variable=' not in source
build=json.loads((HERE/'build/build.json').read_text())
for entry in build['sources']:
    data=Path(entry['path']).read_bytes();assert len(data)==entry['bytes']and hashlib.sha256(data).hexdigest()==entry['sha256']
result={'status':'PASS_ACTUAL_OPTIMIZED_UI_CODE_WITH_MOCKED_SERVICES_NOT_HARDWARE',
        'cases':len(results),'results':results,'fixture_sha256':hashlib.sha256(PE.read_bytes()).hexdigest(),
        'source_bindings':build['sources'],
        'limitations':['Firmware services and SendForm effects are explicit mocks; this is not an ASUS native UI run.',
                       'The real P13 OVMF FormBrowser/persistence test is a separate frozen lab, not added into this case count.',
                       'No plaintext passwords are involved. Synthetic valid credential records remain only in test memory, not in the result log.',
                       'Snapshots do not establish absence of all OEM internal NVRAM writes; delete comparison is cooperative and not an atomic compare-and-swap.']}
(HERE/'ui_test_result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':result['status'],'cases':result['cases'],'fixture_sha256':result['fixture_sha256']}))
