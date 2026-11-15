"""Run the actual linked NVRAM EFI gate/services paths in Unicorn.

Firmware Get/SetVariable are explicit in-memory providers, never host UEFI or
BMC operations. Synthetic record bytes are generated afresh in memory and do
not supply a stage-2 media receipt. This is not a physical persistence test.
"""
from pathlib import Path
import ast,hashlib,json,re,secrets,struct,sys,uuid,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U,capstone as C
from unicorn import x86_const as R
OUT=HERE/'stage1/build';CANDIDATE_EFI=OUT/'BOOTX64.EFI';CANDIDATE_MAP=OUT/'nv_test.map'
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
GET=STOP+0x100;SET=STOP+0x110;CRC=STOP+0x120;CREATE=STOP+0x200;CREATE_EX=STOP+0x210;CLOSE=STOP+0x220
ERR=lambda n:0x8000000000000000|n
q=lambda x:struct.pack('<Q',x);d=lambda x:struct.pack('<I',x)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
helper=HERE.parent.parent/'lock_1904_integrated04/ebs_review/verify_ebs.py'
tree=ast.parse(helper.read_text(encoding='utf8'))
klass=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='VM')
exec(compile(ast.Module(body=[klass],type_ignores=[]),str(helper),'exec'),globals())
manifest=json.loads((OUT/'build.json').read_text(encoding='utf8'))
assert sha(CANDIDATE_EFI)==manifest['efi_sha256'] and manifest['production_object_relink_exact_match']
assert all(sha(HERE/n)==h for n,h in manifest['local_sources'].items())
KEY=('AiTweakerPassword1904',uuid.UUID('750e9d9d-f2d8-4e14-9b53-8923a7190461').bytes_le)
DATA=HEAP+0x9000;HASH=HEAP+0x9100

def record(generation=1,enabled=True):
    r=bytearray(128);r[:8]=b'AITWKP01';struct.pack_into('<HHIIIQ',r,8,1,128,int(enabled),int(enabled),600000 if enabled else 0,generation)
    if enabled:r[32:96]=secrets.token_bytes(64)
    r[96:]=hashlib.sha256(r[:96]).digest();return bytes(r)

class NvVM(VM):
    def __init__(self,value=None,attrs=3):
        super().__init__()
        if value is not None:self.variables[KEY]=(attrs,value)
        self.set_behavior='normal';self.get_count=0;self.get_fault_at=0;self.retire_get_at=0;self.stale_get_at=0
        self.mutate_input_at=0;self.native_sets=[]
    def hook(self,u,a,size,data):
        if a==GET:
            self.get_count+=1
            if self.get_count==self.get_fault_at:self.calls.append(a);self.ret(ERR(7));return
            super().hook(u,a,size,data)
            if self.get_count==self.retire_get_at:
                u.mem_write(self.symbols['console_retired'],d(1));u.mem_write(self.symbols['password_core']+200,b'\0')
            if self.get_count==self.stale_get_at:
                p=self.symbols['password_core']+168;u.mem_write(p,q(self.getq(p)+1))
            if self.get_count==self.mutate_input_at:u.mem_write(DATA,b'X'*128)
            return
        if a==SET:
            self.calls.append(a);key=(self.c16(self.arg(0)),bytes(u.mem_read(self.arg(1),16)))
            attrs,n=self.arg(2),self.arg(3);value=bytes(u.mem_read(self.arg(4),n)) if n else b''
            self.native_sets.append((key,attrs,n,value));self.set_calls.append(key)
            if self.set_behavior=='fail_unchanged':self.ret(ERR(9));return
            if self.set_behavior=='success_unchanged':self.ret(0);return
            if self.set_behavior=='corrupt':self.variables[key]=(attrs,b'?'*128);self.ret(ERR(7));return
            if not n:self.variables.pop(key,None)
            else:self.variables[key]=(attrs,value)
            self.ret(ERR(7) if self.set_behavior=='error_but_committed' else 0);return
        super().hook(u,a,size,data)
    def set_owner(self,value):
        if value:assert self.call('begin_console_session')==1
        else:self.call('end_console_session')
    def state(self):
        p=self.call('nv_status');raw=bytes(self.u.mem_read(p,144));names=['phase','initialized','ready','armed','retired','fault','owned','present','action','gate_busy','sealed','cleanup_complete','attempts','commits','blocked','delete_attempts']
        out=dict(zip(names,struct.unpack_from('<16I',raw)));out.update(generation=struct.unpack_from('<Q',raw,72)[0],hash=raw[112:144])
        return out
    def initialize(self,stage=1,expected=None):
        assert self.call('initialize_services')==1
        if expected is not None:self.u.mem_write(HASH,expected)
        return self.call('nv_prepare',GET,SET,stage,HASH if expected is not None else 0)
    def arm(self,stage=1,expected=None):
        assert self.initialize(stage,expected)==1
        self.u.mem_write(self.symbols['maintenance_exit_event'],q(1));self.u.mem_write(self.symbols['maintenance_before_event'],q(2));self.u.mem_write(self.symbols['resident'],d(1))
        assert self.call('publish_runtime_guards')==1
        assert self.call('nv_activate')==1
        assert self.call('begin_console_session')==1
        return self
    def action(self,new,action=1,commit_core=True):
        assert self.call('nv_begin_action',action)==1
        core=self.symbols['password_core'];self.u.mem_write(core+202,b'\1');self.u.mem_write(DATA,new)
        result=self.call('persist_record',0,DATA,len(new))
        self.u.mem_write(core+202,b'\0');self.call('nv_end_action')
        if not result and commit_core:
            self.u.mem_write(core+40,new);self.u.mem_write(core+196,d(1 if new[12] else 2))
        return result

checks=[]
def check(name,value):
    assert value,name;checks.append(name)

for label,value,attrs in [('absent',None,3),('enabled',record(),3),('disabled',record(enabled=False),3),('unknown',b'x'*128,3),('wrong_attrs',record(),7),('too_big',record()+b'x',3)]:
    v=NvVM(value,attrs);okay=v.initialize()
    check('stage1 '+label+' requires original absence',bool(okay)==(value is None) and not v.native_sets)
    check('prepare '+label+' cannot be repeated',v.call('nv_prepare',GET,SET,1,0)==0 and not v.native_sets)
old=record();expected=hashlib.sha256(old).digest()
for label,value,attrs,h in [('exact',old,3,expected),('wrong_hash',old,3,secrets.token_bytes(32)),('absent',None,3,expected),('disabled',record(enabled=False),3,expected),('attrs',old,7,expected),('invalid',b'?'*128,3,expected),('missing_hash',old,3,None)]:
    v=NvVM(value,attrs);okay=v.initialize(2,h)
    check('stage2 '+label+' adoption boundary',bool(okay)==(label=='exact') and not v.native_sets)

v=NvVM().arm();core=v.symbols['password_core']
check('console owner adapter active and initially locked',v.call('platform_session_owned')==1 and v.call('platform_can_enter')==0)
v.call('end_console_session');v.call('ap_session_begin',core)
check('core-only active token does not authorize console action',v.call('nv_begin_action',1)==0)
v.call('begin_console_session');check('normal explicit console action can begin',v.call('nv_begin_action',1)==1)
v.u.mem_write(core+202,b'\1');new=record();v.u.mem_write(DATA,new)
name=HEAP+0x9500;guid=name+0x100;v.u.mem_write(name,KEY[0].encode('utf-16le')+b'\0\0');v.u.mem_write(guid,KEY[1])
for label,nptr,gptr,attrs,n,p in [('alias_name',name,v.symbols['credential_guid'],3,128,DATA),('alias_guid',v.symbols['credential_name'],guid,3,128,DATA),('attrs',v.symbols['credential_name'],v.symbols['credential_guid'],7,128,DATA),('short',v.symbols['credential_name'],v.symbols['credential_guid'],3,127,DATA),('delete',v.symbols['credential_name'],v.symbols['credential_guid'],0,0,0)]:
    check('private gate rejects '+label,v.call('nv_guard_set',nptr,gptr,attrs,n,p)==ERR(8) and not v.native_sets)
check('runtime credential calls cannot enter private adapter',v.call('guarded_set',v.symbols['credential_name'],v.symbols['credential_guid'],3,128,DATA)==ERR(15) and not v.native_sets)
v.u.mem_write(name,'Other'.encode('utf-16le')+b'\0\0')
check('all other Runtime SetVariable calls denied',v.call('guarded_set',name,guid,3,128,DATA)==ERR(8) and not v.native_sets)

v=NvVM().arm();new=record();check('real production persist creates exact stage1 record',v.action(new)==0 and v.variables[KEY]==(3,new))
check('stage1 successful native call/readback seals one write',v.state()['sealed']==1 and v.state()['commits']==1 and len(v.native_sets)==1)
check('stage1 additional action denied',v.call('nv_begin_action',1)==0 and v.call('nv_begin_action',2)==0)
v.call('end_console_session');check('stage1 never deletes enrolled record',v.call('nv_cleanup_tombstone')==0 and len(v.native_sets)==1)

for label,new in [('bad_checksum',b'?'*128),('generation_two',record(2)),('disabled',record(1,False))]:
    v=NvVM().arm();check('stage1 rejects '+label,v.action(new)!=0 and not v.native_sets)
for behavior in ['fail_unchanged','success_unchanged','corrupt','error_but_committed']:
    v=NvVM().arm();v.set_behavior=behavior;new=record();check(behavior+' production persist reports failure',v.action(new)!=0)
    check(behavior+' exact native attempt count',len(v.native_sets)==1)
    check(behavior+' fault only when status/readback is ambiguous',bool(v.state()['fault'])==(behavior!='fail_unchanged'))

for label,offset in [('private_recheck_retired',2),('production_recheck_retired',1),('private_recheck_stale',2)]:
    v=NvVM().arm();start=v.get_count
    if label.endswith('stale'):v.stale_get_at=start+offset
    else:v.retire_get_at=start+offset
    check(label+' refuses before native SetVariable',v.action(record())!=0 and not v.native_sets)
v=NvVM().arm();v.variables[KEY]=(3,record())
check('unexpected preexisting record after stage1 preflight is preserved',v.action(record())!=0 and not v.native_sets and v.state()['fault'])
v=NvVM().arm();new=record();v.mutate_input_at=v.get_count+2
check('provider mutation cannot change cloned native body',v.action(new)!=0 and v.native_sets[0][3]==new)
check('production readback comparison faults mutated original input',v.getd(v.symbols['password_core']+196)==3)
v=NvVM().arm();v.get_fault_at=v.get_count+3
check('unreadable native post-write state retires ownership',v.action(record())!=0 and v.state()['fault'] and not v.state()['owned'])

old=record();h=hashlib.sha256(old).digest()
v=NvVM(old).arm(2,h)
check('enabled stage2 record cannot be deleted',v.call('nv_cleanup_tombstone')==0 and not v.native_sets)
replacement=record(2);check('stage2 authenticated-path replacement goes through real persist',v.action(replacement)==0 and v.variables[KEY]==(3,replacement))
check('stage2 replacement ownership hash follows exact new record',v.state()['hash']==hashlib.sha256(replacement).digest())
tombstone=record(3,False);check('stage2 clear writes valid disabled tombstone',v.action(tombstone,2)==0 and v.variables[KEY]==(3,tombstone))
check('active console session prevents cleanup',v.call('nv_cleanup_tombstone')==0)
v.call('end_console_session');check('explicit cleanup deletes only known tombstone',v.call('nv_cleanup_tombstone')==1 and KEY not in v.variables)
check('cleanup calls native delete with zero attributes/size/null',v.native_sets[-1][1:]==(0,0,b''))
check('cleanup proves original absence and cannot repeat',v.state()['cleanup_complete']==1 and v.call('nv_cleanup_tombstone')==0 and v.state()['delete_attempts']==1)
for problem in ['replaced_record','changed_attributes','failed_delete','false_success_delete','missing_before_delete','retired_before_cleanup']:
    old=record();v=NvVM(old).arm(2,hashlib.sha256(old).digest());assert v.action(record(2,False),2)==0;v.call('end_console_session')
    n=len(v.native_sets)
    if problem=='replaced_record':v.variables[KEY]=(3,record(5,False))
    if problem=='changed_attributes':v.variables[KEY]=(7,v.variables[KEY][1])
    if problem=='failed_delete':v.set_behavior='fail_unchanged'
    if problem=='false_success_delete':v.set_behavior='success_unchanged'
    if problem=='missing_before_delete':del v.variables[KEY]
    if problem=='retired_before_cleanup':v.call('nv_retire')
    check(problem+' cannot claim successful cleanup',v.call('nv_cleanup_tombstone')==0 and not v.state()['cleanup_complete'])
    check(problem+' does not delete unknown record',len(v.native_sets)==n+(problem in ['failed_delete','false_success_delete']))
    n=len(v.native_sets);check(problem+' never retries delete blindly',v.call('nv_cleanup_tombstone')==0 and len(v.native_sets)==n)

v=NvVM().arm();v.call('nv_retire');check('retired maintenance rejects future action',v.call('nv_begin_action',1)==0 and not v.native_sets)
result={'status':'PASS_COMPILED_NVRAM_GATE_FIXTURE','checks':len(checks),'check_names':checks,
        'efi_sha256':sha(CANDIDATE_EFI),'build_manifest_sha256':sha(OUT/'build.json'),
        'production_driver_sha256':manifest['production_driver_sha256'],
        'sources':{str(f.relative_to(ROOT)):sha(f) for f in [Path(__file__),helper,HERE/'nv_guard.c',HERE/'nv_guard.h',HERE/'nv_maintenance.c',CANDIDATE_MAP]},
        'physical_run':False,'host_firmware_services_called':False,'stage2_receipt_generated':False,
        'limits':['Firmware providers are explicit in-memory fault fixtures.','The real production persist adapter is executed; candidate records here are synthetic, so this does not test password knowledge or physical flash.','Console owner adapter is explicit test architecture; native SendForm is never entered.']}
(OUT/'guard_validation.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:result[k] for k in ['status','checks','efi_sha256']},indent=2))
