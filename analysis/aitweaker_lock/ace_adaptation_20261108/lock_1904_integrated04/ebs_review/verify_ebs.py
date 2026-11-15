"""Execute compiled ACE EBS cleanup and injected service faults in Unicorn.

The exact old ACE production driver supplies negative controls. By default the
new fixture contains services/core code with browser-ownership stubs. With
--integrated --expected-sha HASH, execute the complete production EFI and its
real owner functions. Final notifications receive an unmapped BootServices
pointer. CLI executes only inside Unicorn; HLT is intercepted on the host.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct,sys,uuid,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U,capstone as C
from unicorn import x86_const as R
BASE=0x140000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
GET=STOP+0x100;SET=STOP+0x110;CRC=STOP+0x120
CREATE=STOP+0x200;CREATE_EX=STOP+0x210;CLOSE=STOP+0x220
ERR=lambda x:0x8000000000000000|x
q=lambda x:struct.pack('<Q',x);d=lambda x:struct.pack('<I',x)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
BEFORE_GUID='8be0e274-3970-4b44-80c5-1ab9502f3bfc'
BASELINE=CASE.parent/'lock_1904_history02/driver/build'
NEW=HERE/'build'
assert sha(BASELINE/'AiTweakerLock1904.efi')=='598daaa53564f9b4610e300946fd588c2108a9842cb5f15cf67ee8e8d0a2fd84'
build=json.loads((NEW/'build.json').read_text(encoding='utf8'))
assert sha(NEW/'EBS-SERVICES-ONLY.EFI')==build['efi_sha256']
assert all(sha(ROOT/p)==h for p,h in build['sources'].items())
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--integrated',action='store_true')
parser.add_argument('--expected-sha')
args=parser.parse_args()
if args.integrated and not args.expected_sha:parser.error('--integrated requires --expected-sha')
CANDIDATE=CASE/'driver/build' if args.integrated else NEW
CANDIDATE_EFI=CANDIDATE/('AiTweakerLock1904.efi' if args.integrated else 'EBS-SERVICES-ONLY.EFI')
CANDIDATE_MAP=CANDIDATE/('driver.map' if args.integrated else 'fixture.map')
integrated_build=None
object_binding=None
if args.integrated:
 integrated_build=json.loads((CANDIDATE/'build.json').read_text(encoding='utf8'))
 assert sha(CANDIDATE_EFI)==args.expected_sha==integrated_build['efi_sha256']
 assert all(sha(CASE/p)==h for p,h in integrated_build['sources'].items())
 assert all(sha(ROOT/p)==h for p,h in integrated_build['external_sources'].items())
 raw=(CANDIDATE/'services.obj').read_bytes();fixture_raw=(NEW/'services.obj').read_bytes()
 assert sha(NEW/'services.obj')==build['services_obj_sha256']
 assert struct.unpack_from('<H',raw)[0]==struct.unpack_from('<H',fixture_raw)[0]==0x8664
 # COFF TimeDateStamp is metadata at bytes 4..7. Require every other byte,
 # including section headers, contents, relocations and symbols to match.
 normalize=lambda data:data[:4]+bytes(4)+data[8:]
 assert normalize(raw)==normalize(fixture_raw),'services object differs outside COFF TimeDateStamp'
 object_binding={'production_sha256':sha(CANDIDATE/'services.obj'),
  'fixture_sha256':sha(NEW/'services.obj'),'bytes':len(raw),
  'different_offsets':[i for i,(a,b) in enumerate(zip(raw,fixture_raw)) if a!=b],
  'production_coff_timestamp':struct.unpack_from('<I',raw,4)[0],
  'fixture_coff_timestamp':struct.unpack_from('<I',fixture_raw,4)[0],
  'timestamp_zeroed_sha256':hashlib.sha256(normalize(raw)).hexdigest(),
  'result':'all bytes except the standard COFF TimeDateStamp field are identical'}

class VM:
 def __init__(self,baseline=False):
  self.baseline=baseline
  path=BASELINE/'AiTweakerLock1904.efi' if baseline else CANDIDATE_EFI
  mapfile=BASELINE/'driver.map' if baseline else CANDIDATE_MAP
  self.symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',mapfile.read_text(encoding='utf8'),re.M)}
  self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
  pe=pefile.PE(str(path));pe.relocate_image(BASE);data=pe.get_memory_mapped_image();pe.close()
  self.u.mem_map(BASE,(len(data)+4095)&~4095);self.u.mem_write(BASE,data)
  for addr,size in [(HEAP,0x200000),(STACK,0x200000),(STOP,0x10000)]:self.u.mem_map(addr,size)
  self.st=HEAP;self.bs=HEAP+0x1000;self.rt=HEAP+0x2000
  self.u.mem_write(self.symbols['system_table'],q(self.st));self.u.mem_write(self.st+0x58,q(self.rt)+q(self.bs))
  self.u.mem_write(self.rt,q(0x56524553544e5552)+d(0x200b0)+d(0x88)+d(0)+d(0))
  self.u.mem_write(self.rt+0x48,q(GET));self.u.mem_write(self.rt+0x58,q(SET))
  for off,fn in [(0x50,CREATE),(0x70,CLOSE),(0x158,CRC),(0x170,CREATE_EX)]:self.u.mem_write(self.bs+off,q(fn))
  self.fix_crc();self.calls=[];self.events=[];self.patches=[];self.set_calls=[];self.variables={}
  self.crc_fail=0;self.patch_fail=0;self.patch_kind=None
  self.create_fail=False;self.create_ex_fail=False;self.close_fail=False;self.owner_after_get=None
  self.halted=False;self.fatal_reason=None;self.halt=None
  if 'fatal_handoff' in self.symbols:
   cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64)
   instructions=list(cs.disasm(bytes(self.u.mem_read(self.symbols['fatal_handoff'],256)),self.symbols['fatal_handoff']))
   self.halt=next(i.address for i in instructions if i.mnemonic=='hlt')
   assert any(i.mnemonic=='cli' and i.address<self.halt for i in instructions)
  targets=[STOP,GET,SET,CRC,CREATE,CREATE_EX,CLOSE,self.symbols['patch_memory']]
  if self.halt:targets += [self.halt,self.symbols['fatal_handoff']]
  for addr in targets:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=addr,end=addr)
  self.u.reg_write(R.UC_X86_REG_CR4,0x600)
 def getq(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def getd(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def var(self,n):return self.getd(self.symbols[n])
 def set_owner(self,value):
  if 'fixture_owner' in self.symbols:self.u.mem_write(self.symbols['fixture_owner'],d(value))
  else:
   # Exercise the actual integrated platform owner; no function replacement.
   self.u.mem_write(self.symbols['loop_depth'],d(value))
   self.u.mem_write(self.symbols['password_core']+200,bytes([bool(value)]))
 def arg(self,i):
  return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i]) if i<4 else self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+40+(i-4)*8)
 def ret(self,n):
  sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,n);self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
 def c16(self,p):
  out=[]
  for i in range(128):
   c=int.from_bytes(self.u.mem_read(p+i*2,2),'little')
   if not c:return ''.join(out)
   out.append(chr(c))
  raise AssertionError('unterminated fixture string')
 def fix_crc(self):
  raw=bytearray(self.u.mem_read(self.rt,0x88));raw[16:20]=bytes(4);self.u.mem_write(self.rt+16,d(zlib.crc32(raw)))
 def hook(self,u,a,size,data):
  if a==STOP:u.emu_stop();return
  if a==self.symbols.get('fatal_handoff'):self.fatal_reason=self.arg(0);return
  if a==self.halt:
   assert self.fatal_reason is not None and not u.reg_read(R.UC_X86_REG_EFLAGS)&0x200
   self.halted=True;u.emu_stop();return
  self.calls.append(a)
  if a==CREATE or a==CREATE_EX:
   if self.create_fail if a==CREATE else self.create_ex_fail:self.ret(ERR(9));return
   event=0xabc100+len(self.events)
   record={'event':event,'type':self.arg(0),'tpl':self.arg(1),'callback':self.arg(2)}
   if a==CREATE_EX:record['group']=str(uuid.UUID(bytes_le=bytes(u.mem_read(self.arg(4),16))))
   self.events.append(record);u.mem_write(self.arg(5 if a==CREATE_EX else 4),q(event));self.ret(0);return
  if a==CLOSE:
   if self.close_fail:self.ret(ERR(7));return
   self.events=[e for e in self.events if e['event']!=self.arg(0)];self.ret(0);return
  if a==CRC:
   if self.crc_fail:
    if self.crc_fail>0:self.crc_fail-=1
    self.ret(ERR(7));return
   u.mem_write(self.arg(2),d(zlib.crc32(bytes(u.mem_read(self.arg(0),self.arg(1))))));self.ret(0);return
  if a==self.symbols['patch_memory']:
   dest,src,n=self.arg(0),self.arg(1),self.arg(2);self.patches.append([dest,n])
   if self.patch_fail:
    if self.patch_fail>0:self.patch_fail-=1
    self.ret(0);return
   if self.patch_kind=='pointer_only':u.mem_write(dest+0x58,bytes(u.mem_read(src+0x58,8)));self.ret(0);return
   u.mem_write(dest,bytes(u.mem_read(src,n)))
   if self.patch_kind=='corrupt_success':u.mem_write(dest+16,d(0))
   self.ret(0 if self.patch_kind=='written_but_failed' else 1);return
  if a==GET:
   key=(self.c16(self.arg(0)),bytes(u.mem_read(self.arg(1),16)))
   if self.owner_after_get is not None:self.set_owner(self.owner_after_get)
   if key not in self.variables:self.ret(ERR(14));return
   attr,value=self.variables[key];capacity=self.getq(self.arg(3));u.mem_write(self.arg(3),q(len(value)))
   if self.arg(2):u.mem_write(self.arg(2),d(attr))
   if capacity<len(value):self.ret(ERR(5));return
   u.mem_write(self.arg(4),value);self.ret(0);return
  if a==SET:
   key=(self.c16(self.arg(0)),bytes(u.mem_read(self.arg(1),16)))
   value=bytes(u.mem_read(self.arg(4),self.arg(3)))
   self.variables[key]=(self.arg(2),value);self.set_calls.append(key);self.ret(0);return
  raise AssertionError(hex(a))
 def call(self,name,*args):
  addr=self.symbols[name] if isinstance(name,str) else name
  self.halted=False;sp=STACK+0x1ffd08;self.u.mem_write(sp,q(STOP)+bytes(0x200));self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for i,arg in enumerate(args):
   if i<4:self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i],arg)
   else:self.u.mem_write(sp+40+(i-4)*8,q(arg))
  self.u.reg_write(R.UC_X86_REG_EFLAGS,0x202)
  self.u.emu_start(addr,STOP+0x10000,count=10000000)
  if self.halted:return None
  assert self.u.reg_read(R.UC_X86_REG_RIP)==STOP,hex(self.u.reg_read(R.UC_X86_REG_RIP))
  return self.u.reg_read(R.UC_X86_REG_RAX)
 def prepare(self):
  assert self.call('initialize_services')==1
  assert self.call('install_variable_guard')==1
  core=self.symbols['password_core'];self.u.mem_write(core+40,b'X'*128);self.u.mem_write(core+196,d(1)+b'\1\1\0\0')
  self.set_owner(1)
  return self
 def retired(self):
  core=self.symbols['password_core']
  owner_cleared=self.var('fixture_owner')==0 if 'fixture_owner' in self.symbols else self.var('loop_depth')==0
  return owner_cleared and self.var('boot_services_ended')==1 and bytes(self.u.mem_read(core+200,2))==bytes(2) and bytes(self.u.mem_read(core+40,128))==bytes(128)
 def before(self):return self.call('before_exiting',0,0)
 def final(self):
  count=len(self.calls);self.u.mem_write(self.st+0x60,q(0xdead0000));result=self.call('exiting',0,0)
  assert len(self.calls)==count,'Final callback used an external/permission service'
  return result

checks=[];cases=[]
def check(name,value):assert value,name;checks.append(name)

# Negative controls execute the exact previously built ACE driver, unchanged.
baseline=[]
for fault in ['none','crc_unavailable','permission_provider_failed']:
 v=VM(True).prepare();v.crc_fail=-1 if fault=='crc_unavailable' else 0;v.patch_fail=-1 if fault=='permission_provider_failed' else 0
 count=len(v.calls);v.call('exiting',0,0)
 check('baseline '+fault+' final calls external BootServices-dependent code',len(v.calls)>count)
 dangling=v.getq(v.rt+0x58)==v.symbols['guarded_set']
 check('baseline '+fault+' observed expected dangling guard outcome',dangling==(fault!='none'))
 check('baseline '+fault+' returns after marking boot services ended',v.var('boot_services_ended')==1)
 baseline.append({'fault':fault,'final_external_calls':[hex(x) for x in v.calls[count:]],'returns_with_guarded_pointer':dangling,'boot_services_ended':v.var('boot_services_ended')})

v=VM();check('guard rejected before event registration',v.call('install_variable_guard')==0 and not v.calls)
v.prepare();check('both callbacks registered',len(v.events)==2)
check('exact Before GUID and notify TPL',any(e.get('group')==BEFORE_GUID and e['tpl']==16 and e['callback']==v.symbols['before_exiting'] for e in v.events))
count=len(v.events);old=v.getq(v.symbols['original_set_variable']);check('duplicate init preserves original pointer',v.call('initialize_services')==1 and len(v.events)==count and v.getq(v.symbols['original_set_variable'])==old==SET)
v.before();check('Before restores original pointer and CRC',v.getq(v.rt+0x58)==SET and v.call('local_runtime_crc_valid')==1)
check('Before wipes credential and retires session',v.retired())
count=len(v.calls);v.before();check('duplicate Before invokes no service',len(v.calls)==count)
v.final();check('normal final runs with inaccessible BootServices',not v.halted and v.retired())
v.final();check('duplicate final is idempotent',not v.halted and v.getq(v.rt+0x58)==SET)
check('failed MapKey retry cannot rearm guard',v.call('install_variable_guard')==0)
check('failed MapKey retry cannot reinitialize services',v.call('initialize_services')==0)
cases.append({'case':'normal, duplicate callbacks, failed MapKey retirement','result':'safe return, original pointer/CRC, no final external calls'})

for fault in ['crc_once','write_once']:
 v=VM().prepare();v.crc_fail=1 if fault=='crc_once' else 0;v.patch_fail=1 if fault=='write_once' else 0
 count=len(v.patches);v.before();v.final()
 check(fault+' recovers within two writes',not v.halted and v.getq(v.rt+0x58)==SET and len(v.patches)-count<=2)
 cases.append({'case':fault,'result':'bounded Before recovery'})

faults=[('crc_permanent',2),('write_permanent',2),('bad_current_crc',1),('unknown_interposer',3),('written_but_failed',2),('pointer_only',2),('corrupt_success',4),('missing_Before',5),('missing_Before_pointer_already_restored',5),('late_pointer',5),('late_crc',6)]
for fault,reason in faults:
 v=VM().prepare()
 if fault=='crc_permanent':v.crc_fail=-1
 elif fault=='write_permanent':v.patch_fail=-1
 elif fault=='bad_current_crc':v.u.mem_write(v.rt+16,d(0))
 elif fault=='unknown_interposer':v.u.mem_write(v.rt+0x58,q(STOP+0x900));v.fix_crc()
 elif fault in ['written_but_failed','pointer_only','corrupt_success']:v.patch_kind=fault
 count=len(v.patches)
 if not fault.startswith('missing_Before'):v.before()
 if fault=='missing_Before_pointer_already_restored':v.u.mem_write(v.rt+0x58,q(SET));v.fix_crc()
 if fault=='late_pointer':v.u.mem_write(v.rt+0x58,q(STOP+0x900));v.fix_crc()
 if fault=='late_crc':v.u.mem_write(v.rt+16,d(0))
 check(fault+' bounded writes',len(v.patches)-count<=2)
 v.final();check(fault+' stops without unsafe return',v.halted and v.fatal_reason==reason)
 check(fault+' retires authorization',v.retired())
 if fault=='unknown_interposer':check('unknown interposer not overwritten',v.getq(v.rt+0x58)==STOP+0x900 and len(v.patches)==count)
 cases.append({'case':fault,'result':'terminal emulated CLI/HLT','reason':v.fatal_reason})

for fault in ['no_guard','no_guard_foreign_pointer','no_guard_foreign_crc']:
 v=VM();check(fault+' initialize',v.call('initialize_services')==1)
 if fault!='no_guard':v.u.mem_write(v.rt+0x58,q(STOP+0x900));v.fix_crc()
 if fault=='no_guard_foreign_crc':v.u.mem_write(v.rt+16,d(0))
 pointer=v.getq(v.rt+0x58);count=len(v.patches);v.before();v.final()
 check(fault+' no false ownership claim',not v.halted and v.getq(v.rt+0x58)==pointer and len(v.patches)==count)
 cases.append({'case':fault,'result':'unowned runtime table preserved'})

for fault in ['crc_fail_install','write_fail_install','partial_install']:
 v=VM();assert v.call('initialize_services')==1
 if fault=='crc_fail_install':v.crc_fail=1
 if fault=='write_fail_install':v.patch_fail=1
 if fault=='partial_install':v.patch_kind='pointer_only'
 check(fault+' reports installation failure',v.call('install_variable_guard')==0)
 v.patch_kind=None;v.before();v.final()
 check(fault+' handles possible publication',v.halted and v.fatal_reason==1 if fault=='partial_install' else not v.halted and v.getq(v.rt+0x58)==SET)
 cases.append({'case':fault,'result':'unsafe partial publication stops' if v.halted else 'no publication returns safely'})

for fault in ['final_event_fail','before_event_fail','missing_create_ex','close_event_fail']:
 v=VM()
 if fault=='final_event_fail':v.create_fail=True
 else:v.create_ex_fail=True
 if fault=='missing_create_ex':v.u.mem_write(v.bs+0x170,q(0))
 if fault=='close_event_fail':v.close_fail=True
 result=v.call('initialize_services')
 check(fault+' no orphan callback is returned to loader',v.halted and v.fatal_reason==7 if fault=='close_event_fail' else result==0 and not v.events)
 if fault=='before_event_fail':
  v.create_ex_fail=False;check('clean failed registration can retry',v.call('initialize_services')==1 and len(v.events)==2)
 cases.append({'case':fault,'result':'terminal stop, callback remains resident' if v.halted else 'clean initialization failure'})

for fault in ['bad_crc','bad_signature','too_small','too_large','reserved_nonzero','null_set_variable']:
 v=VM()
 if fault=='bad_crc':v.u.mem_write(v.rt+16,d(0))
 elif fault=='bad_signature':v.u.mem_write(v.rt,q(0));v.fix_crc()
 elif fault=='too_small':v.u.mem_write(v.rt+12,d(0x58))
 elif fault=='too_large':v.u.mem_write(v.rt+12,d(0x90))
 elif fault=='reserved_nonzero':v.u.mem_write(v.rt+20,d(1));v.fix_crc()
 elif fault=='null_set_variable':v.u.mem_write(v.rt+0x58,q(0));v.fix_crc()
 check(fault+' initialization refuses before any provider calls',v.call('initialize_services')==0 and not v.calls and not v.events)

for initial,after,label in [(0,None,'outside native session'),(1,0,'session changes during original GetVariable')]:
 v=VM();assert v.call('initialize_services')==1
 v.set_owner(initial);v.owner_after_get=after
 data=HEAP+0x5000;v.u.mem_write(data,b'R'*128)
 check(label+' credential persistence rejected',v.call('persist_record',0,data,128)==1 and not v.set_calls)

report={'status':'PASS_INTEGRATED_EBS' if args.integrated else 'PASS_EBS_SERVICE_LAYER','checks':len(checks),'check_names':checks,'cases':cases,
 'baseline_driver_sha256':sha(BASELINE/'AiTweakerLock1904.efi'),'baseline_negative_controls':baseline,
 'fixture_sha256':sha(NEW/'EBS-SERVICES-ONLY.EFI'),'services_obj_sha256':build['services_obj_sha256'],
 'build_manifest_sha256':sha(NEW/'build.json'),'verification_source_sha256':sha(Path(__file__)),
 'source_sha256':build['sources'],
 'limits':['Memory/page permission and event providers are explicit fault-injection stubs; original service code is compiled and executed in Unicorn.',
 'Final handlers receive an unmapped BootServices pointer and must make no external calls. CLI is emulated and execution stops before HLT.',
 'Browser ownership is stubbed here; its native lifetime and integrated navigation require the separate owner tests.',
 'No physical firmware, BMC, OS handoff, or unknown interposer compatibility has been tested.',
 'An unknown interposer or unresolvable handoff deliberately stops boot. No automatic reset or recovery is claimed.',
 'A later firmware callback could reintroduce a retired code pointer after this final check; callback ordering and stale external references remain unproven.']}
if args.integrated:
 report.update({'candidate_kind':'complete integrated production EFI',
  'driver_sha256':sha(CANDIDATE_EFI),'driver_path':str(CANDIDATE_EFI.relative_to(ROOT)),
  'driver_map_sha256':sha(CANDIDATE_MAP),'driver_build_manifest_sha256':sha(CANDIDATE/'build.json'),
  'driver_source_sha256':integrated_build['sources'],
  'driver_external_source_sha256':integrated_build['external_sources'],
  'services_obj_sha256':sha(CANDIDATE/'services.obj'),
  'services_object_binding':object_binding,
  'owner_binding':'real integrated platform_session_owned/end_platform execute; fixture initializes or retires actual loop_depth and core.active',
  'physical_run':False})
 report['limits'][2]='Real integrated owner functions execute against explicit loop_depth/core fixtures; native browser entry and full navigation are not executed by this matrix.'
(HERE/('integrated_ebs_regression.json' if args.integrated else 'ebs_regression.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','checks','services_obj_sha256','baseline_driver_sha256']+(['driver_sha256'] if args.integrated else ['fixture_sha256'])},indent=2))
