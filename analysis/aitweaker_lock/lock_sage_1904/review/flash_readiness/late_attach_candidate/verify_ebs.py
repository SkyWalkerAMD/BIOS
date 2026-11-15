"""Exercise the compiled EBS-only candidate with explicit service faults.

The terminal CLI/HLT sequence executes in Unicorn only; its HLT instruction is
intercepted. No firmware code or privileged instruction executes on the host.
"""
from pathlib import Path
import hashlib,json,struct
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];DRIVER=CASE/'driver'
runtime=HERE.parent/'runtime_navigation/verify_runtime_paths.py'
source=runtime.read_text(encoding='utf8').split('\nv=RuntimeVM();v.guard()',1)[0]
marker="ns={'__file__':str(DRIVER/'verify_adapter.py')};"
replacement="prefix=prefix.replace(\"HERE/'build/driver.map'\",\"CANDIDATE/'build/driver.map'\").replace(\"HERE/'build/AiTweakerLock1904.efi'\",\"CANDIDATE/'build/AiTweakerLock1904.efi'\")\nns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':CANDIDATE};"
assert marker in source;source=source.replace(marker,replacement)
ns={'__file__':str(runtime),'CANDIDATE':HERE};exec(compile(source,str(runtime),'exec'),ns)
for name in ['RuntimeVM','U','R','TSE','SETUP','HEAP','STOP','symbols','q','d','w','GET','SET','CRC','LOCATE','HANDLE','FREE','OC','OCGUID','ERR']:globals()[name]=ns[name]
import capstone as C
CREATE=STOP+0x1200;CREATE_EX=STOP+0x1210;CLOSE=STOP+0x1220
BEFORE_GUID='8be0e274-3970-4b44-80c5-1ab9502f3bfc'
checks=[]
def check(name,condition):assert condition,name;checks.append(name)

class CandidateVM(RuntimeVM):
 def __init__(self):
  self.fatal_stop=False;self.fatal_reason=None;self.external_calls=[];self.event_records=[]
  self.crc_fail_remaining=0;self.patch_fail_remaining=0;self.partial_patch_failure=False;self.corrupt_patch_readback=False
  self.create_failure=False;self.create_ex_failure=False;self.close_failure=False
  super().__init__()
  for offset,target in [(0x50,CREATE),(0x170,CREATE_EX),(0x70,CLOSE)]:self.u.mem_write(self.bs+offset,q(target))
  for target in [CREATE,CREATE_EX,CLOSE,symbols['fatal_handoff']]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=target,end=target)
  cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64)
  instructions=list(cs.disasm(bytes(self.u.mem_read(symbols['fatal_handoff'],200)),symbols['fatal_handoff']))
  halt=next(i for i in instructions if i.mnemonic=='hlt')
  assert any(i.mnemonic=='cli' and i.address<halt.address for i in instructions)
  self.halt_address=halt.address;self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=halt.address,end=halt.address)
 def hook(self,u,address,size,data):
  if address==symbols['fatal_handoff']:self.fatal_reason=self.arg(0);return
  if address==self.halt_address:
   assert self.fatal_reason is not None
   assert u.reg_read(R.UC_X86_REG_EFLAGS)&0x200==0
   self.fatal_stop=True;u.emu_stop();return
  if address in [GET,SET,CRC,LOCATE,HANDLE,FREE,CREATE,CREATE_EX,CLOSE,STOP+0x100,STOP+0x110]:self.external_calls.append(hex(address))
  if address==CREATE:
   if self.create_failure:self.ret(ERR(9));return
   event=0xabc100+len(self.event_records);self.event_records.append({'event':event,'type':self.arg(0),'tpl':self.arg(1),'notify':self.arg(2)})
   u.mem_write(self.argn(4),q(event));self.ret(0);return
  if address==CREATE_EX:
   if self.create_ex_failure:self.ret(ERR(9));return
   import uuid
   event=0xabc100+len(self.event_records);self.event_records.append({'event':event,'type':self.arg(0),'tpl':self.arg(1),'notify':self.arg(2),'group':str(uuid.UUID(bytes_le=bytes(u.mem_read(self.argn(4),16))))})
   u.mem_write(self.argn(5),q(event));self.ret(0);return
  if address==CLOSE:
   if self.close_failure:self.ret(ERR(7));return
   self.event_records=[e for e in self.event_records if e['event']!=self.arg(0)];self.ret(0);return
  if address==CRC and self.crc_fail_remaining:
   self.crc_fail_remaining-=1;self.ret(ERR(7));return
  if address==symbols['patch_memory']:
   a,b,n=self.arg(0),self.arg(1),self.arg(2)
   if self.patch_fail_remaining:self.patch_fail_remaining-=1;self.patches.append([a,n]);self.ret(0);return
   if self.partial_patch_failure or self.corrupt_patch_readback:
    self.patches.append([a,n]);u.mem_write(a,bytes(u.mem_read(b,n)))
    if self.corrupt_patch_readback:u.mem_write(a+16,d(0))
    self.ret(0 if self.partial_patch_failure else 1);return
  super().hook(u,address,size,data)
 def call(self,address,*args):
  self.fatal_stop=False
  try:return super().call(address,*args)
  except AssertionError:
   if self.fatal_stop:return None
   raise
 def fix_crc(self):
  import zlib
  data=bytearray(self.u.mem_read(self.rt,0x88));data[16:20]=b'\0'*4
  self.u.mem_write(self.rt+16,d(zlib.crc32(data)))
 def prepared(self):
  check('initialize registers both callbacks',self.call(symbols['initialize_services'])==1)
  check('BeforeExit group GUID is exact',any(e.get('group')==BEFORE_GUID and e['notify']==symbols['before_exiting'] for e in self.event_records))
  self.guard();self.state(1,1,1)
  self.u.mem_write(symbols['password_core']+40,b'X'*128)
  return self
 def before(self):return self.call(symbols['before_exiting'],0,0)
 def final(self):
  previous=len(self.external_calls);result=self.call(symbols['exiting'],0,0)
  check('final EBS invokes no external service',len(self.external_calls)==previous)
  return result

cases=[]
v=CandidateVM().prepared();v.before()
check('normal BeforeExit restores original SetVariable',v.getq(v.rt+0x58)==SET)
check('normal BeforeExit CRC is independently valid',v.call(symbols['local_runtime_crc_valid'])==1)
check('normal handoff clears active and unlocked',not v.observation()['core_active'] and not v.observation()['core_unlocked'])
check('normal handoff wipes credential verifier',bytes(v.u.mem_read(symbols['password_core']+40,128))==bytes(128))
calls=len(v.external_calls);v.before();check('second BeforeExit is idempotent',len(v.external_calls)==calls)
v.final();check('normal final callback returns without halt',not v.fatal_stop)
v.final();check('repeated final callback is idempotent',not v.fatal_stop and v.getq(v.rt+0x58)==SET)
check('failed EBS return cannot reinstall guard',v.call(symbols['install_variable_guard'])==0)
check('failed EBS return cannot reopen native browser',v.call(symbols['browser_loop'])==ERR(15))
cases.append({'condition':'normal and original-core repeated notifications / first invalid MapKey return','result':'restored, idempotent, never rearmed'})

for kind in ['crc_once','write_once']:
 v=CandidateVM().prepared()
 if kind=='crc_once':v.crc_fail_remaining=1
 else:v.patch_fail_remaining=1
 v.before();v.final()
 check(kind+' recovers in bounded BeforeExit retry',not v.fatal_stop and v.getq(v.rt+0x58)==SET and v.getd(symbols['handoff_error'])==0)
 cases.append({'condition':kind,'result':'bounded recovery'})

for kind,expected in [('crc_permanent',2),('write_permanent',2),('bad_current_crc',1),('unknown_interposer',3),('partial_restore_failure',2),('bad_readback_crc',4),('no_Before_event',5),('pointer_changed_after_Before',5),('crc_changed_after_Before',6)]:
 v=CandidateVM().prepared()
 if kind=='crc_permanent':v.crc_fail=True
 elif kind=='write_permanent':v.patch_fail=True
 elif kind=='bad_current_crc':v.u.mem_write(v.rt+16,d(0))
 elif kind=='unknown_interposer':v.u.mem_write(v.rt+0x58,q(STOP+0x2000));v.fix_crc()
 elif kind=='partial_restore_failure':v.partial_patch_failure=True
 elif kind=='bad_readback_crc':v.corrupt_patch_readback=True
 before_patches=len(v.patches)
 if kind!='no_Before_event':v.before()
 if kind=='pointer_changed_after_Before':v.u.mem_write(v.rt+0x58,q(STOP+0x2000));v.fix_crc()
 if kind=='crc_changed_after_Before':v.u.mem_write(v.rt+16,d(0))
 check(kind+' restoration attempts are bounded',len(v.patches)-before_patches<=2)
 v.final()
 check(kind+' reaches terminal CLI/HLT and does not return',v.fatal_stop and v.fatal_reason==expected)
 check(kind+' clears browser authorization before stopping',not v.observation()['core_active'] and not v.observation()['core_unlocked'])
 cases.append({'condition':kind,'result':'terminal emulated halt','reason':v.fatal_reason,'runtime_pointer':hex(v.getq(v.rt+0x58))})

v=CandidateVM();check('unhooked platform initialization succeeds',v.call(symbols['initialize_services'])==1)
v.u.mem_write(v.rt+0x58,q(STOP+0x2000));v.fix_crc();v.before();v.final()
check('never-published guard leaves unrelated runtime interposer alone',not v.fatal_stop and v.getq(v.rt+0x58)==STOP+0x2000)
cases.append({'condition':'guard never published / unrelated platform hook','result':'preserved without unsafe ownership claim'})

for kind,expected in [('final_registration',0),('before_registration',0),('cleanup_close_failure',None)]:
 v=CandidateVM()
 if kind=='final_registration':v.create_failure=True
 else:v.create_ex_failure=True
 if kind=='cleanup_close_failure':v.close_failure=True
 result=v.call(symbols['initialize_services'])
 check(kind+' cannot return with an orphan event into unloaded code',result==expected and (v.fatal_stop if expected is None else not v.event_records))
 cases.append({'condition':kind,'result':'terminal halt' if v.fatal_stop else 'clean initialization failure'})

v=CandidateVM();assert v.call(symbols['initialize_services'])==1
assert v.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a6000)==1
v.state(1);v.start();v.u.mem_write(symbols['password_core']+201,b'\1');v.end()
check('ordinary Setup exit keeps global variable guard',v.getq(v.rt+0x58)==symbols['guarded_set'])
changed=bytearray(26681);changed[4]=1
check('outside-session protected write remains denied',v.write(OC,OCGUID,changed)==ERR(15))

sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
report={'status':'PASS_LOCAL_CANDIDATE','checks':len(checks),'check_names':checks,'cases':cases,
        'candidate_driver_sha256':sha(HERE/'build/AiTweakerLock1904.efi'),'candidate_source_sha256':sha(HERE/'services.c'),
        'baseline_driver_sha256':sha(DRIVER/'build/AiTweakerLock1904.efi'),
        'limits':['Privileged stop instructions execute only in Unicorn and are intercepted at HLT. No BMC, SPI, or host firmware calls.',
                  'BeforeExit uses firmware service and permission stubs here; actual OVMF and original ASUS service behavior need separate evidence.',
                  'Original ASUS DXE static event order is reviewed independently; this suite reproduces those callback sequences but is not whole-core emulation.',
                  'Candidate has a new hash and inherits no physical handoff acceptance from EXP02/HISTORY01.']}
(HERE/'ebs_regression.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({k:report[k] for k in ['status','checks','candidate_driver_sha256','candidate_source_sha256','baseline_driver_sha256']},indent=2))
