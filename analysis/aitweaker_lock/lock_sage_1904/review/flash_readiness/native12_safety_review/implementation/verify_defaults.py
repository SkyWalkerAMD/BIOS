"""Execute original Exit IFR/action parsing and native defaults dispatcher.

OEM effect callbacks are explicit counters; no claim of their side effects or
of the vendor defaults+save protocol's protected-commit compatibility.
"""
from pathlib import Path
import json,struct,uuid
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_guard.py').read_text().split('\nv=GateVM();check(',1)[0]
exec(compile(prefix,str(HERE/'verify_guard.py'),'exec'),globals())
DATA=0x40000000
spf=(HERE/'build/OriginalAMITSESetupData.bin').read_bytes()
u32=lambda at:struct.unpack_from('<I',spf,at)[0]
pages=u32(0x2c);controls=u32(0x30);variables=u32(0x34);properties=u32(0x3c)
original=(CASE/'analysis/modules/AMITSE.efi').read_bytes()
forms=json.loads((CASE/'analysis/modules/Setup_IFR.json').read_text())[0]
question=next(x for x in forms['records']if x.get('question_id')==0x691)
condition=next(x for x in forms['records']if x['offset']==question['offset']-6)
assert question['form']==0x271a and question['prompt']=='Load Optimized Defaults'
assert condition['hex']=='120697060500' and question['hex']=='0f0f5e005f0091060000ffff001a27'

class DefaultsVM(GateVM):
 def __init__(self,baseline=False):
  super().__init__();self.effects=[];self.other_effects=[];self.original_event_lookups=0;self.initializers=0;self.vendor_saves=0
  self.map(DATA,(len(spf)+4095)&~4095);self.u.mem_write(DATA,spf)
  for r,p in [(0x930b0,pages),(0x930c8,controls),(0x930b8,variables),(0x93080,properties)]:self.u.mem_write(TSE+r,q(DATA+p))
  self.u.mem_write(TSE+0x93948,q(DATA))
  # Runtime HII handles are assigned by firmware. Only those two handle fields
  # are fixed here; all page offsets, control bytes, IDs and properties are OEM.
  self.runtime_fixups=[]
  for index in [86,87]:
   at=u32(pages+4+index*4);self.u.mem_write(DATA+at,q(self.handle));self.runtime_fixups.append({'offset':at,'bytes':8,'runtime_HII_handle':hex(self.handle)})
  self.control=HEAP+0x1d0000
  self.loaded_question=None
  targets=[0x36c34,0x5d44c,0x3ce14,0x1425c,0x13a1c,0x5d4cc,0x5a04]
  for r in targets:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+r,end=TSE+r)
  if baseline:self.u.mem_write(TSE+0x5abc,original[0x5abc:0x5ac7])
 def hook(self,u,a,n,data):
  if a==TSE+0x5a04:self.original_event_lookups+=1;return
  if a in [TSE+0x36c34,TSE+0x5d44c,TSE+0x3ce14]:
   self.effects.append({'callback_rva':hex(a-TSE),'arg1':self.arg(0),'arg2':self.arg(1)});self.ret(0);return
  if a in [TSE+0x1425c,TSE+0x13a1c]:
   self.other_effects.append(hex(a-TSE))
   if a==TSE+0x1425c:self.vendor_saves+=1
   self.ret(1);return
  if a==TSE+0x5d4cc:self.initializers+=1;self.ret(0);return
  super().hook(u,a,n,data)
 def load_control(self,qid):
  page=u32(pages+4+86*4);items=u32(page+0x1c)
  at=next(controls+u32(page+0x20+i*4)for i in range(items)if struct.unpack_from('<H',spf,controls+u32(page+0x20+i*4)+12)[0]==qid)
  record=bytearray(spf[at:at+64]);ifr=SETUP+forms['offset']+struct.unpack_from('<Q',record,0x28)[0]
  condition_ptr=ifr+struct.unpack_from('<q',record,0x30)[0]
  struct.pack_into('<Q',record,0,self.handle);struct.pack_into('<Q',record,0x28,ifr);struct.pack_into('<Q',record,0x30,condition_ptr)
  self.u.mem_write(self.control+0x20,bytes(record));self.loaded_question=qid
  return ifr,condition_ptr,at
 def action(self,qid):self.load_control(qid);return self.call(TSE+0x44b14,self.control)
 def direct(self,event=0xffff001d):return self.call(TSE+0x5abc,event,TSE+0x36c34,0x12345678,0x23456789)
 def vendor(self):return self.call(TSE+0x5f688)

checks=[]
v=DefaultsVM(True);ifr,cond,control=v.load_control(0x691)
check('original Exit691 IFR bytes are the referenced question',bytes(v.u.mem_read(ifr,15)).hex()==question['hex'])
check('original Exit691 condition resolves action value5',v.call(TSE+0x1e81c,v.control+0x20,HEAP+0x1d0100)==5)
check('original action property table supplies type2 dispatch',v.getd(v.getq(HEAP+0x1d0100)+0x64)==2)
v.action(0x691)
check('unpatched Exit691 runs all three original registered defaults callbacks',[x['callback_rva']for x in v.effects]==['0x36c34','0x5d44c','0x3ce14'] and v.original_event_lookups==1)
v=DefaultsVM();v.start();result=v.action(0x691)
check('missing provider Exit691 blocks before every registered callback',not v.effects and v.original_event_lookups==0 and v.provider_calls['request']==0)
check('native action dispatcher still returns AL1 after denied effect',result&255==1)
for qid,target in [(0x68f,'0x1425c'),(0x690,'0x13a1c')]:
 v.action(qid);check('unrelated Exit action remains usable '+hex(qid),v.other_effects[-1]==target and not v.effects and v.provider_calls['request']==0)
v.end()
v=DefaultsVM();v.provider_present=True;v.start();v.action(0x691)
check('owned locked Exit691 asks once and cancel blocks all defaults',v.provider_calls['request']==1 and not v.effects)
v.request_accept=True;v.action(0x691)
check('accepted owned Exit691 executes original complete event dispatch',v.provider_calls['request']==2 and len(v.effects)==3 and v.original_event_lookups==1)
v.action(0x691);check('same BIOS invocation reuses defaults authorization',v.provider_calls['request']==2 and len(v.effects)==6)
v.end();v.request_accept=False;v.start();v.action(0x691)
check('new BIOS invocation locks defaults again',v.provider_calls['request']==3 and len(v.effects)==6);v.end()
v=DefaultsVM();check('unknown defaults caller without native UI frame is rejected',v.direct()==ERR(15) and not v.effects)
v.vendor();check('exact original vendor initialization call without UI frame reaches defaults',v.initializers==1 and len(v.effects)==3 and v.vendor_saves==1 and not v.provider_calls['request'])
v=DefaultsVM();v.start();v.vendor()
check('same vendor call inside native UI frame cannot inherit initialization exception',v.initializers==1 and not v.effects and v.vendor_saves==1)
v.end()
# Non-default event has no password requirement and preserves all register args.
v=DefaultsVM();result=v.direct(0x1234)
check('unrelated generic event chains with original fallback arguments',len(v.effects)==1 and v.effects[0]['arg1']==0x12345678 and v.effects[0]['arg2']==0x23456789 and v.provider_calls['query']==0)
v=DefaultsVM();head=TSE+int(manifest['modules']['AMITSE']['context_head_rva'],16);v.memory_deny.append((head,head+8,0));v.vendor()
check('unreadable native UI head does not activate initialization exception',not v.effects)
for bits,label in [(7|16,'busy'),(7|32,'fault'),(7|64,'ended'),(0x107,'unknown')]:
 v=DefaultsVM();v.provider_present=True;v.provider_bits=bits;v.action(0x691)
 check(label+' stale provider state cannot authorize defaults',not v.effects)
r={'status':'PASS_NATIVE_EXIT_DEFAULTS_DISPATCH_WITH_DECLARED_EFFECT_BOUNDARIES','checks':len(checks),'check_names':checks,
 'module_sha256':{n:row['sha256']for n,row in manifest['modules'].items()},'guard_points':sum(len(row['patches'])for row in manifest['modules'].values()),
 'source_sha256':sha(Path(__file__)),'original_setup_data_sha256':sha(HERE/'build/OriginalAMITSESetupData.bin'),'original_IFR_sha256':sha(CASE/'analysis/modules/Setup_IFR.json'),
 'question':question,'condition':condition,'control_original_offset':hex(control),'runtime_data_fixups':v.runtime_fixups,
 'native_chain':['Setup original Exit691 REF preceded by EQ_ID_VAL697=5','AMITSE1E2CC/1E6B8/1E81C resolve original native controls and AMICallback property type2','44B14 ->44A14 key5 -> slot6C4E8=449B4','449CE tail jump5ABC with eventFFFF001D','5A04 looks up original7CFA0 event table','5ABC iterates36C34,5D44C,3CE14'],
 'non_UI_exception':{'method':'5F688','protocol_interface':'79050','method_slot':'79060','defaults_call':'5F6C2','exact_return':'5F6C7','requires_static_UI_head_NULL':True},
 'limits':['HII runtime handle and control IFR pointer fixups are explicit fixtures; original data fields, expressions, property entries and action table are unchanged.','The three OEM defaults effect functions, initialization5D4CC and final save1425C are explicit effect counters. Their complete side effects and boot recovery compatibility are not claimed.','Original action dispatcher overwrites AL with1 after a denied effect. The menu may report action success while defaults remain blocked.','The original vendor defaults+save method ignores denied defaults and still invokes save; local protected-commit gates are separate.','Direct protocol slot7B568 ->6286C ->13B9C bypasses5ABC and remains separately unaccepted.','Provider authentication result and mapped-memory availability are fixtures here; actual provider and page-table code have separate reports.','No CAP/FFS or device write, upload, flash or complete cold boot test.']}
(HERE/'build/defaults_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks)}))
