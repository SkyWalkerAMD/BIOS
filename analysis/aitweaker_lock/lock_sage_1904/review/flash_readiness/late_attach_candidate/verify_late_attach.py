"""Execute new EFI against real relocated OEM hooks; no device or host EFI calls.

Memory/services, full browser body and accepted-password results are explicit
fixtures. Native navigation/history/ESC code runs where stated. Negative UI
entry cases execute the real ensure/manage implementation before any console.
"""
from pathlib import Path
import hashlib,json,struct,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];DRIVER=CASE/'driver'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((HERE/'build/build.json').read_text(encoding='utf8'))
assert sha(HERE/'build/AiTweakerLock1904.efi')==manifest['candidate_driver_sha256']
runtime=HERE.parent/'runtime_navigation/verify_runtime_paths.py'
source=runtime.read_text(encoding='utf8').split('\nv=RuntimeVM();v.guard()',1)[0]
marker="ns={'__file__':str(DRIVER/'verify_adapter.py')};"
replacement="prefix=prefix.replace(\"HERE/'build/driver.map'\",\"CANDIDATE/'build/driver.map'\").replace(\"HERE/'build/AiTweakerLock1904.efi'\",\"CANDIDATE/'build/AiTweakerLock1904.efi'\")\nns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':CANDIDATE};"
assert marker in source;source=source.replace(marker,replacement)
ns={'__file__':str(runtime),'CANDIDATE':HERE};exec(compile(source,str(runtime),'exec'),ns)
for name in ['RuntimeVM','U','R','TSE','SETUP','HEAP','STOP','symbols','q','d','w','GET','SET','OC','OCGUID','MEM','MEMGUID','ERR']:globals()[name]=ns[name]
CALLBACK=STOP+0x2100;ROUTE=STOP+0x2110;PRINT=STOP+0x2120;KEY=STOP+0x2130
checks=[];scenarios=[]
def check(name,value):assert value,name;checks.append(name)

class TestVM(RuntimeVM):
 def __init__(self,attach=True):
  self.ui_entries=0;self.ui_policy='real';self.manage_entries=0;self.original_hii=0;self.original_route_calls=0
  self.read_calls=0;self.drop_owner_on_get=False;self.synthetic_dialog=False;self.input_count=0;self.drop_owner_input=0
  self.core_calls={'ap_unlock':0,'ap_set_password':0,'ap_clear_password':0}
  super().__init__()
  self.u.mem_write(symbols['original_callback'],q(CALLBACK));self.u.mem_write(symbols['original_route'],q(ROUTE))
  for address in [CALLBACK,ROUTE,PRINT,KEY]+[symbols[x] for x in ['manage_password','ap_unlock','ap_set_password','ap_clear_password','save_screen','restore_screen','input_password','ap_retry_remaining_ms']]:
   self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=address,end=address)
  if attach:
   self.u.mem_write(TSE+0x83468,d(4));self.discover()
   assert self.observation()['platform_ready']==1
   self.u.mem_write(TSE+0x83468,d(5))
 def owner(self,depth,active,unlocked,mode=1,busy=0):
  self.state(mode,active,unlocked);self.u.mem_write(symbols['password_core']+202,bytes([busy]));self.u.mem_write(symbols['loop_depth'],d(depth))
 def hook(self,u,address,size,data):
  if address==symbols['ensure_unlocked']:
   self.ui_entries+=1
   if self.ui_policy=='real':return
   if self.ui_policy in ['grant','grant_then_lose_owner']:
    u.mem_write(symbols['password_core']+201,b'\1')
    if self.ui_policy=='grant_then_lose_owner':u.mem_write(symbols['loop_depth'],d(0))
    self.ret(1);return
   assert self.ui_policy=='cancel';self.ret(0);return
  if address==symbols['manage_password']:self.manage_entries+=1;return
  for name in self.core_calls:
   if address==symbols[name]:self.core_calls[name]+=1;return
  if address==CALLBACK:self.original_hii+=1;self.ret(0);return
  if address==ROUTE:self.original_route_calls+=1;self.ret(0);return
  if address==GET:
   self.read_calls+=1
   if self.drop_owner_on_get:u.mem_write(symbols['loop_depth'],d(0));self.drop_owner_on_get=False
  if self.synthetic_dialog:
   if address in [symbols['save_screen'],symbols['restore_screen']]:self.ret(0);return
   if address==symbols['ap_retry_remaining_ms']:self.ret(0);return
   if address==symbols['input_password']:
    self.input_count+=1;u.mem_write(self.arg(1),b'abcdefgh');u.mem_write(self.arg(2),q(8))
    if self.input_count==self.drop_owner_input:u.mem_write(symbols['loop_depth'],d(0))
    self.ret(1);return
   if address==PRINT:self.ret(0);return
   if address==KEY:u.mem_write(self.arg(1),w(0)+w(ord('Y')));self.ret(0);return
  super().hook(u,address,size,data)
 def nav(self,form=0x2714,valid=True):
  x=HEAP+0x9000;guid=uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le
  self.u.mem_write(x,guid+w(0x2713)+bytes(14)+guid+w(form))
  return self.call(TSE+0x626c,x,x+16,x+32 if valid else 0,x+48)
 def callback(self,qid,action=0):
  x=HEAP+0xa000;self.u.mem_write(x,q(0xabcdef0123456789)+q(0xfeedbeefcafebabe)+q(0x1122334455667788))
  result=self.call(symbols['config_callback'],HEAP+0xa100,action,qid,0,0,x+8)
  assert self.getq(x)==0xabcdef0123456789 and self.getq(x+16)==0x1122334455667788
  return result
 def route(self):
  x=HEAP+0xa400;s=('GUID='+OCGUID.hex()+'&OFFSET=0&WIDTH=1&VALUE=01').encode('utf-16le')+b'\0\0';self.u.mem_write(x,s)
  return self.call(symbols['config_route'],HEAP+0xa100,x,x+0x200)
 def dialog(self,drop):
  self.synthetic_dialog=True;self.drop_owner_input=drop
  out=HEAP+0x1a0000;inp=out+0x1000
  self.u.mem_write(self.st+0x40,q(out));self.u.mem_write(self.st+0x30,q(inp));self.u.mem_write(out+8,q(PRINT));self.u.mem_write(inp+8,q(KEY))

# Directly reproduce baseline bypass on the actual original EFI as a before case.
oldns={'__file__':str(runtime)}
exec(compile(runtime.read_text(encoding='utf8').split('\nv=RuntimeVM();v.guard()',1)[0],str(runtime),'exec'),oldns)
b=oldns['RuntimeVM']();b.u.mem_write(oldns['TSE']+0x83468,d(4));b.discover();b.state(1,0,0)
b.current(1);b.call(b.getq(TSE+0x6b928),b.pages[1])
check('baseline exact EFI reproduces late-stage4 render bypass',b.calls['render']==1)
b.state(1,1,1);changed=bytearray(26681);changed[4]=1
check('baseline exact EFI accepts synthetic stale core grant without wrapper',b.write(OC,OCGUID,changed)==0)
baseline={'driver_sha256':sha(DRIVER/'build/AiTweakerLock1904.efi'),'late_stage4_unowned_render_reproduced':True,'synthetic_stale_core_write_reproduced':True,'stale_state_is_robustness_fixture_not_observed_hardware':True}

for label,mode,active,unlocked in [('enabled inactive',1,0,0),('enabled stale unlocked',1,1,1),('unconfigured inactive',0,0,0),('unconfigured stale active',0,1,1),('fault stale active',3,1,1)]:
 v=TestVM();v.owner(0,active,unlocked,mode);token=v.getq(symbols['password_core']+168)
 check(label+': wrapper owner absent',v.call(symbols['platform_session_owned'])==0 and v.call(symbols['platform_can_enter'])==0)
 for i,name in [(1,'Ai'),(2,'Favorites'),(3,'Profile'),(4,'dynamic protected'),(6,'unknown malformed')]:
  for hook,slot in [('render',0x6b928),('page_input',0x6b930)]:
   v.current(i);before=v.calls[hook];result=v.call(v.getq(TSE+slot),v.pages[i],HEAP+0x8000)
   check(label+': '+name+' '+hook+' denied silently',result==0 and v.calls[hook]==before and v.ui_entries==0)
   check(label+': '+name+' '+hook+' redirects to verified Main',v.getd(v.app+0x28)==0)
  v.current(i);before=v.calls['app_input'];result=v.call(v.getq(TSE+0x6b840),v.app,HEAP+0x8000)
  check(label+': '+name+' AppInput denied',result==0 and v.calls['app_input']==before and v.ui_entries==0)
 v.current(1);before=v.calls['poll'];v.call(TSE+0x34b2c)
 check(label+': stage5 poll enforces without wrapper or prompt',v.getd(v.app+0x28)==0 and v.calls['poll']==before+1 and v.ui_entries==0)
 before=v.calls['frame_input'];v.call(TSE+0x15320,v.pages[4]+0x100,HEAP+0x8000)
 check(label+': protected modal frame denied',v.calls['frame_input']==before and v.ui_entries==0)
 v.call(TSE+0x15320,0,HEAP+0x8000)
 check(label+': invalid frame denied',v.calls['frame_input']==before and v.ui_entries==0)
 check(label+': protected native navigation denied',v.nav()==ERR(15) and v.ui_entries==0)
 check(label+': invalid navigation pointers denied',v.nav(valid=False)==ERR(15) and v.ui_entries==0)
 check(label+': safe native navigation retained',v.nav(0x2713)==0 and v.ui_entries==0)
 for i,name in [(0,'Main'),(5,'foreign HII'),(7,'inert Exit')]:
  before=v.calls['render'];v.call(v.getq(TSE+0x6b928),v.pages[i]);check(label+': '+name+' remains usable',v.calls['render']==before+1)
 check(label+': no synthetic session began',v.getd(symbols['loop_depth'])==0 and v.getq(symbols['password_core']+168)==token)
 check(label+': direct actual UI unlock returns denied',v.call(symbols['ensure_unlocked'])==0)
 check(label+': direct actual password management returns denied',v.call(symbols['manage_password'],0)==0 and v.call(symbols['manage_password'],1)==0)
 check(label+': direct UI performed no crypto or persistence',not any(v.core_calls.values()) and not v.set_calls)
 before=v.manage_entries
 check(label+': HII set management denied before UI',v.callback(0xffe0)==ERR(15) and v.manage_entries==before)
 check(label+': HII clear management denied before UI',v.callback(0xffe1)==ERR(15) and v.manage_entries==before)
 check(label+': protected RouteConfig denied',v.route()==ERR(15) and v.original_route_calls==0)
 check(label+': protected variable change denied',v.write(OC,OCGUID,changed)==ERR(15) and not v.set_calls)
 check(label+': identical OC write retained',v.write(OC,OCGUID,bytes(26681))==0 and len(v.set_calls)==1)
 v.set_calls.clear();prior=v.read_calls
 check(label+': private credential persistence denies before service read',v.call(symbols['persist_record'],0,HEAP+0xa000,128)==1 and v.read_calls==prior and not v.set_calls)
 scenarios.append({'case':label,'scope':'real attached UI hooks/HII/storage callbacks with loop_depth0','result':'protected and malformed blocked; no prompt/session; safe UI retained'})

# Known disabled credential intentionally permits normal OC UI/write without a session.
v=TestVM();v.owner(0,0,0,2)
check('explicit disabled without active session is allowed',v.call(symbols['platform_can_enter'])==1)
for slot,method in [(0x6b928,'render'),(0x6b930,'page_input'),(0x6b840,'app_input')]:
 v.current(1);before=v.calls[method];v.call(v.getq(TSE+slot),v.app if method=='app_input' else v.pages[1],HEAP+0x8000)
 check('disabled '+method+' forwards once',v.calls[method]==before+1)
before=v.calls['frame_input'];v.call(TSE+0x15320,v.pages[4]+0x100,HEAP+0x8000)
check('disabled modal frame forwards',v.calls['frame_input']==before+1)
check('disabled native navigation allowed without prompt',v.nav()==0 and v.ui_entries==0)
check('disabled protected route remains allowed',v.route()==0 and v.original_route_calls==1)
check('disabled ordinary boot changed OC write remains allowed',v.write(OC,OCGUID,changed)==0)
check('disabled management still requires owned session',v.callback(0xffe0)==ERR(15) and v.call(symbols['manage_password'],0)==0)
v.owner(0,0,0,2,1);before=v.calls['frame_input'];v.call(TSE+0x15320,v.pages[4]+0x100,HEAP+0x8000)
check('disabled core busy cannot enter protected UI',v.calls['frame_input']==before and v.call(symbols['platform_can_enter'])==0)
v.owner(0,0,0,2);v.u.mem_write(symbols['boot_services_ended'],d(1))
check('EBS disables UI authorization even for disabled mode',v.call(symbols['platform_can_enter'])==0 and v.call(symbols['manage_password'],0)==0)

# HII policy question uses exact generated table, not a guessed ID.
v=TestVM();policy=json.loads((DRIVER/'policy.json').read_text(encoding='utf8'))
qid=next(i for i in range(65536) if v.call(symbols['policy_question'],i))
v.owner(0,1,1);before=v.ui_entries
check('stale grant cannot reach protected HII question callback',v.callback(qid)==ERR(15) and v.ui_entries==before and v.original_hii==0)
v.owner(0,0,0,2)
check('disabled protected HII question forwards without prompt',v.callback(qid)==0 and v.ui_entries==before and v.original_hii==1)

# Wrapper ownership, post-prompt recheck, and malformed state boundaries.
v=TestVM();v.state(1);v.start();v.ui_policy='grant'
check('real wrapper owns active session',v.call(symbols['platform_session_owned'])==1)
check('normal wrapped prompt unlocks native navigation',v.nav()==0 and v.ui_entries==1 and v.unlocked())
check('same owned session second navigation reuses grant without prompt',v.nav()==0 and v.ui_entries==1)
check('same owned session protected HII callback reuses grant without prompt',v.callback(qid)==0 and v.ui_entries==1 and v.original_hii==1)
check('normal wrapped grant permits changed protected write',v.write(OC,OCGUID,changed)==0)
outer=v.body_context;v.call(TSE+0xe1b8)
check('nested wrapper preserves owner and grant',v.call(symbols['platform_session_owned'])==1 and v.unlocked())
v.end(0x11223344);v.body_context=outer
check('nested return retains outer grant without another prompt',v.nav()==0 and v.ui_entries==1 and v.call(symbols['platform_session_owned'])==1)
v.end()
check('outer return ends owner and clears grant',v.call(symbols['platform_session_owned'])==0 and not v.unlocked())
changed[4]=2;check('protected write after outer return denied',v.write(OC,OCGUID,changed)==ERR(15))
for method in ['navigation','frame','poll','callback']:
 v=TestVM();v.state(1);v.start();v.ui_policy='grant_then_lose_owner'
 if method=='navigation':result=v.nav();denied=result==ERR(15)
 elif method=='frame':before=v.calls['frame_input'];v.call(TSE+0x15320,v.pages[4]+0x100,HEAP+0x8000);denied=v.calls['frame_input']==before
 elif method=='poll':v.current(1);v.call(TSE+0x34b2c);denied=v.getd(v.app+0x28)==0
 else:result=v.callback(qid);denied=result==ERR(15) and v.original_hii==0
 check(method+': success result cannot bypass owner loss during prompt',denied and v.ui_entries==1 and v.call(symbols['platform_can_enter'])==0)
v=TestVM();v.owner(17,1,1);check('invalid depth cannot claim ownership',v.call(symbols['platform_session_owned'])==0 and v.nav()==ERR(15) and v.ui_entries==0)

# Actual UI front ends recheck ownership after blocking input. UI device I/O is
# replaced, but core calls must remain absent after the injected owner loss.
for label,fn,clear,mode,drop in [('unlock','ensure_unlocked',None,1,1),('set from unconfigured','manage_password',0,0,2),('clear','manage_password',1,1,1)]:
 v=TestVM();v.owner(1,1,0,mode);v.dialog(drop)
 result=v.call(symbols[fn],*(() if clear is None else (clear,)))
 check('actual '+label+' UI denies owner loss during input',result==0 and v.getd(symbols['loop_depth'])==0)
 check('actual '+label+' UI performs no core update after loss',not any(v.core_calls.values()) and not v.set_calls)

# Credential adapter owner check after the external pre-read, and core-busy
# ownership distinction: legitimate core persistence runs while busy=1.
v=TestVM();v.owner(1,1,0,0,1);v.drop_owner_on_get=True;prior=v.read_calls
check('credential pre-read losing owner blocks original SetVariable',v.call(symbols['persist_record'],0,HEAP+0xa000,128)==1 and v.read_calls==prior+1 and not v.set_calls)
v=TestVM();v.owner(1,1,0,0,1);v.u.mem_write(HEAP+0xa000,bytes(range(128)))
check('legitimate owned core-busy persistence remains possible',v.call(symbols['persist_record'],0,HEAP+0xa000,128)==0 and len(v.set_calls)==1)

# Reuse the actual OEM history/ESC fixture but deliberately remove wrapper
# ownership while retaining active+unlocked to model late/stale context.
history_source=(HERE/'full_regression/verify_history.py').read_text(encoding='utf8').split('\nv=NativeHistoryVM();v.poll()',1)[0]
ctx=json.loads((HERE/'full_regression/build_context.json').read_text(encoding='utf8'))
adapt=lambda s:s.replace("HERE/'build/","CANDIDATE/'build/").replace("HERE/'build'","CANDIDATE/'build'")
hns={'__file__':str(DRIVER/'verify_history.py'),'CANDIDATE':HERE,'CANDIDATE_BUILD_CONTEXT':ctx,'ADAPT_PATHS':adapt}
exec(compile(history_source,str(HERE/'full_regression/verify_history.py'),'exec'),hns)
h=hns['NativeHistoryVM']();h.u.mem_write(symbols['loop_depth'],d(0));h.u.mem_write(symbols['password_core']+201,b'\1')
h.poll();check('unowned stale grant redirects initial protected page to Main with native history',h.getd(h.app+0x28)==1 and h.calls['ui']==0)
h.current(3);h.call(TSE+0x10220,1,3);check('unowned Security history parent is verified Main',h.parent(3)==(0,1))
h.esc(3);check('unowned native Security ESC returns Main',h.getd(h.app+0x28)==1 and h.getd(TSE+0x835b8)==1)
check('unowned history test executed original append/resolve/PageInput/dispatcher',all(h.native_counts[n]>0 for n in h.native_counts))
h2=hns['NativeHistoryVM']();h2.u.mem_write(symbols['loop_depth'],d(0));h2.u.mem_write(TSE+0x835a0,q(0));h2.poll()
check('unowned malformed history ends browser without rendering protected page',h2.u.mem_read(h2.app+0x5a,1)==b'\1' and h2.calls['render']==0 and h2.calls['ui']==0)

# Explicitly retain discovery gaps; the callback fix does not create hooks
# when first discovery sees stage5, and does not retry a failed first attach.
v=TestVM(False);v.u.mem_write(TSE+0x83468,d(5));v.discover()
check('first discovery in stage5 remains unhooked (documented gap)',v.observation()['platform_ready']==0 and v.observation()['attempted']==0)
v=TestVM(False);v.u.mem_write(TSE+0x83468,d(4));v.patch_fail_target=TSE+0x6b928;v.discover();count=len(v.patches);v.patch_fail_target=None;v.discover()
check('first attach failure is still not retried (documented gap)',v.observation()['platform_ready']==0 and v.observation()['attempted']==1 and len(v.patches)==count)

report={'status':'PASS_ISOLATED_LATE_ATTACH_OWNER_CANDIDATE','checks':len(checks),'check_names':checks,'scenarios':scenarios,
 'candidate_driver_sha256':sha(HERE/'build/AiTweakerLock1904.efi'),'source_manifest_sha256':sha(HERE/'source_manifest.json'),
 'source_sha256':manifest['candidate_sources'],'amitse_sha256':sha(CASE/'analysis/modules/AMITSE.efi'),'setup_sha256':sha(CASE/'analysis/modules/Setup.efi'),
 'test_sha256':sha(Path(__file__)),'baseline_defect':baseline,'native_history_counts':h.native_counts,
 'hardware_acceptance_inherited':False,'limits':['Full OEM browser body and firmware services are fixtures. No hardware test, SPI access, BMC call or host execution of EFI.',
 'Accepted passwords in navigation cases are injected; negative ensure/manage UI and ownership checks execute real compiled code. Password crypto retains separate existing evidence.',
 'Synthetic stale AP_CORE state is a robustness test, not an assertion that this state was observed on hardware.',
 'Initial discovery at stage5 and failed-first-attach retry remain unresolved; normal boot protected-write frequency and OEM Save timing remain separate acceptance questions.',
 'No new CAP/ISO/app or firmware deployment was produced.']}
(HERE/'late_attach_regression.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'checks':len(checks),'candidate_driver_sha256':report['candidate_driver_sha256']},indent=2))
