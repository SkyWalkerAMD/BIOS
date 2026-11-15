"""Actual frozen driver callback instructions with registered-address dispatch.

UEFI timers and HII/collector boundaries are mocked; no device is contacted.
The unchanged watchdog code uses the existing full PCI/KCS/NVRAM model.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
NEW=ROOT/'analysis/hero_p6_settings21r_20261108';OLD=ROOT/'analysis/hero_p6_settings21_20261108'
PIN='5adbebb682b957a7877d87918286f7a1cbf297bbf7e2c14d7632c7d1afa3d685'
assert hashlib.sha256((NEW/'HeroIpmiP6.efi').read_bytes()).hexdigest()==PIN
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);x=importlib.util.module_from_spec(spec);spec.loader.exec_module(x);return x
v=load('new_afterboot_model',NEW/'verify_runtime.py');old=load('old_afterboot_model',OLD/'verify_runtime.py')
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
AFTER='8c12a959-70bc-4362-b437-b80514a1916e';SETUP='71202eee-5f53-40d9-ab3d-9e0c26d96657';BEFORE='3677770f-efb2-43b2-b8ae-b302e9604882';READY='7ce88fb3-4bd7-4679-87a8-a8d8dee50d2b'
class ProbeMixin:
 def __init__(self,config=None,**kw):
  self.timer_calls=[];self.boundary=[];self.bind_status=0;self.collect_status=0;self.publish_status=0;self.arm_error=0;self.existing_setup=False
  super().__init__(v.cfg()[:21] if config is None else config,**kw)
  self.boundaries={self.functions[n]:n for n in ('p5_bind','p1_collect','p5_publish')}
  for addr in self.boundaries:self.u.hook_add(UC_HOOK_CODE,self.boundary_hook,begin=addr,end=addr)
 def word(self,name):return int.from_bytes(self.u.mem_read(self.functions[name],4),'little')
 def boundary_hook(self,u,at,size,user):
  name=self.boundaries[at];self.boundary.append(name)
  if name in ('p1_collect','p5_publish'):assert self.word('busy')==1 and self.word('attempted')==1 and self.word('active')==0
  result={'p5_bind':self.bind_status,'p1_collect':self.collect_status,'p5_publish':self.publish_status}[name]
  sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RAX,result);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,self.r64(sp))
 def hook(self,u,at,size,user):
  name=self.stubs.get(at);a,b,c=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8)]
  if name=='P6SetTimer':
   self.timer_calls.append((a,b,c))
   if b==1 and self.arm_error:return self.ret(u,self.arm_error,name)
  if name=='LocateProtocol' and self.existing_setup and self.guid(a)==SETUP:
   self.w64(c,0);return self.ret(u,0,name)
  return super().hook(u,at,size,user)
 def enter(self):
  assert self.call('efi_main',v.IMAGE,self.st)==0 and self.api
  assert len(self.events)==7 and len(self.notifications)==5
 def event(self,guid):
  handle=next((h for g,h in self.notifications if g==guid),None)
  if handle is None:handle=next(h for h,e in self.events.items() if e[3]==guid)
  callback=self.events[handle][2];self.functions['review_registered_callback']=callback
  self.call('review_registered_callback',handle,0)
 def tick(self,n=1):
  handle=next(h for h,e in self.events.items() if e[0]==0x80000200)
  self.functions['review_timer_callback']=self.events[handle][2]
  for _ in range(n):self.call('review_timer_callback',handle,0)
 def count(self,name):return self.boundary.count(name)
 def unchanged_defaults(self):
  assert self.vars=={'HeroIpmiSettings':(3,v.cfg()[:21])} and not self.nv_writes and not self.dev.packets
class Probe(ProbeMixin,v.Machine):pass
class OldProbe(ProbeMixin,old.Machine):pass
rows=[]
def record(name,m):
 rows.append(dict(case=name,passed=True,boundary_calls=m.boundary,timer_calls=m.timer_calls,bmc_model_mutations=len(m.dev.mutations),nv_model_writes=len(m.nv_writes)))

# Counterfactual runs the formerly shipped S21 instructions, not a source model.
m=OldProbe();m.enter();m.event(AFTER);m.tick(25)
assert not m.boundary and not m.timer_calls;m.unchanged_defaults();record('old S21 misses late AfterBoot refresh',m)
m=Probe();m.enter();assert not m.boundary and not m.timer_calls
m.event(AFTER);assert m.word('active')==1 and len(m.timer_calls)==1 and not m.boundary
m.tick();assert m.boundary==['p5_bind','p1_collect','p5_publish']
for _ in range(20):m.event(AFTER);m.event(SETUP);m.tick()
assert m.count('p1_collect')==m.count('p5_publish')==1 and m.word('active')==0;m.unchanged_defaults();record('registered AfterBoot arms once; repeated notifications do not repeat read',m)
m=Probe();m.existing_setup=True;m.enter();assert m.word('active')==1 and not m.boundary
m.event(AFTER);assert len(m.timer_calls)==1;m.tick();assert m.count('p1_collect')==1;m.unchanged_defaults();record('early existing NULL SetupEnter marker still arms; AfterBoot coalesces',m)
m=Probe();m.bind_status=v.ERR(14);m.enter();m.event(AFTER);m.tick(10)
assert m.word('ticks')==10
m.event(AFTER);m.event(SETUP);assert m.word('ticks')==10
m.tick(11);assert m.count('p5_bind')==20 and not m.count('p1_collect') and m.word('active')==0
assert 'P6_NO_MATCHING_NATIVE_RESOURCE' in m.audit()
m.bind_status=0;m.event(AFTER);assert m.word('ticks')==0;m.tick();assert m.count('p1_collect')==1;m.unchanged_defaults();record('twenty bind attempts; active notifications cannot prolong deadline; new real event can rearm',m)
for name,field in [('collect failure','collect_status'),('publish failure','publish_status')]:
 m=Probe();setattr(m,field,v.ERR(7));m.enter();m.event(AFTER);m.tick()
 for _ in range(5):m.event(AFTER);m.event(SETUP);m.tick()
 assert m.count('p1_collect')==m.count('p5_publish')==1 and m.word('attempted')==1;m.unchanged_defaults();record(name+' never causes automatic repeat',m)
m=Probe();m.arm_error=v.ERR(7);m.enter();m.event(AFTER)
assert not m.word('active') and not m.boundary and 'P6_TIMER_ARM_FAILED' in m.audit()
m.arm_error=0;m.event(AFTER);m.tick();assert m.count('p1_collect')==1;m.unchanged_defaults();record('timer arm error does not query; later event can arm',m)
m=Probe();m.enter();m.u.mem_write(m.functions['busy'],struct.pack('<I',1));m.event(AFTER);m.event(SETUP);m.tick()
assert not m.boundary and not m.timer_calls;m.u.mem_write(m.functions['busy'],struct.pack('<I',0));m.event(AFTER);m.tick();assert m.count('p1_collect')==1;m.unchanged_defaults();record('busy notifications do no work and cannot reenter',m)
m=Probe();m.call('on_after',0,0);m.call('on_setup',0,0);m.call('on_timer',0,0)
assert not m.timer_calls and not m.boundary and not m.dev.packets;record('callbacks before resident_ready remain inert',m)
m=Probe(config=v.cfg(enabled=1,minutes=7,action=3)[:21]);m.enter();m.event(READY);m.event(BEFORE)
assert m.dev.sim.wdt[0]&0x40
m.event(AFTER);assert not m.dev.sim.wdt[0]&0x40 and m.word('active')==1
mutations=len(m.dev.mutations);m.tick();m.event(AFTER);assert len(m.dev.mutations)==mutations and m.count('p1_collect')==1;m.no_leak();record('owned watchdog stops first; refresh adds no configuration mutations',m)
changed=[p.name for p in (NEW/'source').iterdir() if p.is_file() and (OLD/'source'/p.name).is_file() and p.read_bytes()!=(OLD/'source'/p.name).read_bytes()]
assert changed==['driver.c'] or set(changed)=={'driver.c'}
for name in ('Setup-forms-P6.bin','native-payload.json'):assert (NEW/'native'/name).read_bytes()==(OLD/'native'/name).read_bytes()
result=dict(passed=True,cases=len(rows),driver_sha256=PIN,ffs_sha256=hashlib.sha256((NEW/'HeroIpmiNativeP6.ffs').read_bytes()).hexdigest(),production_source_changes=changed,settings_journal_policy_and_forms_unchanged=True,results=rows,limits=['Actual driver entry and registered callback addresses exercised with UEFI timer fixtures.','HII bind, read collector and publisher boundaries return configured statuses; their internals are unchanged and not retested here.','The owned-watchdog case uses a synthetic full PCI/KCS/NVRAM model. No real BMC/NV operation.','Real HERO AfterBoot and post-flash early dispatch must be validated separately.'])
(OUT/'callback-delta-tests.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps(dict(passed=True,cases=len(rows),driver_sha256=PIN),indent=2))
