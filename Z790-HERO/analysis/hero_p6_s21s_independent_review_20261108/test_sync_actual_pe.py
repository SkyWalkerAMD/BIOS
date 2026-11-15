"""Independent S21S callback cases. Actual PE; synthetic UEFI/HII/KCS only.

Reuse frozen S21R fixture class definitions for service ABI and allocations,
but bind its runtime/map/image paths to S21S. Do not run the author's tests.
No network, firmware update, device access or driver source mutation.
"""
from pathlib import Path
import gc,hashlib,json,sys
if not __debug__:raise RuntimeError('Run without -O')
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
NEW=ROOT/'analysis/hero_p6_settings21s_20261108'
OLD=ROOT/'analysis/hero_p6_settings21r_20261108'
PIN='401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66'
assert hashlib.sha256((NEW/'HeroIpmiP6.efi').read_bytes()).hexdigest()==PIN
fixture=OLD/'tests/test_refresh_lifecycle.py'
text=fixture.read_text(encoding='utf8').split('\nrows=[]\n',1)[0]
ns={'__file__':str(NEW/'tests/test_refresh_lifecycle.py'),'__name__':'fixture_definitions_only'}
exec(compile(text,str(fixture),'exec'),ns)
Base=ns['Machine'];v=ns['v'];AFTER=ns['AFTER'];SETUP=ns['SETUP'];READY=ns['READY'];BEFORE=ns['BEFORE']
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8

class Machine(Base):
 def __init__(self,*args,**kwargs):
  self.sync_call=False;self.cancel_error=0;self.fail_get=0;self.fail_set=0;self.get_calls=0;self.set_calls=0
  super().__init__(*args,**kwargs)
 def count_entry(self,u,at,size,name):
  if self.sync_call and name in ('p5_bind','p1_collect','p5_publish'):
   assert self.u32('busy')==1 and self.u32('attempted')==1 and self.u32('active')==0
  super().count_entry(u,at,size,name)
 def hook(self,u,at,size,user):
  name=self.stubs.get(at)
  if name is None:return
  a,b,c=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8)]
  if name=='P6SetTimer' and b==0 and self.cancel_error:
   assert a in self.events and c==0
   self.timer_calls.append((0,0));self.event_order.append('timer_cancel_error')
   return self.ret(u,self.cancel_error,name)
  if name=='HiiGet':
   self.get_calls+=1
   if self.fail_get==self.get_calls:return self.ret(u,v.ERR(7),name)
  if name=='HiiSet':
   self.set_calls+=1
   if self.fail_set==self.set_calls:return self.ret(u,v.ERR(7),name)
  return super().hook(u,at,size,user)
 def after(self):
  self.sync_call=True
  try:self.dispatch(AFTER)
  finally:self.sync_call=False
 def stale_tick(self):
  h=next(h for h,e in self.events.items() if e[0]==0x80000200)
  self.invoke(self.events[h][2],h)
 def inert_repeats(self,allow_watchdog_reads=False):
  old=(self.boundary.copy(),len(self.dev.packets),len(self.hii_sets),list(self.timer_calls))
  for _ in range(3):self.after();self.dispatch(SETUP);self.stale_tick()
  assert self.boundary['p5_bind']==old[0]['p5_bind'] and self.boundary['p1_collect']==old[0]['p1_collect'] and self.boundary['p5_publish']==old[0]['p5_publish']
  assert (len(self.hii_sets),self.timer_calls)==old[2:]
  if allow_watchdog_reads:
   # Existing owned-WDT stop may reopen a read session on later notifications.
   # It must not replay refresh or perform any new configuration mutation.
   assert all((p[0]>>2,p[1]) in ((6,1),(6,0x25)) for p in self.dev.packets[old[1]:])
  else:assert len(self.dev.packets)==old[1]
 def successful_sync(self):
  assert self.boundary['p5_bind']==self.boundary['p1_collect']==self.boundary['p5_publish']==1
  assert len(self.hii_sets)==len(ns['langs'])*41
  assert self.u32('attempted')==1 and self.u32('active')==0 and self.u32('busy')==0
  for tag in ('BIND','READ','PUBLISH'):assert 'P6_AFTER_SYNC_'+tag+'_STATUS=0000000000000000' in self.audit()
  assert self.audit().count('P6_AFTER_SYNC_END')==1

rows=[]
def run(name,fn):
 m=fn()
 rows.append({'name':name,'passed':True,'boundary_calls':m.boundary,'timer_calls':m.timer_calls,'ipmi_requests':len(m.dev.packets),'hii_sets':len(m.hii_sets),'nv_writes':len(m.nv_writes),'bmc_mutations':len(m.dev.mutations)})
 del m;gc.collect();print(name,'PASS',flush=True)
def late():
 m=Machine().start();assert not m.timer_calls and not m.dev.packets
 m.after();m.successful_sync();assert not m.timer_calls
 assert m.event_order[:4]==['p6_stop_os_watchdog','p5_bind','p1_collect','p5_publish']
 m.inert_repeats();m.clean_reads();return m
run('late registered AfterBoot runs full HII/read/publish without timer arm, then never repeats',late)
def pending():
 m=Machine(setup_present=True).start();assert m.timer_active
 m.after();m.successful_sync();assert m.timer_calls==[(1,5000000),(0,0)]
 assert m.event_order[-4:]==['timer_cancel','p5_bind','p1_collect','p5_publish']
 m.inert_repeats();m.clean_reads();return m
run('pending early timer is cancelled before synchronous bind; queued callback is inert',pending)
def completed():
 m=Machine(setup_present=True).start();m.tick();m.good_refresh()
 before=(m.boundary.copy(),len(m.dev.packets),len(m.hii_sets));m.after()
 assert m.boundary['p5_bind']==before[0]['p5_bind'] and m.boundary['p1_collect']==before[0]['p1_collect'] and m.boundary['p5_publish']==before[0]['p5_publish']
 assert (len(m.dev.packets),len(m.hii_sets))==before[1:]
 assert 'P6_AFTER_SYNC_BIND_BEGIN' not in m.audit()
 m.inert_repeats();m.clean_reads();return m
run('completed early Setup refresh is not repeated by later AfterBoot',completed)
def bind_failure(kind):
 m=Machine().start()
 if kind=='missing':m.hii_available=False
 elif kind=='forms':m.bad_package=True
 else:m.fail_get=1
 m.after();assert m.boundary['p5_bind']==1 and not m.boundary['p1_collect'] and not m.boundary['p5_publish'] and not m.dev.packets
 assert m.u32('attempted')==1 and not m.u32('busy')
 m.hii_available=True;m.bad_package=False;m.fail_get=0;m.inert_repeats();m.clean_reads();return m
for kind in ('missing','forms','get'):run('bind '+kind+' failure is terminal before KCS and publication',lambda kind=kind:bind_failure(kind))
def read_failure(case):
 m=Machine(case=case).start();m.after()
 assert m.boundary['p1_collect']==1 and not m.boundary['p5_publish'] and not m.hii_sets
 assert 'P6_AFTER_SYNC_READ_STATUS=800000000000000' in m.audit()
 m.inert_repeats();m.clean_reads();return m
for case in ('wrong_board','identity_mismatch','startup_ff'):run('read '+case+' failure cannot publish or retry',lambda case=case:read_failure(case))
def publish_failure():
 m=Machine().start();m.fail_set=17;m.after()
 assert m.boundary['p5_publish']==1 and len(m.hii_sets)==16 and 'P6_AFTER_SYNC_PUBLISH_STATUS=8000000000000007' in m.audit()
 m.inert_repeats();m.clean_reads();return m
run('mid-publication error keeps partial strings but never retries or writes BMC settings',publish_failure)
def cancel_failure():
 m=Machine(setup_present=True).start();m.cancel_error=v.ERR(7);m.after()
 assert m.timer_active and m.u32('active')==0 and m.u32('attempted')==1 and not m.u32('busy')
 assert not m.boundary['p5_bind'] and not m.dev.packets and not m.hii_sets
 m.inert_repeats();m.clean_reads();return m
run('cancel failure stops before bind; possibly queued timer cannot run core',cancel_failure)
def busy():
 m=Machine().start();m.put32('busy',1)
 for guid in (AFTER,SETUP,READY,BEFORE):m.dispatch(guid)
 m.stale_tick();assert not any(m.boundary.values()) and not m.timer_calls and not m.dev.packets
 m.put32('busy',0);m.after();m.successful_sync();m.clean_reads();return m
run('busy guard blocks every relevant callback before any work',busy)
def failed_install():
 m=Machine(entry_fault='install');assert m.call('efi_main',v.IMAGE,m.st)&v.ERR(0)
 m.after();m.dispatch(SETUP);m.stale_tick()
 assert not any(m.boundary.values()) and not m.timer_calls and not m.dev.packets
 assert set(m.events)==set(m.closed);m.clean_reads();return m
run('failed resident install leaves all callbacks inert and closes owned events',failed_install)
def watchdog():
 m=Machine(v.cfg(enabled=1,minutes=7,action=3)[:21]).start();m.dispatch(READY);m.dispatch(BEFORE)
 assert m.dev.sim.wdt[0]&0x40;mutations=len(m.dev.mutations);m.event_order.clear()
 m.after();m.successful_sync();assert not m.dev.sim.wdt[0]&0x40
 assert len(m.dev.mutations)==mutations+1 and m.dev.mutations[-1][:2]==(6,0x24)
 assert m.event_order[:4]==['p6_stop_os_watchdog','p5_bind','p1_collect','p5_publish']
 m.inert_repeats(allow_watchdog_reads=True);assert len(m.dev.mutations)==mutations+1;m.no_leak();return m
run('existing owned-watchdog stop remains before synchronous query and does not restart it',watchdog)
def foreign():
 m=Machine(v.cfg(enabled=1)[:21]).start();m.dev.sim.wdt[0]=0x44;m.dispatch(READY);m.after()
 assert m.dev.sim.wdt[0]==0x44 and not m.dev.mutations;m.no_leak();return m
run('foreign running watchdog is untouched by synchronous refresh',foreign)

changed=[]
for path in (NEW/'source').rglob('*'):
 if path.is_file():
  rel=path.relative_to(NEW/'source');assert (OLD/'source'/rel).is_file()
  if path.read_bytes()!=(OLD/'source'/rel).read_bytes():changed.append(str(rel))
assert changed==['driver.c']
for name in ('Setup-forms-P6.bin','native-payload.json'):assert (NEW/'native'/name).read_bytes()==(OLD/'native'/name).read_bytes()
report={'passed':True,'cases':len(rows),'pe_sha256':PIN,'ffs_sha256':hashlib.sha256((NEW/'HeroIpmiNativeP6.ffs').read_bytes()).hexdigest(),'fixture_source':str(fixture.relative_to(ROOT)),'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'changed_production_sources':changed,'forms_unchanged':True,'results':rows,'limits':['Actual x64 entry/registered callbacks/collector/publisher/settings run against simulated UEFI/HII/KCS services, not hardware.','No low-TPL fallback, timer deadline, or mock can prove real AMITSE reentry safety; S21S remains a separate RAM diagnostic candidate.','Original early SetupEnter timer path is intentionally unchanged, including its existing retry and read-error publication behavior.','The default21 settings cases have no BMC mutation/NV write. The owned-watchdog regression intentionally models its existing configured stop command.']}
(OUT/'sync-callback-independent.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'passed':True,'cases':len(rows),'pe_sha256':PIN}))
