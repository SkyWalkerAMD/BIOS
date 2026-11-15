"""Exact S22 registered callbacks and real HII/KCS instructions, mocked services."""
from pathlib import Path
import gc,hashlib,json,struct
HERE=Path(__file__).resolve().parents[1];ROOT=HERE.parents[1]
prior=ROOT/'analysis/hero_p6_settings21r_20261108/tests/test_refresh_lifecycle.py'
ns={'__file__':str(__file__),'__name__':'s21s_fixture_definitions'}
exec(compile(prior.read_text().split('\nrows=[]')[0],str(prior),'exec'),ns)
Fixture=ns['Machine'];v=ns['v'];AFTER=ns['AFTER'];SETUP=ns['SETUP'];READY=ns['READY'];BEFORE=ns['BEFORE'];unicorn=ns['unicorn']
from unicorn.x86_const import *
class Machine(Fixture):
 def __init__(self,*a,**kw):
  super().__init__(*a,**kw);self.cancel_error=0;self.set_error=0
 def hook(self,u,at,size,ctx):
  name=self.stubs.get(at)
  if name=='P6SetTimer' and u.reg_read(UC_X86_REG_RDX)==0 and self.cancel_error:
   self.timer_calls.append((0,0));self.event_order.append('cancel_error');return self.ret(u,self.cancel_error,name)
  if name=='HiiSet' and self.set_error:return self.ret(u,self.set_error,name)
  return super().hook(u,at,size,ctx)
 def good_sync(self):
  assert self.boundary['p5_bind']==self.boundary['p1_collect']==self.boundary['p5_publish']==1,self.boundary
  assert self.u32('attempted')==1 and self.u32('active')==self.u32('busy')==0
  assert len(self.hii_sets)==410 and not self.pools
  for key in ('BIND','READ','PUBLISH'):assert f'P6_AFTER_SYNC_{key}_STATUS=0000000000000000' in self.audit()
  assert self.audit().count('P6_AFTER_SYNC_END')==1
 def repeat(self):
  for _ in range(5):self.dispatch(AFTER);self.dispatch(SETUP)
  # Explicitly simulate a queued stale timer delivery at the actual registered address.
  h=next(h for h,e in self.events.items() if e[0]==0x80000200);self.invoke(self.events[h][2],h)
rows=[]
def run(name,fn):fn();rows.append(name);print(name,'PASS',flush=True);gc.collect()
def late():
 m=Machine().start();assert not m.dev.packets and not m.timer_calls;m.dispatch(AFTER);m.good_sync();m.clean_reads()
 assert m.event_order==['p6_stop_os_watchdog','p5_bind','p1_collect','p5_publish'] and not m.timer_calls
 (HERE/'tests/OFFLINE-S22-AFTERBOOT.txt').write_bytes(b'OFFLINE / SYNTHETIC UEFI AND BMC\n'+m.audit().encode())
run('genuine registered AfterBoot synchronously runs exact bind/read/publish without timer arm',late)
def repeat():
 m=Machine().start();m.dispatch(AFTER);packets=len(m.dev.packets);m.repeat();m.good_sync();m.clean_reads();assert len(m.dev.packets)==packets and not m.timer_calls
run('repeated AfterBoot SetupEnter and queued timer cannot replay sync refresh',repeat)
def early():
 m=Machine(setup_present=True).start();assert m.timer_calls==[(1,5000000)];m.tick();m.good_refresh();m.clean_reads();n=len(m.dev.packets);m.dispatch(AFTER);assert len(m.dev.packets)==n
run('existing early SetupEnter timer path and completed-refresh suppression unchanged',early)
def active():
 m=Machine(setup_present=True).start();m.hii_available=False;m.tick(7);m.hii_available=True;m.dispatch(AFTER)
 assert m.timer_calls==[(1,5000000),(0,0)] and not m.timer_active and m.boundary['p5_bind']==8
 assert m.boundary['p1_collect']==m.boundary['p5_publish']==1;m.repeat();assert m.boundary['p5_bind']==8;m.clean_reads()
run('AfterBoot takes pending timer over by cancellation and sync query once',active)
def cancel_error():
 m=Machine(setup_present=True).start();m.cancel_error=v.ERR(7);m.dispatch(AFTER)
 assert m.u32('active')==0 and m.u32('attempted')==1 and m.u32('busy')==0
 m.repeat();assert not m.dev.packets and m.boundary['p5_bind']==0 and m.timer_calls==[(1,5000000),(0,0)];m.clean_reads()
run('timer cancel failure consumes attempt with no bind or read and queued callback inert',cancel_error)
def bind_error(bad):
 m=Machine().start();m.bad_package=bad;m.hii_available=bad;m.dispatch(AFTER);m.bad_package=False;m.hii_available=True;m.repeat()
 assert m.boundary['p5_bind']==1 and m.boundary['p1_collect']==m.boundary['p5_publish']==0 and not m.timer_calls and not m.dev.packets
 assert m.u32('busy')==0 and m.u32('attempted')==1;m.clean_reads()
run('missing native HII resource consumes synchronous attempt without retry',lambda:bind_error(False))
run('wrong exact native forms consumes synchronous attempt without retry',lambda:bind_error(True))
def read_error(case):
 m=Machine(case=case).start();m.dispatch(AFTER);m.repeat()
 assert m.boundary['p1_collect']==1 and m.boundary['p5_publish']==0 and not m.hii_sets and m.u32('busy')==0 and not m.timer_calls
 if case!='restore_failure':m.clean_reads()
for case in ('wrong_board','wrong_location','startup_busy','restore_failure'):run('read failure blocks publish and replay '+case,lambda case=case:read_error(case))
def publish_error():
 m=Machine().start();m.set_error=v.ERR(7);m.dispatch(AFTER);m.set_error=0;m.repeat()
 assert m.boundary['p5_publish']==1 and not m.hii_sets and m.u32('busy')==0 and not m.timer_calls;m.clean_reads()
run('publish failure consumes one attempt and restores busy state',publish_error)
def timeout():
 m=Machine(setup_present=True).start();m.hii_available=False;m.tick(21)
 assert m.boundary['p5_bind']==20 and not m.u32('active') and not m.u32('attempted')
 m.hii_available=True;m.dispatch(AFTER);assert m.boundary['p5_bind']==21 and m.boundary['p1_collect']==m.boundary['p5_publish']==1;m.clean_reads()
run('original SetupEnter 20-bind timeout unchanged and later genuine AfterBoot may try once',timeout)
def busy():
 m=Machine().start();m.put32('busy',1);m.dispatch(AFTER);assert not m.dev.packets and not m.timer_calls and not m.boundary['p5_bind'];m.put32('busy',0);m.dispatch(AFTER);m.good_sync();m.clean_reads()
run('busy callback guard prevents reentrancy without consuming later legitimate attempt',busy)
def notready():
 m=Machine(entry_fault='install');assert m.call('efi_main',v.IMAGE,m.st)&v.ERR(0);m.dispatch(AFTER)
 assert not m.dev.packets and not m.timer_calls and not m.boundary['p5_bind'] and set(m.events)==set(m.closed)
run('not resident ready cannot query after failed entry cleanup',notready)
def watchdog():
 m=Machine(v.cfg(enabled=1,minutes=7,action=3)[:21]).start();m.dispatch(READY);m.dispatch(BEFORE);assert m.dev.sim.wdt[0]&0x40
 old=len(m.dev.mutations);m.event_order.clear();m.dispatch(AFTER);m.good_sync();m.no_leak()
 assert len(m.dev.mutations)==old+1 and m.dev.mutations[-1][:2]==(6,0x24) and m.event_order[0]=='p6_stop_os_watchdog' and not m.dev.sim.wdt[0]&0x40
 m.repeat();assert len(m.dev.mutations)==old+1
run('owned watchdog stop remains first and synchronous reads add no configuration writes',watchdog)
def foreign():
 m=Machine(v.cfg(enabled=1)[:21]).start();m.dev.sim.wdt[0]=0x44;m.dispatch(READY);m.dispatch(AFTER);m.good_sync();m.no_leak();assert m.dev.sim.wdt[0]==0x44 and not m.dev.mutations
run('foreign running watchdog ownership unchanged',foreign)
report={'passed':True,'cases':len(rows),'results':rows,'driver_sha256':hashlib.sha256((HERE/'HeroIpmiP6.efi').read_bytes()).hexdigest(),'scope':'Actual PE entry/registered callbacks/HII bind/KCS/read/publication; synthetic UEFI and BMC only.','changed_from_S21S':['source/transport.c','source/hero_bmc_pci.h','source/driver.c log title only'],'limits':['Callback invocation models real notification addresses and TPL metadata, not the complete AMITSE call stack.','No real target or CAP tested. Early SetupEnter timer remains independently unvalidated on hardware.']}
(HERE/'tests/sync-lifecycle-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
