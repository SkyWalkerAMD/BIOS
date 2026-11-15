"""Independent regression of the two review findings on rebuilt P6 machine code.

Imports the device harness, not the firmware implementation. Tests exact AMITSE
notification GUIDs observed in the separate AMITSE replay, and a host-reset gap
after BMC Reset Watchdog acceptance. Real hardware is never accessed.
"""
from pathlib import Path
import copy,hashlib,importlib.util,json,sys
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('p6runtime_review',BASE/'verify_runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
OLD='67c843e1c3c33f5dd27d86fd352d8050880feaeb95f3616ca027c445d2b6932a'

class PowerLoss(Exception):pass

def notify(m,guid):
 matches=[h for g,h in m.notifications if g==guid]
 assert len(matches)==1,(guid,m.notifications)
 m.functions['review_registered_callback']=m.events[matches[0]][2]
 m.call('review_registered_callback',matches[0],0)

def snapshot():
 m=runtime.Machine(runtime.cfg(enabled=1,minutes=1,action=1));m.boot()
 def loss(f,c,p):
  if (f,c)==(6,0x22):
   m.dev.sim.model(f,c,p)
   assert m.dev.sim.wdt[0]&0x40
   raise PowerLoss()
 m.dev.fault=loss
 try:m.call('p6_start_os_watchdog');raise AssertionError('no interruption')
 except PowerLoss:pass
 state=m.vars['HeroIpmiState'][1]
 assert runtime.pending(state) and int.from_bytes(state[16:20],'little')==6
 return copy.deepcopy(m.vars),bytearray(m.dev.sim.wdt)

def main():
 sha=hashlib.sha256((BASE/'HeroIpmiP6.efi').read_bytes()).hexdigest()
 assert sha!=OLD,'This verifier expects the revised driver, not the known-defective PE.'
 out=HERE/('fixed-'+sha[:12]);out.mkdir(exist_ok=True)
 after=json.loads((HERE/'afterboot-lifecycle.json').read_text())
 cases=[]
 for path in after['cases']:
  m=runtime.Machine(runtime.cfg(enabled=1,minutes=1,action=1,erase=2))
  assert m.call('efi_main',runtime.IMAGE,m.st)==0
  m.call('on_ready',0,0)
  for repeat in range(2):
   for i,entry in enumerate(path['publications']):
    notify(m,entry['guid']);assert bool(m.dev.sim.wdt[0]&0x40)==(i==0)
  assert sum(f==10 and c==0x47 and p[-1]==0xaa for f,c,p in m.dev.mutations)==1
  m.no_leak();assert m.vars['HeroIpmiSettings'][1][2]==1
  case=dict(case='registered_afterboot_callback',load_error=path['load_error'],start_error=path['start_error'],boot_manager_guid_sequence=[x['guid'] for x in path['publications']],relaunch_supported=True,erase_once_per_boot=True)
  cases.append(case);(out/('afterboot-'+str(len(cases))+'.txt')).write_text(m.audit())
 vars_,wdt=snapshot()
 for mode in ('match','different_count','different_action','foreign_use','already_stopped'):
  d=runtime.Device();d.sim.wdt=bytearray(wdt)
  if mode=='different_count':d.sim.wdt[4]=d.sim.wdt[4]^1
  if mode=='different_action':d.sim.wdt[1]=2
  if mode=='foreign_use':d.sim.wdt[0]=0x44
  if mode=='already_stopped':d.sim.wdt[0]&=~0x40
  m=runtime.Machine(variables=vars_,device=d)
  assert m.call('p6_seed_settings')==0
  m.call('p6_stop_os_watchdog')
  expected_running=mode not in ('match','already_stopped')
  assert bool(d.sim.wdt[0]&0x40)==expected_running
  state=m.vars['HeroIpmiState'][1]
  assert runtime.pending(state) and int.from_bytes(state[16:20],'little')==6
  assert all(f==6 and c==0x24 for f,c,p in d.mutations)
  assert len(d.mutations)==int(mode=='match')
  packets=len(d.packets)
  m.call('p6_stop_os_watchdog');m.call('p6_apply_settings');m.call('p6_start_os_watchdog')
  assert len(d.packets)==packets,'Recovery or config writes retried without user request'
  m.no_leak()
  cases.append(dict(case='pending_start_recovery',device_state=mode,stopped=not expected_running,mutation_count=len(d.mutations),phase6_blocked_preserved=True,no_automatic_retry=True))
  (out/('pending-'+mode+'.txt')).write_text(m.audit())
 report=dict(passed=True,driver_sha256=sha,cases=cases,source_sha256={str(p.relative_to(BASE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [BASE/'source/settings.c',BASE/'source/driver.c',BASE/'backend/p6_backend.c']},scope='Actual immutable x64 P6 and AMITSE machine code with synthetic UEFI/PCI/KCS/NVRAM. No target hardware.',limits=['Matching watchdog use/action/count is an intent match, not cryptographic or per-program ownership.','Successful finite mocks do not prove BMC timing or native F10 editing on target.'])
 (out/'independent-recovery-review.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
