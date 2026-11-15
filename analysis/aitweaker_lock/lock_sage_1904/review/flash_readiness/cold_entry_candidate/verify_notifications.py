"""Replay bounded original Core notification/loader code, not an ASUS boot."""
from pathlib import Path
import json, hashlib
HERE=Path(__file__).resolve().parent
helper=HERE/'verify_cold_entry.py'
ns={'__file__':str(helper)}
exec(compile(helper.read_text(encoding='utf8').split('\nv=CoreVM(); order=v.before()',1)[0],str(helper),'exec'),ns)
for k in ['CoreVM','U','R','CB','CH','CS','CE','Q','D','CORE','sha','check','checks']:globals()[k]=ns[k]

class NotifyVM(CoreVM):
 def __init__(self):
  super().__init__();self.events=[]
  self.u.mem_write(CB+0x16b30,Q(16))
  self.u.mem_write(CB+0x17b10,Q(1<<8))
  head=CB+0x1f340+8*16;event=CH+0x9000
  self.init_list(head,[event+0x48])
  self.u.mem_write(event+8,D(0x200)+D(1))
  self.u.mem_write(event+0x28,Q(CE+0x200)+Q(0x1234))
  for a in [CB+0xcbfc,CE+0x200]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
 def hook(self,u,a,n,data):
  if a==CB+0xcc98:return # execute original RestoreTPL, including its recursion
  if a==CB+0xe6ec:
   # Lock/interrupt primitive fixture. Event dispatch and comparisons are native.
   u.mem_write(self.arg(0)+8,Q(self.getq(CB+0x16b30)))
   u.mem_write(CB+0x16b30,Q(16));self.ret(0);return
  if a==CB+0xcbfc:self.ret(0);return # never change host interrupt state
  if a==CE+0x200:
   self.events.append({'notify_tpl':self.getq(CB+0x16b30),'event':hex(self.arg(0)),'context':hex(self.arg(1))})
   self.ret(0);return
  super().hook(u,a,n,data)

results=[]
for target in [4,8,16]:
 v=NotifyVM();v.call(0xcc98,target)
 check('original RestoreTPL('+str(target)+') dispatches iff callback TPL is strictly higher',len(v.events)==(1 if target==4 else 0))
 check('original RestoreTPL('+str(target)+') returns at requested TPL',v.getq(CB+0x16b30)==target)
 if target==4:
  check('original native notification executes at TPL8',v.events[0]['notify_tpl']==8)
  check('native event dequeued and pending mask cleared',v.getq(CB+0x17b10)==0)
 else:
  check('notification remains pending without lowering below TPL8',v.getq(CB+0x17b10)==1<<8)
  v.call(0xcc98,4);check('later lowering to TPL4 delivers pending notification',len(v.events)==1)
 results.append({'initial_target_tpl':target,'events':v.events,'return_tpl':v.getq(CB+0x16b30)})

class LoaderVM(CoreVM):
 def __init__(self):
  super().__init__();self.events=[];self.loaded=False
  self.image=CH+0x3000;self.frame=CH+0x4000
  self.u.mem_write(self.image+0x150,D(3))
  self.u.reg_write(R.UC_X86_REG_RBX,self.image)
  self.u.reg_write(R.UC_X86_REG_RBP,self.frame)
  self.u.reg_write(R.UC_X86_REG_R12,self.image+0x28)
  self.u.reg_write(R.UC_X86_REG_R15,self.image+8)
  for a in [0x48b4,0x7ae0,0xadf0,0x90bc,0x8527]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=CB+a,end=CB+a)
 def hook(self,u,a,n,data):
  if a==CB+0x48b4:
   self.events.append({'operation':'install LoadedImage','notify_flag':self.arg(4)&255,'loader_completed':self.loaded})
   u.mem_write(self.arg(0),Q(0x123400));self.ret(0);return
  if a==CB+0x7ae0:
   self.events.append({'operation':'load/relocate image helper'});self.loaded=True;self.ret(0);return
  if a==CB+0xadf0:self.ret(0);return
  if a==CB+0x90bc:
   self.events.append({'operation':'reinstall LoadedImage','loader_completed':self.loaded,'old_and_new_interface_same':self.arg(2)==self.arg(3)})
   self.ret(0);return
  if a==CB+0x8527:u.emu_stop();return
  super().hook(u,a,n,data)
 def run(self):
  sp=CS+0xfe08;self.u.mem_write(sp,Q(CE)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
  self.u.emu_start(CB+0x84a6,0,count=100000)
  assert self.u.reg_read(R.UC_X86_REG_RIP)==CB+0x8527

v=LoaderVM();v.run()
check('original Core initial LoadedImage installation suppresses notification',v.events[0]['notify_flag']==0 and not v.events[0]['loader_completed'])
check('original Core reinstitutes LoadedImage only after loader helper returns',v.events[2]['loader_completed'] and v.events[2]['old_and_new_interface_same'])
check('no native StartImage in replayed load block',not any('StartImage' in x for x in v.events))

report={'status':'PASS_BOUNDED_ORIGINAL_CORE_NOTIFICATION_PATHS','checks':len(checks),'check_names':checks,
 'original_core_sha256':sha(CORE),'verification_source_sha256':sha(Path(__file__)), 'fixture_helper_sha256':sha(helper),
 'RestoreTPL_cases':results,'LoadedImage_sequence':v.events,
 'limits':['Image loading/protocol installation and lock/interrupt primitives are explicit fixtures; core dispatch/list/TPL comparisons and call order execute original instructions.',
 'An installed notify at TPL8 executes before return from a lowering-to-TPL4 Core service. An arbitrary runtime caller TPL is not inferred from this test.',
 'LoadedImage means relocated bytes can be visible before driver entry. It does not establish Setup HII readiness or completion of AMITSE initialization.',
 'No physical cold boot, no protected renderer run to completion, no new driver/firmware output, no BMC or flash write.']}
(HERE/'notification_replay.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'checks':len(checks),'sha256':sha(HERE/'notification_replay.json')}))
