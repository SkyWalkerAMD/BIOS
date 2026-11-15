"""Execute both original native exit reset decision blocks; no proposed patch."""
from pathlib import Path
import json
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_guard.py').read_text().split('\nv=GateVM();check(',1)[0]
exec(compile(prefix,str(HERE/'verify_guard.py'),'exec'),globals())
RESET=STOP+0x4000;UNINSTALL=STOP+0x4010
class ExitVM(GateVM):
 def __init__(self):
  super().__init__();self.reset_calls=0;self.done=False
  self.u.mem_write(self.rt+0x68,q(RESET));self.u.mem_write(self.bs+0x150,q(UNINSTALL))
  for a in [RESET,UNINSTALL,TSE+0x122c,TSE+0x5a68,TSE+0xe61e,TSE+0x21415]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
 def hook(self,u,a,n,data):
  if a==RESET:self.reset_calls+=1;u.emu_stop();return
  if a==UNINSTALL:self.ret(0);return
  if a==TSE+0x122c:self.ret(self.arg(0));return # GUI teardown is not emulated
  if a==TSE+0x5a68 and self.arg(0)==0xffff001e:self.ret(0);return # reset notifications explicit fixture
  if a in [TSE+0xe61e,TSE+0x21415]:self.done=True;u.emu_stop();return
  super().hook(u,a,n,data)
 def run_exit(self,start,pending,outer,error):
  sp=STACK+0x200000;self.u.reg_write(R.UC_X86_REG_RSP,sp);self.u.reg_write(R.UC_X86_REG_RBP,sp+0x100)
  self.u.reg_write(R.UC_X86_REG_R14,0);self.u.reg_write(R.UC_X86_REG_RDI,error);self.u.reg_write(R.UC_X86_REG_RBX,error)
  self.u.mem_write(TSE+0x83580,bytes([pending]));self.u.mem_write(TSE+0x93028,q(outer));self.u.mem_write(TSE+0x93038,q(outer))
  if outer:self.u.mem_write(outer+0x191,q(0))
  self.u.emu_start(TSE+start,0,count=1000000)
  assert self.reset_calls or self.done,(hex(start),pending,hex(outer),hex(self.u.reg_read(R.UC_X86_REG_RIP)))
rows=[];checks=[]
for block,start in [('browser_cleanup',0xe52d),('SendForm_parent_cleanup',0x213b5)]:
 for pending,outer in [(0,0),(1,0),(1,HEAP+0x240000)]:
  for result in [0,ERR(15),ERR(21)]:
   v=ExitVM();v.run_exit(start,pending,outer,result);expected=int(pending==1 and outer==0)
   check(f'{block} pending={pending} outer={bool(outer)} result={result:x}',v.reset_calls==expected)
   rows.append({'block':block,'pending_reset':pending,'native_parent_pointer_present':bool(outer),'browser_result':hex(result),'actual_ResetSystem_reached':bool(v.reset_calls)})
r={'status':'CONFIRMED_TWO_LAYER_RESET_COUNTEREXAMPLE_NOT_SAFE_EXIT_ACCEPTANCE','checks':len(checks),'cases':rows,'original_amitse_sha256':manifest['modules']['AMITSE']['original_sha256'],'tested_amitse_sha256':manifest['modules']['AMITSE']['sha256'],'test_source_sha256':sha(Path(__file__)),'finding':'Skipping browser E5D5/E5E9 alone is insufficient. SendForm 213B5 independently reaches ResetSystem21412 when pending-reset83580 is nonzero and parent chain93038 is null; browser return EFI_ACCESS_DENIED/EFI_ABORTED is ignored by that decision.','native_ranges_unchanged':['e52d:e632','213b5:21415'],'fixtures':['BootServices UninstallMultipleProtocolInterfaces and native GUI teardown122c are explicit success fixtures.','Original hook dispatcher5a68 executes original exit0xffff002b table. Reset notification0xffff001e callbacks are success fixtures; no claim their real side effects are absent.'],'limits':['Full BootManager/SendForm cleanup and arbitrary callback side effects are not accepted.','No exit patch, forced app+5a, CAP, reset, or physical device action was performed.'],'next_required':'Choose and independently prove a selective early refusal or explicit two-caller non-reset unwind; do not equate a single skipped reset call with safety.'}
(HERE/'build/exit_counterexample.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks)}))
