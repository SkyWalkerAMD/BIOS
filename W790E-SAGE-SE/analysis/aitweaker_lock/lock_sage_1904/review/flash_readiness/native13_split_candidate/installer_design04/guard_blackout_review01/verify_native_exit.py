"""Actual original exit/reset and ActionRequest fragments; explicit services.

This is a bounded counterexample. It is not a safe-exit implementation or a
physical GUI test. Never rewrites the frozen TX05/N13 reports.
"""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CORE=HERE.parent/'split_core'
sys.path.insert(0,str(CORE));from verify_split import make_namespace
ns=make_namespace();V=ns['GateVM'];U,R=ns['U'],ns['R']
TSE,HEAP,STACK,STOP=[ns[x]for x in ['TSE','HEAP','STACK','STOP']]
q=ns['q'];ERR=ns['ERR'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
RESET=STOP+0x4000;UNINSTALL=STOP+0x4010
class ExitVM(V):
 def __init__(self):
  super().__init__();self.reset_calls=0;self.done=False;self.callbacks=[]
  self.u.mem_write(self.rt+0x68,q(RESET));self.u.mem_write(self.bs+0x150,q(UNINSTALL))
  for a in [RESET,UNINSTALL,TSE+0x122c,TSE+0x5a68,TSE+0xe61e,TSE+0x21415]:
   self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
 def hook(self,u,a,n,data):
  if a==RESET:self.reset_calls+=1;u.emu_stop();return
  if a==UNINSTALL:self.callbacks.append('UninstallMultipleProtocolInterfaces_model');self.ret(0);return
  if a==TSE+0x122c:self.callbacks.append('native_gui_teardown122c_model');self.ret(self.arg(0));return
  if a==TSE+0x5a68 and self.arg(0)==0xffff001e:
   self.callbacks.append('reset_notification_model');self.ret(0);return
  if a in [TSE+0xe61e,TSE+0x21415]:self.done=True;u.emu_stop();return
  super().hook(u,a,n,data)
 def run_exit(self,start,pending,external,parent,error):
  sp=STACK+0x200000;self.u.reg_write(R.UC_X86_REG_RSP,sp);self.u.reg_write(R.UC_X86_REG_RBP,sp+0x100)
  self.u.reg_write(R.UC_X86_REG_R14,0);self.u.reg_write(R.UC_X86_REG_RDI,error);self.u.reg_write(R.UC_X86_REG_RBX,error)
  self.u.mem_write(TSE+0x83580,bytes([pending]));self.u.mem_write(TSE+0x93028,q(external));self.u.mem_write(TSE+0x93038,q(parent))
  if parent:self.u.mem_write(parent+0x191,q(0))
  self.u.emu_start(TSE+start,0,count=1000000)
  assert self.reset_calls or self.done,(hex(start),pending,external,parent,hex(self.u.reg_read(R.UC_X86_REG_RIP)))
checks=[];rows=[]
def check(label,ok):assert ok,label;checks.append(label)
# Include independent external/parent values; equal pointers hide the second
# layer reset counterexample important to the external-SendForm proposal.
for block,start in [('browser_cleanup',0xe52d),('SendForm_parent_cleanup',0x213b5)]:
 for pending,external,parent in [(0,0,0),(1,0,0),(1,HEAP+0x230000,0),(1,HEAP+0x230000,HEAP+0x240000)]:
  for result in [0,ERR(15),ERR(21)]:
   v=ExitVM();v.run_exit(start,pending,external,parent,result)
   expected=int(bool(pending)and (external==0 if start==0xe52d else parent==0))
   label=f'{block} pending={pending} external={bool(external)} parent={bool(parent)} result={result:x}'
   check(label,v.reset_calls==expected)
   rows.append({'block':block,'pending':pending,'external_nonzero':bool(external),'parent_nonzero':bool(parent),'browser_result':hex(result),'reset_target_reached':bool(v.reset_calls),'service_models_called':v.callbacks})
# Run only the original ActionRequest epilogue, stopping before the next native
# helper. Inputs are controlled to show what the documented OUT parameter does.
action_rows=[]
for flag,initial,nonnull in [(0,0,True),(0,0xffffffffffffffff,True),(1,0,True),(1,0xffffffffffffffff,True),(0,7,False),(1,7,False)]:
 v=V();out=HEAP+0x220000;sp=STACK+0x200000;v.u.reg_write(R.UC_X86_REG_RSP,sp);v.u.reg_write(R.UC_X86_REG_RBP,sp+0x100);v.u.reg_write(R.UC_X86_REG_R14,0)
 v.u.mem_write(sp+0x160,q(out if nonnull else 0));v.u.mem_write(out,q(initial));v.u.mem_write(TSE+0x83678,bytes([flag]));stops=[]
 def stop(u,a,n,d):stops.append(a);u.emu_stop()
 h=v.u.hook_add(U.UC_HOOK_CODE,stop,begin=TSE+0x21435,end=TSE+0x21435)
 v.u.emu_start(TSE+0x21415,0,count=100);v.u.hook_del(h)
 actual=v.getq(out);expected=1 if flag and nonnull else initial
 check(f'ActionRequest reset_flag={flag} initial={initial:x} pointer={nonnull}',actual==expected and stops==[TSE+0x21435] and v.u.mem_read(TSE+0x83678,1)==b'\0')
 action_rows.append({'reset_action_flag':flag,'initial':hex(initial),'nonnull':nonnull,'actual_after':hex(actual),'initial_sentinel_remains_on_normal_path':flag==0 and actual==initial})
report={'status':'CONFIRMED_TWO_LAYER_RESET_AND_ACTION_REQUEST_OUT_CONTRACT','checks':len(checks),'check_names':checks,'exit_cases':rows,'action_request_cases':action_rows,'original_sha256':sha(HERE.parent.parent/'boot_context/AMITSE.original.efi'),'frozen_split_build_sha256':sha(CORE/'build/split_build.json'),'test_source_sha256':sha(Path(__file__)),'findings':['An external SendForm marker93028 does not by itself prevent later parent cleanup ResetSystem when83580 is set and93038 is null. ACCESS_DENIED/ABORTED return values do not prevent either reset decision.','The native ActionRequest fragment writes1 only when83678 is set. With83678==0 it leaves the output untouched; a caller must initialize NONE if it expects0 on ordinary return. This does not explain lack of a return/black screen.'],'limits':['Original decision instructions execute against explicitly synthetic globals. This does not prove physical pending-reset or parent state.','UninstallMultipleProtocolInterfaces, GUI teardown122c and reset-notification callbacks are success models. ResetSystem is only a stopped target observation, never executed. Full cleanup and its arbitrary callbacks are unproven.','No safe-exit implementation, authorization change, firmware change, device or NVRAM operation.']}
(HERE/'native_exit_counterexample.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'report_sha256':sha(HERE/'native_exit_counterexample.json')}))
