"""Actual inline guard fault wait/retry path, separate from normal GUI evidence."""
from pathlib import Path
import json,hashlib,time
import verify_tail as t
from unicorn.x86_const import *
H=Path(__file__).resolve().parent;O=H/'build';Q=t.Q;TSE=t.TSE;OS=t.OS
SOURCE_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
TAIL_SOURCE_SHA=hashlib.sha256((H/'verify_tail.py').read_bytes()).hexdigest()
class VM(t.VM):
 def __init__(self):
  super().__init__();self.repair_on_wait=0
 def hook(self,u,address,size,opaque):
  if hasattr(self,'wait_hook')and address==self.wait_hook and self.repair_on_wait==self.waits+1:
   # Explicit external fixture change while blocked: the original input
   # object's exact original vtable returns. No owner bit is supplied.
   self.w(self.native_input,Q(TSE+0x93dc0))
  return super().hook(u,address,size,opaque)
def main():
 cases=[]
 def retry():
  v=VM();v.ready_full();v.live_fault_wait=True;v.repair_on_wait=2;v.queue('xR')
  v.tail(setup=lambda w:w.w(w.native_input,Q(TSE+0x93de0)))
  assert len(v.faults)==2 and len(v.resumes)==1 and v.waits==2 and not v.terminal,(len(v.faults),len(v.resumes),v.waits,v.terminal)
  assert v.run('n07_last_reason')==1 and v.r(v.app+0x5a,1)==b'\0'
  assert 'Press R to retry validation'in v.transcript and not v.set_count
 def ended():
  v=VM();v.ready_full();v.live_fault_wait=True;v.queue('R');v.end_at_wait=1
  try:v.tail(setup=lambda w:w.w(w.native_input,Q(TSE+0x93de0)))
  except AssertionError as e:assert v.terminal and v.u.reg_read(UC_X86_REG_RIP)==OS['n05_recovery_terminal'],e
  else:raise AssertionError('ended services escaped terminal boundary')
  assert len(v.faults)==1 and not v.resumes and v.waits==1 and not v.efi_after_end and v.r(v.app+0x5a,1)==b'\x01' and not v.set_count
 for name,fn in [('inline fault waits on ordinary key then R reruns real private proof and cancels',retry),('EBS during actual inline wait stops every later UEFI call and native continuation',ended)]:
  start=time.time();fn();cases.append({'name':name,'status':'PASS','seconds':round(time.time()-start,3)});print(name,flush=True)
 assert hashlib.sha256((H/'verify_tail.py').read_bytes()).hexdigest()==TAIL_SOURCE_SHA
 report={'component_sha256':t.SHA,'source_sha256':SOURCE_SHA,'tail_fixture_sha256':TAIL_SOURCE_SHA,'checks':len(cases),'cases':cases,'boundary':'Original input object change during modeled WaitForEvent is explicit. Retry executes the real new assembly and observer, no owner flag. HLT terminal is intercepted before host CPU halt. No full native GUI claim.'}
 (O/'retry_tests.json').write_text(json.dumps(report,indent=2)+'\n')
 print('PASS',len(cases))
if __name__=='__main__':main()
