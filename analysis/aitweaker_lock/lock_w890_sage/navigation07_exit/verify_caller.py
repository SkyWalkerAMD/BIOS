"""Execute the exact original CALL B8DC instead of supplying its return slot."""
from pathlib import Path
import json,hashlib,time
import verify_tail as t
from unicorn.x86_const import *
H=Path(__file__).resolve().parent;O=H/'build';TSE=t.TSE;Q=t.Q;ns=t.ns
SOURCE_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
class VM(t.VM):
 def run(self,name,*args,return_to=None,**kw):
  if name!='no_native_loop' or return_to!=TSE+0xb8e1:return super().run(name,*args,return_to=return_to,**kw)
  code=self.r(TSE+0xb8dc,5);assert code[0]==0xe8 and 0xb8e1+int.from_bytes(code[1:],'little',signed=True)==0x190f4,code.hex()
  self.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)))
  sp=ns['STACK']+0x1ff010;self.target_stop=return_to;self.w(sp,bytes(0x400));self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
  self.u.emu_start(TSE+0xb8dc,0,count=200000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==return_to
  return self.u.reg_read(UC_X86_REG_RAX)
def main():
 begin=time.time();v=VM();v.ready_full();v.tail(continuation=True,setup=lambda w:w.w(w.native_input+8,b'\x01\0'+bytes([0x39])*22))
 assert len(v.resumes)==1 and not v.faults and v.input_resets==v.input_boundaries==1 and not v.set_count
 report={'component_sha256':t.SHA,'source_sha256':SOURCE_SHA,'tail_fixture_sha256':hashlib.sha256((H/'verify_tail.py').read_bytes()).hexdigest(),'checks':1,'cases':[{'name':'exact original B8DC CALL -> detoured190F4 -> private wrapper -> original prologue -> guard -> original next-input path','status':'PASS','seconds':round(time.time()-begin,3)}],'caller_bytes':v.r(TSE+0xb8dc,5).hex(),'limitations':'The selected caller instruction and stack are executed. Earlier caller initialization and surrounding BrowserLoop middle remain modeled, not hardware ownership evidence.'}
 (O/'caller_tests.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actual original CALL B8DC')
if __name__=='__main__':main()
