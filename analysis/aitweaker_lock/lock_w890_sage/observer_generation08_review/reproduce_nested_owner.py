"""Probe occupied outer scope across an actual nested native Loop wrapper.

The original B8DC CALL and compiled wrappers execute; BrowserLoop bodies and
the callback scheduling inside the modeled GetVariable remain fixtures.
"""
from pathlib import Path
import sys,json,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent
import verify_revision02 as r
g=r.g;Q,DATA,TSE,OS,ns=r.Q,r.DATA,r.TSE,r.g.OS,r.ns
from unicorn.x86_const import UC_X86_REG_RSP

class VM(r.VM):
 def __init__(self):
  super().__init__();self.nested_call_active=False;self.nested_caller_returns=0;self.native_loop_entries=[]
 def hook(self,u,address,size,opaque):
  if getattr(self,'nested_call_active',False) and address==OS['no_native_loop']:
   self.native_loop_entries.append({'caller':hex(self.q(u.reg_read(UC_X86_REG_RSP)))})
  if getattr(self,'nested_call_active',False) and address==TSE+0xb8e1:
   self.nested_caller_returns+=1;self.nested_call_active=False;self.ret(0);return
  if hasattr(self,'labmode') and address==self.hooks['get'] and self.labmode=='foreign_nested_loop' and self.r(self.arg(0),32)=='Generation08Lab\0'.encode('utf-16-le'):
   self.lab_calls+=1;self.labmode=None;self.chain_sp=u.reg_read(UC_X86_REG_RSP)
   original=self.r(TSE+0xb8dc,5)
   assert original==bytes.fromhex('e813d80000')
   self.chain=[(self.notify_callback,[2,0,0,0x920000,2]),(TSE+0xb8dc,[]),(OS['og08_test_nested'],[])]
   self.nested_call_active=True;self.start_next();return
  return super().hook(u,address,size,opaque)

def main():
 pins=r.check_inputs();start=time.monotonic();v=VM();v.ready();v.labmode='foreign_nested_loop';v.w(v.result,bytes(64))
 v.loop([('og08_test_read',[v.app,v.result])]);a=v.result_fields()
 assert a['entered']==a['before_valid']==1 and a['after_valid']==a['nested_old_valid']==0
 assert a['nested_entered']==1,a
 assert a['after_generation']==a['before_generation']+1 and a['read_status']==ns['ERR'](15)
 assert v.nested_caller_returns==1 and v.native_loop_entries==[{'caller':hex(TSE+0xb8e1)}]
 assert v.fault()==0 and not v.set_count
 assert r.check_inputs()==pins
 out={'status':'REPRODUCED_OUTER_SLOT_CLEARED_BY_INNER_FRAME_POP','inputs':pins,'source':r.bind(Path(__file__)),
      'actual_consumer_report':a,'original_call_bytes':'e813d80000','native_nested_loop_entries':v.native_loop_entries,
      'native_nested_caller_returns':v.nested_caller_returns,'fault':0,'seconds':round(time.monotonic()-start,3),
      'finding':'Foreign notification invalidates the occupied outer effect ticket. Actual nested native Loop pop clears all active slots unconditionally. Registered nested consumer can then mint in that same slot before the original outer owner leaves.',
      'limits':['No private state or owner boolean injected. Original callsite and compiled wrappers execute.',
                'The original BrowserLoop body is a return fixture and notification/nested-call scheduling is explicit.',
                'No real hardware occurrence, credential write, full GUI or deployment is claimed.']}
 (H/'nested_owner_repro.json').write_text(json.dumps(out,indent=2)+'\n')
 print(json.dumps({'status':out['status'],'nested_entered':a['nested_entered'],'fault':0}))

if __name__=='__main__':main()
