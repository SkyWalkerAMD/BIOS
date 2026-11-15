"""Actual thin SendForm ABI, native prologue/epilogue and exact Loop CALL.

The full SendForm body is deliberately not modeled as a successful function.
Capture cases stop at its first unmodeled native initializer. Return cases
execute original prologue/epilogue around an explicit register-status slice.
The composed case executes original CALL37121 and the bounded original Loop
tail used in verify_lifecycle, then stops at the original SendForm continuation.
"""
from pathlib import Path
import json,hashlib,time
import verify_lifecycle as l
from verify_lifecycle import TSE,DATA,Q,I,OS,SY,ns
from unicorn.x86_const import *
H=Path(__file__).resolve().parent;O=H/'build'

class VM(l.VM):
 def __init__(self):
  super().__init__();self.send_mode=None;self.send_seen=[];self.send_status=0;self.send_return=None;self.pre_native_state=None
  self.interesting.update([self.tramps+0x200,TSE+0x36db3,TSE+0x36de9,TSE+0x12204,TSE+0x37126,TSE+0x37396])
 def hook(self,u,address,size,opaque):
  if self.send_mode:
   if address==self.tramps+0x200:
    self.send_seen=[self.arg(i)for i in range(7)];self.send_entry_rsp=u.reg_read(UC_X86_REG_RSP);return
   # Explicitly override the old harness' synthetic SendForm completion.
   if address==TSE+0x36db3:return
   if address==TSE+0x36de9 and self.send_mode=='return-slice':
    u.reg_write(UC_X86_REG_RBX,self.send_status);u.reg_write(UC_X86_REG_RIP,TSE+0x37396);return
   if address==TSE+0x36de9 and self.send_mode=='loop-call-slice':
    u.reg_write(UC_X86_REG_RIP,TSE+0x37121);return
   if address==TSE+0x12204:
    self.stop_unknown('first original SendForm initializer',pc=hex(address));return
   if address==TSE+0x37126 and self.send_mode=='loop-call-slice':
    self.send_return={'status':hex(u.reg_read(UC_X86_REG_RAX)),'rsp':u.reg_read(UC_X86_REG_RSP),'native_send_body_rsp':self.send_entry_rsp-0x78}
    u.emu_stop();return
  return super().hook(u,address,size,opaque)
 def arguments(self):
  hs=DATA+0x2e800;guid=hs+0x40;dim=guid+0x20;request=dim+0x40
  # Both foreign handles are opaque values. No invented foreign ownership.
  self.w(hs,Q(0x900081)+Q(0x900082));self.w(guid,bytes.fromhex('102030405060708090a0b0c0d0e0f001'))
  self.w(dim,Q(1)+Q(2)+Q(80)+Q(25));self.w(request,Q(0x123456789abcdef0))
  return [TSE+0x943a8,hs,2,guid,0x4567,dim,request]
 def invoke(self,args):
  try:return self.run('no_native_send_form',*args)
  except AssertionError:
   if not self.unknown and self.send_return is None:raise
   return None

def main():
 rows=[]
 def case(name,fn):
  v=VM();t=time.time();d=fn(v);rows.append({'name':name,'status':'PASS','seconds':round(time.time()-t,3),'observations':d});print(name,d,flush=True)
 def capture(v,zero=False):
  v.ready_full();args=v.arguments()
  if zero:args[1]=0;args[2]=0
  before=[v.r(args[3],16),v.r(args[5],32),v.r(args[6],8)]
  v.send_mode='capture';v.invoke(args)
  assert v.send_seen==args and v.unknown['pc']==hex(TSE+0x12204)
  assert before==[v.r(args[3],16),v.r(args[5],32),v.r(args[6],8)] and not v.set_count
  assert v.run('no_identity',v.idbuf)==1 and v.r(v.idbuf+88,8)==bytes(8)
  assert v.run('w890_provider_query',v.p)==1
  return {'seven_arguments_exact':True,'count':args[2],'stopped_before':'original12204 initializer','private_loop_depth':0,'private_send_depth':0,'password_state':'READY, no permission'}
 case('two foreign handles and foreign form parameters reach original SendForm unchanged',capture)
 case('original null/count-zero handling is not replaced by a new Setup-only argument check',lambda v:capture(v,True))
 def return_slice(v,status):
  v.ready_full();args=v.arguments();v.send_mode='return-slice';v.send_status=status
  regs=[UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
  vals=[0x11000000+i*0x100 for i in range(len(regs))]
  for r,x in zip(regs,vals):v.u.reg_write(r,x)
  result=v.invoke(args)
  assert result==status and [v.u.reg_read(r)for r in regs]==vals and v.send_seen==args
  assert v.u.reg_read(UC_X86_REG_RSP)==ns['STACK']+0x1ff010 and not v.set_count
  return {'original_epilogue_status':hex(result),'nonvolatile_registers':8,'boundary':'conditional status-register slice; full native SendForm body not executed'}
 case('thin SendForm preserves successful original epilogue return and ABI',lambda v:return_slice(v,0))
 case('thin SendForm preserves error original epilogue return and ABI',lambda v:return_slice(v,ns['ERR'](14)))
 def loop_call(v):
  v.ready_full();v.empty_outer_frames();args=v.arguments()
  v.w(v.app+0x28,I(v.main));v.w(v.app+0x58,b'\0\0\1');v.w(TSE+0xbaa68,Q(0));v.w(TSE+0xafd00,Q(3));v.w(TSE+0xafdc8,b'\0')
  v.w(TSE+0xbaab8,Q(0x712340));v.protocols[(0x712340,TSE+0x93cd8,TSE+0x93ce8)]=True
  hp=DATA+0x2b000;v.w(hp,bytes(32));v.owned_buffers[hp]=32;v.w(TSE+0xafde8,Q(hp));v.w(TSE+0xafddc,I(70));v.w(TSE+0xafe00,I(1))
  v.full_tail=True;v.original_status=ns['ERR'](14);v.start_rva=0x1995f;v.send_mode='loop-call-slice'
  v.invoke(args);v.full_tail=False
  assert v.send_return and v.send_return['status']==hex(ns['ERR'](14)) and not v.unknown
  assert v.send_return['rsp']==v.send_return['native_send_body_rsp'] and v.send_seen==args
  assert v.run('no_identity',v.idbuf)==1 and v.r(v.idbuf+88,8)==bytes(8)
  assert v.run('w890_provider_query',v.p)==1 and not v.protocols and not v.hist() and not v.set_count
  return {'at_original37126':v.send_return,'known_services':v.events,'private_loop_depth_after':0,'private_send_depth_after':0,'boundary':'SendForm setup body and Loop middle are explicit slices; original37121 CALL, privateBegin/End and original normal-tail instructions executed'}
 case('real original37121 CALL establishes Loop session and ends it before SendForm continuation',loop_call)
 def denied(v,mode):
  v.ready_full();args=v.arguments();v.send_mode='capture'
  if mode=='this':args[0]+=8
  else:v.w(TSE+0x12204,b'\x90')
  assert v.invoke(args)==ns['ERR'](15) and not v.send_seen and not v.unknown and not v.set_count
  return {'original_not_entered':True,'status':hex(ns['ERR'](15))}
 case('wrong native protocol object is rejected before SendForm',lambda v:denied(v,'this'))
 case('unexpected original text change rejects before SendForm',lambda v:denied(v,'code'))
 report={'component_sha256':l.SHA,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'dependency_sha256':l.SOURCE_SHA,'checks':len(rows),'cases':rows,'limits':['No complete SendForm success claim','Foreign handles are forwarding inputs, not ownership evidence','Existing Setup-only page observer remains; root owns foreign/generation integration','No firmware or physical installation']}
 (O/'send_form_tests.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(rows))
if __name__=='__main__':main()
