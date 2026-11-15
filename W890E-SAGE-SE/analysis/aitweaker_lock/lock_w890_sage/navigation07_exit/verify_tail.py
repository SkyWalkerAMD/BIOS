"""Real PE + private native Loop stack + original pre-tail/input instructions.

The beginning/middle of BrowserLoop, UEFI and outer App/Page are explicit
fixtures. The original prologue, new guard, native continuation/reset/read
execute. This cannot prove a full working BIOS or physical ownership.
"""
from pathlib import Path
import sys,json,re,struct,hashlib,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;O=H/'build'
sys.path.insert(0,str(B/'navigation06_actions'))
import verify_actions as a
f=a.f;b=a.b;n=a.n;m=a.m;ns=a.ns;TSE=a.TSE;DATA=a.DATA;Q=a.Q;I=a.I
from unicorn.x86_const import *
import pefile
DLL=O/'W890NavigationExit07.TESTONLY.dll';SHA=hashlib.sha256(DLL.read_bytes()).hexdigest()
m.OP.close();m.OP=pefile.PE(str(DLL));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
OS=m.OS;OS.clear();OS.update({e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols})
SY=m.SY;SY.clear();SY.update({k:int(v,16)for k,v in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(O/'navigation.map').read_text(),re.M)})
ns['SYMBOLS']=SY;n.CALLS=json.loads((O/'consumer_windows.json').read_text())
REGISTERS=[UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,UC_X86_REG_RSP]+[getattr(sys.modules['unicorn.x86_const'],'UC_X86_REG_R'+str(i))for i in range(8,16)]+[getattr(sys.modules['unicorn.x86_const'],'UC_X86_REG_XMM'+str(i))for i in range(16)]+[UC_X86_REG_EFLAGS]
ORIGINAL=bytes.fromhex('488b056a64090038585a0f8490fdffff')

class VM(a.VM):
 def __init__(self):
  super().__init__();self.defer07=False;self.tail_mode=False;self.resumes=[];self.faults=[];self.tail_entries=0;self.input_boundaries=0;self.input_resets=0;self.continue_input=False;self.tail_actions=[];self.before_tail=None;self.mutate_raise=None;self.mutate_restore=None;self.inject_before=None;self.injection_return=ns['HOOK']+0xd000;self.injection_state=None;self.injection_results=[];self.live_fault_wait=False;self.finish_after_retry=False;self.calls_before_end=None
  self.w(self.injection_return,b'\xc3');self.interesting.add(self.injection_return)
  self.interesting.update(TSE+x for x in [0x1910d,0x1995f,0x196ff,0x4cd14,0x23378,0x232dc,0x61fe4,0x19973,0x19994,0x19a76])
 def run(self,name,*args,**kw):
  if self.defer07 and name=='no_prepare':return 0
  return super().run(name,*args,**kw)
 def packet(self):
  self.defer07=True;super().packet();self.defer07=False
  before=self.r(TSE+0x1995f,16);assert before==ORIGINAL
  after=b'\xff\x25'+bytes(4)+Q(OS['n07_native_tail'])+b'\x90\x90'
  self.specs.append(struct.pack('<4I',0,0x1995f,16,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
  assert len(self.specs)==36;self.w(self.patches,b''.join(self.specs));self.w(self.inst+48,I(len(self.specs)))
  return self.run('no_prepare',self.inst)
 def ready_full(self):
  super().ready_full();assert self.run('n07_bind')==0
  self.native_input=DATA+0x2e000;self.w(self.native_input,Q(TSE+0x93dc0)+bytes(40));self.w(self.app+0x20,Q(self.native_input))
  self.w(TSE+0xafdd8,bytes(48));self.w(TSE+0xafddc,I(70));self.w(TSE+0xafde0,I(416));self.w(TSE+0xafde8,Q(DATA+0x2b000));self.w(TSE+0xafe00,I(1));self.w(DATA+0x2b000,bytes([0x53])*32)
  self.w(TSE+0xbaab8,Q(0xdead1200));self.w(TSE+0xafdc8,b'\0')
 def states(self):return {'app':self.r(self.app,96),'input':self.r(self.native_input,48),'history':self.r(TSE+0xafdd8,48),'history_buffer':self.r(DATA+0x2b000,32),'reset':self.r(TSE+0xafdc8,1),'protocol':self.r(TSE+0xbaab8,8),'bypass':self.r(TSE+0xbaa68,8)}
 def native_registers(self):return {str(r):self.u.reg_read(r)for r in REGISTERS}
 def finish_tail(self):
  self.w(self.native_rsp+0xd8,Q(OS['n07_loop_body_return'])) # Fixture cleanup only, after endpoint assertions.
  self.body_rsp=self.native_rsp+0x98;self.finish_body();self.tail_mode=False
 def enter_tail(self,setup=None):
  u=self.u
  for i,r in enumerate(REGISTERS[:-1]):
   if r not in [UC_X86_REG_RSP,UC_X86_REG_RBP]:u.reg_write(r,0x1020304050607080+i)
  for i in range(16):u.reg_write(getattr(sys.modules['unicorn.x86_const'],'UC_X86_REG_XMM'+str(i)),(0x112233445566778899aabbccddeeff00+i))
  u.reg_write(UC_X86_REG_RSP,self.native_rsp);u.reg_write(UC_X86_REG_RBP,self.native_rsp+0x79)
  u.reg_write(UC_X86_REG_RBX,0);u.reg_write(UC_X86_REG_RDI,self.index());u.reg_write(UC_X86_REG_RSI,self.page_list[self.index()]);u.reg_write(UC_X86_REG_R14,self.native_input);u.reg_write(UC_X86_REG_R12,0);u.reg_write(UC_X86_REG_R13,1);u.reg_write(UC_X86_REG_EFLAGS,0x202)
  if setup:setup(self)
  self.before_tail=self.native_registers();self.before_state=self.states();u.reg_write(UC_X86_REG_RIP,TSE+0x1995f)
 def hook(self,u,address,size,opaque):
  if self.tail_mode:
   if address==self.injection_return:
    self.injection_results.append(u.reg_read(UC_X86_REG_RAX))
    for r,value in self.injection_state.items():u.reg_write(r,value)
    self.injection_state=None;return
   if address==SY['n07_cached']and self.inject_before:
    mode=self.inject_before;self.inject_before=None;self.injection_state={r:u.reg_read(r)for r in REGISTERS+[UC_X86_REG_RIP]}
    sp=u.reg_read(UC_X86_REG_RSP)-0x208;self.w(sp,Q(self.injection_return));u.reg_write(UC_X86_REG_RSP,sp)
    if mode=='hii':target=self.notify_callback;args=[2,0,0,self.setup_hii,2]
    elif mode=='end':target=OS['no_end_boot'];args=[0,0];self.calls_before_end=len(self.uefi_calls)
    else:
     # Actually execute the assembly's CALL n07_exit_dispatch while busy.
     target=OS['n07_dispatch_return']-5;args=[self.native_rsp-192]
     self.w(sp,Q(self.injection_return));self.interesting.add(OS['n07_dispatch_return'])
    for i,r in enumerate(ns['REGS']):u.reg_write(r,args[i]if i<len(args)else 0)
    for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
    u.reg_write(UC_X86_REG_RIP,target);return
   if address==OS['n07_dispatch_return']and self.injection_state is not None:
    # Nested actual inline CALL returned; no second assembly unwind is run.
    u.reg_write(UC_X86_REG_RIP,self.injection_return);return
   if address==TSE+0x19106:return # Execute the actual original SUB RSP,98.
   if address==TSE+0x1910d:
    self.native_rsp=u.reg_read(UC_X86_REG_RSP);assert self.q(self.native_rsp+0xd8)==OS['n07_loop_body_return']
    self.enter_tail(self.tail_setup);return
   if address==TSE+0x1995f:
    self.tail_entries+=1
    if self.tail_entries>1:
     self.finish_tail();return
   if address==TSE+0x196ff:
    regs=self.native_registers();expected=dict(self.before_tail);expected[str(UC_X86_REG_RAX)]=self.app;expected[str(UC_X86_REG_EFLAGS)]=(expected[str(UC_X86_REG_EFLAGS)]&~0x8d5)|0x44
    assert regs==expected,[(r,hex(expected[r]),hex(regs[r]))for r in regs if expected[r]!=regs[r]]
    self.resumes.append({'registers':regs,'state':self.states()})
    if not self.continue_input:self.finish_tail();return
   if address==TSE+0x4cd14:self.ret(0);return # Original callee boundary, no UI claim.
   if address==TSE+0x23378:self.input_resets+=1
   if address==TSE+0x61fe4:
    self.input_boundaries+=1;assert self.r(self.native_input+8,24)==bytes(24)
    self.ret(ns['ERR'](6));return # Fresh event backend is an explicit boundary.
   if address in [TSE+0x19973,TSE+0x19994,TSE+0x19a76]:raise AssertionError(('tail side effect reached',hex(address)))
   if address==OS['n07_fault_wait']:
    self.faults.append({'reason':int.from_bytes(self.r(SY['n07_reason'],4),'little'),'state':self.states()})
    if not self.live_fault_wait:self.finish_tail();return
   if address==self.oh['raise']and self.arg(0)==16 and self.mutate_raise:
    change=self.mutate_raise;self.mutate_raise=None;change(self)
   if address==self.oh['restore']and self.current_tpl==16 and self.mutate_restore:
    change=self.mutate_restore;self.mutate_restore=None;change(self)
  return super().hook(u,address,size,opaque)
 def tail(self,request=1,reset=0,bypass=0,which='main',setup=None,continuation=False):
  self.w(self.app+0x28,I(getattr(self,which)));self.w(self.app+0x58,b'\0\0'+bytes([request]));self.w(TSE+0xafdc8,bytes([reset]));self.w(TSE+0xbaa68,Q(bypass))
  self.tail_setup=setup;self.continue_input=continuation;self.tail_mode=True
  assert self.run('no_native_loop',return_to=TSE+0xb8e1)==0
  assert not self.destroyed and not self.cleanup and not self.free_trace and not self.form_callbacks and not self.set_count
  return self.resumes

def main():
 cases=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(s.lower()in name.lower()for s in sys.argv[1:]):return
  t=time.time();v=VM()
  try:fn(v)
  except Exception as e:
   failure={'name':name,'component_sha256':SHA,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'error':repr(e),'rip':hex(v.u.reg_read(UC_X86_REG_RIP)),'faults':v.faults,'native':v.observe_native[-12:]}
   (O/('failure_'+str(time.time_ns())+'.json')).write_text(json.dumps(failure,indent=2,default=lambda x:x.hex()if isinstance(x,bytes)else str(x))+'\n');raise
  cases.append({'name':name,'status':'PASS','seconds':round(time.time()-t,3)});print(name,flush=True)
  (O/'tail_progress.json').write_text(json.dumps({'component_sha256':SHA,'cases':cases},indent=2)+'\n')
 def good(v,request=1,reset=0,bypass=0,which='main',only=False,continuation=False):
  v.ready_full()
  if only:v.only_main_active()
  def setup(w):w.w(w.native_input+8,struct.pack('<H',1)+bytes([0x39])*22)
  v.tail(request,reset,bypass,which,setup=setup,continuation=continuation)
  assert len(v.resumes)==1 and not v.faults,(v.faults,v.run('n07_last_reason'),v.run('n07_last_batch_reason'))
  original=dict(v.before_state);new=bytearray(original['app']);new[0x5a]=0;original['app']=bytes(new)
  assert v.resumes[0]['state']==original
  assert v.run('n07_last_reason')==(0 if not request else 2 if only else 1)
  if continuation:assert v.input_resets==v.input_boundaries==1 and v.tail_entries==2
 case('no exit request preserves native state and exact register/flag branch',lambda v:good(v,0))
 case('normal exit cancellation keeps nonempty history and protocol intact',good)
 case('reset request cancellation preserves pending reset marker',lambda v:good(v,reset=1))
 case('bypass flag does not bypass cancellation',lambda v:good(v,bypass=1))
 case('known Main-only close batch still cannot authorize earlier teardown',lambda v:good(v,only=True))
 case('Security cancellation retains current page',lambda v:good(v,which='security'))
 case('Ai cancellation grants no credential and preserves page/input guard state',lambda v:good(v,which='ai'))
 case('cancel executes original input reset/read and reaches fresh event boundary',lambda v:good(v,continuation=True))
 def bad_context(v,change):
  v.ready_full();v.tail(setup=change)
  assert not v.resumes and len(v.faults)==1 and v.faults[0]['state']==v.before_state and v.faults[0]['reason']in [4,5]
 case('wrong native RBP refuses before exit flag mutation',lambda v:bad_context(v,lambda w:w.u.reg_write(UC_X86_REG_RBP,w.native_rsp+0x78)))
 case('wrong native BL refuses before exit flag mutation',lambda v:bad_context(v,lambda w:w.u.reg_write(UC_X86_REG_RBX,1)))
 case('wrong current page register refuses before exit flag mutation',lambda v:bad_context(v,lambda w:w.u.reg_write(UC_X86_REG_RSI,w.page_list[w.security])))
 case('wrong original input vtable refuses before exit flag mutation',lambda v:bad_context(v,lambda w:w.w(w.native_input,Q(TSE+0x93de0))))
 case('wrong private original-body return anchor refuses before mutation',lambda v:bad_context(v,lambda w:w.w(w.native_rsp+0xd8,Q(TSE+0xb8e1))))
 case('unknown foreign current page does not acquire native resume permission',lambda v:bad_context(v,lambda w:w.w(w.page_list[w.index()]+0x20,Q(0x900099))))
 def drift(v,after=False,field='reset'):
  v.ready_full()
  def change(w):
   if field=='reset':w.w(TSE+0xafdc8,b'\x01')
   elif field=='history':w.w(TSE+0xafe00,I(2))
   else:w.w(w.native_input+8,struct.pack('<H',3))
  if after:v.mutate_restore=change
  else:v.mutate_raise=change
  v.tail();assert not v.resumes and v.faults[0]['reason']==6
  assert v.faults[0]['state']['app'][0x5a]==(0 if after else 1)
 case('reset marker drift at TPL boundary denies before cancellation',drift)
 case('nonempty history count drift at TPL boundary denies before cancellation',lambda v:drift(v,field='history'))
 case('input event drift at TPL boundary denies before cancellation',lambda v:drift(v,field='input'))
 case('post-Restore drift prevents GUI resume and records already-cleared request',lambda v:drift(v,after=True))
 def interruption(v,mode):
  v.ready_full();v.inject_before=mode;v.tail()
  assert not v.resumes and v.faults[0]['state']==v.before_state and v.faults[0]['reason']==6 and v.injection_state is None
  if mode=='end':assert len(v.injection_results)==1 and len(v.uefi_calls)==v.calls_before_end # Callback is void; RAX is not an ABI result.
  else:assert v.injection_results==[0]
 case('actual nested inline dispatch poisons the current cancellation',lambda v:interruption(v,'nested'))
 case('actual HII notification revokes private epoch before flag write',lambda v:interruption(v,'hii'))
 case('actual ExitBootServices callback revokes private epoch before flag write',lambda v:interruption(v,'end'))
 def direct(v):
  v.ready_full();before=v.states();assert v.run('n07_exit_dispatch',DATA+0x2c000)==0 and v.run('n07_last_reason')==3 and v.states()==before
 case('direct public call cannot mint private cancellation authority',direct)
 def wait(v,text,substitute=False):
  v.ready_full();v.queue(text);v.change_input_at_wait=substitute
  assert v.run('n07_fault_wait')==(2 if substitute else 1 if text=='R'else 0)
  assert v.waits==1 and not v.set_count and 'Press R to retry'in v.transcript
 case('fault wait uses blocking original UEFI event and explicit retry key',lambda v:wait(v,'R'))
 case('ordinary key remains in fault isolation without claiming GUI resume',lambda v:wait(v,'x'))
 case('Input substitution during fault wait refuses the later key read',lambda v:wait(v,'R',True))
 report={'component_sha256':SHA,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'parser_zip_sha256':f.ZS,'checks':len(cases),'cases':cases,'models':['UEFI and CPU mapping','BrowserLoop middle skipped after actual prologue; App/Page outer containers','4CD14 returns0;61FE4 new-input backend returnsNOT_READY','SHA/PBKDF/RDSEED explicit frozen oracles; no owner bool'],'not_proved':['complete native GUI','all BrowserLoop exits','full teardown/effect authorization','hardware ownership or deployment']}
 (O/('tail_tests.json'if len(sys.argv)==1 else'tail_selected_tests.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases))
if __name__=='__main__':main()
