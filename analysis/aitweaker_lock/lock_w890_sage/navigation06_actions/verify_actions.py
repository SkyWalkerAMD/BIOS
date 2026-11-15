"""New PE + real observer + exact original native action/cleanup chain.

No owner flag is supplied. UEFI, outer native containers, destructor and four
post-close cleanup callees are explicit models; no complete GUI claim.
"""
from pathlib import Path
import sys,json,hashlib,struct,re,time
H=Path(__file__).resolve().parent;B=H.parent;N=B/'navigation05';O=H/'build'
sys.path.insert(0,str(N))
import verify_form_open as f
b=f.b;n=b.n;m=b.m;ns=b.ns;TSE=b.TSE;DATA=b.DATA;Q=b.Q;I=b.I
from unicorn.x86_const import *
import pefile
DLL=O/'W890NavigationActions06.TESTONLY.dll';SHA=hashlib.sha256(DLL.read_bytes()).hexdigest()
m.OP.close();m.OP=pefile.PE(str(DLL));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
OS=m.OS;OS.clear();OS.update({e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols})
SY=m.SY;SY.clear();SY.update({k:int(v,16)for k,v in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(O/'navigation.map').read_text(),re.M)})
ns['SYMBOLS']=SY;n.CALLS=json.loads((O/'consumer_windows.json').read_text())
class VM(f.VM):
 def __init__(self):
  super().__init__();self.defer06=False;self.destroyed=[];self.cleanup=[];self.close_trace=[];self.mutate_close=None;self.interrupt_close=None;self.interrupt_state=None;self.interrupt_results=[]
  self.extra06=ns['HOOK']+0xc000
  self.reset_console=ns['HOOK']+0xc100;self.w(self.reset_console,b'\xc3');self.w(self.console,Q(self.reset_console));self.interesting.add(self.reset_console)
  self.interrupt_return=ns['HOOK']+0xc200;self.w(self.interrupt_return,b'\xc3');self.interesting.add(self.interrupt_return)
  self.interesting.update(TSE+r for r in [0x748c,0x189a4,0x18a01,0x18ab1,0x3f5cc,0x3f6e3,0x3f6e8,0x3f414,0x1c100,0x1c078,0x18c58,0x40b3c])
  self.destructor=self.q(TSE+0x93cf8);self.interesting.add(self.destructor)
 def run(self,name,*args,**kw):
  if self.defer06 and name=='no_prepare':return 0
  return super().run(name,*args,**kw)
 def packet(self):
  self.defer06=True;super().packet();self.defer06=False
  before=self.r(TSE+0x748c,14);assert before.hex()=='40534883ec20488bd9e80a150100'
  tr=self.extra06
  self.w(tr,before[:9]+b'\xe8'+struct.pack('<i',TSE+0x189a4-(tr+14))+b'\xe9'+struct.pack('<i',TSE+0x749a-(tr+19)))
  self.w(OS['n06_exit_trampoline'],Q(tr))
  after=b'\xff\x25'+bytes(4)+Q(OS['n06_native_exit'])
  self.specs.append(struct.pack('<4I',0,0x748c,14,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
  assert len(self.specs)==35
  self.w(self.patches,b''.join(self.specs));self.w(self.inst+48,I(35))
  return self.run('no_prepare',self.inst)
 def hook(self,u,address,size,opaque):
  if hasattr(self,'destroyed'):
   if address==self.interrupt_return:
    self.interrupt_results.append(u.reg_read(UC_X86_REG_RAX))
    for r,value in self.interrupt_state.items():u.reg_write(r,value)
    self.interrupt_state=None;return
   if address==OS['no_native_visit_identity'] and self.interrupt_close and self.q(TSE+0xafdd0)==0:
    mode=self.interrupt_close;self.interrupt_close=None
    regs=[UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_RBP,UC_X86_REG_EFLAGS]+[getattr(sys.modules['unicorn.x86_const'],'UC_X86_REG_R'+str(i))for i in range(8,16)]+[getattr(sys.modules['unicorn.x86_const'],'UC_X86_REG_XMM'+str(i))for i in range(16)]
    self.interrupt_state={r:u.reg_read(r)for r in regs};sp=u.reg_read(UC_X86_REG_RSP)-0x208;self.w(sp,Q(self.interrupt_return));u.reg_write(UC_X86_REG_RSP,sp)
    args=[self.raw(self.main),4,DATA+0x2a000] if mode=='reenter'else[2,0,0,self.setup_hii,2]
    for i,r in enumerate(ns['REGS']):u.reg_write(r,args[i]if i<len(args)else 0)
    for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
    u.reg_write(UC_X86_REG_RIP,OS['n05_native_form_open']if mode=='reenter'else self.notify_callback);return
   if address==self.reset_console:self.ret(0);return
   if address==self.destructor:
    self.destroyed.append((self.arg(0),self.arg(1)));self.ret(0);return
   if address in [TSE+r for r in [0x1c100,0x1c078,0x18c58,0x40b3c]]:
    self.cleanup.append(address-TSE);self.ret(0);return
   if address in [TSE+r for r in [0x189a4,0x18a01,0x18ab1,0x3f5cc,0x3f6e3,0x3f6e8]]:
    self.close_trace.append({'rva':address-TSE,'app_global':self.q(TSE+0xafdd0),'action':self.arg(0) if address==TSE+0x3f5cc else None})
   if address==TSE+0x3f6e3 and self.mutate_close:
    todo=self.mutate_close;self.mutate_close=None;todo(self)
  return super().hook(u,address,size,opaque)
 def ready_full(self):
  super().ready_full()
  for rva in [0xba9b8,0xba9c8,0xba9d8]:self.w(TSE+rva,f.p['MAPPED'][rva:rva+4])
  self.w(TSE+0xbaa68,Q(1));self.w(TSE+0xafec8,Q(0));self.w(TSE+0xafec4,I(0))
 def only_main_active(self):
  # Explicit bounded positive fixture: retain the real Main parser records;
  # other original raw pages become inactive HII=0 entries. Not factory state.
  for row in f.S['pages']:
   if row['index']!=self.main:self.w(self.raw(row['index']),Q(0))
  self.w(self.app+0x28,I(self.main))
 def local_action(self,index,action=3):
  self.w(self.app+0x28,I(index));self.w(DATA+0x2a000,I(0))
  # Execute actual CALL 23E00 with original register contract and stop at its
  # exact return. Surrounding PageHandleAction containers remain fixtures.
  return (TSE+0x23e00,[self.raw(index),action,DATA+0x2a000],{},TSE+0x23e05)
 def exit_step(self,status=0,reset=False):
  at=0x199e6 if reset else 0x19a76
  return (TSE+at,[status],{},TSE+at+5)
def main():
 cases=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(x.lower()in name.lower()for x in sys.argv[1:]):return
  begin=time.time();v=VM();fn(v);cases.append({'name':name,'status':'PASS','seconds':round(time.time()-begin,3)});print(name,flush=True)
  (O/'actions_progress.json').write_text(json.dumps({'component_sha256':SHA,'cases':cases},indent=2)+'\n')
 def local(v,action):
  v.ready_full();v.loop([v.local_action(v.main,action)])
  assert v.sequence_values==[0]and not v.form_callbacks and v.observe_native.count(0x3f423)==1 and not v.set_count,(v.sequence_values,v.run('n06_last_reason'))
 case('actual native CALL and original batch: Main FORM_OPEN3',lambda v:local(v,3))
 case('actual native CALL and original batch: local Main FORM_CLOSE4',lambda v:local(v,4))
 def exit_main(v):
  v.ready_full();v.only_main_active();v.loop([v.exit_step(0x800000000000000e)])
  assert v.sequence_values==[0x800000000000000e],(v.sequence_values,v.run('n06_last_reason'),v.close_trace)
  assert v.destroyed==[(v.app,1)]and v.q(TSE+0xafdd0)==0 and not v.form_callbacks
  assert [x['rva']for x in v.close_trace].count(0x18ab1)==1
  assert all(x['app_global']==0 for x in v.close_trace if x['rva']in(0x3f5cc,0x3f6e3,0x3f6e8))
  assert v.observe_native.count(0x3f423)==1 and v.cleanup==[0x1c100,0x1c078,0x18c58,0x40b3c]and not v.set_count
  assert v.run('n06_last_reason')==0
 case('normal native cleanup: private pre-destructor capture survives App destruction once',exit_main)
 def blocked(v,which,reason):
  v.ready_full();v.loop([v.local_action(getattr(v,which),4)])
  assert v.sequence_values==[ns['ERR'](15)]and v.run('n06_last_reason')==reason and not v.form_callbacks and not v.destroyed and not v.set_count
 case('protected Ai close remains denied without side-effect closure',lambda v:blocked(v,'ai',4))
 def granted(v):
  password=b'NavTest5';v.record=ns['core'].signed_record(password=password)
  v.ready_full();v.queue(password.decode()+'\r')
  v.loop([('n05_check',[2,v.page_list[v.ai],0]),v.local_action(v.ai,4)])
  assert v.sequence_values==[0,ns['ERR'](15)]and not v.form_callbacks and not v.destroyed and not v.set_count,(v.sequence_values,v.transcript[-800:],v.uefi_calls[-20:])
 case('real password grant does not bypass unknown protected CLOSE effects',granted)
 case('ordinary Security callback-bearing close remains denied',lambda v:blocked(v,'security',5))
 def full(v):
  v.ready_full();v.w(v.app+0x28,I(v.main));v.loop([v.exit_step()])
  assert v.sequence_values==[ns['ERR'](15)]and not v.destroyed and not v.cleanup and not v.form_callbacks and not v.set_count
 case('complete original bounded parser batch rejected before destructor and first callback',full)
 def bad_action(v):
  v.ready_full();v.loop([v.local_action(v.main,2)])
  assert v.sequence_values==[ns['ERR'](15)]and v.run('n06_last_reason')==1 and not v.form_callbacks
 case('Action2 is RETRIEVE and is not misreported as close',bad_action)
 def foreign(v):
  v.ready_full();v.only_main_active();v.w(v.raw(v.ai),Q(0x12345678));v.loop([v.exit_step()])
  assert v.sequence_values==[ns['ERR'](15)]and v.run('n06_last_reason')==3 and not v.destroyed
 case('foreign HII denies whole exit before any destructor side effect',foreign)
 def mutate(v,offset):
  v.ready_full();v.only_main_active();c=v.q(TSE+0xbab08)+int.from_bytes(v.r(v.raw(v.main)+0x20,4),'little')
  v.w(c+offset,bytes([v.r(c+offset,1)[0]^32]));v.loop([v.exit_step()])
  assert v.sequence_values==[ns['ERR'](15)]and not v.destroyed and not v.form_callbacks
 case('Main callback bit changed denies complete batch before destruction',lambda v:mutate(v,0x1c))
 def post_drift(v):
  v.ready_full();v.only_main_active()
  def change(w):
   c=w.q(TSE+0xbab08)+int.from_bytes(w.r(w.raw(w.main)+0x20,4),'little');w.w(c+0x1c,I(int.from_bytes(w.r(c+0x1c,4),'little')|32))
  v.mutate_close=change;v.loop([v.exit_step()])
  assert v.sequence_values==[ns['ERR'](15)]and v.destroyed and not v.form_callbacks and 0x3f423 not in v.observe_native
 case('post-destructor callback-bit drift refuses callbacks and reports irreversible partial cleanup',post_drift)
 def interruption(v,mode):
  v.ready_full();v.only_main_active();v.interrupt_close=mode;v.loop([v.exit_step()])
  assert v.sequence_values==[ns['ERR'](15)]and v.destroyed and not v.form_callbacks and 0x3f423 not in v.observe_native and v.interrupt_state is None
  assert v.interrupt_results==[ns['ERR'](15) if mode=='reenter' else 0]
 case('actual nested close entry cannot reuse the in-flight teardown lease',lambda v:interruption(v,'reenter'))
 case('actual HII-change callback revokes teardown before original close callback execution',lambda v:interruption(v,'hii'))
 def wrongcaller(v):
  v.ready_full();v.only_main_active();v.loop([v.exit_step(reset=True)])
  assert v.sequence_values==[ns['ERR'](15)]and v.run('n06_last_reason')==7 and not v.destroyed
 case('reset caller that ignores status remains excluded from cleanup lease',wrongcaller)
 def direct(v):
  v.ready_full();v.only_main_active();assert v.run('n06_native_exit',0)==ns['ERR'](15)and not v.destroyed
 case('direct call cannot mint private teardown authority',direct)
 report={'component_sha256':SHA,'parser_zip_sha256':f.ZS,'checks':len(cases),'cases':cases,
  'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'actual_original':['CALL23E00','CALL19A76','748C relocated first14 and original continuation','189A4 App-clear and close dispatch','3F5CC page loop','3F414 callback-free Main loop'],
  'models':['UEFI and CPU mapping; App/Page outer objects','App destructor call target and console reset return success; four post-close cleanup helpers return success','positive teardown uses original Main descriptors and marks all other pages inactive','negative nested-entry/HII-notify injection preserves registers and then resumes the actual private observer function','local Close4 supplies action4 at the original page-transition CALL fixture; the true factory close4 is separately executed through189A4','cryptographic hashes/KDF/entropy use frozen explicit oracles; no owner/session flag oracle'],
  'not_proved':['full native destructor or GUI teardown','callback-bearing ordinary/Ai or foreign close','initial global FORM_OPEN3 before private Loop','reset branch status propagation','complete hardware parser boot or flashability'],
  'frozen_inputs_unchanged':True}
 (O/('actions_tests.json'if len(sys.argv)==1 else'actions_selected_tests.json')).write_text(json.dumps(report,indent=2)+'\n')
 print('PASS',len(cases))
if __name__=='__main__':main()
