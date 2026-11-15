"""Actual compiled navigation/observer/runtime + original W890 machine code.

UEFI, CPU mappings, initial native page construction, and BrowserLoop body are
explicit fixtures. Native history functions, allocations' callers, allocator,
zero/copy logic, ownership checks, password UI and Main transaction execute
real instructions. SHA/PBKDF/RDSEED use the frozen harness' explicit oracles.
"""
from pathlib import Path
import sys,importlib.util,re,json,hashlib,struct,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent
spec=importlib.util.spec_from_file_location('observer04_readonly',B/'native_observer04/verify_observer.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
import pefile
from unicorn import UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
Q=m.Q;I=m.I;TSE=m.TSE;SETUP=m.SETUP;DATA=m.DATA;ns=m.ns
EFI=H/'build/W890Navigation05.TESTONLY.dll'
IMAGE_SHA=hashlib.sha256(EFI.read_bytes()).hexdigest()
SOURCES={str(p.relative_to(H)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [H/'navigation.c',H/'navigation.h',H/'free_stubs.S',Path(__file__)]}
m.OP.close();m.OP=pefile.PE(str(EFI));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
m.OS={e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols}
m.SY={n:int(a,16)for n,a in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(H/'build/navigation.map').read_text(),re.M)}
ns['SYMBOLS']=m.SY;OS=m.OS;SY=m.SY
CALLS=json.loads((H/'build/consumer_windows.json').read_text())
NATIVE_PATCHES=[(0x194cf,5,'n05_history_allocate','call'),(0x1b988,5,'n05_history_allocate','call'),(0x195ac,5,'n05_history_reallocate','call'),(0x1ba79,5,'n05_history_reallocate','call'),(0x22862,11,'n05_menu_free_stub','jump'),(0x19a5d,10,'n05_loop_free_stub','jump')]

class VM(m.VM):
 def __init__(self):
  super().__init__();self.pool=DATA+0x100000;self.allocations={};self.alloc_trace=[];self.free_trace=[];self.copy_trace=[];self.fail_alloc=False
  self.sequence=[];self.sequence_values=[];self.stepdone=ns['HOOK']+0x6800;self.w(self.stepdone,b'\xc3')
  self.copyhook=ns['HOOK']+0x6900;self.w(self.copyhook,b'\xc3');self.w(self.bs+0x160,Q(self.copyhook))
  self.stop_native=None;self.native_writes=[];self.call_trace=[];self.fault_on_return=False
  self.skip_status_code=False
  self.notify_after_main=False;self.drift_on_exclusion=False
  self.omit=None
  self.u.hook_add(UC_HOOK_MEM_WRITE,self.memwrite)
 def memwrite(self,u,access,address,size,value,opaque):
  if hasattr(self,'allocations'):
   for start,n in self.allocations.items():
    if start<=address<start+n:self.native_writes.append((self.u.reg_read(UC_X86_REG_RIP),address,size));break
 def hook(self,u,address,size,opaque):
  if hasattr(self,'allocations'):
   if address==TSE+0x10648 and self.skip_status_code:self.ret(0);return
   if address==self.oh['raise']and self.arg(0)==16 and self.drift_on_exclusion:
    self.drift_on_exclusion=False;self.w(self.page_list[1]+0x2a,struct.pack('<H',0x2713))
   if address==self.oh['restore']and self.current_tpl==16 and self.notify_after_main and self.index()==1:
    self.notify_after_main=False;self.current_tpl=self.arg(0);self.nested(self.notify_callback,[2,0,0,self.setup_hii,2],0);return
   if address in [TSE+0xfc40,TSE+0x59b50]:self.call_trace.append({'rva':address-TSE,'caller':self.q(u.reg_read(UC_X86_REG_RSP)),'rcx':self.arg(0),'rdx':self.arg(1),'r8':self.arg(2)})
   if address==self.hooks['allocate']:
    n=self.arg(1);assert 0<n<=0x20000
    self.calls.append('allocate');self.uefi_calls.append('allocate')
    if self.fail_alloc:self.w(self.arg(2),Q(0));self.ret(ns['ERR'](9));return
    p=(self.pool+15)&~15;self.pool=p+n+64;assert self.pool<DATA+0x400000
    self.allocations[p]=n;self.alloc_trace.append((p,n));self.w(p,bytes([0xa5])*n);self.w(self.arg(2),Q(p));self.ret(0);return
   if address==self.hooks['free']:
    p=self.arg(0);self.free_trace.append(p);self.allocations.pop(p,None);self.calls.append('free');self.uefi_calls.append('free');self.ret(0);return
   if address==self.copyhook:
    d,s,n=self.arg(0),self.arg(1),self.arg(2);assert n<0x20000;self.copy_trace.append((d,s,n));self.w(d,self.r(s,n));self.ret(0);return
   if address==self.stepdone:
    self.sequence_values.append(u.reg_read(UC_X86_REG_RAX));self.next_step();return
   if self.stop_native is not None and address==self.stop_native:
    self.sequence_values.append(u.reg_read(UC_X86_REG_RAX));self.stop_native=None;self.next_step();return
   if address==TSE+0x19106 and self.sequence:
    self.original_body.append('browser_loop');self.seq_rsp=u.reg_read(UC_X86_REG_RSP);self.next_step();return
  try:return super().hook(u,address,size,opaque)
  except Exception:
   print('hook failure',hex(address),'return',hex(self.q(u.reg_read(UC_X86_REG_RSP))),'native calls',self.call_trace[-4:],flush=True);raise
 def next_step(self):
  while self.sequence and callable(self.sequence[0]):self.sequence.pop(0)(self)
  if not self.sequence:
   self.body_rsp=self.seq_rsp;self.finish_body();return
  name,args,*extra=self.sequence.pop(0);sp=self.seq_rsp-0x100
  self.w(sp,bytes(0x90));self.w(sp,Q(self.stepdone));self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
  for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
  if extra:
   regs,stop=extra;self.stop_native=stop
   for reg,val in regs.items():self.u.reg_write(reg,val)
  self.u.reg_write(UC_X86_REG_RIP,OS.get(name,SY.get(name))if isinstance(name,str)else name)
 def packet(self):
  specs=[];tr=[]
  for i,w in enumerate(m.WINDOWS):
   target=OS[{'cold_entry':'no_native_entry','browser_loop':'no_native_loop','send_form':'no_native_send_form'}[w['role']]]
   before=bytes.fromhex(w['hex']);after=b'\xff\x25'+bytes(4)+Q(target)+b'\x90'*(len(before)-14)
   specs.append(struct.pack('<4I',0,w['rva'],len(before),0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
   a=self.tramps+i*0x100;tr.append(a);self.w(a,before+b'\xff\x25'+bytes(4)+Q(TSE+w['resume_rva']))
  specs.append(struct.pack('<4I',1,0x2fd50,8,0)+Q(SETUP+0x2250).ljust(32,b'\0')+Q(self.oh['bridge']).ljust(32,b'\0'))
  for i,(rva,n,name,kind)in enumerate(NATIVE_PATCHES):
   if self.omit==rva:continue
   before=self.r(TSE+rva,n);relay=ns['HOOK']+0x8000+i*0x100;self.w(relay,b'\xff\x25'+bytes(4)+Q(OS[name]))
   after=bytes([0xe8 if kind=='call'else 0xe9])+struct.pack('<i',relay-TSE-rva-5)+b'\x90'*(n-5)
   specs.append(struct.pack('<4I',0,rva,n,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
  rec=b''.join(struct.pack('<QII',m.OB+c['return_rva'],c['kind'],0)+bytes.fromhex(c['window'])for c in CALLS)
  self.w(self.callers,rec);self.specs=specs;self.w(self.patches,b''.join(specs))
  self.w(self.inst,struct.pack('<IIQQQQQIIQIIQQQ',4,96,tr[1],tr[2],tr[0],self.p,self.patches,len(specs),0,self.callers,len(CALLS),0,self.oh['bridge'],self.oh['publisher'],0))
  return self.run('no_prepare',self.inst)
 def pages(self):
  # Initial native parser output remains a declared fixture. Every page/raw
  # descriptor contains the actual canonical Setup form IDs; observer checks.
  self.setup_page();self.page_list=[self.page+i*0x200 for i in range(4)]
  self.w(self.app+0x28,I(2)+I(4)+Q(self.pa));self.w(self.pa,b''.join(Q(p)for p in self.page_list));self.w(self.pt,I(4)+b''.join(I(0x100+i*0x80)for i in range(4)))
  for i,(p,form)in enumerate(zip(self.page_list,[0x2711,0x2712,0x2713,0x271d])):
   self.w(p,bytes(104));self.w(p+0x20,Q(self.setup_hii));self.w(p+0x2a,struct.pack('<H',form));self.w(p+0x30,struct.pack('<H',i))
   d=self.blob+0x100+i*0x80;self.w(d,bytes(0x40));self.w(d,Q(self.setup_hii));self.w(d+10,struct.pack('<H',form))
  self.w(TSE+0xafddc,bytes(0x28));self.w(TSE+0xafdd0,Q(self.app))
 def ready(self):
  assert self.initialize()==0 and self.run('n05_bind')==0 and self.packet()==0
  self.apply();assert self.bind_real_host()==0;self.pages();self.free_trace.clear()
 def loop(self,steps):
  self.sequence=list(steps);r=self.run('no_native_loop',return_to=TSE+0xb8e1);assert r==0;return self.sequence_values
 def run(self,name,*args,return_to=None):
  self.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)))
  address=OS[name]if name in OS else ns['SYMBOLS'][name]
  sp=ns['STACK']+0x1ff008;stop=return_to or ns['STOP'];self.target_stop=stop
  self.w(sp,bytes(0x400));self.w(sp,Q(stop));self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
  for i in range(4,len(args)):self.w(sp+40+(i-4)*8,Q(args[i]))
  self.u.emu_start(address,0,count=200000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==stop,('instruction budget',name,hex(self.u.reg_read(UC_X86_REG_RIP)))
  return self.u.reg_read(UC_X86_REG_RAX)
 def partial_first(self):
  self.skip_status_code=True
  return(TSE+0x19463,[self.app],{UC_X86_REG_RBP:DATA+0x2c000,UC_X86_REG_R13:1,UC_X86_REG_RSI:0,UC_X86_REG_RSP:ns['STACK']+0x1e0000},TSE+0x1964f)
 def hist(self):return self.q(TSE+0xafde8)
 def index(self):return int.from_bytes(self.r(self.app+0x28,4),'little')
 def used(self):return int.from_bytes(self.r(TSE+0xafe00,4),'little')
 def main_ok(self):
  p=self.hist();return self.index()==1 and self.used()==1 and int.from_bytes(self.r(TSE+0xafddc,4),'little')==1 and self.r(p,32)==Q(self.setup_hii)+I(0x2712)+bytes(20)

def main():
 cases=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(s.lower()in name.lower()for s in sys.argv[1:]):return
  started=time.time();v=VM();fn(v);cases.append({'name':name,'status':'PASS','seconds':round(time.time()-started,3)});print(name,flush=True)
  (H/'build/navigation_progress.json').write_text(json.dumps({'component_sha256':IMAGE_SHA,'sources':SOURCES,'checks_completed':len(cases),'cases':cases},indent=2)+'\n')
 def allocation(v):
  v.ready();v.loop([(TSE+0x1b928,[1,2])]);assert v.used()==1 and v.alloc_trace[-1][1]==24*32 and v.hist()==v.alloc_trace[-1][0]
 case('actual native push allocates and tracks 24 records through exact call',allocation)
 def firstalloc(v):
  v.ready();v.loop([v.partial_first()]);assert v.index()==2 and v.used()==1 and v.alloc_trace[-1][1]==24*32 and v.call_trace[0]['rva']==0x59b50
 case('actual native initial history path executes first allocation call',firstalloc)
 def grow(v,first=False):
  v.ready();saved={}
  def fill(w):
   old=w.hist();saved['old']=old;saved['bytes']=bytes([0x6b])*(24*32);w.w(old,saved['bytes']);w.w(TSE+0xafe00,I(24))
  if first:
   growth=(TSE+0x19598,[],{UC_X86_REG_RAX:24,UC_X86_REG_RBX:0,UC_X86_REG_RSI:2,UC_X86_REG_RBP:DATA+0x2c000,UC_X86_REG_R13:1,UC_X86_REG_RSP:ns['STACK']+0x1e0000},TSE+0x1964f)
   def fillfirst(w):fill(w);growth[2][UC_X86_REG_RBX]=w.hist()
   steps=[(TSE+0x1b928,[1,2]),fillfirst,growth]
  else:steps=[(TSE+0x1b928,[1,2]),fill,(TSE+0x1b928,[1,3])]
  v.loop(steps);p=v.hist();assert v.used()==25 and v.alloc_trace[-1][1]==44*32 and v.copy_trace[-1]==(p,saved['old'],24*32)and v.free_trace==[saved['old']]and v.r(p,24*32)==saved['bytes'],(v.used(),v.alloc_trace,v.copy_trace,v.free_trace,v.call_trace,v.sequence_values)
 case('adapted push growth uses byte extents and copies all prior records',grow)
 case('adapted initial-path growth uses byte extents at the other exact CALL',lambda v:grow(v,True))
 def parked(v):
  v.ready();context=DATA+0x2d000
  # The native restore also derives BAA C8 from saved BAA E8 + u32(+4).
  # This bounded backing is a context fixture, not formset GUID evidence.
  v.w(TSE+0xbaae8,Q(DATA+0x2f000));v.w(DATA+0x2f000,I(1)+I(8)+bytes(32))
  v.loop([(TSE+0x1b928,[1,2]),(TSE+0x1bb6c,[context]),('n05_fallback_main',[]),(TSE+0x1bcdc,[context]),('n05_fallback_main',[])])
  assert v.sequence_values[-3]==0 and v.sequence_values[-1]==2 and v.main_ok()and not v.free_trace
 case('actual native context save then restore preserves tracked history lifetime',parked)
 def free(v):
  v.ready();saved={};cookie=TSE+0x94758;v.w(cookie,I(8)+I(0)+struct.pack('<H',1))
  def save(w):saved['old']=w.hist()
  def aba(w):
   assert not w.hist()and w.used()==0 and w.index()==1 and w.free_trace==[saved['old']]
   w.w(TSE+0xafde8,Q(saved['old']));w.w(TSE+0xafde0,I(24));w.w(TSE+0xafe00,I(1))
  v.loop([(TSE+0x1b928,[1,2]),save,(TSE+0x22818,[v.app,0,cookie]),aba,('n05_fallback_main',[])])
  assert v.sequence_values[-1]==0 and v.free_trace==[saved['old']]
 case('native menu FreePool retires lifetime before address reuse',free)
 def cleanup(v):
  v.ready();saved={}
  step=(TSE+0x19a5d,[0],{UC_X86_REG_RAX:v.bs,UC_X86_REG_RDI:0,UC_X86_REG_RSP:ns['STACK']+0x1e0000},TSE+0x19a76)
  def args(w):saved['old']=w.hist();step[1][0]=w.hist()
  v.loop([(TSE+0x1b928,[1,2]),args,step]);assert v.hist()==0 and v.used()==0 and v.free_trace==[saved['old']]
 case('native normal cleanup free boundary retires lifetime without reset path',cleanup)
 def missing(v):
  v.omit=0x22862;v.ready();v.loop([('n05_fallback_main',[])]);assert v.sequence_values==[0]and v.index()==2
 case('partial tracker installation with missing free boundary cannot grant ownership',missing)
 def menu(v):
  v.ready();cookie=TSE+0x94758;v.w(cookie,I(8)+I(0)+struct.pack('<H',1))
  p=v.page_list[2];v.w(p+0x4c,I(1)+Q(v.fa));v.w(v.fa,Q(v.framep));v.w(v.framep+0x20,I(4));v.w(v.framep+0x3c,I(1));v.w(v.framep+0x48,Q(v.ca));v.w(v.ca,Q(v.control));v.w(v.control,Q(TSE+0x95680));v.w(v.control+0x10,Q(v.framep)+Q(cookie))
  v.loop([(TSE+0x1b928,[1,2]),('w890_provider_fault',[]),('n05_menu',[v.app,v.control,cookie])]);assert v.sequence_values[-1]==0 and v.index()==1 and not v.hist()and len(v.free_trace)==1
 case('actual menu callback to safe Main works while credential provider is faulted',menu)
 def late(v):
  v.ready();v.notify_after_main=True;v.loop([(TSE+0x1b928,[1,2]),('n05_fallback_main',[])])
  assert v.sequence_values[-1]==0 and v.index()==1 and not v.notify_after_main
 case('queued actual HII notification at RestoreTPL prevents continuation',late)
 def drift(v):
  v.ready();v.drift_on_exclusion=True;v.loop([(TSE+0x1b928,[1,2]),('n05_fallback_main',[])])
  assert v.sequence_values[-1]==0 and v.index()==2 and v.used()==1
 case('Main pointer content changes before excluded commit and mutation refuses',drift)
 def cancel(v):
  v.ready();v.queue('\x1b');v.loop([(TSE+0x1b928,[1,2]),('n05_first',[]),lambda w:assert_main(w),(TSE+0x1b928,[1,3]),lambda w:assert_security(w),(TSE+0x1b814,[3,DATA+0x29000,DATA+0x29008])])
  assert v.sequence_values[1]==2 and v.sequence_values[-1]==0 and int.from_bytes(v.r(DATA+0x29000,2),'little')==1 and not v.set_count and v.hist()not in v.free_trace,(v.sequence_values,v.free_trace,v.hist())
 def assert_main(v):assert v.main_ok()
 def assert_security(v):
  p=v.hist();assert v.used()==2 and v.r(p+32,28)==Q(v.setup_hii)+I(0x271d)+bytes(4)+Q(v.setup_hii)+I(0x2712)
 case('Escape with owned nonempty history returns Main and native next/back works',cancel)
 def empty(v):
  v.ready();v.queue('\x1b');v.loop([('n05_first',[]),lambda w:assert_empty_main(w),(TSE+0x1b928,[0,1]),lambda w:assert_main(w)])
  assert v.sequence_values[0]==2 and not v.set_count
 def assert_empty_main(v):assert v.index()==1 and not v.hist()and not v.used()
 case('Escape before first history allocation returns usable Main',empty)
 def wrong(v):
  v.ready();v.queue('WrongPassword!42\r!');v.loop([(TSE+0x1b928,[1,2]),('n05_first',[])]);assert v.sequence_values[-1]==2 and v.main_ok()and not v.set_count
 case('wrong password with nonempty history returns Main without credential write',wrong)
 def correct(v):
  v.ready();v.queue(ns['core'].PW.decode()+'\r');v.loop([(TSE+0x1b928,[1,2]),('n05_first',[])]);assert v.sequence_values[-1]==1 and v.index()==2 and v.used()==1 and not v.set_count
 case('correct password preserves current page and history',correct)
 def old(v):
  v.ready();old=DATA+0x2a000;v.w(old,Q(v.setup_hii)+I(0x2713)+bytes(20));v.w(TSE+0xafde8,Q(old));v.w(TSE+0xafde0,I(416));v.w(TSE+0xafe00,I(1));v.w(TSE+0xafddc,I(70));v.queue('\x1b')
  before=v.r(old,32);v.loop([('n05_first',[])]);assert v.sequence_values==[0]and v.index()==2 and v.r(old,32)==before and old not in v.free_trace
 case('hardware-shaped unknown history never becomes owned writable storage',old)
 def fault(v):
  v.ready();v.loop([(TSE+0x1b928,[1,2]),('w890_provider_fault',[]),('n05_first',[]),('n05_check',[2,v.page_list[1],0]),('n05_check',[2,v.page_list[2],0])])
  assert v.sequence_values[-3:]==[2,0,ns['ERR'](15)]and v.main_ok()
 case('credential FAULT keeps proven Main usable and still denies Ai Tweaker',fault)
 filename='navigation_pe_tests.json'if len(sys.argv)==1 else'navigation_selected_tests.json'
 (H/'build'/filename).write_text(json.dumps({'component_sha256':IMAGE_SHA,'sources':SOURCES,'checks':len(cases),'cases':cases,'boundary':'CPU/UEFI/native page construction and BrowserLoop body are fixtures; no physical owner claim; actual original history functions and actual compiled navigation/provider/UI execute'},indent=2)+'\n')
 print('PASS',len(cases))

if __name__=='__main__':main()
