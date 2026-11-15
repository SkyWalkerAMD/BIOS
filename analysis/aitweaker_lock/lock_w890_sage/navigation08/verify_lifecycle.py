"""Original lifecycle runs with narrow compiled lock; unknown services stop.

No original native callee is replaced with a successful return. The original
Loop middle and outer containers are explicit fixtures. Declared standard
UEFI protocol/free services implement checked synthetic object state only.
"""
from pathlib import Path
import sys,json,hashlib,re,struct,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;O=H/'build';sys.path.insert(0,str(B/'navigation05'))
import verify_form_open as f
b=f.b;n=b.n;m=b.m;ns=b.ns;TSE=b.TSE;DATA=b.DATA;Q=b.Q;I=b.I
from unicorn.x86_const import *
from unicorn import UC_HOOK_MEM_INVALID
import pefile
DLL=O/'W890Navigation08Lifecycle.TESTONLY.dll';SHA=hashlib.sha256(DLL.read_bytes()).hexdigest();SOURCE_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();ORIG=pefile.PE(str(B/'navigation/modules/AMITSE.efi'))
m.OP.close();m.OP=pefile.PE(str(DLL));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
OS=m.OS;OS.clear();OS.update({e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols})
SY=m.SY;SY.clear();SY.update({k:int(v,16)for k,v in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(O/'navigation.map').read_text(),re.M)})
ns['SYMBOLS']=SY;n.CALLS=json.loads((O/'consumer_windows.json').read_text());PLAN=json.loads((O/'static_hook_plan.json').read_text())
class VM(f.VM):
 def __init__(self):
  super().__init__();self.defer08=False;self.unknown=None;self.full_tail=False;self.native_calls=[];self.protocols={};self.events=[];self.console_events=[];self.boundary=None;self.service_errors={};self.owned_buffers={};self.after_end=False;self.event_failure=None;self.notify_failure=None
  self.reset_console=ns['HOOK']+0xd100;self.uninstall=ns['HOOK']+0xd200;self.w(self.reset_console,b'\xc3');self.w(self.uninstall,b'\xc3');self.w(self.console,Q(self.reset_console));self.w(self.bs+0x150,Q(self.uninstall));self.interesting.update([self.reset_console,self.uninstall])
  self.protocol_notify=ns['HOOK']+0xd300;self.w(self.protocol_notify,b'\xc3');self.w(self.bs+0xa8,Q(self.protocol_notify));self.interesting.add(self.protocol_notify)
  self.interesting.update(TSE+r for r in [0x1910d,0x196ec,0x196f7,0x1995f,0x19973,0x19994,0x19a76,0x748c,0x189a4,0x1d6e8,0xfd18,0xfcb4,0x64b2c,0x80b8c,0x540fc,0x3e700])
  self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
 def invalid(self,u,access,address,size,value,opaque):
  self.unknown={'kind':'unmapped native/service state','pc':hex(u.reg_read(UC_X86_REG_RIP)),'address':hex(address),'size':size};return False
 def run(self,name,*args,**kw):
  if self.defer08 and name=='no_prepare':return 0
  return super().run(name,*args,**kw)
 def packet(self):
  self.defer08=True;n.VM.packet(self);self.defer08=False
  for i,r in enumerate(PLAN['records']):
   rva,sz,target=r['rva'],r['length'],OS[r['export']];before=self.r(TSE+rva,sz)
   if r['kind']=='pointer64':after=Q(target)
   else:
    relay=ns['HOOK']+0xa600+i*0x20;self.w(relay,b'\xff\x25'+bytes(4)+Q(target));after=bytes([0xe8 if r['kind']=='call'else 0xe9])+struct.pack('<i',relay-(TSE+rva+5))+b'\x90'*(sz-5)
   self.specs.append(struct.pack('<4I',0,rva,sz,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
  assert len(self.specs)==32;self.w(self.patches,b''.join(self.specs));self.w(self.inst+48,I(len(self.specs)))
  return self.run('no_prepare',self.inst)
 def ready_full(self):
  super().ready_full()
  for rva in [0xba9b8,0xba9c8,0xba9d8]:self.w(TSE+rva,f.p['MAPPED'][rva:rva+4])
  # Original parser produced this variable-descriptor table in the same
  # immutable pool snapshot. Do not manufacture neighboring pointers.
  for rva in [0xbaaf8,0xbaac0]:self.w(TSE+rva,f.p['MAPPED'][rva:rva+8])
  for lo,hi in [(0x748c,0x749a),(0x3f414,0x3f423),(0x1995f,0x1996f),(0x239e7,0x239ec)]:assert self.r(TSE+lo,hi-lo)==ORIG.get_data(lo,hi-lo)
 def stop_unknown(self,kind,**data):self.unknown={'kind':kind,**data};self.u.emu_stop()
 def hook(self,u,address,size,opaque):
  if hasattr(self,'unknown'):
   if address==TSE+0x3e700:
    self.stop_unknown('original callback business/service boundary',descriptor=self.arg(0),qid=self.arg(1),action=self.arg(3));return
   if address==self.reset_console:
    assert self.arg(0)==self.console and self.arg(1)==0
    self.console_events.append('Reset');self.w(self.outmode+12,I(0)+I(0));self.ret(self.service_errors.get('Reset',0));return
   if address in [self.hooks['clear'],self.hooks['enable']]:self.console_events.append('ClearScreen'if address==self.hooks['clear']else'EnableCursor')
   if address==self.uninstall:
    key=(self.arg(0),self.arg(1),self.arg(2));assert key in self.protocols,tuple(hex(x)for x in key)
    self.protocols.pop(key);self.events.append('UninstallProtocolInterface');self.ret(self.service_errors.get('UninstallProtocolInterface',0));return
   if self.full_tail:
    if address==TSE+0x19106:return
    if address==TSE+0x1910d:
     self.body_sp=u.reg_read(UC_X86_REG_RSP);self.w(self.body_sp+0xf8,Q(self.original_status));self.w(self.body_sp+0x40,Q(0x880800));u.reg_write(UC_X86_REG_RBX,0);u.reg_write(UC_X86_REG_RDI,self.main);u.reg_write(UC_X86_REG_RSI,0);u.reg_write(UC_X86_REG_R12,0);u.reg_write(UC_X86_REG_R13,1);u.reg_write(UC_X86_REG_R14,0);u.reg_write(UC_X86_REG_R15,0)
     if self.start_rva==0x19235:u.reg_write(UC_X86_REG_RAX,self.original_status)
     if self.start_rva==0x19370:u.reg_write(UC_X86_REG_RCX,self.app);u.reg_write(UC_X86_REG_RDI,0);self.w(self.app+0x30,Q(0))
     u.reg_write(UC_X86_REG_RIP,TSE+self.start_rva);return
    if address==self.hooks['create']and self.event_failure is not None:
     assert self.arg(0)==0x200 and self.arg(1)==8 and self.arg(2)==TSE+0x7650 and self.arg(3)==0
     self.events.append('CreateEvent failure');self.ret(self.event_failure);return
    if address==self.protocol_notify:
     assert self.notify_failure is not None and self.arg(0)==TSE+0x93588 and self.arg(1)==0x880800
     self.events.append('RegisterProtocolNotify failure');self.ret(self.notify_failure);return
    if TSE<=address<TSE+0xde000 and address in self.interesting:self.native_calls.append(address-TSE)
    if address==self.hooks['free']:
     ptr=self.arg(0)
     if ptr not in self.owned_buffers:self.stop_unknown('unproven FreePool object',pointer=hex(ptr));return
     length=self.owned_buffers.pop(ptr);self.w(ptr,bytes([0xdd])*length);self.events.append('FreePool');self.ret(0);return
   if self.boundary==address:self.stop_unknown('selected original boundary',pc=hex(address));return
  return super().hook(u,address,size,opaque)
 def full(self,original_status=0,start=0x1995f,retained=True,reset=0):
  self.w(self.app+0x28,I(self.main));self.w(self.app+0x58,b'\0\0\1');self.w(TSE+0xbaa68,Q(0));self.w(TSE+0xafd00,Q(3 if retained else 0));self.w(TSE+0xafdc8,bytes([reset]));self.w(TSE+0xbaab8,Q(0x712340));self.protocols[(0x712340,TSE+0x93cd8,TSE+0x93ce8)]=True
  hp=DATA+0x2b000;self.w(hp,bytes(32));self.owned_buffers[hp]=32;self.w(TSE+0xafde8,Q(hp));self.w(TSE+0xafddc,I(70));self.w(TSE+0xafe00,I(1))
  self.full_tail=True;self.original_status=original_status;self.start_rva=start
  try:r=self.run('no_native_loop',return_to=TSE+0xb8e1)
  except Exception:
   if not self.unknown:raise
   return None
  finally:self.full_tail=False
  return r
 def empty_outer_frames(self):
  # A bounded synthetic outer-container premise, not original parser output
  # or a claim about the physical Main page. Native cleanup sees empty frame
  # controls and executes its own no-free branches; no callee is stubbed.
  array=DATA+0x2d000;frames=[DATA+0x2d100+0x80*i for i in range(6)]
  self.w(array,b''.join(Q(x)for x in frames));self.w(self.page_list[self.main]+0x4c,I(6)+Q(array))
  for p in frames:self.w(p,bytes(0x58))
def main():
 cases=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(x.lower()in name.lower()for x in sys.argv[1:]):return
  v=VM();t0=time.time()
  try:details=fn(v)
  except Exception as e:
   (O/('failure_'+str(time.time_ns())+'.json')).write_text(json.dumps({'name':name,'error':repr(e),'unknown':v.unknown,'trace':v.native_calls,'component_sha256':SHA},indent=2)+'\n');raise
  cases.append({'name':name,'status':'PASS','seconds':round(time.time()-t0,3),'observations':details});print(name,details,flush=True)
 def form(v,action):
  v.ready_full();v.w(TSE+0x93aa0,b'\0\0');v.w(DATA+0x2a000,I(0));v.loop([(TSE+0x3f414,[v.raw(v.main),action,DATA+0x2a000])]);assert v.sequence_values==[0]and not v.unknown and not v.set_count;return {'original_result':0,'action':action}
 case('unpatched original Main FORM_OPEN3 returns its own result',lambda v:form(v,3))
 case('unpatched original Main FORM_CLOSE4 returns its own result',lambda v:form(v,4))
 def callback(v):
  v.ready_full();v.w(TSE+0x93aa0,b'\0\0')
  try:v.loop([(TSE+0x3f414,[v.raw(v.security),4,DATA+0x2a000])])
  except AssertionError:assert v.unknown and v.unknown['kind']=='original callback business/service boundary'
  else:raise AssertionError('unknown original callback was treated as complete')
  assert v.unknown['action']==4 and not v.set_count;return v.unknown
 case('Security close reaches unchanged callback boundary without fabricated return',callback)
 def full(v,retained=True,status=None,start=0x1995f):
  status=ns['ERR'](14)if status is None else status
  v.ready_full();v.empty_outer_frames();result=v.full(status,start=start,retained=retained)
  if v.unknown:
   assert not retained,('unexpected normal-return failure',v.unknown)
   return {'status':'STOPPED_UNKNOWN','boundary':v.unknown,'trace':v.native_calls,'known_services':v.events}
  assert result==status and not v.set_count and not v.protocols and v.q(TSE+0xafde8)==0 and v.used()==0
  assert v.console_events==['Reset','ClearScreen','EnableCursor']and v.q(TSE+0xafdd0)==v.app
  return {'status':'ORIGINAL_RETURNED','return':hex(result),'known_services':v.events,'console':v.console_events,'private_provider_after':v.run('w890_provider_query',v.p)}
 case('original normal tail with exact retained-App predicate',full)
 case('original successful normal return preserves status0 and closes private session',lambda v:full(v,status=0))
 case('original pre-loop exit196F7 takes native19973 without forced cancellation',lambda v:full(v,status=0,start=0x196ec))
 case('original no-page-array branch19370 reaches19994 without inventing an input loop',lambda v:full(v,status=0,start=0x19370))
 def early(v,kind):
  v.ready_full();v.empty_outer_frames();status=ns['ERR'](9 if kind=='create'else 7 if kind=='notify'else 14)
  if kind=='create':v.event_failure=status;start=0x1968f
  elif kind=='notify':v.notify_failure=status;start=0x196c0
  else:start=0x19235
  result=v.full(status,start=start)
  assert not v.unknown and result==status and not v.set_count and v.run('w890_provider_query',v.p)==1
  assert v.q(TSE+0xafde8)!=0 and v.used()==1 and v.protocols
  if kind!='init':assert not v.console_events and 0x748c not in v.native_calls
  return {'status':'ORIGINAL_RETURNED','return':hex(result),'known_services':v.events,'native_trace':v.native_calls,'premise':'init test starts at the original return-site slice after an unspecified failing native initializer; initializer itself is not replaced or executed'if kind=='init'else'exact standard UEFI service failure model'}
 case('original CreateEvent failure directly returns without entering GUI or teardown',lambda v:early(v,'create'))
 case('original RegisterProtocolNotify failure directly returns and ends password session',lambda v:early(v,'notify'))
 case('native initializer failure return-site preserves original19A76 cleanup and status',lambda v:early(v,'init'))
 case('original full-cleanup branch stops at first unproven object/service',lambda v:full(v,False))
 report={'component_sha256':SHA,'source_sha256':SOURCE_SHA,'checks':len(cases),'cases':cases,'boundary':'PASS means expected bounded behavior including STOPPED_UNKNOWN; only ORIGINAL_RETURNED denotes a completed original return. No unknown native function is assigned success.'}
 (O/('lifecycle_tests.json'if len(sys.argv)==1 else'lifecycle_selected_tests.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases))
if __name__=='__main__':main()
