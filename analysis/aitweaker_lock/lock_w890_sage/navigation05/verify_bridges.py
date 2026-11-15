"""Actual guard bridges + exact original dispatch/first/FormOpen instructions.
UEFI, CPU map and outer GUI containers are fixtures. No fabricated owner bool.
"""
from pathlib import Path
import sys,json,re,struct,hashlib,time,ast
import verify_navigation as n
from verify_navigation import m,ns,H,B,TSE,DATA,Q,I
from unicorn.x86_const import *
import pefile
O=H/('bridges_next'if '--next'in sys.argv else'bridges_build')
if '--next'in sys.argv:sys.argv.remove('--next')
DLL=O/'W890NavigationBridges05.TESTONLY.dll';SHA=hashlib.sha256(DLL.read_bytes()).hexdigest()
m.OP.close();m.OP=pefile.PE(str(DLL));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
m.OS={e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols};m.SY={k:int(v,16)for k,v in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(O/'navigation.map').read_text(),re.M)}
n.OS=m.OS;n.SY=m.SY;ns['SYMBOLS']=m.SY;OS=m.OS;SY=m.SY
n.CALLS=json.loads((O/'consumer_windows.json').read_text());PLAN=json.loads((O/'static_hook_plan.json').read_text())
SOURCES={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in [Path(__file__),H/'bridges.c',H/'first_bridge.S',H/'verify_navigation.py',H/'visit/observer_visit05.c']}

class VM(n.VM):
 def __init__(self):
  super().__init__();self.defer_prepare=False;self.wait_hook=ns['HOOK']+0x6a00;self.w(self.wait_hook,b'\xc3');self.w(self.bs+0x60,Q(self.wait_hook));self.w(self.input+16,Q(0x990050))
  self.waits=0;self.end_at_wait=0;self.change_input_at_wait=False;self.terminal=False;self.observe_native=[];self.stop_before={};self.efi_after_end=[];self.did_end=False
  # Dispatch Python models only at their declared boundaries. Unicorn still
  # executes every target instruction; this does not replace native code.
  self.interesting=set(OS.values())|set(SY.values())|set(self.hooks.values())|set(self.oh.values())|{ns['STOP'],ns['TAIL'],self.wait_hook,self.stepdone,self.copyhook}
  self.interesting.update(TSE+x['resume_rva']for x in m.WINDOWS)
  self.interesting.update(TSE+x for x in [0x10648,0xfc40,0x59b50,0x19106,0x37126,0x3f423,0x1946b,0x40094,0x2372c,0x238bc,0x21ef4,0x71540])
 def hook(self,u,address,size,opaque):
  if hasattr(self,'interesting')and address not in self.interesting and address!=self.target_stop and address!=self.stop_native and address not in self.stop_before:return
  if hasattr(self,'wait_hook'):
   if self.did_end and address in list(self.hooks.values())+list(self.oh.values())+[self.wait_hook]:self.efi_after_end.append(address)
   if address==self.wait_hook:
    assert self.current_tpl==4 and self.arg(0)==1 and self.q(self.arg(1))==0x990050
    self.waits+=1;self.w(self.arg(2),Q(0))
    if self.end_at_wait==self.waits:self.did_end=True;self.nested(OS['no_end_boot'],[0,0],0);return
    if self.change_input_at_wait:self.w(self.st+0x30,Q(0x12345000))
    self.ret(0);return
   if address==OS['n05_recovery_terminal']:self.terminal=True;u.emu_stop();return
   if address in self.stop_before:self.observe_native.append(address-TSE);self.ret(self.stop_before[address]);return
   if TSE<=address<TSE+0xde000 and address in [TSE+0x3f423,TSE+0x1946b,TSE+0x40094,TSE+0x2372c,TSE+0x238bc,TSE+0x21ef4,TSE+0x71540]:self.observe_native.append(address-TSE)
  return super().hook(u,address,size,opaque)
 def run(self,name,*args,**kw):
  if self.defer_prepare and name=='no_prepare':return 0
  return super().run(name,*args,**kw)
 def packet(self):
  # The inherited method emits data/trampolines; defer its sole validation
  # until the whole 34-entry packet exists, then call real no_prepare once.
  self.defer_prepare=True;super().packet();self.defer_prepare=False
  for i,r in enumerate(PLAN['records']):
   rva,sz,target=r['rva'],r['length'],OS[r['export']];before=self.r(TSE+rva,sz)
   if r['kind']=='pointer64':after=Q(target)
   elif rva==0x3f414:
    after=b'\xff\x25'+bytes(4)+Q(target)+b'\x90';tr=ns['HOOK']+0xa500
    self.w(tr,before+b'\xe9'+struct.pack('<i',TSE+0x3f423-(tr+20)));self.w(OS['n05_form_open_trampoline'],Q(tr))
   else:
    relay=ns['HOOK']+0xa600+i*0x20;self.w(relay,b'\xff\x25'+bytes(4)+Q(target))
    after=bytes([0xe8 if r['kind']=='call'else 0xe9])+struct.pack('<i',relay-(TSE+rva+5))+b'\x90'*(sz-5)
   self.specs.append(struct.pack('<4I',0,rva,sz,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
  assert len(self.specs)==34;self.w(self.patches,b''.join(self.specs));self.w(self.inst+48,I(len(self.specs)))
  return self.run('no_prepare',self.inst)
 def ready(self):
  assert self.initialize()==0 and self.run('n05_bind')==0 and self.run('n05_bridges_bind')==0 and self.packet()==0
  self.apply();assert self.bind_real_host()==0;self.pages();self.free_trace.clear()
 def control_fixture(self,kind=1):
  # Canonical original numeric IFR and actual registry type4, source Ai page.
  current=0;at=4;op=None
  while at<len(m.FORMS):
   sz=m.FORMS[at+1]&127
   if m.FORMS[at]==1:current=struct.unpack_from('<H',m.FORMS,at+2)[0]
   if current==0x2713 and m.FORMS[at]in(5,7):op=m.FORMS[at:at+sz];break
   at+=sz
  assert op;self.w(self.opcode,op);self.w(self.control,Q(TSE+0xa5380));self.w(self.control+0x20,Q(self.setup_hii));self.w(self.control+0x34,struct.pack('<H',4));self.w(self.control+0x3c,b'\x01');self.w(self.control+0x48,Q(self.opcode))
  self.w(self.page_list[2]+0x4c,I(1)+Q(self.fa));self.w(self.fa,Q(self.framep));self.w(self.framep+0x3c,I(1));self.w(self.framep+0x44,I(0)+Q(self.ca));self.w(self.ca,Q(self.control))
  pd=self.blob+0x200;self.w(pd+0x1c,I(1)+I(0));self.w(self.cb,Q(self.setup_hii));self.w(self.cb+0x14,struct.pack('<H',4));self.w(self.cb+0x28,Q(self.opcode))
  self.ev=DATA+0x2e000;self.w(self.ev,bytes(0x30));self.w(self.ev+8,struct.pack('<H',kind))
 def page_tail(self):
  return(TSE+0x23aa8,[self.framep,self.ev],{UC_X86_REG_RSP:ns['STACK']+0x1e0000,UC_X86_REG_RBP:DATA+0x2c000,UC_X86_REG_RBX:self.page_list[2],UC_X86_REG_RSI:self.ev,UC_X86_REG_R14:0,UC_X86_REG_R13:0},TSE+0x23b05)
 def extra_fixture(self,scan=0x14,unknown=False,mouse=False):
  self.w(self.app+0x28,I(1));self.ev=DATA+0x2e000;self.w(self.ev,bytes(0x30));self.w(self.ev+8,struct.pack('<H',3 if mouse else 1))
  self.extra=DATA+0x2e100;array=DATA+0x2e200;self.w(self.extra,bytes(0x40));self.w(array,Q(self.extra))
  self.w(self.app+0x38,bytes(0x20));self.w(self.app+(0x48 if mouse else 0x38),Q(1)+Q(array))
  self.w(self.extra,Q(TSE+(0x93e70 if mouse else 0x93ea0))+Q(TSE+(0x4af48 if mouse else 0x4ae8c))+Q(self.app)+Q(0))
  if mouse:
   self.w(self.extra+0x20,struct.pack('<5I',1,3,65,29,0));self.w(self.ev+0xc,I(10)+I(20))
  else:
   self.w(self.extra+0x20,struct.pack('<3I',0x14,0,0));self.w(self.ev+0xc,struct.pack('<HH',scan,0))
  if unknown:self.w(self.extra+8,Q(TSE+0x1234))
  self.w(TSE+0x93a68,I(0));self.w(TSE+0x93a70,I(0))

def main():
 cases=[]
 def case(name,fn):
  if len(sys.argv)>1 and not any(x.lower()in name.lower()for x in sys.argv[1:]):return
  start=time.time();v=VM();fn(v);cases.append({'name':name,'status':'PASS','seconds':round(time.time()-start,3)});print(name,flush=True)
  (O/'progress.json').write_text(json.dumps({'sha256':SHA,'cases':cases},indent=2)+'\n')
 def first(v):
  v.ready();v.queue('\x1b');v.loop([v.partial_first()]);assert v.index()==1 and v.main_ok()and 0x1946b in v.observe_native and not v.terminal and v.waits==0
 case('actual first inline bridge Escape replays native window on Main',first)
 def frame(v,kind=1):
  v.ready();v.control_fixture(kind)
  if kind==1:v.queue('\x1b')
  v.loop([v.page_tail()]);assert v.sequence_values[-1]==0 and 0x21ef4 in v.observe_native and 0x71540 not in v.observe_native
  assert v.index()==2 and v.set_count==0
 case('original Page then original Frame dispatch consumes denied control as zero',frame)
 case('original kind2 fanout never prompts or invokes a locked control',lambda v:frame(v,2))
 def render(v):
  v.ready();v.stop_before[TSE+0x2372c]=0x42;v.loop([('w890_provider_fault',[]),('n05_native_render',[v.page_list[1]])]);assert v.sequence_values[-1]==0x42 and v.observe_native.count(0x2372c)==1
 case('safe Main render bridge reaches original method despite credential FAULT',render)
 def unknown(v):
  v.ready();v.loop([('w890_provider_fault',[]),('n05_native_render',[v.page_list[2]])]);assert v.sequence_values[-1]==0 and v.index()==1 and 0x2372c not in v.observe_native
 case('protected render refusal selects Main without invoking old renderer',unknown)
 def app(v,scan=0x11,unknown=False):
  v.ready();v.extra_fixture(scan,unknown);v.stop_before[TSE+0x1fc84]=0
  v.loop([('n05_native_app_input',[v.app,v.ev])]);assert v.sequence_values==[0 if unknown or scan==0x14 else ns['ERR'](3)],v.sequence_values
  assert (0x1fc84 in v.observe_native)==(scan==0x14 and not unknown) and v.set_count==0
  if scan==0x14:assert v.r(v.app+0x5a,1)==b'\0'
 case('ordinary F7 key retains original unsupported fallthrough',app)
 case('original F10 hotkey reaches native save-confirm destination',lambda v:app(v,0x14))
 case('unknown hotkey callback is consumed before native dispatch',lambda v:app(v,0x14,True))
 def unknown_menu(v):
  v.ready();v.extra_fixture(0x11);cookie=TSE+0x94758;v.w(cookie,I(8)+I(0)+struct.pack('<H',3))
  page=v.page_list[1];v.w(page+0x4c,I(1)+Q(v.fa));v.w(v.fa,Q(v.framep));v.w(v.framep+0x20,I(4));v.w(v.framep+0x3c,I(1));v.w(v.framep+0x48,Q(v.ca));v.w(v.ca,Q(v.control));v.w(v.control,Q(TSE+0x95680));v.w(v.control+0x10,Q(v.framep)+Q(cookie))
  v.w(v.page_list[3]+0x20,Q(0x900099))
  v.loop([('n05_menu',[v.app,v.control,cookie]),('n05_native_app_input',[v.app,v.ev])])
  assert v.sequence_values==[ns['ERR'](15),ns['ERR'](3)]and v.index()==1 and not v.set_count
 case('unknown menu target stays on Main and does not swallow the following F7 key',unknown_menu)
 def mouse(v):
  v.ready();v.extra_fixture(mouse=True);v.stop_before[TSE+0x4af48]=0
  v.loop([('n05_native_alt_input',[v.extra,v.ev])]);assert v.sequence_values==[0]and 0x4af48 in v.observe_native and not v.set_count
 case('original mouse hit-test reaches exact native region callback',mouse)
 def recovery(v,swap=False):
  v.ready();v.queue('x');v.change_input_at_wait=swap;v.loop([('n05_recovery_poll',[v.app])]);assert v.waits==1 and v.sequence_values==[2 if swap else 0]and not v.set_count
 case('recovery waits at TPL_APPLICATION and reads one explicit key',recovery)
 case('recovery detects Input substitution after Wait before dereference',lambda v:recovery(v,True))
 def ended(v):
  v.ready();v.w(TSE+0xafde8,Q(DATA+0x2b000));v.w(TSE+0xafde0,I(416));v.w(TSE+0xafe00,I(1));v.queue('\x1bR');v.end_at_wait=2
  try:v.loop([v.partial_first()])
  except AssertionError as e:assert v.terminal and v.u.reg_read(UC_X86_REG_RIP)==OS['n05_recovery_terminal'],e
  else:raise AssertionError('unknown first entry escaped recovery')
  assert v.waits==2 and 0x1946b not in v.observe_native and not v.efi_after_end and not v.set_count and 'could not be verified'in v.transcript
 case('unknown first identity waits then EBS stops every UEFI call and native continuation',ended)
 def pending(v):
  v.ready();v.w(TSE+0xaff30,Q(DATA+0x2b000));v.w(DATA+0x2b000,Q(1)+Q(DATA+0x2b100)+Q(DATA+0x2b100))
  v.loop([(TSE+0x239e7,[0,0,0],{UC_X86_REG_RSP:ns['STACK']+0x1e0000},TSE+0x239ec)]);assert v.sequence_values==[ns['ERR'](15)]and 0x40094 not in v.observe_native
 case('actual pending CALL is denied before unknown producer batch',pending)
 def empty_pending(v,head=False):
  v.ready();v.w(TSE+0xaff30,Q(DATA+0x2b000 if head else 0));v.w(DATA+0x2b000,bytes(24));v.w(TSE+0xaff20,b'\x01\x01\x00\x00')
  v.loop([(TSE+0x239e7,[0,0,0],{UC_X86_REG_RSP:ns['STACK']+0x1e0000},TSE+0x239ec)])
  assert v.sequence_values==[ns['ERR'](14)]and 0x40094 in v.observe_native and v.r(TSE+0xaff20,4)==b'\x00\x01\x00\x01'and not v.set_count
 case('null pending queue preserves original not-found result and flag cleanup',empty_pending)
 case('allocated but fully empty pending head preserves original empty branch',lambda v:empty_pending(v,True))
 def nativeid(v):
  v.ready();v.loop([('no_native_visit_identity',[v.out,v.out+8])]);assert v.sequence_values==[1]and v.q(v.out)!=0 and v.r(v.out+8,4)==bytes(4)
  assert v.run('no_native_visit_identity',v.out,v.out+8)==0
 case('private native visit identity expires when actual Loop scope returns',nativeid)
 def cold_fault(v):
  v.ready();v.run('w890_provider_fault');assert v.run('no_native_loop',return_to=TSE+0xb8e1)==ns['ERR'](15)and not v.original_body
 case('incomplete immutable fault catalogue cannot release a credential-fault native body',cold_fault)
 report={'component_sha256':SHA,'sources':SOURCES,'checks':len(cases),'cases':cases,'limitations':['UEFI and outer native GUI containers modeled','safe render positive verifies arrival at original method; full drawing not executed','F10 executes original hotkey callback to save-confirm boundary; actual save effects covered separately','mouse executes original hit-test to original callback boundary; callback effects not modeled here','F7 is absent from the original nine hotkey descriptors and preserves unsupported fallthrough','unknown hotkey objects and nonempty pending producer batches remain denied','failed Begin still closed pending fixed complete effect catalogue','no hardware install or flash image']}
 (O/('bridge_tests.json'if len(sys.argv)==1 else'bridge_selected_tests.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(cases))

if __name__=='__main__':main()
