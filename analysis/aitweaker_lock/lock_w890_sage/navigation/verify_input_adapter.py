"""Compiled input adapter -> original control/frame/page and pending boundaries.

Runtime02 actual masked UI and provider execute. UEFI, native-owner/IFR authority
and producer/effect classification are fixtures; PBKDF uses the Python oracle.
"""
from pathlib import Path
import sys,ctypes,struct,json
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'integration/native02'))
from verify_runtime_chain import RuntimeChain,rt,SYMBOLS,CORE,HOOK,STACK,BASE,GBASE,DATA,APP,PAGES,COOKIE,ROWS,GATE,BS,OBSERVE,FREE,Snapshot,sha,ERR,q,ORIGINAL_SHA,GATE_SHA,RUNTIME_SHA,STOP
import pefile
from unicorn.x86_const import *
IBASE=0x0a000000;BIND=DATA+0xe000;FRAME=DATA+0x10000;CARRAY=DATA+0x17000;EVENT=DATA+0x16000
SCOPE=HOOK+0x5000;RANGE=HOOK+0x5100;EFFECT=HOOK+0x5200
DLL=HERE/'build/W890InputAdapter.TESTONLY.dll';BUILD=json.loads((HERE/'build/input_build.json').read_text());assert sha(DLL)==BUILD['sha256']
REGISTRY=json.loads((HERE/'control_registry_0603.json').read_text())['items']
class InputBinding(ctypes.Structure):
 _fields_=[(n,ctypes.c_uint64)for n in ['abi','native_base','gate','check','opaque','range','scope','effects','menu_callback']]+[('busy',ctypes.c_uint32),('reserved',ctypes.c_uint32)]
class Effects(ctypes.Structure):
 _fields_=[(n,ctypes.c_uint64)for n in ['session','epoch','producer_root','list_root']]+[(n,ctypes.c_uint32)for n in ['count','proof','classification','reserved']]+[('digest',ctypes.c_ubyte*32)]

class InputVM(RuntimeChain):
 def __init__(self,protected=(True,),*,kind=1,menu=False):
  self.controls=[];self.scope_ok=True;self.scope_seen=[];self.pending_class=1;self.effect_calls=0;self.effect_change=False;self.translate=0;self.translations=0;self.page_stop=None;self.pending_stop=False;self.control_ifr_unknown=False;self.menu_mode=menu;self.lose_owner_after_scope=False
  super().__init__()
  p=pefile.PE(str(DLL));p.relocate_image(IBASE);self.u.mem_map(IBASE,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.w(IBASE,p.get_memory_mapped_image());self.iexports={e.name.decode():IBASE+e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
  for row in REGISTRY:
   slot=BASE+row['input_slot_rva'];before=self.Q(slot)
   assert before in [BASE+row['input_rva'],self.iexports['wi_control']];self.w(slot,q(self.iexports['wi_control']))
  self.w(BIND,bytes(InputBinding(0x3130304930393857,BASE,GATE,self.exports['wg_check'],DATA,RANGE,SCOPE,EFFECT,self.exports['wg_native_menu_thunk'],0,0)))
  self.w(self.iexports['wi_binding'],q(BIND))
  self.w(BASE+0x239e7,b'\xe8'+struct.pack('<i',self.iexports['wi_pending']-(BASE+0x239ec)))
  self.w(FRAME+0x3c,struct.pack('<I',len(protected)));self.w(FRAME+0x44,bytes(4));self.w(FRAME+0x48,q(CARRAY));self.w(EVENT+8,struct.pack('<H',kind))
  self.w(APP+0x28,struct.pack('<I',2));self.w(PAGES[2]+0x2a,struct.pack('<H',0x2712));self.w(PAGES[2]+0x4c,struct.pack('<I',1))
  for i,yes in enumerate(protected):
   c=DATA+0x11000+i*0x100;ifr=DATA+0x15000+i*0x100;self.controls.append(c);self.w(CARRAY+i*8,q(c));self.w(c,q(BASE+(0x95680 if menu else 0xa5250)))
   self.w(c+0x34,struct.pack('<H',14 if menu else 3));self.w(c+0x3c,b'\1\1');self.w(c+0x48,q(ifr));self.w(c+0x20,q(DATA+0xc000));self.w(c+0x88,b'\2')
   self.w(ifr,struct.pack('<BB5HBB',6,14,1,2,0xf000+i,35 if yes else 0,0,0,0))
   if menu:
    self.w(c+8,q(self.exports['wg_native_menu_thunk']));self.w(c+0x10,q(APP));self.w(c+0x18,q(COOKIE));self.w(c+0x80,q(ROWS));self.w(c+0x72,struct.pack('<HH',3,1));self.translate=2
  self.w(BASE+0xaff30,q(0));self.w(BASE+0xaff20,b'\1');self.w(BASE+0xaff23,b'\0')
 def hook(self,u,a,size,data):
  if a in [BASE+0x23b05,BASE+0x23ac1]:self.page_stop=a-BASE;u.emu_stop();return
  if a==BASE+0x239ec:self.pending_stop=True;u.emu_stop();return
  if a==BASE+0xff10:self.translations+=1;self.ret(self.translate);return
  if a in [BASE+0x21e68,BASE+0x3fed4]:self.ret(0);return
  if a==RANGE:
   p,n=self.arg(1),self.arg(2);self.ret(int((BASE<=p and p+n<=BASE+0xde000)or(DATA<=p and p+n<=DATA+0x20000)));return
  if a==SCOPE:
   c,e,kind,table,target=[self.arg(i)for i in range(1,6)];self.scope_seen.append(c)
   allowed=any(kind==r['type']and table==BASE+r['vtable_rva']and target==BASE+r['input_rva']for r in REGISTRY)
   result=int(self.scope_ok and c in self.controls and e==EVENT and allowed and self.active and self.profile)
   if self.lose_owner_after_scope and len(self.scope_seen)==2:self.active=False
   self.ret(result);return
  if a==OBSERVE and self.arg(1)==4:
   c=self.arg(2);assert c in self.controls and self.arg(3)==EVENT
   self.observations+=1;s=Snapshot();s.session=self.Q(self.out);s.native_base=BASE;s.application=APP;s.application_index=2;s.page_index=2;s.page=PAGES[2];s.hii=DATA+0xc000;s.control=c;s.form=0x2712;s.owner=1;s.proof=63;s.ifr_size=14
   s.formset[:]=rt['uuid'].UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le;s.ifr[:14]=self.r(self.Q(c+0x48),14)
   if self.control_ifr_unknown:s.ifr[0]=0xff
   s.history=self.Q(BASE+0xafde8);s.history_count=self.dword(BASE+0xafe00);s.history_root=self.dword(BASE+0xafddc);self.w(self.arg(4),bytes(s));self.ret(1);return
  if a==EFFECT:
   self.effect_calls+=1;x=Effects();x.session=self.Q(self.out);x.epoch=7+int(self.effect_change and self.effect_calls==2);x.producer_root=DATA+0x18000;x.list_root=0;x.count=0;x.proof=31;x.classification=self.pending_class if self.pending_class>=0 else 0xffffffff
   self.w(self.arg(1),bytes(x));self.ret(int(self.pending_class>=0));return
  # Chain's menu observer expects its fixed test CONTROL; this instance uses
  # a frame-owned menu object, so provide that exact object in the snapshot.
  if a==OBSERVE and self.arg(1)==5:
   c=self.arg(2);assert c in self.controls and self.arg(3)==COOKIE
   s=Snapshot();s.session=self.Q(self.out);s.native_base=BASE;s.application=APP;s.application_index=self.dword(APP+0x28);s.page_index=4;s.page=PAGES[4];s.hii=DATA+0xc000;s.control=c;s.form=0x2713;s.owner=1;s.proof=31;s.history=self.Q(BASE+0xafde8);s.history_count=self.dword(BASE+0xafe00);s.history_root=self.dword(BASE+0xafddc)
   s.formset[:]=rt['uuid'].UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le;self.w(self.arg(4),bytes(s));self.ret(1);return
  super().hook(u,a,size,data)
 def page(self,consume=True):
  sp=STACK+0x1fd000;self.w(sp,bytes(0x300));self.u.reg_write(UC_X86_REG_RSP,sp);self.u.reg_write(UC_X86_REG_RBP,sp+0x100)
  for r,v in [(UC_X86_REG_RCX,FRAME),(UC_X86_REG_RDX,EVENT),(UC_X86_REG_RBX,PAGES[2]),(UC_X86_REG_RSI,EVENT),(UC_X86_REG_R14,0),(UC_X86_REG_R13,0)]:self.u.reg_write(r,v)
  self.u.emu_start(BASE+0x23aa8,STOP+1,count=6000000)
  assert self.page_stop==(0x23b05 if consume else 0x23ac1)and self.u.reg_read(UC_X86_REG_RSP)==sp and self.dword(BIND+72)==0
  return {'page_consumed':consume,'stop_rva':hex(self.page_stop),'native_control_calls':sum(1 for a in self.native if a==0x6db18),'prompt_count':self.prompt_entries,'control_scopes':len(self.scope_seen)}
 def run_pending(self,allow):
  native=len(self.native);sp=STACK+0x1fd000;self.u.reg_write(UC_X86_REG_RSP,sp)
  for r in [UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8]:self.u.reg_write(r,0)
  self.u.emu_start(BASE+0x239e7,STOP+1,count=1000000)
  assert self.pending_stop and self.u.reg_read(UC_X86_REG_RSP)==sp
  assert (0x40094 in self.native[native:])==allow
  assert self.r(BASE+0xaff20,1)==(b'\0'if allow else b'\1')
  assert self.r(BASE+0xaff23,1)==(b'\1'if allow else b'\0')
  return {'native_pending_entered':allow,'result':hex(self.u.reg_read(UC_X86_REG_RAX)),'effect_observations':self.effect_calls}

def main():
 cases=[]
 def new(**kw):
  v=InputVM(**kw);assert v.bind()==0 and v.begin()==0;return v
 def add(name,v,detail):cases.append({'name':name,'status':'PASS',**detail})
 for mode in ['cancel','wrong','correct','unknown_owner','unknown_ifr','unknown_type']:
  v=new()
  if mode=='cancel':v.cancel()
  if mode=='wrong':v.key_text(CORE.WRONG_PW.decode(),ack=True)
  if mode=='correct':v.key_text(CORE.PW.decode())
  if mode=='unknown_owner':v.scope_ok=False
  if mode=='unknown_ifr':v.control_ifr_unknown=True
  if mode=='unknown_type':v.w(v.controls[0]+0x34,struct.pack('<H',0xffff))
  d=v.page(consume=mode!='correct');assert d['native_control_calls']==int(mode=='correct')
  if mode in ['cancel','wrong','correct']:v.screen_restored()
  if mode!='correct':assert v.translations==0
  add('keyboard_'+mode+'_through_original_frame_and_page',v,d)
 for protected in [(True,True),(False,True),(True,False),(False,False)]:
  v=new(protected=protected,kind=2);d=v.page(consume=any(protected));assert v.prompt_entries==0
  assert [v.r(c+0x88,1)[0]for c in v.controls]==[2 if yes else 1 for yes in protected]
  assert set(v.scope_seen)==set(v.controls)
  add('kind2_each_control_'+str(protected),v,d)
 v=new();v.key_text(CORE.PW.decode());v.lose_owner_after_scope=True;d=v.page(True);assert d['native_control_calls']==0;add('owner_revoked_after_scope_before_original_method',v,d)
 v=new(kind=2);v.w(GATE,q(0));d=v.page(True);assert d['native_control_calls']==0 and v.prompt_entries==0;add('invalid_gate_ABI_silent_input_denies',v,d)
 for mode in ['cancel','correct','callback_unbound']:
  v=new(menu=True)
  if mode=='cancel':v.cancel()
  elif mode=='correct':v.key_text(CORE.PW.decode())
  else:v.w(v.controls[0]+8,q(BASE+0x22818))
  d=v.page(True);assert v.dword(APP+0x28)==(4 if mode=='correct' else 2)
  assert(0x22818 in v.native)==(mode=='correct')
  add('menu_type14_'+mode+'_through_original_input_layers',v,d)
 for classification,granted,change,allow in [(1,False,False,False),(0,False,False,True),(-1,False,False,False),(0,False,True,False),(1,True,False,True)]:
  v=new();v.pending_class=classification;v.effect_change=change
  if granted:v.key_text(CORE.PW.decode());v.page(False);v.screen_restored()
  add('independent_pending_'+str((classification,granted,change)),v,v.run_pending(allow))
 # The nonempty history shape observed on the live 396-page system is not a
 # first-entry ownership proof. Existing strict fallback must reject it.
 from verify_first_fallback import First as F,BASE as B,q as Q
 v=F();assert v.init()==0 and v.begin()==0;v.prompt='deny';v.w(B+0xafde8,Q(0x3b8b3018));v.w(B+0xafddc,struct.pack('<I',70));v.w(B+0xafde0,struct.pack('<I',416));v.w(B+0xafe00,struct.pack('<I',1));d=v.first('fault');add('hardware_observed_nonempty_history_shape_refused_without_owner_or_allocation_proof',v,d)
 out={'status':'PASS_COMPILED_INPUT_ADAPTER_ORIGINAL_TWO_LAYER_AND_PENDING_BOUNDARIES','case_count':len(cases),'cases':cases,'input_adapter_sha256':sha(DLL),'original_amitse_sha256':ORIGINAL_SHA,'gate_sha256':GATE_SHA,'runtime02_sha256':RUNTIME_SHA,'source_sha256':sha(__file__),'binding_bytes':ctypes.sizeof(InputBinding),'effects_bytes':ctypes.sizeof(Effects),'scope':__doc__,'limits':['Native scope, range, IFR and pending producer/effect proofs remain modeled and unbound.','Original helper3FED4 is modeled as no new pending work in the allowed empty-list fixture.','Native FrameInput dereferences the object vtable before the virtual input wrapper; a production installer also needs an earlier frame/object validation boundary.','Other native direct input callers and pending callers require complete installation coverage.','No installer, no ASUS runtime hook, no physical writes.'],'hardware_or_firmware_writes':0}
 (HERE/'input_adapter_tests.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':out['status'],'case_count':len(cases),'input_adapter_sha256':out['input_adapter_sha256']}))

if __name__=='__main__':main()
