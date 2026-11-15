"""Execute compiled gate + original menu selection/callback in one Unicorn VM.

Only the native observer and provider/service callbacks are modeled. This does
not prove those callbacks against live HII/loaded-image ownership or install hooks.
"""
from native_replay import *
import ctypes,uuid
GBASE=0x6000000
DLL=HERE/'build/W890Navigation.TESTONLY.dll'
class Snapshot(ctypes.Structure):
 _fields_=[(x,ctypes.c_uint64)for x in ['session','native_base','application','page','hii','control','history']]+[(x,ctypes.c_uint32)for x in ['page_index','application_index','history_count','history_root','owner','proof','ifr_size']]+[('form',ctypes.c_uint16),('formset',ctypes.c_uint8*16),('ifr',ctypes.c_uint8*127)]
class Gate(ctypes.Structure):
 _fields_=[(x,ctypes.c_uint64)for x in ['abi','opaque','provider','observe','query','request','native_base']]+[('busy',ctypes.c_uint32),('reserved',ctypes.c_uint32)]
APP=DATA+0x2000;CONTROL=DATA+0x3000;COOKIE=DATA+0x4000;BS=DATA+0x5000;HIST=DATA+0x6000;ROWS=DATA+0x7000;ARRAY=DATA+0x8000;GATE=DATA+0xa000
PAGES=[DATA+0xb000+i*0x100 for i in range(6)]
def create(name,*,form=0x2713,initial_flags=3,request_result=0,request_grants=True,owner=1,proof=31,change=None,deny_observe=0,query_fail_at=0,busy=False,binding=True,route=5):
 m=Machine();p=pefile.PE(str(DLL));p.relocate_image(GBASE);b=p.get_memory_mapped_image();m.uc.mem_map(GBASE,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);m.uc.mem_write(GBASE,b)
 exports={e.name.decode():GBASE+e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
 g=Gate(0x3130304730393857,DATA,DATA+0x100,STUB+0x100,STUB+0x200,STUB+0x300,BASE,int(busy),0)
 m.uc.mem_write(GATE,bytes(g));m.w64(exports['wg_binding'],GATE if binding else 0)
 # Actual native descriptor callback slot is changed in emulator memory only.
 assert m.r64(BASE+0x94408)==BASE+0x22818
 m.w64(BASE+0x94408,exports['wg_native_menu_thunk'])
 m.w64(CONTROL+8,m.r64(BASE+0x94408));m.w64(CONTROL+0x10,APP);m.w64(CONTROL+0x18,COOKIE);m.w64(CONTROL+0x80,ROWS)
 m.w32(COOKIE,8);m.w16(ROWS+2*16+8,4)
 m.w64(BASE+0xafdd0,APP);m.w32(APP+0x28,2);m.w32(APP+0x2c,6);m.w64(APP+0x30,ARRAY)
 for i,page in enumerate(PAGES):m.w64(ARRAY+i*8,page);m.w64(page+0x20,DATA+0xc000);m.w16(page+0x2a,form if i==4 else 0x2712);m.w16(page+0x30,i)
 m.w64(BASE+0xafbc8,BS);m.w64(BS+0x48,STUB+0x400)
 m.w64(BASE+0xafde8,HIST);m.w32(BASE+0xafe00,3);m.w32(BASE+0xafddc,2)
 flags=initial_flags;observations=0;queries=0;requests=0;frees=[];compiled=[]
 def observe():
  nonlocal observations
  observations+=1
  if observations==deny_observe:m.reg(UC_X86_REG_RAX,0);return
  dest=m.r64(m.reg(UC_X86_REG_RSP)+40);r=m.reg(UC_X86_REG_RDX)
  assert r==route
  s=Snapshot();s.session=1;s.native_base=BASE;s.application=APP
  idx=int.from_bytes(m.uc.mem_read(COOKIE+8,2),'little') if r==5 else 4
  s.page_index=idx;s.application_index=m.r32(APP+0x28);s.page=PAGES[idx];s.hii=m.r64(s.page+0x20);s.form=int.from_bytes(m.uc.mem_read(s.page+0x2a,2),'little')
  s.control=CONTROL;s.history=m.r64(BASE+0xafde8);s.history_count=m.r32(BASE+0xafe00);s.history_root=m.r32(BASE+0xafddc);s.owner=owner;s.proof=proof
  s.formset[:]=uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le
  if r==4:s.ifr_size=14;s.proof|=32;s.ifr[:14]=bytes.fromhex('060e010002000100230000000000')
  if observations==2:
   if change=='session':s.session+=1
   elif change=='page':s.page+=8
   elif change=='hii':s.hii+=8
   elif change=='history':s.history_count+=1
   elif change=='form':s.form=0x2712
   elif change=='control':s.control+=8
   elif change=='module':s.native_base+=4096
   elif change=='application_index':s.application_index+=1
   elif change=='ifr' and r==4:s.ifr[2]^=1
  m.uc.mem_write(dest,bytes(s));m.reg(UC_X86_REG_RAX,1)
 def query():
  nonlocal queries
  queries+=1;m.reg(UC_X86_REG_RAX,0x40 if queries==query_fail_at else flags)
 def request():
  nonlocal requests,flags
  requests+=1
  if request_result==0 and request_grants:flags|=4
  m.reg(UC_X86_REG_RAX,request_result)
 def free():frees.append(m.reg(UC_X86_REG_RCX));m.reg(UC_X86_REG_RAX,0)
 m.callbacks.update({STUB+0x100:observe,STUB+0x200:query,STUB+0x300:request,STUB+0x400:free})
 m.uc.hook_add(UC_HOOK_CODE,lambda u,a,n,d:compiled.append(a-GBASE)if GBASE<=a<GBASE+len(b)else None)
 return m,exports,lambda:{'requests':requests,'queries':queries,'observations':observations,'frees':len(frees),'compiled_instructions':len(compiled)},g
def run_case(name,allow,*,menu=True,**kwargs):
 route=5 if menu else kwargs.pop('route',1)
 m,e,counts,g=create(name,route=route,**kwargs);sp=m.setup()
 if menu:m.reg(UC_X86_REG_RCX,CONTROL);m.reg(UC_X86_REG_RDX,2);m.run(0x6af54)
 else:
  for reg,arg in zip(ARGS,[GATE,route,CONTROL,COOKIE]):m.reg(reg,arg)
  m.uc.emu_start(e['wg_check'],END,count=200000);assert m.reg(UC_X86_REG_RIP)==END
  assert m.reg(UC_X86_REG_RAX)==(0 if allow else DENY)
 c=counts()
 if menu:
  assert m.r32(APP+0x28)==(4 if allow else 2)
  assert c['frees']==int(allow)
  assert m.r64(BASE+0xafde8)==(0 if allow else HIST)
  assert m.r32(BASE+0xafe00)==(0 if allow else 3)
  assert m.r32(BASE+0xafddc)==(0 if allow else 2)
  assert m.r32(APP+0x5c)==int(allow)
  assert (0x22818 in m.trace)==allow
 assert m.reg(UC_X86_REG_RSP)==sp+8
 assert [m.reg(r)for r in NONVOL]==[0x11110000+i for i in range(len(NONVOL))]
 assert bytes(m.uc.mem_read(sp+40,26))==b'CANARY-ABOVE-SHADOW-SPACE!'
 assert m.r32(GATE+56)==int(kwargs.get('busy',False))
 return {'name':name,'passed':True,'allow':allow,'entry':'original_menu_selection_0x6af54'if menu else 'compiled_wg_check','native_menu_callback_executed':0x22818 in m.trace,**c}
def main():
 cases=[]
 cases.append(run_case('menu_protected_challenge_then_granted',True))
 cases.append(run_case('menu_protected_cancel_preserves_native_page_and_history',False,request_result=DENY))
 cases.append(run_case('menu_unconfigured_preserves_native_state',False,request_result=0x8000000000000003))
 cases.append(run_case('menu_protected_request_success_without_grant_is_denied',False,request_grants=False))
 cases.append(run_case('menu_already_granted',True,initial_flags=7))
 cases.append(run_case('menu_disabled_policy',True,initial_flags=11))
 cases.append(run_case('menu_main_requires_no_password',True,form=0x2712))
 for what in ['session','page','hii','history','form','control','module','application_index']:cases.append(run_case('stale_'+what,False,change=what))
 for i in [1,2]:cases.append(run_case('observer_failure_'+str(i),False,deny_observe=i))
 for i in [1,2,3]:cases.append(run_case('session_ended_at_query_'+str(i),False,query_fail_at=i))
 cases.append(run_case('unknown_owner',False,owner=0))
 cases.append(run_case('foreign_without_proof',False,owner=2))
 cases.append(run_case('foreign_attested_no_setup_controls',True,owner=2,proof=95))
 cases.append(run_case('unobserved_pointer_extents',False,proof=27))
 cases.append(run_case('reentrant_busy',False,busy=True))
 cases.append(run_case('unbound_callback',False,binding=False))
 for route in [1,2,3,4,6,7]:
  cases.append(run_case('boundary_'+str(route)+'_cancel',False,menu=False,route=route,request_result=DENY))
  cases.append(run_case('boundary_'+str(route)+'_granted',True,menu=False,route=route))
 cases.append(run_case('control_ifr_changed_after_prompt',False,menu=False,route=4,change='ifr'))
 out={'status':'PASS','scope':__doc__,'case_count':len(cases),'cases':cases,'original_amitse_sha256':sha((NEW/'AMITSE.efi').read_bytes()),'gate_sha256':sha(DLL.read_bytes()),'test_sha256':sha(Path(__file__).read_bytes()),'snapshot_bytes':ctypes.sizeof(Snapshot),'gate_bytes':ctypes.sizeof(Gate),'patch_emulator_memory_only':{'slot':'0x94408','old_target':'0x22818','new_target':'compiled wg_native_menu_thunk'},'not_verified':['Actual pointer-range/HII ownership observer','Provider password and persistent-storage operations (modeled here)','Full BrowserLoop first-page redirect, native callbacks, update/save entry coverage','Real hook installation, boot/distribution/signature or hardware behavior']}
 (HERE/'compiled_native_gate_tests.json').write_text(json.dumps(out,indent=2),encoding='utf-8');print(json.dumps({'status':out['status'],'case_count':len(cases),'gate_sha256':out['gate_sha256'],'native_menus_allowed':sum(c['native_menu_callback_executed']for c in cases)},indent=2))
if __name__=='__main__':main()
