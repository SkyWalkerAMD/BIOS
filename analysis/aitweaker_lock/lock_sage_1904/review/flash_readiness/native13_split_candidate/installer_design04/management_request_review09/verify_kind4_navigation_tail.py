"""Exact original selection callback and Page.Input navigation tail.

This is a bounded path fixture, not a kind4 allow patch. Original15C44 executes
against synthetic records; then the original16F76 tail executes with declared
saved caller state. The actual626C/5A04 dispatcher and frozen07 navigation guard
execute. History allocation/free, provider, and later lifecycle bodies are
explicit models. No original PE or frozen candidate on disk is modified.
"""
from pathlib import Path
import hashlib,json,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;C07=HERE.parent/'static_chrome_candidate07'
text=(C07/'verify_chrome.py').read_text(encoding='utf8').split('\nchecks=[];observations=[]',1)[0]
ns={'__file__':str(C07/'verify_chrome.py')};exec(compile(text,str(C07/'verify_chrome.py')+' [prefix only]','exec'),ns)
V,S,q,d,w,U,R,TSE,HEAP=[ns[x]for x in ['ChromeVM','S','q','d','w','U','R','TSE','HEAP']]
base_ns=ns['ns'];STACK,STOP,ERR=[base_ns[x]for x in ['STACK','STOP','ERR']]
SETUP_GUID=uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le
FOREIGN_GUID=uuid.UUID('b16b94e6-99f4-4f60-8f7b-b6d234e4a513').bytes_le

class TailVM(V):
 def __init__(self,formid,formset,hii,pending_refresh=False,native_menu_input=False):
  self.trace=[];self.pending_refresh=pending_refresh;self.native_menu_input=native_menu_input;super().__init__(4)
  self.page0=self.pages[0];self.page1=self.pages[1]
  self.forms=HEAP+0x274000;self.cookie=HEAP+0x276000
  # Two explicitly synthetic native page/formset records.
  self.u.mem_write(self.app+0x28,d(0)+d(2)+q(self.array))
  self.u.mem_write(self.array,q(self.page0)+q(self.page1))
  self.u.mem_write(self.table,d(2)+d(0)+d(64))
  self.u.mem_write(self.records,bytes(128))
  self.u.mem_write(self.records,q(0x99998888)+w(0)+w(1)+bytes(4)+w(0))
  self.u.mem_write(self.records+64,q(hii)+w(1)+w(formid)+bytes(4)+w(1))
  self.u.mem_write(self.forms,d(2)+d(32)+d(64))
  self.u.mem_write(self.forms+32,FOREIGN_GUID);self.u.mem_write(self.forms+64,formset)
  self.u.mem_write(TSE+0x930a8,q(self.forms))
  self.u.mem_write(self.page0+0x20,q(0x99998888));self.u.mem_write(self.page0+0x30,w(0));self.u.mem_write(self.page0+0x4c,d(0))
  self.u.mem_write(self.page1+0x20,q(hii));self.u.mem_write(self.page1+0x30,w(1))
  self.u.mem_write(self.page1+0x4c,d(0))
  self.u.mem_write(TSE+0x83610,q(0));self.u.mem_write(TSE+0x836d8,bytes([int(pending_refresh)]))
  self.provider_present=True;self.provider_bits=3;self.request_accept=False
  self.u.mem_write(self.cookie,d(8)+d(0)+w(1)+bytes(6))
  self.menu=HEAP+0x278000;self.key=HEAP+0x279000
  self.u.mem_write(self.menu,q(0x99998888)+w(0)+bytes(6)+q(hii)+w(1)+bytes(6))
  self.u.mem_write(self.control+0x72,w(2)+w(0)+b'\0')
  self.u.mem_write(self.control+0x80,q(self.menu))
  self.u.mem_write(self.key+8,w(1));self.u.mem_write(self.key+12,w(3))
  self.u.mem_write(self.page0+0x34,d(0))
  for at in [TSE+x for x in [0x626c,0x5a04,0x5c60,0x15c44,0x4ecb8,0x4ecfc,0x10220,0x29020,0x29ae4,0x3297c,0x171b6]]+[S['AMITSE']['gate_navigation']]:
   self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=at,end=at)
 def hook(self,u,a,n,data):
  if a==TSE+0x171b6:
   self.trace.append({'point':'Page.Input common return','current_index':self.getd(self.app+0x28)});u.emu_stop();return
  if a in [TSE+0x4ecfc,TSE+0x4ecb8,TSE+0x15c44]:
   self.trace.append({'point':'actual native menu input/selection/callback','rva':hex(a-TSE),'current_index':self.getd(self.app+0x28)});return
  if a==TSE+0x5c60:
   self.trace.append({'point':'modeled key decoder5C60','decoded_action':2});self.ret(2);return
  if a==TSE+0x626c:
   self.trace.append({'point':'native626C navigation dispatcher','old_guid':bytes(u.mem_read(self.arg(0),16)).hex(),'old_form':int.from_bytes(u.mem_read(self.arg(1),2),'little'),'new_guid':bytes(u.mem_read(self.arg(2),16)).hex(),'new_form':int.from_bytes(u.mem_read(self.arg(3),2),'little')});return
  if a==TSE+0x5a04:
   self.trace.append({'point':'native5A04 table lookup','event':hex(self.arg(0))});return
  if a==S['AMITSE']['gate_navigation']:
   self.trace.append({'point':'actual frozen07 navigation guard'});return
  if a==base_ns['REQUEST']:
   self.trace.append({'point':'modeled provider Request','current_index':self.getd(self.app+0x28)});super().hook(u,a,n,data);return
  if a==TSE+0x10220:
   self.trace.append({'point':'modeled10220 history update','old_page':self.arg(0),'new_page':self.arg(1)});self.ret(0);return
  if a==TSE+0x29020:
   self.trace.append({'point':'modeled29020 lifecycle body','action':self.arg(1),'record_form':int.from_bytes(u.mem_read(self.arg(0)+10,2),'little'),'current_index':self.getd(self.app+0x28)});self.ret(0);return
  if a==TSE+0x3297c:
   self.trace.append({'point':'modeled3297C post-navigation helper','index':self.arg(0)});self.ret(0);return
  if a==TSE+0x29ae4:
   self.trace.append({'point':'modeled29AE4 pending refresh work','current_index':self.getd(self.app+0x28),'processing_flag':self.u.mem_read(TSE+0x836d9,1)[0]});self.ret(0);return
  super().hook(u,a,n,data)
 def run(self):
  target_class=self.call(S['AMITSE']['page_protected'],self.page1)
  if target_class in [0xffffffff,0xffffffffffffffff]:target_class=-1
  # Direct actual input study deliberately bypasses the earlier page/frame
  # gates; no production allow rule is introduced by the test.
  self.trace=[]
  if self.native_menu_input:self.call(TSE+0x4ecfc,self.control,self.key)
  else:self.call(TSE+0x15c44,self.frame,self.control,self.cookie)
  assert self.getd(self.app+0x28)==1
  assert self.getq(TSE+0x835a0)==0 and self.getd(TSE+0x835b8)==0
  history_cleared=True
  selection_trace=self.trace;self.trace=[]
  rsp=STACK+0x2fe000;rbp=rsp+0x80
  self.u.mem_write(rsp,bytes(0x200))
  for reg,val in [(R.UC_X86_REG_RSP,rsp),(R.UC_X86_REG_RBP,rbp),(R.UC_X86_REG_R15,0),(R.UC_X86_REG_R13,0),(R.UC_X86_REG_R12,ERR(3)),(R.UC_X86_REG_RBX,0),(R.UC_X86_REG_RDI,self.page0)]:self.u.reg_write(reg,val)
  try:self.u.emu_start(TSE+(0x16f4b if self.pending_refresh else 0x16f76),0,count=200000000)
  except U.UcError as exc:
   raise AssertionError({'emulator_error':str(exc),'rip':hex(self.u.reg_read(R.UC_X86_REG_RIP)),'trace':self.trace})from exc
  assert self.u.reg_read(R.UC_X86_REG_RIP)==TSE+0x171b6,hex(self.u.reg_read(R.UC_X86_REG_RIP))
  return {'index_after_tail':self.getd(self.app+0x28),'target_page_class_in_separate_precheck':target_class,'history_cleared_by_real_callback':history_cleared,'history_still_null':self.getq(TSE+0x835a0)==0,'request_calls':self.provider_calls['request'],'pending_refresh_fixture':self.pending_refresh,'native_menu_input_fixture':self.native_menu_input,'selection_trace':selection_trace,'trace':self.trace}

cases=[]
for label,formid,guid,hii,expected_index,expected_request,expected_lifecycle,pending_refresh,native_menu_input in [
 ('known Setup protected destination',0x2714,SETUP_GUID,0x12345678,0,1,False,False,False),
 ('known Setup unprotected form destination',0x2713,SETUP_GUID,0x12345678,1,0,True,False,False),
 ('known foreign destination with numerically protected form',0x2714,FOREIGN_GUID,0x99998888,1,0,True,False,False),
 ('unknown HII destination before later owner classification',0x6002,FOREIGN_GUID,0xdead1111,1,0,True,False,False),
 ('pending-refresh branch precedes protected navigation rejection',0x2714,SETUP_GUID,0x12345678,0,1,False,True,False),
 ('actual4ECFC and4ECB8 select protected destination then actual guard rejects',0x2714,SETUP_GUID,0x12345678,0,1,False,False,True),
 ('actual4ECFC and4ECB8 select unknown destination then lifecycle reached',0x6002,FOREIGN_GUID,0xdead1111,1,0,True,False,True),
 ('inconsistent foreign GUID and Setup-owned protected page is not resolved by navigation-only gate',0x2714,FOREIGN_GUID,0x12345678,1,0,True,False,True),
]:
 v=TailVM(formid,guid,hii,pending_refresh,native_menu_input);ans=v.run()
 assert ans['index_after_tail']==expected_index,(label,ans)
 assert ans['request_calls']==expected_request,(label,ans)
 lifecycle=[x for x in ans['trace']if x['point']=='modeled29020 lifecycle body']
 assert bool(lifecycle)==expected_lifecycle,(label,ans)
 assert all(x['action']==3 for x in lifecycle)
 if expected_index==0:assert not any(x['point'].startswith('modeled') and x['point'] not in ['modeled provider Request','modeled29AE4 pending refresh work']for x in ans['trace'])
 if pending_refresh:
  assert ans['trace'][0]['point']=='modeled29AE4 pending refresh work' and ans['trace'][0]['processing_flag']==1
  assert v.u.mem_read(TSE+0x836d9,1)==b'\0'
 if native_menu_input:
  assert [x.get('rva')for x in ans['selection_trace']if 'rva'in x]==['0x4ecfc','0x4ecb8','0x15c44']
 if label.startswith('inconsistent'):assert ans['target_page_class_in_separate_precheck']==1
 if label.startswith('unknown') or 'select unknown'in label:assert ans['target_page_class_in_separate_precheck']==-1
 cases.append({'case':label,**ans})
report={'status':'PASS_BOUNDED_ORIGINAL_NAVIGATION_TAIL_NOT_FULL_BROWSER','cases':len(cases),'rows':cases,
 'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'actual_paths':['4ECFC menu Input and4ECB8 selection in three cases','15C44 selection callback','16F76..171B6 original Page.Input tail','626C event dispatcher','5A04 event table lookup','frozen07 gate_navigation'],
 'scope':['Synthetic two-page native records and exact caller registers are explicit inputs. Seven cases start the tail at16F76; the pending-refresh fifth case starts at16F4B and executes1009C with an explicitly empty old page frame array.',
 'Three cases directly execute actual4ECFC/4ECB8/15C44 on the real-constructed control, a synthetic two-entry menu and modeled key-decoder action2. Earlier page/frame gates are deliberately bypassed to study native behavior, not asserted to have allowed it.',
 'History update10220, lifecycle29020, post-navigation3297C, HII/allocator/provider and memory predicate are modeled endpoints. No protected callback body or native graphics is executed.',
 'Known protected Setup form is denied by the actual navigation guard and index restored before lifecycle; actual15C44 has already freed/cleared history and that side effect is not rolled back by this denial.',
 'Foreign or unknown-HII destinations are not classified by navigation guard; original tail can reach FORM_OPEN action3 before next poll/render. This proves a needed review boundary, not an observed OC modification or a new bypass.',
 'An intentionally inconsistent foreign formset-GUID versus Setup-owned protected page is also an explicit negative fixture: separate actual page_protected returns1 while GUID-only navigation permits. No claim this inconsistency occurs in native valid tables or on hardware.',
 'The pending-refresh flag836D8 can route through29AE4 before navigation guard; its body is modeled. It is not proved inert, and the test does not claim actual hardware had this flag or queue.',
 'No kind4 allowance, original field write on hardware, provider/app change, host EFI execution or device access.']}
(HERE/'kind4_navigation_tail.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'cases':len(cases)}))
