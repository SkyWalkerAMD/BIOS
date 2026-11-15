"""Real original constructors into the new actual-byte chrome classifier.

HII ownership, allocation, CopyMem and color endpoints are explicit models.
No provider rebinding, hardware, native GUI or installer is represented here.
"""
from pathlib import Path
import hashlib,json,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;PROOF=HERE.parent/'guard_blackout_review01'
source=(PROOF/'verify_native_static_controls.py').read_text().split('\nchecks=[];rows=[]',1)[0]
source=source.replace("CORE=HERE.parent/'split_core'","CORE=HERE")
scope={'__file__':str(Path(__file__))};exec(compile(source,str(PROOF/'verify_native_static_controls.py')+' [new classifier mapping]','exec'),scope)
StaticVM,U,R,TSE,HEAP,S,q,d,w=[scope[x]for x in ['StaticVM','U','R','TSE','HEAP','S','q','d','w']]
ns=scope['ns'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
LOADED_GUID=uuid.UUID('5b1b31a1-9562-11d2-8e3f-00a0c969723b').bytes_le
class ChromeVM(StaticVM):
 def __init__(self,kind=1):
  super().__init__(kind);out=HEAP+0x260000
  self.li=HEAP+0x264000;self.amih=0x99887766;self.loaded_good=True;self.amih_driver=True
  self.u.mem_write(TSE+0x93970,q(self.amih))
  self.u.mem_write(self.li+0x40,q(TSE)+q(0xa1f40))
  assert self.call(TSE+0x148e4,out)==0;self.frame=self.getq(out)
  layout=self.getq(TSE+0x6c1a0)+self.layout_index*24
  assert self.call(TSE+0x14a00,self.frame,layout)==0
  assert self.call(TSE+0x33634,self.frame,layout,out+0x100)==0
  self.control=self.getq(self.getq(self.frame+0x48));self.ifr=self.getq(self.control+0x48)
  self.page=self.pages[5];self.page_array=HEAP+0x268000
  self.u.mem_write(self.page+0x30,w(0));self.u.mem_write(self.page+0x2a,w(1))
  self.u.mem_write(self.page+0x4c,d(1)+q(self.page_array));self.u.mem_write(self.page_array,q(self.frame))
  self.u.mem_write(self.table,d(1)+d(0));self.u.mem_write(self.records+10,w(1))
  self.u.mem_write(self.app+0x28,d(0)+d(1));self.u.mem_write(self.array,q(self.page))
  self.u.mem_write(TSE+0x83594,d(0));self.u.mem_write(TSE+0x835b8,d(1))
  self.u.mem_write(self.getq(TSE+0x835a0),q(0x99998888)+d(1))
 def hook(self,u,a,n,data):
  if a==ns['GETDRIVER'] and self.arg(1)==getattr(self,'amih',None):
   if not self.amih_driver:self.ret(ns['ERR'](14));return
   u.mem_write(self.arg(2),q(0xa003));self.ret(0);return
  if a==ns['HANDLE']:
   guid=bytes(u.mem_read(self.arg(1),16))
   if self.arg(0)==0xa003:
    if guid==LOADED_GUID and self.loaded_good:u.mem_write(self.arg(2),q(self.li));self.ret(0);return
    self.ret(ns['ERR'](14));return
  super().hook(u,a,n,data)
 def classified(self):return self.call(S['AMITSE']['frame_protected_trace'],self.frame,0)
checks=[];observations=[]
def check(s,ok):assert ok,s;checks.append(s)
for kind in [1,2,3,5]:
 v=ChromeVM(kind)
 check(f'kind{kind} actual frame/descriptor/populator creates expected sentinel class',v.getq(v.frame)==TSE+0x6b8b8 and v.getq(v.control+0x20)==0xffffffffffffffff)
 check(f'kind{kind} new actual classifier accepts exact native chrome',v.classified()==0)
 check(f'kind{kind} foreign page with real static frame remains unprotected',v.call(S['AMITSE']['page_protected_trace'],v.page,0)==0)
 key=HEAP+0x26c000;v.u.mem_write(key+8,w(1));v.u.mem_write(key+12,w(0x17))
 for fn,args in [('gate_render',[v.page]),('gate_page_input',[v.page,key]),('gate_app_input',[v.app,key]),('gate_poll',[])]:v.call(S['AMITSE'][fn],*args)
 check(f'kind{kind} render/ESC/poll endpoints remain reachable without grant',all(v.calls[x]==1 for x in ['render','page_input','app_input','poll'])and not v.provider_calls['request'])
 for source_hii,label in [(v.handle,'Setup'),(0x99998888,'known foreign'),(v.amih,'AMITSE strings')]:
  v.u.mem_write(v.control+0x20,q(source_hii));check(f'kind{kind} post-render exact {label} source accepted',v.classified()==0)
 v.u.mem_write(v.control+0x20,q(0xffffffffffffffff));v.u.mem_write(v.page+0x20,q(v.handle));v.u.mem_write(v.records+10,w(0x2714))
 check(f'kind{kind} protected Ai page remains protected with chrome present',v.call(S['AMITSE']['page_protected_trace'],v.page,0)==1)

def mutated(name,fn,kind=1):
 v=ChromeVM(kind);fn(v);x=v.classified();check(name,x in [0xffffffff,0xffffffffffffffff]);observations.append({'case':name,'class':'UNKNOWN'})
for name,fn in [
 ('null source',lambda v:v.u.mem_write(v.control+0x20,q(0))),
 ('unknown source',lambda v:v.u.mem_write(v.control+0x20,q(0x98886644))),
 ('wrong frame vtable',lambda v:v.u.mem_write(v.frame,q(TSE+0x6b910))),
 ('wrong control vtable',lambda v:v.u.mem_write(v.control,q(TSE+0x6bbe0))),
 ('frame kind main body',lambda v:v.u.mem_write(v.frame+0x20,d(0))),
 ('frame kind nonnative',lambda v:v.u.mem_write(v.frame+0x20,d(8))),
 ('control kind mismatch',lambda v:v.u.mem_write(v.control+0x6c,d(2))),
 ('multiple controls',lambda v:v.u.mem_write(v.frame+0x3c,d(2))),
 ('object callback field',lambda v:v.u.mem_write(v.control+8,q(TSE+0x11164))),
 ('object callback context',lambda v:v.u.mem_write(v.control+16,q(HEAP))),
 ('object third field',lambda v:v.u.mem_write(v.control+24,q(HEAP))),
 ('Question id field',lambda v:v.u.mem_write(v.control+0x28,w(1))),
 ('wrong control type',lambda v:v.u.mem_write(v.control+0x34,w(9))),
 ('extra descriptor flags',lambda v:v.u.mem_write(v.control+0x3c,d(3))),
 ('condition expression pointer',lambda v:v.u.mem_write(v.control+0x50,q(v.ifr))),
 ('extra descriptor tail',lambda v:v.u.mem_write(v.control+0x58,q(1))),
 ('IFR question opcode',lambda v:v.u.mem_write(v.ifr,b'\x05')),
 ('IFR scoped subtitle',lambda v:v.u.mem_write(v.ifr+1,b'\x87')),
 ('IFR extra help id',lambda v:v.u.mem_write(v.ifr+4,w(1))),
 ('IFR extra flags',lambda v:v.u.mem_write(v.ifr+6,b'\x01')),
 ('wrong exact method slot',lambda v:v.u.mem_write(TSE+0x6bb40,q(TSE+0x11164))),
 ('wrong native constructor code',lambda v:v.u.mem_write(TSE+0x16354,b'\xcc')),
 ('wrong native input code',lambda v:v.u.mem_write(TSE+0x1c2cc,b'\xcc')),
 ('wrong native frame render code',lambda v:v.u.mem_write(TSE+0x14a80,b'\xcc')),
 ('wrong original frame body code',lambda v:v.u.mem_write(TSE+0x1532f,b'\xcc')),
 ('wrong current frame-input detour',lambda v:v.u.mem_write(TSE+0x15321,d(0))),
 ('wrong current frame-input padding',lambda v:v.u.mem_write(TSE+0x1532e,b'\xcc')),
 ('wrong original PE machine',lambda v:v.u.mem_write(TSE+0xc8+4,w(0x14c))),
 ('unreadable control',lambda v:v.memory_deny.append((v.control,v.control+0x88,0))),
 ('unreadable IFR',lambda v:v.memory_deny.append((v.ifr,v.ifr+7,0))),
 ('unreadable method table',lambda v:v.memory_deny.append((TSE+0x6bb20,TSE+0x6bb80,0))),
 ('read-only frame',lambda v:v.memory_deny.append((v.frame,v.frame+0x78,1))),
 ('read-only control',lambda v:v.memory_deny.append((v.control,v.control+0x88,1))),
 ('read-only IFR',lambda v:v.memory_deny.append((v.ifr,v.ifr+7,1))),
]:mutated(name,fn)
for slot in range(10):mutated(f'wrong native frame method slot{slot}',lambda v:v.u.mem_write(TSE+0x6b8b8+slot*8,q(TSE+0x11164)))
def copy_ifr(v):
 dest=HEAP+0x26d000;v.u.mem_write(dest,bytes(v.u.mem_read(v.ifr,7)));v.u.mem_write(v.control+0x48,q(dest))
mutated('kind1 lookalike IFR outside exact original slot',copy_ifr)
mutated('kind5 wrong dynamic footer token',lambda v:v.u.mem_write(v.ifr+2,w(4)),5)
for label,fn in [
 ('wrong AMITSE LoadedImage base',lambda v:v.u.mem_write(v.li+0x40,q(TSE+0x1000))),
 ('wrong AMITSE LoadedImage size',lambda v:v.u.mem_write(v.li+0x48,q(0xa2000))),
 ('missing AMITSE LoadedImage',lambda v:setattr(v,'loaded_good',False)),
 ('missing AMITSE HII driver',lambda v:setattr(v,'amih_driver',False)),
 ('AMITSE string slot no longer matches',lambda v:v.u.mem_write(TSE+0x93970,q(0x11111111))),
]:
 def mutate(v):v.u.mem_write(v.control+0x20,q(v.amih));fn(v)
 mutated(label,mutate)
for source,label in [('Setup','Setup'),('foreign','known foreign'),('AMITSE','AMITSE strings')]:
 for mutation,fn in [
  ('object callback',lambda v:v.u.mem_write(v.control+8,q(TSE+0x11164))),
  ('expression',lambda v:v.u.mem_write(v.control+0x50,q(v.ifr))),
  ('wrong control class',lambda v:v.u.mem_write(v.control,q(TSE+0x6bbe0))),
  ('wrong frame class',lambda v:v.u.mem_write(v.frame,q(TSE+0x6b910))),
  ('wrong frame kind with native control marker',lambda v:v.u.mem_write(v.frame+0x20,d(0))),
  ('wrong descriptor type',lambda v:v.u.mem_write(v.control+0x34,w(5))),
  ('read-only control',lambda v:v.memory_deny.append((v.control,v.control+0x88,1))),
 ]:
  def mutate(v):
   h={'Setup':v.handle,'foreign':0x99998888,'AMITSE':v.amih}[source];v.u.mem_write(v.control+0x20,q(h));fn(v)
  mutated(f'post-render {label} {mutation} remains UNKNOWN without generic fallback',mutate)
v=ChromeVM();v.u.mem_write(v.control+0x20,q(v.handle));question=HEAP+0x26e000
v.u.mem_write(question,bytes.fromhex('05910000000034121d0010000010000100'));v.u.mem_write(v.control+0x48,q(question))
check('protected Setup question cannot be hidden behind claimed chrome',v.classified()in[0xffffffff,0xffffffffffffffff])
v.u.mem_write(v.frame+0x20,d(0));v.u.mem_write(v.control+0x6c,d(0))
check('ordinary main-body real protected Setup question still classified protected',v.classified()==1)
report={'status':'PASS_LOCAL_NATIVE_CHROME_CLASSIFIER_ACTUAL_BYTES_NOT_DEPLOYABLE','checks':len(checks),'check_names':checks,'negative_cases':observations,'new_build_sha256':sha(HERE/'build/split_build.json'),'new_source_sha256':sha(HERE/'source/gate.c'),'new_guard_sha256':{n:sha(HERE/'build'/(n+'.split-guard.bin'))for n in ['AMITSE','Setup']},'test_source_sha256':sha(Path(__file__)),'frozen_native_fixture_source_sha256':sha(PROOF/'verify_native_static_controls.py'),'limits':['Original frame148E4/layout14A00/populate33634/static16354 and constructors execute with explicit allocation/color/CopyMem service models; actual new guard instructions execute.','HII ownership and AMITSE string-package LoadedImage association are explicit models. The real ASUS association must still be observed; a differing driver topology remains refused.','Original render/input/poll endpoints in this test are models. No physical graphics, SendForm, full browser, password/provider acceptance, permanent firmware or RAM installer acceptance.','No-safe-page unwind is unchanged and still unproven. Unrelated unknown controls remain denied.','Provider13 binds the old template and cannot bind this new guard; no deployable app/ISO was created.']}
(HERE/'build/chrome_verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'sha256':sha(HERE/'build/chrome_verification.json')}))
