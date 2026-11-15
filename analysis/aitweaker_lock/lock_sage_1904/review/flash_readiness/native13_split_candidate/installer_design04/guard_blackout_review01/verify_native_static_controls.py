"""Execute native1904 static-control constructors before the frozen guard.

The original routine chooses the descriptor/IFR. Allocation/CopyMem/color
services are explicit models. No renderer is represented as physical output.
"""
from pathlib import Path
import hashlib,json,sys,struct
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CORE=HERE.parent/'split_core'
sys.path.insert(0,str(CORE));from verify_split import make_namespace
ns=make_namespace();V=ns['GateVM'];U,R=ns['U'],ns['R'];TSE,HEAP,STOP=[ns[x]for x in ['TSE','HEAP','STOP']]
S=ns['S'];q,d,w=[ns[x]for x in ['q','d','w']];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
COPY=STOP+0x4500
class StaticVM(V):
 def __init__(self,kind):
  super().__init__();self.next_alloc=HEAP+0x280000;self.native_counts={};self.models=[]
  self.frame=HEAP+0x220000;self.native_kind=kind
  self.u.mem_write(self.bs+0x160,q(COPY))
  layout=self.getq(TSE+0x6c1a0)
  self.layout_index=next(i for i in range(6)if self.getd(layout+i*24)==kind)
  self.u.mem_write(self.frame+0x20,bytes(self.u.mem_read(layout+self.layout_index*24,24)))
  for at in [COPY,TSE+0x5df8,TSE+0x16354,TSE+0x1bd14,TSE+0x1bdac,TSE+0x1cb7c,TSE+0x171d4]:
   self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=at,end=at)
 def hook(self,u,a,n,data):
  if a==ns['ALLOC']:
   assert self.arg(0)==4 and 0<self.arg(1)<0x10000
   address=self.next_alloc;self.next_alloc=(address+self.arg(1)+15)&~15
   assert self.next_alloc<HEAP+0x300000
   # Real native3F714 runs its zeroing helper over this poison allocation.
   u.mem_write(address,b'\xaf'*self.arg(1));u.mem_write(self.arg(2),q(address))
   self.models.append('AllocatePool');self.ret(0);return
  if a==COPY:
   u.mem_write(self.arg(0),bytes(u.mem_read(self.arg(1),self.arg(2))))
   self.models.append('CopyMem');self.ret(self.arg(0));return
  if a==TSE+0x5df8:self.models.append('color_resolver5df8');self.ret(0);return
  if a in [TSE+x for x in [0x16354,0x1bd14,0x1bdac,0x1cb7c,0x171d4]]:
   self.native_counts[hex(a-TSE)]=self.native_counts.get(hex(a-TSE),0)+1;return
  super().hook(u,a,n,data)
checks=[];rows=[]
def check(s,ok):assert ok,s;checks.append(s)
IFR={1:0x6bc98,2:0x6be48,3:0x6be50,5:0x6bdd0}
for kind in [1,2,3,5]:
 v=StaticVM(kind);result=v.call(TSE+0x16354,v.frame,kind);array=v.getq(v.frame+0x48);control=v.getq(array);ifr=v.getq(control+0x48)
 check(f'kind{kind} real constructor chain succeeds',result==0 and v.getd(v.frame+0x3c)==1 and all(v.native_counts.get(hex(x))==1 for x in [0x16354,0x1bd14,0x1bdac,0x1cb7c]))
 check(f'kind{kind} real constructor creates HII sentinel -1',v.getq(control+0x20)==0xffffffffffffffff)
 check(f'kind{kind} real exact class and native subtitle descriptor',v.getq(control)==TSE+0x6bb20 and int.from_bytes(v.u.mem_read(control+0x34,2),'little')==8 and ifr==TSE+IFR[kind] and bytes(v.u.mem_read(ifr,2))==b'\x02\x07')
 classification=v.call(S['AMITSE']['frame_protected'],v.frame)
 check(f'kind{kind} frozen guard rejects real-constructed static frame as unknown',classification in [0xffffffff,0xffffffffffffffff])
 before=bytes(v.u.mem_read(control,0x88))
 # Execute the native renderer's exact helper, not a substitute mutation.
 page=HEAP+0x230000;frames=page+0x100
 v.u.mem_write(page+0x4c,d(6));v.u.mem_write(page+0x50,q(frames));v.u.mem_write(frames,q(v.frame)*6)
 v.call(TSE+0x171d4,page,kind,0x99998888,0x1234)
 check(f'kind{kind} actual171D4 late assigns HII and subtitle string',v.getq(control+0x20)==0x99998888 and bytes(v.u.mem_read(ifr+2,2))==w(0x1234))
 check(f'kind{kind} same frame passes guard after native HII assignment',v.call(S['AMITSE']['frame_protected'],v.frame)==0)
 rows.append({'frame_kind':kind,'native_constructor_status':result,'control_vtable_rva':'0x6bb20','initial_hii':'0xffffffffffffffff','native_ifr_rva':hex(IFR[kind]),'opcode':2,'classification_before':'UNKNOWN','classification_after_171d4_with_valid_foreign_hii':'UNPROTECTED','native_counts':v.native_counts,'explicit_models':v.models})
report={'status':'CONFIRMED_ORIGINAL_CONSTRUCTOR_SENTINEL_BEFORE_RENDER_GUARD_COMPATIBILITY_DEFECT','checks':len(checks),'check_names':checks,'cases':rows,'original_sha256':sha(HERE.parent.parent/'boot_context/AMITSE.original.efi'),'split_build_sha256':sha(CORE/'build/split_build.json'),'test_source_sha256':sha(Path(__file__)),'findings':['Original16354 creates standard frame kinds1/2/3/5 with descriptor HII=-1, type8 and native EFI_IFR_SUBTITLE opcode02 length7. Actual1BD14/1BDAC/1CB7C copy it into the control at+20 before a render.','Frozen frame_protected attempts HII ownership before examining IFR opcode and rejects these real-constructed static controls. Actual171D4 later assigns a real HII; gate_render runs before this native helper can execute.','This proves a native layout/lifecycle mismatch. It still does not capture actual physical frame/control state during the black screen.'],'limits':['Allocation/CopyMem and color helper5DF8 are explicit service models; full page construction, native rendering, input loop and physical state are not executed.','171D4 is directly called with a controlled valid foreign HII for all tested kinds to show its exact mutation semantics; the report does not claim16A90 calls it for every kind.','No new allow rule, installer, native exit patch or physical action. Original and frozen bytes unchanged.']}
(HERE/'native_static_control_counterexample.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'report_sha256':sha(HERE/'native_static_control_counterexample.json')}))
