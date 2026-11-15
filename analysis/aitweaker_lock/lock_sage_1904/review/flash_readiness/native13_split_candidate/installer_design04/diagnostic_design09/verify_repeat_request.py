"""Exact P14/07 bytes: repeat a modeled unknown-page poll after ESC acknowledge.

This deliberately seeds a sole foreign page with an invalid form index. It is
NOT a dump or asserted cause of physical TX08 screens376/377. Console, HII,
memory services and native loop body are explicit models; real provider UI,
session/owner and gate_poll execute. SHA uses exact-byte hashlib acceleration.
No production source is modified.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
spec=importlib.util.spec_from_file_location('p14_owner',D04/'provider14_chrome07/verify_owner.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
U,R,S,TSE,HEAP,STOP,q,d=O.U,O.R,O.S,O.TSE,O.HEAP,O.STOP,O.q,O.d
w=lambda x:struct.pack('<H',x)
GOP=uuid.UUID('9042a9de-23dc-4a38-96fb-7aded080516a').bytes_le
OUT=STOP+0xa000;KEY=STOP+0xa020;NOP=STOP+0xa040;SET=STOP+0xa060
class VM(O.OwnerVM):
 def __init__(self):
  self.lines=[];self.keys=0;self.requests=0;self.varwrites=0
  super().__init__();out=HEAP+0x2e0000;inp=out+0x100
  self.u.mem_write(self.st+0x30,q(inp));self.u.mem_write(self.st+0x40,q(out))
  for off,ptr in [(8,OUT),(0x28,NOP),(0x30,NOP),(0x38,NOP),(0x40,NOP)]:self.u.mem_write(out+off,q(ptr))
  self.u.mem_write(inp+8,q(KEY));self.u.mem_write(self.rt+0x58,q(SET))
  self.page=self.pages[5]
  self.u.mem_write(self.page+0x20,q(0x99998888))
  self.u.mem_write(self.app+0x28,d(0)+d(1));self.u.mem_write(self.array,q(self.page))
  self.u.mem_write(self.page+0x30,w(0xffff));self.u.mem_write(self.page+0x2a,w(1))
  self.u.mem_write(self.table,d(1)+d(0));self.u.mem_write(self.records+10,w(1))
  self.u.mem_write(self.app+0x5a,b'\0')
  self.u.mem_write(TSE+0x83594,d(0));self.u.mem_write(TSE+0x835b8,d(1))
  self.u.mem_write(self.getq(TSE+0x835a0),q(0x99998888)+d(1))
  for a in [OUT,KEY,NOP,SET,O.symbols['provider_request'],O.symbols['ap_sha256']]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
 def hook(self,u,a,n,data):
  if a==OUT:self.lines.append(self.c16(self.arg(1)));self.ret(0);return
  if a==KEY:self.keys+=1;u.mem_write(self.arg(1),w(0x17)+w(0));self.ret(0);return
  if a==NOP:self.ret(0);return
  if a==SET:self.varwrites+=1;raise AssertionError('unexpected SetVariable')
  if a==O.symbols['provider_request']:self.requests+=1;return
  if a==O.symbols['ap_sha256']:
   u.mem_write(self.arg(2),hashlib.sha256(bytes(u.mem_read(self.arg(0),self.arg(1)))).digest());self.ret(0);return
  if a==O.scope['LOC']and bytes(u.mem_read(self.arg(0),16))==GOP:self.ret(O.ERR(14));return
  super().hook(u,a,n,data)
checks=[]
def check(label,ok):assert ok,label;checks.append(label)
v=VM();check('actual P14 binds frozen07 and unconfigured absent credential initializes',v.bind()==1 and v.initialize()==1)
v.start();check('actual native wrapper owns the session before polls',v.query()==3)
check('synthetic page explicitly belongs to fixture-verified foreign HII',v.call(S['AMITSE']['gate_owner'],0x99998888,0)==0)
check('seeded bad form index is unknown and no safe redirect exists',v.call(S['AMITSE']['page_protected'],v.page)in[0xffffffff,0xffffffffffffffff]and v.call(S['AMITSE']['gate_redirect'])==0)
v.u.mem_write(TSE+0x83468,q(5))
for i in [1,2]:
 v.call(S['AMITSE']['gate_poll'])
 check('poll'+str(i)+' executes actual request and UI acknowledges one modeled ESC',v.requests==i and v.keys==i)
 check('poll'+str(i)+' remains owned locked without grant or variable write',v.query()==3 and v.varwrites==0)
 check('poll'+str(i)+' leaves original poll/input exit state unavailable',v.calls['poll']==0 and bytes(v.u.mem_read(v.app+0x5a,1))==b'\0')
text=''.join(v.lines)
check('same unconfigured status and acknowledge text emitted twice',text.count('Set an independent password under Security first.')==2 and text.count('Press any key to return.')==2)
v.end();check('actual outer End still revokes session',v.query()==1)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r={'status':'PASS_POSSIBLE_REPEAT_REQUEST_COUNTEREXAMPLE_NOT_PHYSICAL_ROOT_CAUSE','checks':len(checks),'check_names':checks,'requests':v.requests,'modeled_ESC_reads':v.keys,'observed_fixture_SetVariable_calls':v.varwrites,'provider_sha256':sha(D04/'provider14_chrome07/build/AiTweakerSplitProvider14.UNSIGNED.local.efi'),'guard_template_sha256':sha(D04/'static_chrome_candidate07/build/guard_template.bin'),'test_sha256':sha(Path(__file__)),'console_text':text,'limits':['Native page with out-of-range form index is synthetic; not captured hardware state.','Console input/output, GOP absence, HII ownership, memory services and stopped native loop body are models. No real keyboard/KVM or complete ASUS GUI.','SHA256 uses Python hashlib on the actual requested bytes for runtime bounds; it never substitutes a fixed accepted hash. Actual native SHA was separately exercised in frozen P14 owner tests.','Shows that identical screens after ESC are compatible with acknowledgment followed by another denied poll request. Does not prove input was consumed or a repeated poll happened physically.','No production changes, new diagnostic candidate, bypass, credential or device operation.']}
(HERE/'repeat_request_counterexample.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'checks':len(checks)}))
