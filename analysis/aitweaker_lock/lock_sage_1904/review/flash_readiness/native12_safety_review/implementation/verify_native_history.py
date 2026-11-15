"""Native Main -> Security -> Esc after the static missing-provider redirect.

Execute actual AMITSE parent lookup, history mutation and PageInput. Keyboard
decoding and page/form notifications are explicit fixtures; no visual BIOS.
"""
from pathlib import Path
import hashlib,json,uuid
HERE=Path(__file__).resolve().parent
prefix=(HERE/'verify_guard.py').read_text().split('\nv=GateVM();check(',1)[0]
exec(compile(prefix,str(HERE/'verify_guard.py'),'exec'),globals())
HISTORY=HEAP+0x180000;OUT=HEAP+0x190000;CAPACITY=28
class HistoryVM(GateVM):
 def __init__(self):
  self.native_counts={0x1012c:0,0x10220:0,0x16c20:0,0x626c:0}
  super().__init__()
  for r in [0x5c60,0x32264,0x3297c,0x1012c,0x10220,0x626c]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+r,end=TSE+r)
  for i,f in enumerate([0x6003,0x2713,0x2714,0x271e,0x6000,0x6001,0x6002,0x271b]):
   self.u.mem_write(self.records+i*64+10,w(f));self.u.mem_write(self.pages[i]+0x2a,w(f))
  self.u.mem_write(self.pages[0]+0x20,q(0));self.u.mem_write(self.pages[3]+0x32,w(1))
  self.u.mem_write(self.pages[3]+0x50,q(HEAP+0xc000));self.u.mem_write(HEAP+0xc000,q(HEAP+0xd000)*6)
  self.u.mem_write(TSE+0x930a8,q(HEAP+0xb000));self.u.mem_write(HEAP+0xb000,d(1)+d(16))
  self.u.mem_write(HEAP+0xb010,uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le)
  self.u.mem_write(TSE+0x835a0,q(HISTORY));self.u.mem_write(TSE+0x83598,d(CAPACITY));self.u.mem_write(TSE+0x83594,d(2));self.u.mem_write(TSE+0x835b8,d(0))
  self.start();self.current(2);self.call(TSE+0x10220,0,2);assert self.getd(TSE+0x835b8)==1
 def hook(self,u,a,n,data):
  r=a-TSE
  if r in self.native_counts:self.native_counts[r]+=1;return
  if r==0x5c60:self.ret(0xd);return
  if r in [0x32264,0x3297c]:self.ret(0);return
  super().hook(u,a,n,data)
 def parent(self,index):
  self.u.mem_write(OUT,b'\xff'*16);r=self.call(TSE+0x1012c,index,OUT,OUT+8)
  return r,int.from_bytes(self.u.mem_read(OUT,2),'little')
 def poll(self):return self.native_site(0xe6bd,0xe6c2)
 def esc(self,index):
  key=HEAP+0xe000;self.u.mem_write(key+8,w(1));self.u.mem_write(key+0xc,w(0x17))
  return self.native_site(0xe8a3,0xe8a9,self.pages[index],key)

checks=[];v=HistoryVM();v.poll()
check('initial Ai refusal with provider missing selects verified Main',v.getd(v.app+0x28)==1 and bytes(v.u.mem_read(v.app+0x5a,1))==b'\0')
check('Main history root stores native HII and FormId',v.getq(HISTORY)==v.handle and v.getd(HISTORY+8)==0x2713)
check('Main root has no parent and only one entry',v.getq(HISTORY+16)==0 and v.getd(HISTORY+24)==0 and v.getd(TSE+0x835b8)==1)
check('history search lower bound and original allocation retained',v.getd(TSE+0x83594)==1 and v.getq(TSE+0x835a0)==HISTORY and v.getd(TSE+0x83598)==CAPACITY)
for k in range(3):
 v.current(3);v.call(TSE+0x10220,1,3)
 check(f'round{k+1} actual parent helper selects Main from Security',v.parent(3)==(0,1))
 v.esc(3)
 check(f'round{k+1} actual native PageInput Esc returns Main',v.getd(v.app+0x28)==1)
 check(f'round{k+1} native history truncates back to root',v.getd(TSE+0x835b8)==1 and v.parent(1)[0]==ERR(14))
 v.current(2);v.poll()
 check(f'round{k+1} repeated Ai refusal remains coherent',v.getd(v.app+0x28)==1 and v.getd(TSE+0x835b8)==1)
check('actual native parent/history/PageInput/navigation routines all executed',all(v.native_counts.values()))
check('missing provider produced no authentication or provider callbacks',not any(v.provider_calls.values()))
v.end();check('missing-provider outer return clears static frame head',v.getq(TSE+int(manifest['modules']['AMITSE']['context_head_rva'],16))==0)
r={'status':'PASS_NATIVE_NORMAL_MAIN_SECURITY_ESC_WITH_PROVIDER_MISSING','checks':len(checks),'check_names':checks,
 'module_sha256':{n:row['sha256']for n,row in manifest['modules'].items()},'native_function_call_counts':{hex(k):n for k,n in v.native_counts.items()},
 'test_source_sha256':sha(Path(__file__)),'shared_fixture_source_sha256':sha(HERE/'verify_guard.py'),
 'limits':['Native page/history structures and HII ownership are explicit fixtures; full rendering and physical cold entry are not executed.','Keyboard-to-action mapping, page-leave/form notifications and mapped-memory queries are fixtures. Original parent lookup, history append/truncate, PageInput and static guard execute actual bytes.','This covers normal verified Main availability. Missing safe page/invalid history still has no accepted safe-exit proof; dual native ResetSystem paths remain separately documented.','No old driver hook is installed and no prior hardware pass is inherited.']}
(HERE/'build/native_history_verification.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'checks':len(checks)}))
