"""Execute production hooks + original SAGE history and PageInput in Unicorn.

Firmware memory/services, password dialog result, key decoding, page-leave
callback, and form notifications are fixtures. Native Esc parent resolution,
the native dispatcher, and history truncate/append execute original bytes.
"""
from pathlib import Path
import hashlib,json,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parent;ROOT=CASE.parents[2];DRIVER=HERE
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
HARDWARE_DRIVER_SHA='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
AMITSE_SHA='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
SETUP_SHA='719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d'
build=CANDIDATE_BUILD_CONTEXT
assert sha(CANDIDATE/'build/AiTweakerLock1904.efi')==build['candidate_driver_sha256']
assert build['baseline_driver_sha256']==HARDWARE_DRIVER_SHA
assert sha(CASE/'analysis/modules/AMITSE.efi')==AMITSE_SHA
assert sha(CASE/'analysis/modules/Setup.efi')==SETUP_SHA
assert all(sha(CASE/name)==expected for name,expected in build['sources'].items())
assert all(sha(ROOT/name)==expected for name,expected in build['external_sources'].items())
prefix=(DRIVER/'verify_adapter.py').read_text(encoding='utf8').split('\nchecks=[]',1)[0]
prefix=ADAPT_PATHS(prefix)
ns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':CANDIDATE};exec(compile(prefix,str(DRIVER/'verify_adapter.py'),'exec'),ns)
for name in ['VM','U','R','TSE','SETUP','HEAP','STOP','symbols','q','d','w']:globals()[name]=ns[name]
HISTORY=HEAP+0x180000;OUT=HEAP+0x190000;CAPACITY=28
NOT_FOUND=0x800000000000000e
checks=[]
def check(name,value):assert value,name;checks.append(name)

class NativeHistoryVM(VM):
 def __init__(self):
  self.denied_memory=[];self.native_counts={0x1012c:0,0x10220:0,0x16c20:0,0x626c:0}
  super().__init__()
  for fn in [0x5c60,0x32264,0x3297c,0x1012c,0x10220,0x626c]:
   self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=TSE+fn,end=TSE+fn)
  for i,form in enumerate([0x6003,0x2713,0x2714,0x271e,0x6000,0x6001,0x6002,0x271b]):
   self.u.mem_write(self.records+i*64+10,w(form));self.u.mem_write(self.pages[i]+0x2a,w(form))
  self.u.mem_write(self.pages[0]+0x20,q(0))
  self.u.mem_write(self.pages[3]+0x32,w(1))
  self.u.mem_write(self.pages[3]+0x50,q(HEAP+0xc000))
  self.u.mem_write(HEAP+0xc000,q(HEAP+0xd000)*6)
  self.u.mem_write(TSE+0x930a8,q(HEAP+0xb000))
  self.u.mem_write(HEAP+0xb000,d(1)+d(16))
  self.u.mem_write(HEAP+0xb010,uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le)
  self.u.mem_write(TSE+0x835a0,q(HISTORY));self.u.mem_write(TSE+0x83598,d(CAPACITY));self.u.mem_write(TSE+0x83594,d(2));self.u.mem_write(TSE+0x835b8,d(0))
  check('exact pinned production driver and modules attach',self.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a6000)==1)
  self.start();self.current(2)
  self.call(TSE+0x10220,0,2)
  assert self.getd(TSE+0x835b8)==1
 def hook(self,u,address,size,data):
  if address==symbols['memory_present']:
   a,n,write=self.arg(0),self.arg(1),self.arg(2)
   blocked=any(a<hi and lo<a+n and (write or not write_only) for lo,hi,write_only in self.denied_memory)
   self.ret(int(not blocked and n>0 and any(lo<=a and a+n<=hi for lo,hi in self.ranges)));return
  rva=address-TSE
  if rva in self.native_counts:self.native_counts[rva]+=1
  if rva in [0x1012c,0x10220,0x16c20,0x626c]:return
  if rva==0x5c60:self.ret(0xd);return # Native Esc action mapping.
  if rva in [0x32264,0x3297c]:self.ret(0);return
  super().hook(u,address,size,data)
 def parent(self,index):
  self.u.mem_write(OUT,b'\xff'*16);status=self.call(TSE+0x1012c,index,OUT,OUT+8)
  return status,int.from_bytes(self.u.mem_read(OUT,2),'little')
 def poll(self):self.call(TSE+0x34b2c)
 def snapshot(self):return bytes(self.u.mem_read(HISTORY,CAPACITY*32)),self.getd(TSE+0x835b8),self.getd(TSE+0x83594)
 def esc(self,index):
  event=HEAP+0xe000;self.u.mem_write(event+8,w(1));self.u.mem_write(event+0xc,w(0x17))
  self.call(self.getq(TSE+0x6b930),self.pages[index],event)

v=NativeHistoryVM();v.poll()
check('initial denied Ai redirects to Main',v.getd(v.app+0x28)==1 and v.u.mem_read(v.app+0x5a,1)==b'\0')
check('history root key comes from Main native page',v.getq(HISTORY)==v.handle and v.getd(HISTORY+8)==0x2713)
check('root has no parent and count is one',v.getq(HISTORY+16)==0 and v.getd(HISTORY+24)==0 and v.getd(TSE+0x835b8)==1)
check('search lower bound changes from Ai to Main',v.getd(TSE+0x83594)==1)
check('OEM buffer address and capacity are preserved',v.getq(TSE+0x835a0)==HISTORY and v.getd(TSE+0x83598)==CAPACITY)
for iteration in range(3):
 v.current(3);v.call(TSE+0x10220,1,3)
 check(f'pass {iteration+1}: original helper resolves Security parent as Main',v.parent(3)==(0,1))
 v.esc(3)
 check(f'pass {iteration+1}: actual native PageInput Esc returns Main',v.getd(v.app+0x28)==1)
 check(f'pass {iteration+1}: actual native history truncates to root',v.getd(TSE+0x835b8)==1 and v.parent(1)[0]==NOT_FOUND)
 # A future stale protected page repeats the production redirect consistently.
 v.current(2);v.poll()
 check(f'pass {iteration+1}: repeated denied redirect remains coherent',v.getd(v.app+0x28)==1 and v.getd(TSE+0x835b8)==1)
check('native routines genuinely executed',all(v.native_counts[n]>0 for n in v.native_counts))
normal_counts=dict(v.native_counts)

def invalid(name,mutate):
 t=NativeHistoryVM();mutate(t);before=t.snapshot();t.poll()
 check(name+': invocation ends fail closed',t.u.mem_read(t.app+0x5a,1)==b'\1')
 check(name+': current protected page not committed to a false safe root',t.getd(t.app+0x28)==2)
 check(name+': history remains unchanged',t.snapshot()==before)
 rendered=t.calls['render'];native_input=t.native_counts[0x16c20]
 t.call(t.getq(TSE+0x6b928),t.pages[2])
 consumed=t.call(t.getq(TSE+0x6b930),t.pages[2],HEAP+0xe000)
 check(name+': stale protected render is suppressed during exit',t.calls['render']==rendered)
 check(name+': stale protected input is consumed during exit',consumed==0 and t.native_counts[0x16c20]==native_input)

for name,mutate in [
 ('null buffer',lambda t:t.u.mem_write(TSE+0x835a0,q(0))),
 ('unmapped buffer',lambda t:t.u.mem_write(TSE+0x835a0,q(0xdead0000))),
 ('unaligned buffer',lambda t:t.u.mem_write(TSE+0x835a0,q(HISTORY+1))),
 ('buffer overlaps original AMITSE',lambda t:t.u.mem_write(TSE+0x835a0,q(TSE+0x84000))),
 ('buffer overlaps original Setup',lambda t:t.u.mem_write(TSE+0x835a0,q(SETUP+0x84000))),
 ('buffer overlaps app structure',lambda t:t.u.mem_write(TSE+0x835a0,q(t.app))),
 ('buffer overlaps target page',lambda t:t.u.mem_write(TSE+0x835a0,q(t.pages[1]))),
 ('buffer overlaps page array',lambda t:t.u.mem_write(TSE+0x835a0,q(t.array))),
 ('zero capacity',lambda t:t.u.mem_write(TSE+0x83598,d(0))),
 ('excessive capacity',lambda t:t.u.mem_write(TSE+0x83598,d(8213))),
 ('zero used records',lambda t:t.u.mem_write(TSE+0x835b8,d(0))),
 ('used exceeds capacity',lambda t:t.u.mem_write(TSE+0x835b8,d(CAPACITY+1))),
 ('search start outside page array',lambda t:t.u.mem_write(TSE+0x83594,d(8))),
 ('history read only',lambda t:t.denied_memory.append((HISTORY,HISTORY+CAPACITY*32,True))),
 ('root search global read only',lambda t:t.denied_memory.append((TSE+0x83594,TSE+0x83598,True))),
 ('history count global read only',lambda t:t.denied_memory.append((TSE+0x835b8,TSE+0x835bc,True))),
 ('app current index read only',lambda t:t.denied_memory.append((t.app+0x28,t.app+0x2c,True))),
 ('app redraw flag read only',lambda t:t.denied_memory.append((t.app+0x58,t.app+0x59,True))),
]:invalid(name,mutate)

t=NativeHistoryVM();t.u.mem_write(t.app+0x2c,d(8193));t.poll()
check('oversized page array ends browser',t.u.mem_read(t.app+0x5a,1)==b'\1')
t=NativeHistoryVM()
for p in t.pages:t.u.mem_write(p+0x32,w(1))
t.poll();check('no safe root ends browser instead of rebasing a child',t.u.mem_read(t.app+0x5a,1)==b'\1')

report={'status':'PASS','checks':len(checks),'cases':len(checks),'check_names':checks,
        'driver_sha256':sha(CANDIDATE/'build/AiTweakerLock1904.efi'),
        'hardware_history01_driver_sha256':HARDWARE_DRIVER_SHA,
        'original_amitse_sha256':AMITSE_SHA,'original_setup_sha256':SETUP_SHA,
        'build_manifest_sha256':sha(CANDIDATE/'build/build.json'),'linker_map_sha256':sha(CANDIDATE/'build/driver.map'),
        'compiled_source_sha256':build['sources'],
        'external_source_sha256':build['external_sources'],
        'verification_source_sha256':{p.name:sha(p) for p in [HERE/'verify_adapter.py',Path(__file__).resolve()]},
        'native_function_call_counts':{hex(k):n for k,n in normal_counts.items()},
        'limits':['Constructed native page/state fixtures; complete OEM visual browser and BMC hardware are not executed.',
                  'Password result, firmware services, memory-range checks, key decoding, page-leave callback and form notifications are explicit stubs.',
                  'This report verifies original native parent traversal and production redirect consistency; it adds no new visual UI or hardware validation claim.',
                  'Firmware persistence, flash acceptance, and recovery are outside this regression.']}
(CANDIDATE/'build/history_regression.json').write_text(json.dumps(report,indent=2),encoding='utf8')
print(json.dumps(report,indent=2))
