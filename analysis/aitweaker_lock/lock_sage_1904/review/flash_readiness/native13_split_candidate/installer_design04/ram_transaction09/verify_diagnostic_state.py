"""Actual TX09 platform/state transactions; no native policy replacements.

The inherited fixture explicitly models firmware services, seeded inventory,
CPU-register reads and SHA acceleration, as documented in verify_platform.py.
This supplement tests only the new private extent and lifetime consequences.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('tx09_platform_fixture',HERE/'verify_platform.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
MAGIC=0x3930474149444753;TRACE=struct.pack('<QII',MAGIC,1,576)+bytes(560)
def state_image():
 b=bytearray(4096);struct.pack_into('<QI',b,16,0x3331535441544547,1);b[64:640]=TRACE;return bytes(b)
class Observed(T.VM):
 def __init__(self):
  self.state_regions=[];self.state_writes=[];self.first_site_state=None;self.load_state=None
  super().__init__()
 def hook(self,u,a,n,unused):
  if a==T.SERV['load']:
   assert self.state_regions
   state=self.state_regions[-1][0]+4096
   self.load_state=bytes(u.mem_read(state,4096))
   assert self.load_state==state_image(),'trace must be initialized before provider LoadImage'
  old=len(self.allocated)
  super().hook(u,a,n,unused)
  if a==T.SERV['alloc']and len(self.allocated)>old:
   base,pages,typ=self.allocated[-1]
   if typ==4:
    assert pages==3
    # Ensure observed zeroes came from the app's whole-state memset, not from
    # Unicorn's default zero page allocation. Neighbor bytes must be retained.
    u.mem_write(base,b'\xa7'*(pages*4096));self.state_regions.append((base,pages))
    def written(uc,access,address,size,value,_):
     assert base+4096<=address and address+size<=base+8192,'write outside owned state payload'
     self.state_writes.append((address-(base+4096),size,value))
    u.hook_add(T.U.UC_HOOK_MEM_WRITE,written,begin=base,end=base+pages*4096-1)
 def write(self,u,access,a,n,value,unused):
  if self.first_site_state is None:
   self.first_site_state=bytes(u.mem_read(self.state_regions[-1][0]+4096,4096))
  super().write(u,access,a,n,value,unused)

checks=[]
def check(label,value):assert value,label;checks.append(label)
for slot in [0,1]:
 v=Observed();check(f'mode{slot+1} prepares with nonzero fresh allocation',v.prepare(slot)==1)
 ctx=v.session(slot);state=v.getq(ctx+104);allocation=v.state_regions[0][0]
 check(f'mode{slot+1} exact full state prefix gap trace and tail initialization',bytes(v.u.mem_read(state,4096))==state_image())
 check(f'mode{slot+1} unchanged two neighboring pages',bytes(v.u.mem_read(allocation,4096))==b'\xa7'*4096 and bytes(v.u.mem_read(allocation+8192,4096))==b'\xa7'*4096)
 check(f'mode{slot+1} no new allocation for diagnostics',len(v.allocated)==3 and v.allocated[-1][1:]==(3,4))
 for i,name in enumerate(['AMITSE','Setup']):
  expected=(T.meta['module_fixtures'][name]['guard_bytes']+4095)//4096+2
  check(f'mode{slot+1} {name} dynamically sizes new guard',v.allocated[i][1]==expected)
 check(f'mode{slot+1} state remains RW NX',v.getq(v.pte(state))&2 and v.getq(v.pte(state))&(1<<63))
 for i in range(2):
  address=v.allocated[i][0]+4096;entry=v.getq(v.pte(address))
  check(f'mode{slot+1} guard{i} is RX',not(entry&2)and not(entry&(1<<63)))
 check(f'mode{slot+1} no original-site writes during state preparation',not v.foreign_writes)
 if slot:check('state initialized before any provider LoadImage',v.load_state==state_image())
 before=list(v.state_writes);allocations=list(v.allocated)
 check(f'mode{slot+1} repeated prepare refuses without resetting diagnostics',v.prepare(slot)==0 and v.state_writes==before and v.allocated==allocations)
 check(f'mode{slot+1} exact installation after initialization',v.call('platform_install',ctx)==0 and v.first_site_state==state_image())
 before_trace=bytes(v.u.mem_read(state+64,576))
 if slot:
  check('start failure retains state and exact trace',v.call('platform_start_provider',ctx)==0 and bytes(v.u.mem_read(state+64,576))==before_trace)
 check(f'mode{slot+1} removal preserves diagnostics while restoring original sites',v.call('platform_remove',ctx)==2 and v.originals()and bytes(v.u.mem_read(state+64,576))==before_trace)
 check(f'mode{slot+1} only existing state phase becomes retired',v.getd(state+24)==2 and bytes(v.u.mem_read(state+32,32))==bytes(32)and bytes(v.u.mem_read(state+640,4096-640))==bytes(4096-640))

changes=[('magic',0,struct.pack('<Q',0)),('revision',8,struct.pack('<I',2)),
 ('extent',12,struct.pack('<I',4096)),('sequences',16,b'\xff'*16),
 ('counters',32,b'\xff'*24),('writer_lock',56,struct.pack('<I',1)),
 ('diagnostic_flags',60,struct.pack('<I',0xffffffff)),('all_records',64,b'\xa5'*512)]
for label,offset,raw in changes:
 v=Observed();assert v.prepare()==1;ctx=v.session();state=v.getq(ctx+104)
 v.u.mem_write(state+64+offset,raw);before=bytes(v.u.mem_read(state+64,576))
 check('trace '+label+' never alters original installation decision',v.call('platform_install',ctx)==0)
 check('trace '+label+' never blocks exact rollback or gets cleared',v.call('platform_remove',ctx)==2 and v.originals()and bytes(v.u.mem_read(state+64,576))==before)

v=Observed();assert v.prepare()==1;ctx=v.session();state=v.getq(ctx+104)
v.u.mem_write(state+16,T.q(0))
check('original public state magic still blocks installation',v.call('platform_install',ctx)==1 and not v.foreign_writes)

v=Observed();assert v.prepare()==1;ctx=v.session();state=v.getq(ctx+104)
v.u.mem_write(state+64,bytes(range(256))*2+bytes(64));before=bytes(v.u.mem_read(state+64,576))
check('existing EBS tx_end does not interpret or clear trace',v.call('tx_end',ctx)==0 or v.getd(ctx+16)==1)
check('EBS marks public state ended and retains trace',v.getd(state+24)==3 and bytes(v.u.mem_read(state+64,576))==before)

report={'status':'PASS_ACTUAL_COMPLETE_TX09_DIAGNOSTIC_EXTENT_AND_LIFETIME_WITH_EXPLICIT_MODELS',
 'checks':len(checks),'check_names':checks,'efi_sha256':T.sha(T.FILE),
 'build_sha256':T.sha(T.BUILD/'app_build.json'),'test_sha256':T.sha(Path(__file__)),
 'base_fixture_sha256':T.sha(HERE/'verify_platform.py'),
 'limits':['Actual final platform/transaction/ending code executes on exact full app PE.',
           'UEFI services, CPU register reads, initial inventory and exact SHA acceleration use the inherited explicit fixture models.',
           'Corrupted private diagnostics are shown not to enter transaction install/removal decisions. Native gate policy unchangedness is separate guard-author evidence.',
           'No provider entry/UI, native ASUS browser, hardware, password, disk or firmware operation runs in this supplement.']}
(HERE/'app_build/diagnostic_state_verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'checks':len(checks),'efi_sha256':report['efi_sha256']}))
