"""Actual native12 compiled scope + original117-record save loop, no intervention.

Only firmware storage/services/default-effect construction are explicit fixtures.
No native save return value or native exit field is replaced by this verifier.
"""
from pathlib import Path
import sys,json,hashlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;SOURCE=HERE/'native_harness.py'
text=SOURCE.read_text().replace("OLD=DEST.parent/'cold_entry_candidate/implementation'","OLD=DEST/'implementation'")
ns={'__file__':str(SOURCE)};exec(compile(text,str(SOURCE),'exec'),ns)
for k in ['InitializationVM','ProtocolDefaultsVM','TSE','SETUP','HEAP','STOP','U','R','MEM','OC','q','d','ERR','manifest','records']:globals()[k]=ns[k]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
checks=[];cases=[]
def ck(n,c):assert c,n;checks.append(n)
def prepared(cls=InitializationVM):
 v=cls();v.set_cache(88,v.variables[OC]);v.set_cache(92,v.variables[MEM]);return v
def private(v):return TSE+int(manifest['modules']['AMITSE']['context_head_rva'],16)+8
for name,index,size in [(MEM,92,1392),(OC,88,26681)]:
 for mode in ['changed','missing','unchanged']:
  v=prepared();fresh=bytearray(size)
  if mode=='changed':fresh[0x10 if name==MEM else 4]=1
  if mode=='missing':v.missing.add(name)
  v.set_cache(index,fresh);result=v.vendor();allow=mode=='unchanged'
  status=next(x['status']for x in v.commit_status if x['index']==index)
  ck(f'{name}/{mode}: actual compiler wrapper aggregates denial',v.save_results==[1] and result==(0 if allow else ERR(21)))
  ck(f'{name}/{mode}: original storage authorization unchanged',status==hex(0 if allow else ERR(15)) and bool([x for x in v.set_calls if x['name']==name])==allow)
  ck(f'{name}/{mode}: private save head cleaned',v.getq(private(v))==0)
  ck(f'{name}/{mode}: all original iterator records except special skip8 executed',{x['index']for x in v.commit_status}==set(range(117))-{8})
  cases.append({'name':name,'mode':mode,'vendor_status':hex(result),'original_body_bool':v.save_results,'protected_commit':status,'private_head_after':v.getq(private(v))})
v=prepared();x=bytearray(v.variables[MEM]);x[0x11]=0x5a;v.set_cache(92,x)
ck('unrelated memory byte persists with successful native save',v.direct_save()&255==1 and v.variables[MEM][0x11]==0x5a)
v=prepared();x=bytearray(v.variables[MEM]);x[0x10]=1
ck('outside-save denial remains ACCESS_DENIED',v.commit(92,x)==ERR(15))
ck('outside-save denial does not poison later unchanged save',v.direct_save()&255==1 and v.getq(private(v))==0)
v=prepared();v.start();ui=v.getq(private(v)-8);x=bytearray(v.variables[MEM]);x[0x10]=1;v.set_cache(92,x)
ck('owned native UI stack retains denial feedback without provider',v.direct_save()==0)
ck('private save scope leaves public UI frame head intact',v.getq(private(v)-8)==ui and v.getq(private(v))==0)
v.end();ck('UI outer return clears only its own head',v.getq(private(v)-8)==0 and v.getq(private(v))==0)

class Nested(InitializationVM):
 def __init__(self):self.nested_once=False;self.nested_change=False;super().__init__()
 def hook(self,u,a,n,data):
  if a==TSE+0x5a68 and not self.nested_once:
   self.nested_once=True
   if self.nested_change:
    value=bytearray(self.variables[MEM]);value[0x10]=1;self.set_cache(92,value)
   # Exact original outer post-event call tail-dispatches one inner original
   # save. Both real compiled save wrappers and original bodies execute.
   u.reg_write(R.UC_X86_REG_RCX,0);u.reg_write(R.UC_X86_REG_RIP,TSE+0x1425c);return
  super().hook(u,a,n,data)
for change in [False,True]:
 v=prepared(Nested);v.nested_change=change;result=v.direct_save()
 ck(f'nested save change={change}: inner failure propagates only to enclosing scope',(result&255)==int(not change))
 ck(f'nested save change={change}: both complete original bodies ran',v.save_results==[1,1] and len(v.commit_status)==232)
 ck(f'nested save change={change}: no stale private head',v.getq(private(v))==0)
 if change:
  v.set_cache(92,v.variables[MEM]);ck('fresh save after nested failure can succeed',v.direct_save()&255==1)

for mode in ['bad_magic','cycle','depth_limit','read_only_head','unmapped_head']:
 v=prepared();state=private(v);at=HEAP+0x100000
 if mode=='read_only_head':v.memory_deny.append((state,state+8,1))
 elif mode=='unmapped_head':v.u.mem_write(state,q(0xdead0000))
 elif mode=='depth_limit':
  for depth in range(1,17):v.u.mem_write(at+(depth-1)*64,q(0x3231534556415347)+d(1)+d(32)+q(0 if depth==1 else at+(depth-2)*64)+d(depth)+d(0))
  v.u.mem_write(state,q(at+15*64))
 else:
  v.u.mem_write(at,q(0 if mode=='bad_magic'else 0x3231534556415347)+d(1)+d(32)+q(at if mode=='cycle'else 0)+d(1)+d(0));v.u.mem_write(state,q(at))
 result=v.direct_save()
 ck(mode+': malformed scope fails before original variable iteration',result==0 and not v.commit_status and not v.set_calls)

class Corrupt(InitializationVM):
 def hook(self,u,a,n,data):
  if a==TSE+0x5a68:self.u.mem_write(private(self),q(0))
  super().hook(u,a,n,data)
v=prepared(Corrupt);ck('unexpected private scope mutation makes result false',v.direct_save()==0 and v.save_results==[1])
ck('unexpected scope mutation clears orphan scope',v.getq(private(v))==0)
v=prepared(ProtocolDefaultsVM);fresh=bytearray(1392)
for offset in [0x10,0xbd,0xbe]:fresh[offset]=1
at=v.set_cache(92,bytes(1392),fresh);v.direct_defaults()
ck('direct protocol actual OEM effect still changes cached protected bytes',all(v.u.mem_read(at+o,1)==b'\1'for o in [0x10,0xbd,0xbe]))
ck('subsequent direct protocol save now reports denial',v.direct_save()==0 and not [x for x in v.set_calls if x['name']==MEM])
ck('direct protocol failure does not write new persistent memory value',v.variables[MEM]==bytes(1392))
r={'status':'PASS_COMPILED_NATIVE12_SAVE_SCOPE_WITH_ORIGINAL_SAVE_BODY','checks':len(checks),'check_names':checks,'cases':cases,
 'module_sha256':{k:v['sha256']for k,v in manifest['modules'].items()},'build_manifest_sha256':sha(HERE/'implementation/build/build.json'),
 'source_sha256':{p.name:sha(p)for p in [Path(__file__),SOURCE]},'test_harness_redirect':'Only OLD input root redirected to isolated implementation; assertions and original native bodies retained.',
 'new_patch':'AMITSE1425C first13B detour, original push sequence trampoline to14269; C scope preserves full original body and normal return, replaces result only on ACCESS_DENIED/malformed scope.',
 'authorization_change':False,'missing_variable_creation_exception':False,'public_provider_or_frame_ABI_changed':False,
 'limits':['Services, data cache and optional provider are explicit fixtures; full ASUS UI and actual NVRAM are not executed.','Only EFI_ACCESS_DENIED from the local generic commit is aggregated. This does not claim propagation of every other OEM status or event callback failure.','Original defaults effect protocol can change RAM cache while locked; tested later generic commit still blocks persistent protected changes.','Known5F688 external call is a Redfish defaults/save path, not proven clear-CMOS initialization. Missing protected storage remains denied by design.','Native144EF/14604/14779/1482E direct special Boot/Driver variable writes are not protected OC stores and remain original; no global RuntimeServices replacement.','Save-Stay44986 still clears original state byte83578 even after false; native save14880 clears835C9 and invokes29CC4. Their full visual/cache semantics are unproven. No complete GUI feedback or dirty-state acceptance.']}
(HERE/'save_scope_verification.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'status':r['status'],'checks':len(checks),'module_sha256':r['module_sha256']}))
