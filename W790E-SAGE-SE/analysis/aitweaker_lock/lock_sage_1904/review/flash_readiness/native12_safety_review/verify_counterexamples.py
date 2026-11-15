"""Reproduce OEM defaults/save denial and direct-default RAM/write split.

5F688's established external caller belongs to a Redfish ResetBios request
chain. No physical CMOS recovery or normal cold-init trigger is established.
"""
from pathlib import Path
import sys,json,hashlib
sys.dont_write_bytecode=True
import native_harness as h
HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
checks=[];scenarios=[]
def ck(n,c):assert c,n;checks.append(n)
for baseline in [True,False]:
 for name,index,size in [(h.MEM,92,1392),(h.OC,88,26681)]:
  for mode in ['missing','existing_changed','existing_identical']:
   v=h.InitializationVM(baseline);fresh=bytearray(size)
   if mode=='missing':v.missing.add(name)
   if mode=='existing_changed':fresh[0x10 if name==h.MEM else 4]=1
   v.set_cache(index,fresh);status=v.vendor()
   commit=next(x for x in v.commit_status if x['index']==index)
   writes=[x for x in v.set_calls if x['name']==name]
   allow=baseline or mode=='existing_identical'
   ck(f'{baseline}/{name}/{mode}: original complete iterator commit result',commit['status']==hex(0 if allow else h.ERR(15)))
   ck(f'{baseline}/{name}/{mode}: protected persistent fixture outcome',bool(writes)==allow)
   ck(f'{baseline}/{name}/{mode}: OEM reports success even when commit denied',status==0 and v.save_results==[1])
   ck(f'{baseline}/{name}/{mode}: original 117-record table retained',bytes(v.u.mem_read(h.DATA,len(h.original_data)))==h.original_data)
   scenarios.append({'original_baseline':baseline,'name':name,'mode':mode,'vendor_status':hex(status),'generic_commit':commit,'protected_set_variable_calls':writes,'native_save_bool':v.save_results,'native_trace':v.native_trace,'declared_fixture_calls':v.fixture_calls})
for baseline in [True,False]:
 v=h.ProtocolDefaultsVM(baseline);fresh=bytearray(1392)
 for offset in [0x10,0xbd,0xbe]:fresh[offset]=1
 at=v.set_cache(92,bytes(1392),fresh)
 ck(f'protocol baseline={baseline}: original interface slot is exact6286C',v.getq(h.TSE+0x7b568)==h.TSE+0x6286c)
 v.direct_defaults()
 ck(f'protocol baseline={baseline}: actual13B9C changes all three protected cache bytes',all(v.u.mem_read(at+o,1)==b'\1'for o in [0x10,0xbd,0xbe]))
 ck(f'protocol baseline={baseline}: direct effect has no variable write before save',not v.set_calls)
 v.direct_save();commit=next(x for x in v.commit_status if x['index']==92);writes=[x for x in v.set_calls if x['name']==h.MEM]
 ck(f'protocol baseline={baseline}: subsequent original generic commit gated',commit['status']==hex(0 if baseline else h.ERR(15)) and bool(writes)==baseline)
 scenarios.append({'direct_protocol_defaults':True,'original_baseline':baseline,'control_records':v.control_evidence,'runtime_fixups':v.runtime_fixups,'protected_cache_offsets_changed':['0x10','0xbd','0xbe'],'generic_commit':commit,'persistent_memory_writes':writes})
r={'status':'CONFIRMED_NATIVE11_OEM_RESET_SAVE_DENIAL_AND_BOUNDED_PROTOCOL_COMMIT_CONTAINMENT','checks':len(checks),'check_names':checks,'scenarios':scenarios,
 'frozen_module_sha256':{n:r['sha256']for n,r in h.manifest['modules'].items()},'original_AMITSE_sha256':sha(h.CASE/'analysis/modules/AMITSE.efi'),'original_Setup_sha256':sha(h.CASE/'analysis/modules/Setup.efi'),
 'original_setup_data_sha256':sha(h.OLD/'build/OriginalAMITSESetupData.bin'),'source_sha256':{p.name:sha(p)for p in [Path(__file__),HERE/'native_harness.py',HERE/'inspect_paths.py']},
 'actual_native_paths':['5F688 -> native5D4CC already-initialized short branch ->5F6C2/5ABC ->5F6C9/1425C ->117-record iterator1484A/11164 ->111E8 for memory','OC formatter1D8D8 is explicit bridge into actual Setup152C/2568/27EC and actual original HiiDatabase5FB8','Published slot7B568 ->6286C ->13B9C -> original IFR accessors1CDFC/1CE6C ->CopyMem; then1425C generic commit'],
 'findings':['Native11 rejects creating missing SocketMemoryConfig and VARSTORE_OCMR_SETTINGS_NAME where relevant original commit and route bytes create them. This is an exact OEM defaults/save behavior difference under the declared prepared-cache premise; it is not proof of a CMOS initialization regression.','The established external caller is a Redfish ResetBios request chain. Native11 also rejects changed existing protected bytes in that method. No missing-variable or initialization exception is authorized merely by this observation.','Direct6286C bypasses the defaults prompt and changes protected RAM cache, but native11 generic commit subsequently denies all three tested memory offsets; storage bypass was not reproduced on this path.','Original save BOOL and vendor status still indicate success after denied protected commit.'],
 'limits':['Runtime storage, memory availability, BS allocation/CopyMem and OEM service events are explicit fixtures; no true NVRAM or host execution.','Prepared runtime cache and the already-initialized5D4CC branch are supplied. This does not prove physical clear-CMOS dispatch or complete cold initialization.','Protocol effect tests expose only three original memory controls; unrelated control IFR runtime pointers are unset. Other OEM callback effects are outside this bounded trace.','Baseline restores original relevant commit/defaults/route bytes within otherwise frozen loaded images.','No approved bypass or new module has yet been created; no BMC/upload/flash/device access.']}
(HERE/'counterexamples.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':r['status'],'checks':len(checks),'scenarios':len(scenarios),'report_sha256':sha(HERE/'counterexamples.json')}))
