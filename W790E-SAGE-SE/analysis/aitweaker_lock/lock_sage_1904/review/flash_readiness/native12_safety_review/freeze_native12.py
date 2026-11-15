"""Bind the isolated native12 modules and bounded machine-code evidence."""
from pathlib import Path
import json,hashlib,re
HERE=Path(__file__).resolve().parent;IMPL=HERE/'implementation';OLD=HERE.parent/'cold_entry_candidate/implementation'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((IMPL/'build/build.json').read_text());baseline=json.loads((HERE/'implementation_baseline.json').read_text())
for n,h in baseline['copied'].items():assert sha(OLD/n)==h,'Frozen native11 input changed: '+n
for n,h in b['source_sha256'].items():assert sha(IMPL/'source'/n)==h
for name,row in b['modules'].items():assert sha(IMPL/row['path'])==row['sha256']
for pattern in [r'struct GATE_PROVIDER \{.*?\n\};',r'struct GATE_FRAME \{.*?\n\};']:
 assert re.search(pattern,(IMPL/'source/gate.h').read_text(),re.S).group()==re.search(pattern,(OLD/'source/gate.h').read_text(),re.S).group()
reports=['guard_regression.json','structure_verification.json','memory_verification.json','native_save_verification.json','native_commit_verification.json','hotkey_verification.json','defaults_verification.json','native_history_verification.json','defaults_entries_verification.json']
rows={}
for name in reports:
 p=IMPL/'build'/name;r=json.loads(p.read_text());assert r['status'].startswith('PASS'),name
 rows[str(p.relative_to(HERE))]={'sha256':sha(p),'checks':r['checks'],'status':r['status']}
scope=json.loads((HERE/'save_scope_verification.json').read_text())
assert scope['module_sha256']=={n:r['sha256']for n,r in b['modules'].items()}
assert scope['build_manifest_sha256']==sha(IMPL/'build/build.json')
for n,h in scope['source_sha256'].items():assert sha(HERE/n)==h
rows['save_scope_verification.json']={'sha256':sha(HERE/'save_scope_verification.json'),'checks':scope['checks'],'status':scope['status']}
native={n:{k:row[k]for k in ['path','sha256','bytes','context_head_rva','patches']}for n,row in b['modules'].items()}
r={'status':'FROZEN_NATIVE12_SAVE_SCOPE_MODULES_FOR_PROVIDER_REBIND_NOT_RELEASE_READY','modules':native,'build_manifest_sha256':sha(IMPL/'build/build.json'),
 'source_sha256':b['source_sha256'],'evidence':rows,'public_provider_and_frame_ABI_unchanged':True,
 'private_binding_revision':2,'private_binding_bytes':72,'gstate_bytes':16,'gstate_layout':{'0':'unchanged public native UI frame head','8':'private stack-bound save-scope head'},
 'guard_points':sum(len(x['patches'])for x in b['modules'].values()),'new_behavior':'Existing generic commit ACCESS_DENIED marks current bounded save scope; exact original1425C body completes and then returns false to original save callers. New scope has no authorization grant.',
 'unchanged_authorization':{'missing_variable_creation_exception':False,'initialization_authorization_added':False,'global_RuntimeServices_table_hook':False},
 'clarified_existing_limits':{'OEM_ResetBios_chain':{'path':'reset_call_chain.json','sha256':sha(HERE/'reset_call_chain.json'),'conclusion':'Known5F688 caller is Redfish ResetBios=true chain, not proven physical clear-CMOS or normal cold-init.'},
 'original_behavior_counterexamples':{'path':'counterexamples.json','sha256':sha(HERE/'counterexamples.json'),'checks':json.loads((HERE/'counterexamples.json').read_text())['checks'],'label':'Counterexample/behavior difference evidence, not native12 firmware acceptance'}},
 'required_separate_acceptance':['New provider must bind these exact modules and rerun owner/UI/HII/EBS/OVMF checks; frozen old provider is not automatically valid.',
 'Full original graphical feedback remains incomplete: Save-Stay44986 clears83578, save14880 clears835C9 and calls29CC4 despite denied commits. No semantic dirty-state guarantee.',
 'Common save status handling does not establish all native side-effect callbacks, proprietary direct writes or arbitrary privileged UEFI behavior.',
 'Missing-safe-page recovery, complete cold boot/module dispatch, physical NVRAM, exact real graphical session boundary, runtime permissions and flash/recovery/signature constraints remain separate.',
 'No new full firmware image or provider was produced by this module build; later integration requires independent capacity and image verification.'],
 'frozen_native11_preserved':True,'frozen_native11_build_sha256':sha(OLD/'build/build.json'),'device_access':False,'flash_performed':False,'script_sha256':sha(Path(__file__))}
(HERE/'native12_review.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'status':r['status'],'sha256':sha(HERE/'native12_review.json'),'module_sha256':{n:x['sha256']for n,x in native.items()},'checks':sum(x['checks']for x in rows.values())}))
