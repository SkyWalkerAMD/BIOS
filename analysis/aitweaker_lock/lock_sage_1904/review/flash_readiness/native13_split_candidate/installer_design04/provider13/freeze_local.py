"""Freeze a reviewable P13/guard snapshot without declaring release readiness."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;CORE=HERE.parent/'split_core'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((HERE/'build/build.json').read_text());guard=json.loads((CORE/'build/split_build.json').read_text())
assert sha(HERE/'build/AiTweakerSplitProvider13.UNSIGNED.local.efi')==build['efi_sha256']
for name,h in build['sources'].items():assert sha(HERE/'source'/name)==h
for name,h in guard['sources'].items():assert sha(CORE/'source'/name)==h
reports=[]
for path,key,expected in [(CORE/'build/split_guard_regression.json','checks',198),(CORE/'build/split_native_regression.json','checks',117),(CORE/'build/split_boundary_regression.json','checks',15),(HERE/'build/owner_verification.json','checks',31)]:
 r=json.loads(path.read_text());assert r[key]==expected and r['status'].startswith('PASS')
 assert r['split_build_sha256']==sha(CORE/'build/split_build.json')
 if 'provider_sha256'in r:assert r['provider_sha256']==build['efi_sha256']
 reports.append({'path':str(path),'sha256':sha(path),'checks':expected,'status':r['status']})
paths=[]
for root in [HERE,CORE]:
 paths.extend(root.glob('*.py'));paths.extend(root.glob('*.json'))
 paths.extend(p for p in (root/'source').iterdir()if p.is_file())
 paths.extend(p for p in (root/'build').iterdir()if p.is_file())
paths=[p for p in paths if p.name!='local_candidate_manifest.json']
review={'status':'FROZEN_LOCAL_SPLIT_PROFILE_1_NOT_INSTALLER_NOT_RELEASE_READY','provider_sha256':build['efi_sha256'],'public_provider_guid':'87e3c6fa-11fb-4e77-af2d-ea50b640fa13','public_provider_size':56,'frame_size':48,'load_options_context_size':96,'immutable_guard_binding_size':160,'state_bytes':4096,'state_used_bytes':32,'state_offsets':{'ui_head':0,'save_head':8,'magic':16,'phase':24,'reserved':28},'phase_values':{'ARMED':1,'RETIRED':2,'ENDED':3},'tests':reports,'total_checks':361,'handoff':['Independent OVMF entry/HII/UI/persistence harness belongs in a NEW sibling directory; do not edit or rebuild this frozen candidate.','P13 pins full original OEM text. Do not replace E1CA body bytes or weaken identity for a fixture. TCG-only #DB context redirection is an explicitly separate fixture possibility, never a hardware installer.','Report any real defect for a new candidate revision; do not silently edit frozen artifacts.'],'limits':['No publication/rollback installer, native ASUS GUI, real NVRAM or production firmware boot integration acceptance.','HII package is generated from official formats but actual NewPackageList/export/GUI path not yet tested.','Load requires already-installed exact12 detours and an initial empty detached UI/save chain; caller must establish allocation ownership and permissions.','All previously frozen N12/P12/EP/probe04 files are unchanged.']}
(HERE/'local_candidate_review.json').write_text(json.dumps(review,indent=2)+'\n');paths.append(HERE/'local_candidate_review.json')
manifest={'status':review['status'],'path_base':str(HERE.parent),'artifacts':[{'path':str(p.relative_to(HERE.parent)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(set(paths))]}
(HERE/'local_candidate_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'files':len(manifest['artifacts']),'manifest_sha256':sha(HERE/'local_candidate_manifest.json'),'review_sha256':sha(HERE/'local_candidate_review.json'),'provider_sha256':build['efi_sha256'],'checks':361}))
