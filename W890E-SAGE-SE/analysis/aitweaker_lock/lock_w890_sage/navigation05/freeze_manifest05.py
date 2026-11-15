"""Freeze the tested local navigation bridge; never package a BIOS image."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3];B=H.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
O=H/'bridges_build';dll=O/'W890NavigationBridges05.TESTONLY.dll';digest=sha(dll)
reports={}
for name,want in [('bridge_tests.json',18),('form_open_tests.json',9),('error_return_tests.json',1)]:
 j=json.loads((O/name).read_text());assert j['component_sha256']==digest and j['checks']==want,(name,j.get('checks'))
 for file,value in j['sources'].items():
  f=H/file
  # Older bridge report keys use basenames for the generated observer.
  if not f.exists()and file=='observer_visit05.c':f=H/'visit'/file
  assert f.exists()and sha(f)==value,(name,file,'source mismatch')
 reports[name]={'checks':j['checks'],'sha256':sha(O/name)}
build=json.loads((O/'build.json').read_text());assert build['component_sha256']==digest
for file,value in build['sources'].items():assert sha(R/file)==value,('linked source changed',file)
legacy=H/'build/W890Navigation05.TESTONLY.dll';legacy_sha=sha(legacy)
for name in ['navigation_pe_tests.json','parser_navigation_tests.json']:
 assert json.loads((H/'build'/name).read_text())['component_sha256']==legacy_sha
evidence=[]
for f in sorted((H/'rea').glob('W890-*.json')):
 j=json.loads(f.read_text());x=j.get('structuredContent',{});evidence.append({'file':str(f.relative_to(H)),'sha256':sha(f),'evidence_id':x.get('evidence_id'),'operation':x.get('operation'),'procedure':x.get('parameters',{}).get('procedure')})
files=list(H.glob('*.c'))+list(H.glob('*.h'))+list(H.glob('*.S'))+list(H.glob('*.py'))
files +=[H/x for x in ['README.md','development_failures.json','pending_static_review.json','hotkey_catalog.json','hook_plan.json','history_refs.json','plan-lifetime.json','rea_session.mjs','seeds.tsv']]
files +=[f for f in(H/'visit').iterdir()if f.is_file()]
files +=list((H/'rea').glob('*.json'))+list((H/'rea').glob('*.txt'))
files +=[H/'build'/x for x in ['W890Navigation05.TESTONLY.dll','navigation.map','build.json','consumer_windows.json','navigation_pe_tests.json','parser_navigation_tests.json','original_growth_evidence.json']]
files +=[O/x for x in ['W890NavigationBridges05.TESTONLY.dll','navigation.map','build.json','consumer_windows.json','static_hook_plan.json','bridge_tests.json','form_open_tests.json','error_return_tests.json']]
dependencies={R/x for x in build['sources']if not str((R/x).resolve()).startswith(str(H.resolve()))}
dependencies.update([B/x for x in ['native_observer04/observer.h','native_observer04/verify_observer.py','native_observer04/profile_windows.h','password_runtime02/verify_runtime_pe.py','installer04/source/memory.h','integration05/observer05.c','integration05/parser-snapshot.zip','navigation/modules/AMITSE.efi','navigation/modules/Setup.efi','navigation/input_registry_data.h','password/w890_policy.h','password/w890_policy_data.h']])
def binding(f):return {'path':str(f.relative_to(R)),'bytes':f.stat().st_size,'sha256':sha(f)}
out={'status':'LOCAL_COMPONENT_REGRESSION_ONLY_NOT_INSTALLABLE_NOT_FLASHABLE','component_sha256':digest,'legacy_component_sha256':legacy_sha,'test_reports':reports,'legacy_tests':{'component_cases':17,'original_growth_boundaries':2,'parser_snapshot_compositions':1},'real_execution':['actual compiled observer/provider/password UI/navigation bridges','original first-window continuation, selected Page/Frame dispatch, native history functions','original key/mouse handlers and FormOpen/FormClose batch loop','original pending empty-queue branch'],'explicit_model_boundaries':['UEFI services and synthetic CPU page mappings','outer App/Page/Frame fixtures','FormOpen callback destination3E700 success model','F10 save-confirm destination and mouse callback destination models','SHA/PBKDF/RDSEED independent oracles'],'remaining_gaps':['canonical Setup HII only; foreign HII ownership and exact variable/Ref policy require new integration','nonempty pending batches and other40094 callers remain outside this bridge','private effect ticket is not yet a nested frame stack for profile callbacks','pre-existing provider FAULT cannot release original browser body until the complete fixed guard catalogue is bound','no whole native GUI or hardware execution is claimed'],'files':[binding(f)for f in sorted(set(files))if f.exists()],'dependencies':[binding(f)for f in sorted(dependencies)],'rea_evidence':evidence}
target=H/'component_manifest.json';target.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'manifest_sha256':sha(target),'component_sha256':digest,'bindings':len(out['files'])+len(out['dependencies']),'new_checks':sum(x['checks']for x in reports.values())},indent=2))
