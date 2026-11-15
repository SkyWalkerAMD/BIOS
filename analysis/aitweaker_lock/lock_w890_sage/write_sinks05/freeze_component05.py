"""Freeze this component's offline evidence; ongoing root review is separate."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((H/'build/build.json').read_text());test=json.loads((H/'build/native_save_tests.json').read_text())
assert test['status']=='PASS'and test['checks']==62
assert test['compiled_model_sha256']==sha(H/'build/W890SaveGuard05.MODEL.dll')
for row in build['products']:assert sha(H/row['path'])==row['sha256']
files=set()
names=['save_guard05.c','save_guard05.h','save_thunk05.S','catalog05.inc','fixture05.c','profile_gate_fixture.S','build.py','test_native_save.py','README.md','patch_contract05.py','patch_contract05.json','notifications_review05.py','notification_closure05.json','notification_xrefs.py','save_notification_modules.json','notification_xrefs.json','oc_downstream_notifications.json','downstream_xrefs.json','native_cache_protocol_refs.json','final_notify_refs.json','final_notify_protocol_modules.json','final_notify_protocol_refs.json','profile_qid_refs.json','profile_callback_bindings.json','profile_direct_callers.json','native_action_calls.json','server_save_targets.json','inspect_final_notify.py','extract_rea.py','rea_summary.json','rea_session.mjs','freeze_component05.py','build/build.json','build/native_save_tests.json','build/W890SaveGuard05.UNBOUND.dll','build/W890SaveGuard05.MODEL.dll','build/save_guard05.obj','build/save_thunk05.obj']
for name in names:files.add(H/name)
for run in ['rea','rea02','rea04','rea05']:
 d=H/run
 for pattern in ['command-*.json','response-*.json','*-seeds.tsv','final-close.json','evidence-export.json','evidence.json','initial_schema_failure.json']:
  files.update(d.glob(pattern))
for p in (H/'rea_text').glob('rea*_response-*'):files.add(p)
for name,expected in build['sources'].items():
 p=R/name;assert sha(p)==expected;files.add(p)
for name in ['password/w890_policy.h','password/w890_management.h','password/core/password_core.h','password/provider/provider.h','password_runtime02/source/efi.h','installer04/source/memory.h','navigation/gate_adapter.h','write_sinks04/policy04.h','write_sinks04/native_variable_catalog.json','write_sinks04/inputs/AMITSESetupData.bin']:
 files.add(H.parent/name)
bound=[{'path':str(p.relative_to(R)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)]
manifest={'component':'W890E-SAGE SE0603 write_sinks05','status':'OFFLINE_COMPONENT_SOURCES_AND_EVIDENCE_BOUND_NOT_DEPLOYABLE','products':build['products'],'native_machine_checks':62,
 'abi':{'binding_revision':5,'header':sha(H/'save_guard05.h'),'profile_gate':'CONFIG*,UINTN,UINT16,UINT8,void*,UINTN*,void* -> int','request_return_symbol':'ws05_provider_request_return','requires_real_global_provider':True},
 'implementation':['Protected diff/absence gate before first Save effect; allowed original Save body unchanged.','Default and original ASUS User Profile actions gated before effects.','Real private observer and actual provider are production dependencies; no owner=true substitute.','Exact static hook/trampoline contracts are separate from an installed firmware image.'],
 'integration_required':['Private actual native owner/session and compiled consumer call windows from final linked artifact.','Root early-dispatch passthrough and nonNULL nativeSave cancellation target before static patches may run.','Navigation/pending-HII/profile-original-caller coverage and credential lifecycle in final aggregate.','Whole board startup/acceptance/recovery before any formal flashing claim.'],
 'scope_exclusions':['MODEL.dll, fixture05.c, profile_gate_fixture.S are test-only and must not enter root production aggregation.','Standalone UNBOUND.dll has no firmware entry or installation action.','Mutable packaging independent review reports are intentionally outside this component manifest and bound independently by root.'],
 'bindings':bound,'physical_writes':False,'created_CAP':False,'release_ready':False}
(H/'component_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'bindings':len(bound),'sha256':sha(H/'component_manifest.json'),'checks':62}))
