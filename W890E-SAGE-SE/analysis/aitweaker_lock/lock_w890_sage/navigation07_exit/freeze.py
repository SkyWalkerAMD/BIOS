"""Freeze only after final actual-byte reports and all input hashes agree."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];O=H/'build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
row=lambda p:{'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
DLL=O/'W890NavigationExit07.TESTONLY.dll';digest=sha(DLL)
build=json.loads((O/'build.json').read_text());assert build['component_sha256']==digest
for path,s in build['sources'].items():assert sha(R/path)==s,path
reports={name:json.loads((O/name).read_text())for name in ['tail_tests.json','retry_tests.json','caller_tests.json']}
assert reports['tail_tests.json']['checks']==25 and reports['retry_tests.json']['checks']==2 and reports['caller_tests.json']['checks']==1
for name,d in reports.items():assert d['component_sha256']==digest and all(x['status']=='PASS'for x in d['cases']),name
assert reports['tail_tests.json']['source_sha256']==sha(H/'verify_tail.py')
assert reports['retry_tests.json']['source_sha256']==sha(H/'verify_retry.py')
assert reports['retry_tests.json']['tail_fixture_sha256']==sha(H/'verify_tail.py')
assert reports['caller_tests.json']['source_sha256']==sha(H/'verify_caller.py') and reports['caller_tests.json']['tail_fixture_sha256']==sha(H/'verify_tail.py')
parents=[B/'navigation06_actions/component_manifest.json',B/'exit_control07/component_manifest.json']
for p in parents:
 d=json.loads(p.read_text())
 for key in ['files','local_bindings','external_bindings']:
  for r in d.get(key,[]):assert sha(R/r['path'])==r['sha256'],r['path']
local=[p for p in H.iterdir()if p.is_file()and p.name!='component_manifest.json']
local+=list((H/'visit').glob('*'))
local+=[p for p in O.iterdir()if p.is_file()and p.name not in ['tail_progress.json','tail_selected_tests.json']]
external={R/p for p in build['sources']if not (R/p).is_relative_to(H)}
external.update(parents)
external.update(B/p for p in ['navigation/modules/AMITSE.efi','navigation/rea/W890-seeded-loop190f4.json','navigation/rea_text/W890-seeded-loop190f4.c','integration05/parser-snapshot.zip','navigation06_actions/verify_actions.py','navigation05/verify_form_open.py','navigation05/verify_parser_navigation.py','navigation05/verify_bridges.py','navigation05/verify_navigation.py','native_observer04/verify_observer.py','password_runtime02/verify_runtime_pe.py'])
report={'status':'FROZEN_PARTIAL_OFFLINE_EARLY_EXIT_CANCELLATION_NO_INSTALLER_NOT_FLASHABLE','component_sha256':digest,'checks':{'actual_pe_tail':25,'actual_inline_fault_wait_retry':2,'actual_original_loop_caller':1,'static_original_windows':'MATCH','frozen_parent_bindings':'MATCH'},'scope':'Established private Loop1995F cancellation only; no teardown permission. Native196FF input continuation tested to fresh-event backend. Other direct tail entries remain unpatched.','local_bindings':[row(p)for p in sorted(set(local))],'external_bindings':[row(p)for p in sorted(external)],'parent_manifests_verified':True,'failure_evidence':'failure_notes.json and any recorded failure_*.json are retained, not counted as passes.','explicit_models':['UEFI/CPU mappings and native App/Page containers','BrowserLoop initialization/middle skipped after real original prologue','4CD14 returns0 and61FE4 fresh-input backend returnsNOT_READY','cryptographic/entropy oracles as in frozen test harness'],'not_proved':['full native GUI and all exit/error paths','all callback/OEM/free/protocol/reset batches','foreign HII owner or history allocation lifetime','static aggregate integration or hardware deployment'],'no_device_operations':True}
p=H/'component_manifest.json';p.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'manifest_sha256':sha(p),'dll_sha256':digest,'local_files':len(report['local_bindings']),'external_files':len(report['external_bindings'])},indent=2))
