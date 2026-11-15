"""Freeze exact source/binary/evidence after final bounded-byte tests agree."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];O=H/'build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
row=lambda p:{'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
DLL=O/'W890Navigation08Lifecycle.TESTONLY.dll';digest=sha(DLL)
build=json.loads((O/'build.json').read_text());assert build['component_sha256']==digest
for path,s in build['sources'].items():assert sha(R/path)==s,path
expected={'lifecycle_tests.json':('verify_lifecycle.py',11),'send_form_tests.json':('verify_send.py',7),'navigation_tests.json':('verify_navigation08.py',8),'protocol_boundary_tests.json':('verify_protocol_boundary.py',1)}
reports={}
for name,(script,count)in expected.items():
 d=json.loads((O/name).read_text());assert d['component_sha256']==digest and d['checks']==count,name
 assert d['source_sha256']==sha(H/script) and all(x['status']=='PASS'for x in d['cases']),name
 if script!='verify_lifecycle.py':assert d['dependency_sha256']==sha(H/'verify_lifecycle.py'),name
 reports[name]=d
plan=json.loads((O/'static_hook_plan.json').read_text());assert plan['component_sha256']==digest and len(plan['records'])==22
for r in plan['records']:
 for untouched in [0x3f414,0x239e7,0x748c,0x1995f,0x196f7,0x19973,0x19994,0x19a76]:
  assert not r['rva']<=untouched<r['rva']+r['length'],(r,untouched)
parents=[B/'navigation07_exit/component_manifest.json',B/'native_callbacks08/manifest.json']
for p in parents:
 d=json.loads(p.read_text())
 if p.parent.name=='native_callbacks08':
  for x in d['files']:assert sha(p.parent/x['path'])==x['sha256'],x['path']
  for x in d['external_read_only_inputs']:assert sha(R/x['path'])==x['sha256'],x['path']
 else:
  for key in ['local_bindings','external_bindings']:
   for x in d[key]:assert sha(R/x['path'])==x['sha256'],x['path']
external={R/p for p in build['sources']if not (R/p).is_relative_to(H)}
external.update(parents)
external.update(B/p for p in ['navigation/modules/AMITSE.efi','navigation/modules/Setup.efi','integration05/parser-snapshot.zip','navigation05/verify_form_open.py','navigation05/verify_parser_navigation.py','navigation05/verify_bridges.py','navigation05/verify_navigation.py','native_observer04/verify_observer.py','native_observer04/hook_windows.json','native_observer04/observer.h','password_runtime02/verify_runtime_pe.py','navigation/rea/W890-seeded-actual-sendform36da4.json','navigation/rea_text/W890-seeded-actual-sendform36da4.c'])
for rec in json.loads((H/'existing_evidence.json').read_text()):
 p=Path(rec['source']);assert sha(p)==rec['sha256'];external.add(p)
local=[p for p in H.iterdir()if p.is_file()and p.name!='component_manifest.json']
for folder in [H/'visit',H/'existing',H/'rea',H/'rea02',O]:
 local.extend(p for p in folder.iterdir()if p.is_file()and not p.name.endswith('_selected_tests.json'))
report={
 'status':'FROZEN_LOCAL_NAVIGATION_LIFECYCLE_DERIVATIVE_NOT_FINAL_OBSERVER_NO_INSTALLER_NOT_FIRMWARE',
 'component_sha256':digest,
 'checks':{'actual_original_lifecycle_bounded':11,'actual_thin_sendform_abi_and_loop_call':7,'actual_navigation_and_recovery':8,'actual_uninstall_multiple_protocol_abi':1,'original_unpatched_lifecycle_sites':'MATCH','total_bounded_cases':27},
 'scope':'Preserve original lifecycle/exit; retain password navigation guards. Thin original SendForm forwarding creates no permission.',
 'local_bindings':[row(p)for p in sorted(set(local))],
 'external_bindings':[row(p)for p in sorted(external)],
 'explicit_models':['UEFI services, CPU mappings, outer native App/Page/Frame containers','Original BrowserLoop initialization/middle and SendForm middle are explicitly selected slices','Six empty Main outer frames and exact retained-App scalar predicate for normal return','Original parser raw data from immutable snapshot','Independent inherited crypto/entropy oracles'],
 'unknown_stop_boundaries':['Original Security3E700 callback business path','Full App teardown first unproven Page FreePool object','Original F10 save-confirm and mouse region callback destinations','Original SendForm12204 initializer in forwarding capture'],
 'not_proved':['Root generation08/foreign08 final composition and nested ticket occupancy','Full original UI and complete native SendForm body','Full original App/Frame/control cleanup or Reset/OEM effects','Initial credential-FAULT restricted cold-entry profile','All OC Save/default/profile business bypasses','Hardware, firmware carrier or FlashBack'],
 'failure_evidence':'Development failure_*.json and nav_failure_*.json are retained; not counted as passes. In particular stale previous-visit history after an omitted native cleanup was refused, then the fixture included actual19A5D cleanup.',
 'no_device_operations':True,
 'owned_rea_closed':True,
 'transient_cache_exclusions':['__pycache__','rea/tmp','rea02/tmp'],
}
p=H/'component_manifest.json';p.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'manifest_sha256':sha(p),'dll_sha256':digest,'local_bindings':len(report['local_bindings']),'external_bindings':len(report['external_bindings']),'bounded_cases':27},indent=2))
