from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
def bind(p):
 d=p.read_bytes();return {'path':p.relative_to(R).as_posix(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
b=json.loads((H/'build/build.json').read_text());t=json.loads((H/'generation_tests.json').read_text())
dll=H/'build/W890ObserverGeneration08.TESTONLY.dll'
assert t['passed'] and t['checks']==9 and t['component_sha256']==bind(dll)['sha256']==b['component_sha256']
assert t['source_sha256']==bind(H/'verify_generation.py')['sha256']
for p,d in b['sources'].items():assert bind(R/p)['sha256']==d,p
local=[H/x for x in ('README.md','api.h','build.py','test_consumer.c','verify_generation.py','generation_tests.json','freeze.py',
 'visit/observer08.c','visit/restricted_profile.h','visit/restricted_check.inc','visit/form_descriptor.inc',
 'build/build.json','build/consumer_windows.json','build/navigation.map','build/W890ObserverGeneration08.TESTONLY.dll')]
ext=[R/p for p in b['sources'] if not (R/p).is_relative_to(H)]
ext += [B/x for x in ('navigation05/verify_navigation.py','native_observer04/verify_observer.py',
 'password_runtime02/verify_runtime_pe.py','navigation/modules/AMITSE.efi','navigation/modules/Setup.efi',
 'password/official_forms_0603.pack','pending_hii08/component_manifest.json','native_callbacks08/manifest.json')]
m={'status':'FROZEN_CATALOG_GENERATION_COMPONENT_NOT_AGGREGATE','files':[bind(p) for p in sorted(set(local))],
 'external_bindings':[bind(p) for p in sorted(set(ext))],'actual_pe_cases':9,
 'test_only_exports':['og08_test_read','og08_test_nested'],'production_api':'no_catalog_generation',
 'firmware_artifact_created':False,'hardware_operations':False,'complete_gui_qualification':False}
p=H/'component_manifest.json';p.write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({'manifest':bind(p),'files':len(m['files']),'external_bindings':len(m['external_bindings'])}))
