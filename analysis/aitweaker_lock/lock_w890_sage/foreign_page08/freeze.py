from pathlib import Path
import json,hashlib,sys
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sys.path.insert(0,str(R/'tools/pydeps'));import pefile
sources=set()
for rel,expected in [('policy05/component_manifest.json',None),('observer_generation08/component_manifest.json','4fc68d969c583e39cf1bfbf798dcf52c5bcc6a7fe4e00e8616eb168b9e778d30')]:
 p=B/rel;manifest=json.loads(p.read_text());sources.add(p)
 if expected:assert sha(p)==expected
 for key in('files','external_bindings'):
  for row in manifest.get(key,[]):assert sha(R/row['path'])==row['sha256'],row['path']
for row in json.loads((H/'scope_catalog.json').read_text())['bindings']:
 p=R/row['path'];assert sha(p)==row['sha256'];sources.add(p)
sources.update(B/x for x in ['policy05/storage_policy.json','observer_generation08/api.h','navigation05/visit/observer_visit05.c',
 'navigation05/visit/form_descriptor.inc','integration05/observer.h','navigation/gate_adapter.h',
 'password/w890_policy.c','password/w890_policy.h','password/w890_policy_data.h','password/core/password_crypto.c','password/core/password_core.h',
 'password_runtime02/source/efi.h','callback_shapes07/inputs.json','callback_shapes07/manifest.json',
 'native_callbacks08/manifest.json','native_callbacks08/lifecycle_boundary.json',
 'dynamic_forms06/physical_appendix07/manifest.json','hardware_hii06/reconciled01.json'])
t=json.loads((H/'test_results.json').read_text());build=json.loads((H/'build/build.json').read_text())
assert t['scenario_count']==41 and t['mechanical_page_and_callback_samples']==607 and t['protected_alias_controls']==861
assert t['source_sha256']==sha(H/'test_component.py')
assert t['component_sha256']==build['component_sha256']==sha(H/'build/W890ForeignPage08.TESTONLY.dll')
for path,digest in build['sources'].items():assert sha(R/path)==digest
pe=pefile.PE(str(H/'build/W890ForeignPage08.TESTONLY.dll'));assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.AddressOfEntryPoint==0
def binding(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
local=[]
for p in sorted(H.rglob('*')):
 if not p.is_file()or p.name=='component_manifest.json'or any(x in p.relative_to(H).parts for x in('zig-local','zig-global','__pycache__')):continue
 assert p.suffix.lower()not in('.efi','.cap','.rom');local.append(binding(p))
manifest={'status':'FROZEN_FOREIGN_UI_SCOPE_COMPONENT_NOT_AGGREGATE','files':local,'external_bindings':[binding(p)for p in sorted(sources)],
 'actual_native_PE_scenarios':41,'mechanical_page_and_callback_samples':607,'protected_alias_queries':861,
 'production_sources':['foreign_page.c','foreign_page.h','scope_data.h'],
 'test_only_sources':['test_host.c'],'integration_requires':'observer_generation08 no_catalog_generation; applicationTPL description; root private view and generation binding; existing Setup publication branch.',
 'code_execution_granted':False,'hardware_operations':0,'password_operations':0,'firmware_artifact_created':False,'complete_gui_qualification':False}
(H/'component_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for row in local+manifest['external_bindings']:assert sha(R/row['path'])==row['sha256']
print(json.dumps({'manifest_sha256':sha(H/'component_manifest.json'),'component_sha256':t['component_sha256'],
 'local_bindings':len(local),'external_bindings':len(sources),'scenarios':41}))
