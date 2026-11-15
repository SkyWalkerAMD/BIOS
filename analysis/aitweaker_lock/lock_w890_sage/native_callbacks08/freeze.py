from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def binding(p,base):return {'path':p.relative_to(base).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
review=json.loads((H/'review.json').read_text());assert review['hardware_actions']==review['firmware_changes']==review['password_operations']==0
assert not review['runtime_authorized']
local=[binding(p,H)for p in sorted(H.rglob('*'))if p.is_file()and p.name!='manifest.json'and'tmp'not in p.relative_to(H).parts and'__pycache__'not in p.relative_to(H).parts]
external={B/'navigation/modules/AMITSE.efi',B/'navigation/modules/Setup.efi',B/'callback_shapes07/manifest.json',
 B/'callback_shapes07/replay.py',B/'callback_shapes07/inputs.json',B/'callback_shapes07/qid_action_type_candidates.json',
 B/'callback_shapes07/runtime_premises.json',B/'callback_shapes07/review.json',B/'navigation06_actions/rea_index.json',
 B/'integration05/parser-snapshot.zip',B/'integration05/disasm-3e700.txt',B/'integration05/disasm-3e424.txt',
 B/'dynamic_forms06/physical_appendix07/manifest.json',B/'dynamic_forms06/physical_appendix07/result.json'}
idx=json.loads((H/'rea_index.json').read_text())
for x in idx['reused_frozen_dossiers']:
 external.add(R/x['full_path']);external.add(B/'navigation06_actions'/x['decoded'])
for name in('AMITSE_3e700.c.txt','AMITSE_3e424.c.txt','AMITSE_3f90c.c.txt'):external.add(B/'navigation06_actions/decoded'/name)
manifest={'status':'FROZEN_ORIGINAL_LIFECYCLE_EVIDENCE_NOT_RUNTIME_AUTHORIZATION','files':local,
 'external_read_only_inputs':[binding(p,R)for p in sorted(external)],'hardware_actions':0,'firmware_changes':0,'password_operations':0,
 'runtime_authorized':False,'recommendation':'Preserve original lifecycle; constrain newly added UI gates to verified protectedentry and provenOCbypass boundaries.'}
(H/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for x in manifest['files']:assert sha(H/x['path'])==x['sha256']
for x in manifest['external_read_only_inputs']:assert sha(R/x['path'])==x['sha256']
print(json.dumps({'manifest_sha256':sha(H/'manifest.json'),'review_sha256':sha(H/'review.json'),
 'local_bindings':len(local),'external_bindings':len(external),'runtime_authorized':False}))
