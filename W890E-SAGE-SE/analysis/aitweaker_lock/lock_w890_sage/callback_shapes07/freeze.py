"""Freeze the independent offline callback-shape evidence checkpoint."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3]
sha=lambda b:hashlib.sha256(b).hexdigest()
out=H/'manifest.json';assert not out.exists(),'already frozen'
for run in ('rea05','rea06','rea07'):
 c=json.loads((H/run/'final-close.json').read_text());assert not c.get('isError')
def bind(p,root):
 data=p.read_bytes();return {'path':p.relative_to(root).as_posix(),'bytes':len(data),'sha256':sha(data)}
inputs=json.loads((H/'inputs.json').read_text());external={R/e['path']for e in inputs['inputs']}
for e in json.loads((H/'rea_index.json').read_text())['reused_frozen_actual_REA_dossiers']:external.add(R/e['full_response_path'])
files=[bind(p,H)for p in sorted(H.rglob('*'))if p.is_file()and p!=out and'tmp'not in p.parts and'__pycache__'not in p.parts]
manifest={'status':'OFFLINE_EVIDENCE_FROZEN_NOT_RUNTIME_AUTHORIZATION','files':files,
 'external_read_only_inputs':[bind(p,R)for p in sorted(external)],'hardware_actions':0,'firmware_changes':0,'runtime_authorized':False}
out.write_text(json.dumps(manifest,indent=2)+'\n')
for e in files:assert sha((H/e['path']).read_bytes())==e['sha256']
for e in manifest['external_read_only_inputs']:assert sha((R/e['path']).read_bytes())==e['sha256']
print(json.dumps({'manifest_sha256':sha(out.read_bytes()),'review_sha256':sha((H/'review.json').read_bytes()),
 'files':len(files),'external_inputs':len(external),'all_bindings_verified':True}))
