"""Freeze this completed offline checkpoint; future physical evidence is additive."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;ROOT=H.parents[3]
sha=lambda b:hashlib.sha256(b).hexdigest()
target=H/'manifest.json';assert not target.exists(),'checkpoint already frozen'
def bind(p,root):
 b=p.read_bytes();return {'path':p.relative_to(root).as_posix(),'bytes':len(b),'sha256':sha(b)}
files=[bind(p,H)for p in sorted(H.rglob('*'))if p.is_file()and'__pycache__'not in p.parts and'tmp'not in p.parts and p!=target]
inputs=json.loads((H/'inputs.json').read_text())
external=[B/'foreign_hii05/catalog.json',B/'hardware_hii06/capture01.json',B/'hardware_hii06/reconciled01.json',
 B/'remote_172_20_2_245/hardware-inventory01-1794115320552-227fa99e/hardware-log.txt']
for m in inputs['modules']:
 external.append(ROOT/m['original_pe_path'])
 for form in m['forms']:external.extend([ROOT/form['blob_path'],ROOT/form['decoded_path']])
manifest={'checkpoint':'offline_original_dynamic_paths06','scope':'Existing listed evidence is frozen. Future physical-byte comparison must be additive and separately pinned.',
 'status':'NATIVE_REPLAY_PASS_PHYSICAL_BYTE_IDENTITY_PENDING','files':files,
 'external_read_only_inputs':[bind(p,ROOT)for p in external],
 'hardware_actions':0,'firmware_mutations':0,'authorization':False}
target.write_text(json.dumps(manifest,indent=2)+'\n')
for rec in files:assert sha((H/rec['path']).read_bytes())==rec['sha256']
for rec in manifest['external_read_only_inputs']:assert sha((ROOT/rec['path']).read_bytes())==rec['sha256']
print(json.dumps({'manifest_sha256':sha(target.read_bytes()),'files':len(files),'external_inputs':len(external),
 'review_sha256':sha((H/'review.json').read_bytes()),'all_bindings_verified':True}))
