from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
def bind(p):
 d=p.read_bytes();return {'path':p.relative_to(R).as_posix(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
c=json.loads((H/'comparison.json').read_text());t=json.loads((H/'bounds_tests.json').read_text())
assert c['native_pages_in_both']==396 and c['original_bound_control_opcodes_and_types_equal'] and c['control_counts']==[13827,13830]
assert len(t['results'])==12
files=[H/x for x in ('README.md','freeze.py','replay_hardware.py','verify_bounds.py','comparison.json','bounds_tests.json','original_unmodified.json','original_bounds.json','changed_bounds.json')]
paths=[B/x for x in ('navigation/modules/AMITSE.efi','parser_catalog05/replay.py','parser_catalog05/investigate_boundary.py',
 'parser_review06/boundary_contract.py','parser_review06/component_manifest.json','integration05/parser_lab.py',
 'hardware_delta07/component_manifest.json','hardware_delta07/capture_6e7a57f9729b082c/reconciled.json',
 'foreign_hii05/catalog.json','password/profile_0603.json','password/official_forms_0603.pack')]
for name in ('original_bounds.json','changed_bounds.json'):
 for x in json.loads((H/name).read_text())['inputs']:paths.append(R/x['path'])
m={'status':'FROZEN_COMPOSITE_PARSER_EXPERIMENT_NOT_ACCEPTED_FIRMWARE_PATCH',
 'files':[bind(p) for p in files],'external_bindings':[bind(p) for p in sorted(set(paths))],
 'patch_applied_to_disk_pe':False,'firmware_artifact_created':False,'hardware_operations':False,
 'physical_first_parser_state_proven':False,'production_callback_authority':False}
p=H/'component_manifest.json';p.write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({'manifest':bind(p),'files':len(m['files']),'external_bindings':len(m['external_bindings'])}))
