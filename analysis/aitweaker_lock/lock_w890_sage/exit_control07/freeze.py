from pathlib import Path
import hashlib
import json
H = Path(__file__).resolve().parent
B = H.parent
R = H.parents[3]
def bind(p):
    data=p.read_bytes()
    return {'path':p.relative_to(R).as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
t=json.loads((H/'original_tail_tests.json').read_text())
assert t['passed'] and t['count']==10
m={'status':'FROZEN_ORIGINAL_CONTROL_FLOW_EVIDENCE_NOT_IMPLEMENTATION',
   'files':[bind(H/n) for n in ('README.md','freeze.py','verify_original_tail.py','original_tail_tests.json','original_tail.asm.txt')],
   'external_bindings':[bind(B/n) for n in ('navigation/modules/AMITSE.efi','navigation/rea/W890-seeded-loop190f4.json','navigation/rea_text/W890-seeded-loop190f4.c','navigation06_actions/component_manifest.json')],
   'hardware_effects':False,'production_cancellation_guard_implemented':False}
p=H/'component_manifest.json';p.write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps(bind(p)))
