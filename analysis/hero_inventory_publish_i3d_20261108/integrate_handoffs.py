"""Copy reviewed inputs into I3D after verifying their producer manifests."""
from pathlib import Path
import hashlib,json,shutil
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
NATIVE=ROOT/'analysis/hero_inventory_20261108/native_i3d'
DX=ROOT/'analysis/hero_ipmi_r2_followup_20261108/dispatch-audit'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
h=json.loads((NATIVE/'handoff.json').read_text(encoding='utf-8'))
assert h['native_mock_tests_passed']==29 and h['frozen_i3b_unchanged']
for name,meta in h['sources'].items():
 assert sha(NATIVE/name)==meta['sha256']
 shutil.copyfile(NATIVE/name,OUT/'source'/name)
dxbuild=json.loads((DX/'probe-build.json').read_text())
dxtests=json.loads((DX/'probe-tests.json').read_text())
assert dxtests['failures']==0 and dxtests['errors']==0 and dxtests['tests']>=18
for name in ('dxe_state_probe.c','dxe_state_probe.h','dxe_core_anchors.h'):
 assert sha(DX/name)==dxbuild['inputs'][str(DX/name)]
 shutil.copyfile(DX/name,OUT/'source'/name)
for folder in ('native','dxe-probe'):(OUT/'review'/folder).mkdir(parents=True,exist_ok=True)
for name in ('handoff.json','接入说明-I3d.txt','processor-summary.patch.json'):
 shutil.copyfile(NATIVE/name,OUT/'review/native'/name)
for name in ('probe-build.json','probe-tests.json','code-identity.json'):
 shutil.copyfile(DX/name,OUT/'review/dxe-probe'/name)
proof={'native_handoff_sha256':sha(NATIVE/'handoff.json'),'native_sources':h['sources'],
       'dxe_sources':{n:sha(DX/n) for n in ('dxe_state_probe.c','dxe_state_probe.h','dxe_core_anchors.h')},
       'dxe_probe_tests':dxtests,'dxe_scope':'D only; once GetMemoryMap, bounded read of exact pinned DXE core RAM; no dispatch/LoadImage/StartImage call.',
       'inventory_scope':'Independent of DXE probe outcome; explicit W/W and S/S only.'}
(OUT/'handoff-integration.json').write_text(json.dumps(proof,indent=2)+'\n',encoding='utf-8')
print('Reviewed native continuation and read-only DXE state modules copied into I3D.')
