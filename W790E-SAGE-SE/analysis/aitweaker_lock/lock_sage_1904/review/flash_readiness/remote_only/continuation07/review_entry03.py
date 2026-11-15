"""Parent exact-source delta and immutable EP3 artifact review."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,difflib
HERE=Path(__file__).resolve().parent;N13=HERE.parents[1]/'native13_split_candidate'
EP=N13/'entry_probe03';OLD=N13/'entry_probe02'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=EP/'entry_context03_manifest.json'
assert sha(manifest)=='56bff292b3fe57b8d29888129e2db854d91f79ef61e546aa901234d4297dbc6c'
m=json.loads(manifest.read_text());assert len(m['artifacts'])==110
for r in m['artifacts']:
 p=(N13/r['path']).resolve();assert p.is_relative_to(N13.resolve())
 assert p.stat().st_size==r['bytes'] and sha(p)==r['sha256'],str(p)
assert sha(EP/'entry_context03_review.json')=='4727bc687e593c99f1e550d5008fd4919baecd4e2ad823b3437d1e448833928d'
diffs={}
for name in ['preflight.c','context_inspect.inc','entry.S']:
 a=(OLD/'source'/name).read_text().splitlines();b=(EP/'source'/name).read_text().splitlines()
 diffs[name]='\n'.join(difflib.unified_diff(a,b,fromfile='EP2/'+name,tofile='EP3/'+name))
assert not diffs['entry.S']
launch=(EP/'source/launch_frame.inc').read_text()
assert 'raw_rsp+0x131' in launch and 'stack_frame_readable(raw_rsp,0x198)' in launch
assert 'u64(sp+0x188)' in launch and 'u64(sp+0x190)' in launch
assert '0x2d7d,0x9025,0x960c,0x9754,0x97c9' in launch
assert 'ap_sha256(images[0]+0x9f78,0xaada-0x9f78' in launch
r={'status':'PASS_PARENT_EP3_FROZEN_SOURCE_DELTA_REVIEW','utc':datetime.now(timezone.utc).isoformat(),
 'manifest_sha256':sha(manifest),'frozen_bindings_verified':110,'review_sha256':sha(EP/'entry_context03_review.json'),
 'source_delta':diffs,'new_launch_frame_source_sha256':sha(EP/'source/launch_frame.inc'),
 'manual_review':'Exact original Core and AMITSE identity/frame gates precede two bounded data-stack slot reads. Fresh launch-function hash, saved-RBP relation and known direct-CALL target check; no saved outer-RBP dereference or arbitrary stack search. NO browser-absence marker is unconditional.',
 'physical_scope':'Read-only entry diagnostic only; no installer, native provider, SendForm call or firmware/variable/disk write.',
 'browser_absence_proven':False,'hardware_result_pending':True}
(HERE/'entry_probe03_parent_review.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'status':r['status'],'bindings':110,'diff':diffs},indent=2))
