"""Separate pre-tail cancellation candidate. Frozen inputs are only read."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];N=B/'navigation05';A=B/'navigation06_actions'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=A/'component_manifest.json';data=json.loads(manifest.read_text());bindings={}
for key in ['local_bindings','external_bindings']:
 for row in data.get(key,[]):
  p=R/row['path'];assert sha(p)==row['sha256'],str(p);bindings[row['path']]=row['sha256']
def bound(p):
 k=p.relative_to(R).as_posix();assert k in bindings and sha(p)==bindings[k],k
 return p.read_text()
for name in ['actions06.inc','main_profile.inc']:(H/name).write_text(bound(A/name))
(H/'bridges07.c').write_text(bound(A/'bridges06.c')+'\n#include "exit07.inc"\n')
V=H/'visit';V.mkdir(exist_ok=True)
for name in ['restricted_profile.h','restricted_check.inc','form_descriptor.inc']:
 p=N/'visit'/name
 # Inputs not individually present in the lifecycle manifest are also bound
 # by that frozen component's original compiler source/header inventory below.
 (V/name).write_bytes(p.read_bytes())
observer=(N/'visit/observer_visit05.c').read_text()
old='ES r=((ES(EA *)(void))s.install.loop_trampoline)();pop(f);return r;'
assert observer.count(old)==1
observer=observer.replace(old,'ES r=n07_loop_body_call(s.install.loop_trampoline);pop(f);return r;')
observer=observer.replace('API ES EA no_native_loop(void){','extern ES EA n07_loop_body_call(void *);\nAPI ES EA no_native_loop(void){')
(V/'observer07.c').write_text(observer+'\n#include "../observer_tail.inc"\n')
t=(N/'build.py').read_text().replace("O=H/'build'","O=Path("+repr(str(H/'build'))+")")
t=t.replace("B/'native_observer04/observer.c'",','.join('Path('+repr(str(p))+')'for p in [H/'bridges07.c',H/'tail07.S',N/'first_bridge.S',V/'observer07.c',N/'visit/restricted_catalog.c']))
t=t.replace('assert len(calls)==2,calls','assert len(calls)==6,calls')
extra=['n05_bridges_bind','n05_native_render','n05_native_page_input','n05_native_frame_input','n05_native_control_input','n05_native_app_input','n05_native_extra_input','n05_native_alt_input','n05_native_form_open','n05_native_pending','n05_native_first','n05_first_dispatch','n05_recovery_poll','n05_recovery_terminal','n05_first_resume','n05_form_open_trampoline','no_native_visit_identity','no_describe_form_callback','n06_native_exit','n06_exit_trampoline','n06_last_reason','n07_bind','n07_exit_dispatch','n07_fault_wait','n07_last_reason','n07_last_batch_reason','n07_resume','n07_native_tail','n07_dispatch_return','n07_loop_body_call','n07_loop_body_return','no_native_tail_context']
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'",'exports += '+repr(extra)+"\nout=O/'W890NavigationExit07.TESTONLY.dll'")
exec(compile(t,str(N/'build.py'),'exec'),{'__file__':str(N/'build.py'),'__name__':'exit07_build'})
p=H/'build/build.json';d=json.loads(p.read_text())
sources=[H/'build.py',H/'exit07.inc',H/'observer_tail.inc',H/'actions06.inc',H/'main_profile.inc',V/'restricted_profile.h',V/'restricted_check.inc',V/'form_descriptor.inc',N/'build.py',N/'visit/observer_visit05.c',N/'visit/restricted_profile.h',N/'visit/restricted_check.inc',N/'visit/form_descriptor.inc',A/'component_manifest.json',A/'bridges06.c']
d['sources'].update({str(p.relative_to(R)):sha(p)for p in sources})
d['status']='PRE_TAIL_CANCELLATION_CANDIDATE_NO_INSTALLER_NO_TEARDOWN_PERMISSION'
d['frozen_actions_manifest_sha256']=sha(manifest)
d['limitations']=['No full exit permission; unknown callback and earlier teardown effects remain refused','Only1995F established-loop tail covered;196F7 and initialization-failure jumps are not patched','No hardware, full GUI, aggregate or firmware deployment claim']
p.write_text(json.dumps(d,indent=2)+'\n')
