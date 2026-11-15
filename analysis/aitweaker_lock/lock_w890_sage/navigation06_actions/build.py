"""Build a separate action/lifecycle boundary; never rewrite frozen inputs."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;N=H.parent/'navigation05'
t=(N/'build.py').read_text()
t=t.replace("O=H/'build'","O=Path("+repr(str(H/'build'))+")")
t=t.replace("B/'native_observer04/observer.c'","Path("+repr(str(H/'bridges06.c'))+"),H/'first_bridge.S',H/'visit/observer_visit05.c',H/'visit/restricted_catalog.c'")
t=t.replace("assert len(calls)==2,calls","assert len(calls)==5,calls")
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'","exports += ['n05_bridges_bind','n05_native_render','n05_native_page_input','n05_native_frame_input','n05_native_control_input','n05_native_app_input','n05_native_extra_input','n05_native_alt_input','n05_native_form_open','n05_native_pending','n05_native_first','n05_first_dispatch','n05_recovery_poll','n05_recovery_terminal','n05_first_resume','n05_form_open_trampoline','no_native_visit_identity','no_describe_form_callback','n06_native_exit','n06_exit_trampoline','n06_last_reason']\nout=O/'W890NavigationActions06.TESTONLY.dll'")
exec(compile(t,str(N/'build.py'),'exec'),{'__file__':str(N/'build.py'),'__name__':'actions06_build'})
p=H/'build/build.json';d=json.loads(p.read_text())
for f in [H/'build.py',H/'actions06.inc',H/'main_profile.inc',H/'main_profile.json',N/'bridges.c',N/'build.py',N/'visit/restricted_profile.h',N/'visit/form_descriptor.inc']:
 d['sources'][str(f.relative_to(H.parents[3]))]=hashlib.sha256(f.read_bytes()).hexdigest()
d['status']='OFFLINE_NARROW_ACTION_LIFECYCLE_NO_INSTALLER'
d['limitations']=['Only exact Main callback-free descriptors admitted for new actions 3/4','Protected and unknown local callbacks and all valid foreign HII remain denied','No source or aggregate from prior frozen components changed']
p.write_text(json.dumps(d,indent=2)+'\n')
