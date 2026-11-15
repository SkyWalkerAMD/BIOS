"""Lifecycle-preserving derivative; never changes frozen inputs or firmware."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];N=B/'navigation05';O=H/'build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
parent=B/'navigation07_exit/component_manifest.json';p=json.loads(parent.read_text())
for key in ['local_bindings','external_bindings']:
 for row in p[key]:assert sha(R/row['path'])==row['sha256'],row['path']
bridges=(N/'bridges.c').read_text().replace('#include "bridges.h"','#include "../navigation05/bridges.h"').replace('#include "hotkeys_data.h"','#include "../navigation05/hotkeys_data.h"');first=bridges.index('static int callback_batch(');last=bridges.index('static int recovery_services(void){')
bridges=bridges[:first]+'''/* n08: native 3F414 lifecycle callbacks remain original and unpatched.
 * Page-selection/render/input protection is independent of the original
 * FORM_OPEN/FORM_CLOSE, original pending HII updates and teardown bookkeeping. No fabricated callback
 * status, ActionRequest or global lifecycle permission is introduced. */
'''+bridges[last:]
old='UN old=saved_bs.raise_tpl(31);saved_bs.restore_tpl(old);'
assert bridges.count(old)==1;bridges=bridges.replace(old,'UN old=saved_bs.raise_tpl(31);if(!recovery_services())return 2;saved_bs.restore_tpl(old);')
old='UN tpl=saved_bs.raise_tpl(31);saved_bs.restore_tpl(tpl);'
assert bridges.count(old)==1;bridges=bridges.replace(old,'UN tpl=saved_bs.raise_tpl(31);if(!recovery_services())n05_recovery_terminal();saved_bs.restore_tpl(tpl);')
(H/'bridges08.c').write_text(bridges)
V=H/'visit';V.mkdir(exist_ok=True)
for name in ['restricted_profile.h','restricted_check.inc','form_descriptor.inc']:(V/name).write_bytes((N/'visit'/name).read_bytes())
observer=(N/'visit/observer_visit05.c').read_text();begin=observer.index('API ES EA no_native_send_form(');end=observer.index('API ES EA no_native_entry(',begin)
observer=observer[:begin]+'#include "../send_form08.inc"\n'+observer[end:]
(V/'observer08.c').write_text(observer)
t=(N/'build.py').read_text().replace("O=H/'build'","O=Path("+repr(str(O))+")")
t=t.replace("B/'native_observer04/observer.c'",','.join('Path('+repr(str(p))+')'for p in [H/'bridges08.c',N/'first_bridge.S',V/'observer08.c',N/'visit/restricted_catalog.c']))
exports=['n05_bridges_bind','n05_native_render','n05_native_page_input','n05_native_frame_input','n05_native_control_input','n05_native_app_input','n05_native_extra_input','n05_native_alt_input','n05_native_first','n05_first_dispatch','n05_recovery_poll','n05_recovery_terminal','n05_first_resume','no_native_visit_identity','no_describe_form_callback']
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'",'exports += '+repr(exports)+"\nout=O/'W890Navigation08Lifecycle.TESTONLY.dll'")
exec(compile(t,str(N/'build.py'),'exec'),{'__file__':str(N/'build.py'),'__name__':'navigation08_build'})
plan=json.loads((N/'bridges_build/static_hook_plan.json').read_text());before=len(plan['records'])
plan['records']=[x for x in plan['records']if x['rva']not in [0x3f414,0x239e7]];assert len(plan['records'])==before-2
build=json.loads((O/'build.json').read_text());out=O/'W890Navigation08Lifecycle.TESTONLY.dll'
for x in plan['records']:x['export_rva']=build['exports'][x['export']]
plan['component_sha256']=sha(out);plan['status']='NARROW_NAVIGATION_DERIVATIVE_PRESERVING_ORIGINAL_LIFECYCLE_NO_INSTALLER'
plan['unpatched_native_rvas']=[0x3f414,0x239e7,0x748c,0x196f7,0x1995f,0x19973,0x19994,0x19a76]
plan['remaining_boundaries']=['Current private observer still Setup-only and revokes HII changes; root owns next observer derivative','Original pending HII caller now left intact; root owns catalog-generation separation','No complete GUI/flashable-image claim']
(O/'static_hook_plan.json').write_text(json.dumps(plan,indent=2)+'\n')
build['sources'].update({str(p.relative_to(R)):sha(p)for p in [Path(__file__),H/'send_form08.inc',V/'restricted_profile.h',V/'restricted_check.inc',V/'form_descriptor.inc',N/'visit/observer_visit05.c',N/'bridges.c',N/'build.py',parent]})
build['status']=plan['status'];build['change']='Remove global FormOpen/Close and exit/tail interception; keep original statuses/parameters/order. Preserve guarded navigation, not an unknown lifecycle allowlist.'
(O/'build.json').write_text(json.dumps(build,indent=2)+'\n')
print(json.dumps({'sha256':sha(out),'bridge_records':len(plan['records']),'consumer_calls':len(build['consumer_windows'])},indent=2))
