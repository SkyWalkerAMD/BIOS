"""Compile unified UI component, with no fixture permission providers."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3];N=B/'navigation05';A=B/'navigation08';F=B/'foreign_page08';O=H/'build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
d=json.loads((H/'derivation.json').read_text())
for group in ('generated','derivation_sources'):
 for p,h in d[group].items():assert sha(R/p)==h,p
for v in d['parents'].values():assert sha(R/v['path'])==v['sha256']
t=(N/'build.py').read_text().replace("O=H/'build'",'O=Path('+repr(str(O))+')')
t=t.replace("H/'navigation.c'",'Path('+repr(str(H/'navigation08.c'))+')')
t=t.replace("B/'native_observer04/observer.c'",','.join('Path('+repr(str(p))+')' for p in (H/'bridges08.c',N/'first_bridge.S',H/'observer08.c',N/'visit/restricted_catalog.c',F/'foreign_page.c')))
marker=" cmd+=['-c',str(p),'-o',str(obj)]"
assert t.count(marker)==1
t=t.replace(marker," if p.suffix!='.S':cmd+=['-include',"+repr(str(H/'gate_adapter.h'))+"]\n"+marker)
extra=['n05_bridges_bind','n05_native_render','n05_native_page_input','n05_native_frame_input','n05_native_control_input',
 'n05_native_app_input','n05_native_extra_input','n05_native_alt_input','n05_native_first','n05_first_dispatch',
 'n05_recovery_poll','n05_recovery_terminal','n05_first_resume','no_native_visit_identity','no_describe_form_callback',
 'no_catalog_generation','fp08_describe_page','fp08_describe_control','fp08_view_bytes','ui08_snapshot_bytes']
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'",'exports += '+repr(extra)+"\nout=O/'W890UI08.TESTONLY.dll'")
exec(compile(t,str(N/'build.py'),'exec'),{'__file__':str(N/'build.py'),'__name__':'ui08_build'})
p=O/'build.json';b=json.loads(p.read_text())
files=[H/x for x in ('build.py','derive.py','derivation.json','input_pins.json','gate_adapter.h','foreign_observer.inc','form_descriptor.inc')]
files += [F/'foreign_page.h',F/'scope_data.h',N/'build.py']
b['sources'].update({str(p.relative_to(R)):sha(p) for p in files})
b['status']='COMPOSED_NATIVE_UI_COMPONENT_NOT_FULL_AGGREGATE'
b['test_fixture_sources_present']=False
b['parent_manifests']=d['parents']
assert not any(n.startswith(('og08_test_','fp08_test_')) for n in b['exports'])
p.write_text(json.dumps(b,indent=2)+'\n')
plan=json.loads((A/'build/static_hook_plan.json').read_text())
for r in plan['records']:r['export_rva']=b['exports'][r['export']]
plan['component_sha256']=b['component_sha256'];plan['status']=b['status']
plan['remaining_boundaries']=['Current source preserves original lifecycle; callback code is not newly authorized.',
 'Independent normal/unknown foreign UI integration tests are required for these exact bytes.',
 'Cold credential FAULT still needs a complete narrow entry profile; incomplete restricted catalog remains closed.',
 'No full firmware, complete GUI, hardware lock or FlashBack acceptance test.']
(O/'static_hook_plan.json').write_text(json.dumps(plan,indent=2)+'\n')
print(json.dumps({'component_sha256':b['component_sha256'],'plan_records':len(plan['records']),'test_exports':0}))
