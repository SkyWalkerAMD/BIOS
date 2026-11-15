from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;P=H.parent;B=P.parent;R=B.parents[2]
def bind(p):
 d=p.read_bytes();return {'path':p.relative_to(R).as_posix(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
b=json.loads((H/'build/build.json').read_text());t=json.loads((H/'generation_tests.json').read_text())
review=B/'observer_generation08_review/revision03_replay.json';r=json.loads(review.read_text())
assert t['passed'] and t['checks']==9 and all(c['passed'] for c in t['cases'])
assert len(r['cases'])==7 and all(c['status']=='PASS' for c in r['cases'])
assert t['source_sha256']==bind(H/'verify_generation.py')['sha256']
assert t['component_sha256']==r['inputs']['dll']['sha256']==b['component_sha256']
for p,d in b['sources'].items():assert bind(R/p)['sha256']==d,p
for row in [r['source'],*r['inputs'].values()]:assert bind(R/row['path'])['sha256']==row['sha256']
files=[H/x for x in ('README.md','build.py','freeze.py','observer08r3.c','verify_generation.py','generation_tests.json',
 'build/build.json','build/consumer_windows.json','build/navigation.map','build/W890ObserverGeneration08r3.TESTONLY.dll')]
ext=[R/p for p in b['sources'] if not (R/p).is_relative_to(H)]
ext += [P/'component_manifest.json',P/'verify_generation.py',review,R/r['source']['path'],R/r['inputs']['preserved_repro']['path']]
ext += [B/x for x in ('navigation05/verify_navigation.py','native_observer04/verify_observer.py','password_runtime02/verify_runtime_pe.py',
 'observer_generation08_review/revalidation_repro.json','observer_generation08_review/nested_owner_repro.json')]
m={'status':'FROZEN_REVISION03_POST_SERVICE_AND_FRAME_OWNER_FIX_NOT_AGGREGATE',
 'files':[bind(p) for p in sorted(set(files))],'external_bindings':[bind(p) for p in sorted(set(ext))],
 'regression_pe_cases':9,'independent_pe_cases':7,'test_only_exports':['og08_test_read','og08_test_nested'],
 'preserved_revisions':['../component_manifest.json','../revision02/build/build.json'],
 'hardware_operations':False,'firmware_artifact_created':False,'complete_gui_qualification':False}
p=H/'component_manifest.json';p.write_text(json.dumps(m,indent=2)+'\n');print(json.dumps({'manifest':bind(p),'files':len(m['files']),'external':len(m['external_bindings'])}))
