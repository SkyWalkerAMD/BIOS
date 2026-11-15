from pathlib import Path
import hashlib,json,zipfile
HERE=Path(__file__).resolve().parent;CAND=HERE.parent/'native_provider12_candidate'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((HERE/'latest_result.json').read_text());run=Path(r['shared_writable_vars_file']).parent
efi=CAND/'build/AiTweakerNativeProvider1904.UNSIGNED.review.efi';assert sha(efi)==r['provider_sha256']
assert sha(HERE/'run_persist_ui.py')==r['runner_sha256']and sha(HERE/'persist_ui.c')==r['fixture_source_sha256']
target=run/'provider-under-test.efi'
if target.exists():assert sha(target)==sha(efi)
else:target.write_bytes(efi.read_bytes())
archive=run/'provider-and-fixture-sources.zip'
if not archive.exists():
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED)as z:
    for p in (CAND/'source').glob('*'):z.write(p,'provider/source/'+p.name)
    for name in ['guard_binding.json','build_state.py','build_driver.py','bind_guard.py','build/build.json','build/state_build.json','build/provider.map']:
        z.write(CAND/name,'provider/'+name)
    for name in ['persist_ui.c','run_persist_ui.py','freeze_run.py','build/binding.h','build/build.json']:
        z.write(HERE/name,'simulation/'+name)
with zipfile.ZipFile(archive)as z:assert z.testzip()is None
(run/'snapshot.json').write_text(json.dumps({'provider_sha256':sha(target),'source_archive_sha256':sha(archive),'result_sha256':sha(run/'result.json')},indent=2)+'\n')
print(json.dumps({'snapshot':str(run),'provider_sha256':sha(target),'source_archive_sha256':sha(archive)}))
