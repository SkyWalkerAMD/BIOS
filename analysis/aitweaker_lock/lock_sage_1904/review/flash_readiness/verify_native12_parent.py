"""Independent final bindings/range audit; no device or firmware write calls."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
DIR=HERE/'native12_safety_review/implementation/build/integration_native12_review'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8'))
bound=lambda p:{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}

def main():
    v=read(DIR/'verification.json');build=read(DIR/'integration_manifest.json')
    image=DIR/'W790E-SAGE-SE-1904-NATIVE12-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
    assert sha(image)==v['candidate_sha256']==build['candidate_sha256']=='b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    assert v['input_manifest_sha256']==sha(DIR/'integration_manifest.json')
    old=Path(build['source_CAP']);assert sha(old)==build['source_CAP_sha256']=='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
    a=old.read_bytes();b=image.read_bytes();assert len(a)==len(b)==67112960
    cursor=0
    ranges=sorted(v['allowed_changed_ranges'],key=lambda x:x['offset'])
    for r in ranges:
        lo=r['offset'];hi=lo+r['size'];assert cursor<=lo<hi<=len(b)
        assert a[cursor:lo]==b[cursor:lo]
        assert hashlib.sha256(a[lo:hi]).hexdigest()==r['old_sha256'] and hashlib.sha256(b[lo:hi]).hexdigest()==r['new_sha256']
        cursor=hi
    assert a[cursor:]==b[cursor:] and len(ranges)==2
    pins={'AMITSE':'620b83adfd75d77f40d7f6e65b1120af733c8fdea56e0b480efaa3feb70ab9df',
          'Setup':'8639b4369648aaf87e21259a53efa5d2c32bf1dfc4567b4e2b7cb3ec94a2395a',
          'Provider':'d71f2891d25f52ddf19a7b8b86222b3d7df498ebdbc8c8c05fe7cafa0f49a305'}
    for name,digest in pins.items():assert sha(DIR/f'reextracted-{name}.UNSIGNED.review.efi')==digest
    provider=HERE/'native_provider12_candidate';manifest=provider/'candidate_manifest.json'
    assert sha(manifest)=='96ebb21125bbab8f63d687cbb0eda40c1760c792271b29c53f434db2493f4b7a'
    entries=read(manifest)['artifacts']
    for item in entries:
        p=Path(item['path']).resolve();assert p.is_relative_to(ROOT.resolve()) and p.stat().st_size==item['bytes'] and sha(p)==item['sha256']
    pr=read(provider/'provider_review.json');assert pr['efi']['sha256']==pins['Provider']
    for name in ('AMITSE','Setup'):assert pr['bound_static_modules'][name]['module_sha256']==pins[name]
    ui=HERE/'native_provider12_ui_simulation/latest_result.json';run=read(ui)
    assert run['status']=='PASS_TWO_PROCESS_OVMF_REAL_STORAGE_AND_CONSOLE_UI' and run['provider_sha256']==pins['Provider']
    assert len(run['boot_reports'])==2 and sum(x['checks'] for x in run['boot_reports'])==169
    assert run['boot_reports'][0]['vars_after_sha256']==run['boot_reports'][1]['vars_before_sha256']
    assert run['readonly_boot_disk_unchanged']
    for item in run['boot_reports']:
        assert item['status']=='PASS' and item['error'] is None and sha(Path(item['debug_log']))==item['debug_sha256']
    feedback=HERE/'save_feedback_review/native12_feedback_verification.json';f=read(feedback)
    assert f['cases']==24 and f['counterfactual_return_interventions']==0
    assert f['module_sha256']=={k:v for k,v in pins.items() if k!='Provider'}
    assert f['source_sha256']==sha(feedback.parent/'replay_native12_feedback.py')
    assert f['inherited_fixture_sha256']==sha(feedback.parent/'replay_ui_feedback.py')
    assert f['frozen_harness_snapshot_sha256']==sha(feedback.parent/'input-native-harness.py')
    out={'status':'PASS_PARENT_NATIVE12_BINDINGS_RANGES_AND_TEST_IDENTITY_NOT_RELEASE_ACCEPTANCE',
         'image':bound(image),'allowed_changed_ranges':ranges,'all_other_image_bytes_identical':True,
         'reextracted_module_sha256':pins,'provider_manifest_bindings':len(entries),
         'independent_UI_caller_cases':24,'OVMF_independent_processes':2,'OVMF_checks':169,
         'evidence':[bound(p) for p in [DIR/'verification.json',DIR/'integration_manifest.json',manifest,provider/'provider_review.json',ui,feedback]],
         'release_ready':False,'hardware_password_lock_tested':False,'firmware_upload_or_flash':False,
         'limits':['Native save replay uses explicitly modeled services/caches/OEM event effects. OVMF uses real storage and console but substitutes the OEM browser body.',
                   'File/range identity is not proof of cold boot, BMC updater acceptance, recoverability or runtime page protections.'],
         'script':bound(Path(__file__))}
    (HERE/'native12_parent_review.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({k:out[k] for k in ['status','provider_manifest_bindings','independent_UI_caller_cases','OVMF_checks','release_ready']}))
if __name__=='__main__':main()
