"""Freeze the additional evidence without touching the NATIVE11 candidate."""
from pathlib import Path
import hashlib,json,zipfile
HERE=Path(__file__).resolve().parent;CAND=HERE.parent/'native_provider_candidate';ROOT=HERE.parents[5]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8'))
raw=read(HERE/'latest_result.json');assert raw['status']=='PASS_TWO_PROCESS_OVMF_REAL_STORAGE_AND_CONSOLE_UI'
assert raw['runner_sha256']==sha(HERE/'run_persist_ui.py')and raw['fixture_source_sha256']==sha(HERE/'persist_ui.c')
assert raw['fixture_sha256']==sha(HERE/'build/PERSIST-UI-SIMULATION.EFI')
manifest=read(CAND/'candidate_manifest.json')
for item in manifest['artifacts']:assert sha(Path(item['path']))==item['sha256']
boots=raw['boot_reports'];assert len(boots)==2 and boots[0]['vars_after_sha256']==boots[1]['vars_before_sha256']
run=Path(raw['shared_writable_vars_file']).parent
for boot in boots:
    assert boot['status']=='PASS'and boot['exit_code']==33
    log=Path(boot['debug_log']);assert sha(log)==boot['debug_sha256']
    text=log.read_text(encoding='ascii',errors='replace');assert text.count('PASS ')==boot['checks']and'FAIL 'not in text
    for image in boot['screenshots']:assert sha(Path(image['path']))==image['sha256']
assert sha(Path(raw['shared_writable_vars_file']))==raw['final_vars_sha256']
source=HERE/'simulation-source.zip'
with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED)as z:
    for name in ['persist_ui.c','run_persist_ui.py','finalize_simulation.py','build/binding.h','build/build.json']:
        z.write(HERE/name,name)
with zipfile.ZipFile(source)as z:assert z.testzip()is None
report={
 'status':'REAL_STORAGE_AND_PASSWORD_OPERATIONS_PASS_VISUAL_RENDERING_ISSUE_OPEN',
 'provider_sha256':raw['provider_sha256'],'bound_modules':raw['bound_modules'],
 'frozen_candidate_manifest_sha256':sha(CAND/'candidate_manifest.json'),'frozen_candidate_artifacts_verified_unchanged':len(manifest['artifacts']),
 'additional_run':str(run),'raw_result_sha256':sha(run/'result.json'),'functional_checks':sum(b['checks']for b in boots),
 'independent_qemu_processes':2,'shared_vars_continuity_verified':True,
 'observed':['First process: keyboard-driven enrollment, wrong-password rejection, correct unlock, current-password-authorized change, record generation 1 then 2.',
             'Second process: complete stored record digest matches the prior process, old password rejected, new password accepted, ESC cancels, authenticated clear persists disabled generation 3.',
             'Each actual native outer wrapper creates/pops its frame and revokes ownership/grant on exit. Real ExitBootServices revokes permanently on both boots.',
             'Actual OVMF variable and input/output protocols remain in use; no credential get/set adapter replacement.'],
 'visual_review':{'status':'OPEN_RENDERING_DEFECT','method':'Direct inspection of QMP framebuffer PNGs.',
   'observations':['First enrollment screen shows full management title and explanation.',
                   'Later management and unlock screenshots omit approximately the first 10-11 characters of title/help lines. Password/Current password prompts remain visible.',
                   'Keyboard operations and credential checks completed despite this visual defect.'],
   'suspected_cause_not_proven':'Interaction between direct GOP save/restore and console text rendering/cache; no candidate code was changed to test this hypothesis.',
   'examples':[str(run/'boot1/enroll_a-prompt.png'),str(run/'boot1/change_to_b-prompt.png'),str(run/'boot2/unlock_b-prompt.png')]},
 'scope_limits':raw['substitutions']+raw['limits']+['The 143 functional checks are not a clean visual UI acceptance or an actual ASUS GUI test.',
    'The initial TCP QMP attempt could not connect in this environment; its failed run remains under runs/20261103_155232. The successful run used private stdio QMP pipes, no networking.'],
 'source_archive':{'path':str(source),'sha256':sha(source)},'hardware_or_BMC_access':False,'flash_or_CAP_change':False}
(HERE/'simulation_review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
artifacts=[p for p in run.rglob('*')if p.is_file()]+[HERE/'persist_ui.c',HERE/'run_persist_ui.py',HERE/'finalize_simulation.py',source,HERE/'latest_result.json',HERE/'simulation_review.json']
artifacts += [HERE/'build'/name for name in ['binding.h','build.json','persist_ui.obj','PERSIST-UI-SIMULATION.EFI']]
items=[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(set(artifacts),key=str)]
(HERE/'simulation_manifest.json').write_text(json.dumps({'status':'ADDITIONAL_SIMULATION_EVIDENCE_ONLY','artifacts':items},indent=2)+'\n')
print(json.dumps({'status':report['status'],'functional_checks':report['functional_checks'],'review_sha256':sha(HERE/'simulation_review.json'),'manifest_sha256':sha(HERE/'simulation_manifest.json'),'artifact_count':len(items)}))
