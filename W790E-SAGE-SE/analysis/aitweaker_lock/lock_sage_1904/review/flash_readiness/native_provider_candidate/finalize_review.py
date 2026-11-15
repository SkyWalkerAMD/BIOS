"""Bind only the current exact build and tests; never promote to flash release."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,zipfile
HERE=Path(__file__).resolve().parent;OUT=HERE/'build';SRC=HERE/'source'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8'))
build=read(OUT/'build.json');state=read(OUT/'state_build.json');binding=read(HERE/'guard_binding.json')
efi=OUT/'AiTweakerNativeProvider1904.UNSIGNED.review.efi';digest=sha(efi);assert digest==build['efi_sha256']
for name,h in build['sources'].items():assert sha(SRC/name)==h,name
for name,h in build['objects'].items():assert sha(OUT/name)==h,name
assert state['objects']['provider.obj']==build['objects']['provider.obj']
assert sha(HERE/'guard_binding.json')==build['guard_binding_sha256']
for module in binding['modules'].values():assert sha(Path(module['module_file']))==module['module_sha256']
names=['build/state_verification.json','build/native_owner_verification.json','build/native_hii_verification.json',
       'build/native_entry_verification.json','build/native_joint_verification.json','build/ebs_boundary_verification.json',
       'build/active_hii_verification.json','ovmf_load_result.json']
tests=[]
for name in names:
    p=HERE/name;r=read(p);assert r['status'].startswith('PASS'),name
    if 'efi_sha256'in r:assert r['efi_sha256']==digest
    if 'dll_sha256'in r:assert r['dll_sha256']==sha(OUT/'provider_state.dll')
    if 'guard_binding_sha256'in r:assert r['guard_binding_sha256']==sha(HERE/'guard_binding.json')
    mapping={'build/state_verification.json':'verify_state.py','build/native_owner_verification.json':'verify_native_owner.py',
             'build/native_hii_verification.json':'verify_native_hii.py','build/native_entry_verification.json':'verify_native_entry.py',
             'build/native_joint_verification.json':'verify_native_joint.py','build/ebs_boundary_verification.json':'verify_ebs_boundaries.py',
             'build/active_hii_verification.json':'verify_active_hii.py'}
    if name in mapping:assert r['test_source_sha256']==sha(HERE/mapping[name])
    if 'fixture_source_sha256'in r and name!='ovmf_load_result.json':assert r['fixture_source_sha256']==sha(HERE/'verify_native_owner.py')
    for script,h in r.get('fixture_source_hashes',{}).items():assert sha(HERE/script)==h
    tests.append({'path':str(p),'sha256':sha(p),'status':r['status'],
                  'scenario_count':r.get('scenario_count',r.get('case_count')),'check_count':r.get('check_count')})
ovmf=read(HERE/'ovmf_load_result.json');assert ovmf['fixture_source_sha256']==sha(HERE/'ovmf_load.c')and ovmf['runner_sha256']==sha(HERE/'run_ovmf_load.py')
assert sha(Path(ovmf['debug_log']))==ovmf['debug_sha256']
baseline=HERE/'revisions/99b761c631b3ed7eb3add65a2be4d819200960ed00fa76690eb6a33f7d873ff9'
counterexamples=[baseline/'ebs_boundary_counterexamples.json',baseline/'active_hii_counterexample.json']
origins=read(HERE/'source_origins.json')
for name,info in origins.items():
    info['current_sha256']=sha(SRC/name)
    info['current_adaptation']='provider include plus explicit EBS guards around console/GOP/input callbacks'if name=='ui.c'else info['change']
(HERE/'source_origins.json').write_text(json.dumps(origins,indent=2)+'\n')
archive=OUT/'source-snapshot.zip'
files=[p for p in SRC.glob('*')if p.is_file()]+[p for p in HERE.glob('*.py')if p.is_file()]+[HERE/'ovmf_load.c',HERE/'source_origins.json',HERE/'guard_binding.json']
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED)as z:
    for p in files:z.write(p,p.relative_to(HERE).as_posix())
with zipfile.ZipFile(archive)as z:
    assert z.testzip()is None
    for p in files:assert hashlib.sha256(z.read(p.relative_to(HERE).as_posix())).hexdigest()==sha(p)
report={'status':'INTERNAL_PROVIDER_COMPLETE_WITH_LOCAL_VALIDATION_NOT_FLASH_RELEASE',
 'created_utc':datetime.now(timezone.utc).isoformat(),'target':'ASUS Pro WS W790E-SAGE SE BIOS1904 static native gate integration',
 'efi':{'path':str(efi),'bytes':efi.stat().st_size,'sha256':digest},
 'provider_abi':{'revision':1,'bytes':56,'guid':'f29d11ab-c12a-455a-95d3-9a8ecf045c04','methods':['begin','end','query','request','manage']},
 'frame_abi':{'revision':1,'bytes':48,'context_head_rva':hex(binding['modules']['AMITSE']['context_head_rva'])},
 'bound_static_modules':binding['modules'],'tests':tests,
 'implemented':['Independent boot-only NVRAM credential using the preserved128B record and600000-iteration PBKDF2-SHA256 core.',
  'Unconfigured means locked; explicit authenticated Clear writes a DISABLED record rather than deleting storage.',
  'Begin/End bind exact native CALL return RVAs, loaded FFS identity, payload SHA256 and real native frame membership; nested depth is bounded32.',
  'A missing provider on outer entry cannot acquire ownership in a later nested invocation. Query walks the full recorded frame chain.',
  'Changing/clearing an enabled password requires its current password. UI and persistence callbacks recheck ownership before returning success.',
  'NVRAM write adapter verifies current record against the authenticated cached record before writing, and verifies exact readback afterward; uncertain mutation faults closed.',
  'HII inserts two management actions in original Security IFR, leaves native ConfigAccess method pointers unchanged, and checks exported package after update/rollback.',
  'HII mutations require an authenticated native context head that is NULL. Active ownerless wrappers and unknown/unmapped context states defer; the real discovery callback can retry after the outer wrapper exits.',
  'Every reviewed service boundary in entropy, clock, allocation, credential persistence, HII, entry and console UI rechecks EBS before proceeding; 58 actual-byte injected ending cases have no subsequent firmware service call.',
  'ExitBootServices revokes/wipes state without replacing RuntimeServices or permanently stopping normal OS handoff.'],
 'review_defects_resolved':{'superseded_efi_sha256':baseline.name,'baseline_evidence':[{'path':str(p),'sha256':sha(p),'status':read(p)['status']}for p in counterexamples],
   'findings':['Old candidate continued firmware/protocol calls or returned success after ending in 30 of 37 targeted cases.',
               'Old candidate mutated HII while an actual ownerless outer native frame was active.'],
   'current_regression':['58 EBS boundary cases PASS with real ending execution; finite synthetic callback schedules only.',
                         'Actual AMITSE wrapper plus direct installer and actual discover callback both defer with zero HII writes and retry after the wrapper exits.']},
 'limitations':['This optional provider requires the exact newly modified static AMITSE/Setup modules. It cannot be substituted into old EXP02/EXP03 or used as a standalone no-flash permanent lock.',
  'No complete signed/accepted CAP, compression/container integration, physical cold-boot/password persistence or BMC recovery test is established here.',
  'OVMF loaded both OEM PE files but never started their private entrypoints. It started the full provider; it did not run the actual ASUS Setup GUI.',
  'The native joint test executes the real modified wrapper and real provider with a stubbed original browser body; whole OEM navigation/save coverage belongs to the separate guard review.',
  'Real BIOS console password input, actual OEM HII package update behavior and NVRAM enrollment across physical cold boots remain unvalidated for this new architecture.',
  'OVMF observed both guard and context pages as writable/executable despite the PE section flags. No runtime W^X acceptance is claimed.',
  'A lost/corrupted native frame chain denies access; unusual context corruption may keep the provider locked until a reboot.',
  'An EBS transition during allocation or HII mutation may leave allocated buffers or a partially applied package resident; no post-EBS cleanup/rollback service is attempted, and provider access is permanently revoked.',
  'The HII updater defers if first discovered during an already active native browser. The management actions may appear only on a later verified idle interval and subsequent BIOS entry.',
  'Same-privilege malicious UEFI code or direct flash/variable tampering is outside this menu-lock trust boundary; the credential is not an authenticated variable scheme.',
  'Existing parent vendor capsule signature, deployment and complete backup/recovery blockers remain unchanged.'],
 'hardware_or_BMC_access':False,'CAP_or_FFS_written':False,'runtime_or_native_hook_pointers_replaced':False,
 'source_archive':{'path':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive)}}
(HERE/'provider_review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
artifacts=files+[efi,archive,OUT/'build.json',OUT/'state_build.json',OUT/'provider_state.dll',OUT/'provider.map',OUT/'provider_state.map',
                *[OUT/n for n in build['objects']],*[HERE/n for n in names],Path(ovmf['debug_log']),Path(ovmf['debug_log']).parent/'result.json',
                HERE/'provider_review.json',*[Path(m['module_file'])for m in binding['modules'].values()]]
artifacts+=counterexamples
unique=sorted(set(p.resolve()for p in artifacts),key=str)
manifest={'status':'EXACT_LOCAL_PROVIDER_CANDIDATE_BINDINGS_NOT_FLASH_RELEASE','efi_sha256':digest,
 'artifacts':[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}for p in unique]}
(HERE/'candidate_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
# Keep the independently tested revision reconstructable when the next guard
# binding changes the current module copies. Existing revisions are immutable.
revision=HERE/'revisions'/digest;revision.mkdir(parents=True,exist_ok=True)
for p in [efi,archive,HERE/'provider_review.json',HERE/'candidate_manifest.json',HERE/'guard_binding.json',OUT/'provider.map',*[HERE/n for n in names]]:
    target=revision/p.name
    if target.exists():
        if target.read_bytes()!=p.read_bytes():continue # Earlier exact report retained.
    else:target.write_bytes(p.read_bytes())
print(json.dumps({'status':report['status'],'efi_sha256':digest,'review_sha256':sha(HERE/'provider_review.json'),
                 'manifest_sha256':sha(HERE/'candidate_manifest.json'),'artifact_count':len(unique)}))
