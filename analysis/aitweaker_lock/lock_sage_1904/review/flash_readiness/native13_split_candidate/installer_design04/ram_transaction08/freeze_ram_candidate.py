"""Freeze exact TX08 only after hash-bound local and independent evidence.

This writes a flat author manifest. Independent aggregate manifests must remain
outside it to avoid cycles; their exact leaf test reports can be included.
"""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;BUILD=HERE/'app_build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest_path=HERE/'ram_candidate_manifest.json';review_path=HERE/'ram_candidate_review.json'
if '--verify' in sys.argv:
 m=json.loads(manifest_path.read_text())
 for row in m['artifacts']:
  p=D04/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['path']
 print(json.dumps({'status':'PASS_FROZEN_TX08_ARTIFACTS','artifacts':len(m['artifacts']),'manifest_sha256':sha(manifest_path)}));sys.exit(0)
assert not manifest_path.exists(),'Already frozen: use --verify'
expected='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
efi=BUILD/'SageNative13RamTest08.efi';assert sha(efi)==expected
b=json.loads((BUILD/'app_build.json').read_text());assert b['efi_sha256']==expected
for row in b['sources']:assert sha(HERE/row['path'])==row['sha256']
for name,h in b['objects'].items():assert sha(BUILD/name)==h
p14=D04/'provider14_chrome07';pm=json.loads((p14/'local_candidate_manifest.json').read_text())
for row in pm['artifacts']:
 p=D04/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
tests=[]
for name,count,key in [('integrated_core_verification.json',75,'transaction_efi_sha256'),('platform_verification.json',43,'efi_sha256'),('platform_edges.json',37,'efi_sha256'),('globals_verification.json',23,'efi_sha256')]:
 p=BUILD/name;r=json.loads(p.read_text());assert r[key]==expected and r['checks']==count and r['status'].startswith('PASS')
 tests.append({'path':str(p.relative_to(D04)),'sha256':sha(p),'checks':count,'scope':r['status']})
package_dir=D04/'ram_test08_delivery/packages'/expected[:16]
package_file=package_dir/'package.json';package=json.loads(package_file.read_text());assert package['efi_sha256']==expected
iso=Path(package['iso']);assert sha(iso)==package['iso_sha256']=='44aa175e37bc367da4ded343df814ca0f3271391bc03cc53fc73371ebfd61dfe'
smoke=D04/'ram_test08_delivery/ovmf/20261103_230018/result.json';sm=json.loads(smoke.read_text());assert sm['efi_sha256']==expected and sm['iso_sha256']==sha(iso) and sm['status'].startswith('PASS_')
extra=[Path(x).resolve()for x in sys.argv[1:]]
assert len(extra)>=4,'Supply independent exact-app entry, UI, actual OVMF validator and P14 two-boot leaf reports'
for p in extra:assert p.is_file() and p.is_relative_to(D04.resolve()),p
e=[json.loads(p.read_text())for p in extra]
assert any(r.get('efi_sha256')==expected and r.get('cases')==20 and r.get('status','').startswith('PASS')for r in e),'entry20 missing'
assert any(r.get('actual_app_sha256')==expected and r.get('cases')==139 and r.get('status','').startswith('PASS')for r in e),'UI139 missing'
assert any(r.get('result',{}).get('actual_app_sha256')==expected and r.get('result',{}).get('checks',0)>=85 and r.get('result',{}).get('status','').startswith('PASS')for r in e),'actual OVMF validator missing'
assert any(r.get('provider_sha256')=='495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630' and r.get('status')=='PASS_TWO_PROCESS_OVMF_REAL_STORAGE_AND_CONSOLE_UI' and [b.get('checks')for b in r.get('boot_reports',[])]==[173,192]for r in e),'P14 two-process UI/persistence missing'
design=json.loads((HERE/'integration_design.json').read_text())
comparison=Path(design['comparison_evidence']['baseline_log']);assert sha(comparison)==design['comparison_evidence']['sha256']
r={
 'status':'FROZEN_REVIEWABLE_TX08_VOLATILE_NATIVE_TEST_NOT_FIRMWARE_RELEASE',
 'target':'ASUS Pro WS W790E-SAGE SE BIOS1904 only','efi_sha256':expected,'iso_sha256':sha(iso),'provider_sha256':'495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630',
 'guard_template_sha256':'2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa',
 'hardware_execution_by_author':False,'firmware_release_ready':False,
 'integration_design_sha256':sha(HERE/'integration_design.json'),'source_delta_sha256':sha(HERE/'integration_delta.json'),
 'comparison':design['comparison_evidence'],
 'changes':['Rebind independently reviewed native static SUBTITLE classifier07 into actual P14, runtime guard construction and exact12 transactional plan.','Independent provider implementation, public ABI, password record semantics and 991B HII package are unchanged from frozen P13. Exact identities are regenerated, never weakened.','ActionRequest starts NONE so original SendForm may legally leave it unchanged on normal ESC.','Before/after SendForm log six original globals with bounded mapped supervisor reads and unchanged original headers. Pointer values are not followed and are never idle evidence.'],
 'retained_constraints':['Original module PE sizes/headers unchanged; separately allocated guard/state with exact immutable160B bindings.','No foreign page attribute changes, CR0.WP bypass, RT table replacement or generic firmware/variable writer. Original eight target pages must still pass effective supervisor RWX proof.','BSP high-TPL transaction calls no firmware service. Unknown target bytes or failed restoration are terminal CPU hold without RestoreTPL or diagnostics.','Once-published code/state/context/provider and application remain resident until power off. No second mode2 instance or unloading after partial StartImage.','Only initial private absence allows mode2. Cleanup deletes only exact last-observed valid owned128B record; unknown retained. OC/MEM only read/compared.'],
 'exit_behavior':design['exit_limitation'],
 'reviewed_operator_stages':['Initial Q snapshot and exact preflight.','Mode1 install/check/rollback; Q independently confirms exact12 restoration before mode2.','Mode2 attach; Q confirms exact provider/guards/READY.','First M display -> native ESC -> Q with no password input. This is separate from password-action testing.','After root reviews that observed return, proceed with bounded password set/verify/change/clear and B native Setup entry checks within the existing task authorization; record each stage separately.','R observes private/OC state, deletes only exact owned private record if present, restores hooks; Q then root powers off. No BIOS save or boot override.'],
 'logging':{'maximum_bytes':24575,'header':'AITWK-P3-KVM\\r\\nSAGE_NATIVE13_RAM_TEST08\\r\\n','end':'SAGE_NATIVE13_RAM_TEST08_END','snapshot_id':'one monotonic16hex field per immutable Q snapshot','secret_or_record_hash_logged':False,'overflow':'Explicit incomplete marker; remaining actions stop except R cleanup.'},
 'author_tests':tests,'author_checks':178,'independent_leaf_reports':[{'path':str(p.relative_to(D04)),'sha256':sha(p)}for p in [smoke,*extra]],
 'limits':['No-safe-page unknown classification can still suppress render/input/poll; automatic safe unwind remains unproven and unimplemented. The reviewed chrome correction is deliberately narrow.','C10 proves only unhooked original browser display/ESC for identical independent HII, not a guarded password UI. TX05 prior black screen has no captured internal trace and is not retrospectively assigned a proven cause.','Actual-machine-code fault suites explicitly model UEFI services, CPU environment or browser body. OVMF evidence does not equal complete ASUS GUI or physical acceptance.','TPL excludes ordinary BSP callback reentry, not arbitrary AP/SMM mutation. CPU faults are not converted into recoverable TX results.','OC/MEM snapshots do not prove no other OEM internal NVRAM effects. Only the fixed private password variable is deliberately written by P14/cleanup.','This volatile test is neither a signed flashable BIOS nor proof of permanent every-boot protection. N12/P12 and all frozen predecessors remain unchanged.']
}
review_path.write_text(json.dumps(r,indent=2)+'\n')
files=set(p for p in (HERE/'source').rglob('*')if p.is_file())
files.update(HERE.glob('*.py'));files.update(HERE.glob('*.json'));files.discard(manifest_path)
files.add(HERE/'integration_source.diff')
files.update(p for p in BUILD.iterdir()if p.is_file())
files.update([p14/'local_candidate_manifest.json',p14/'local_candidate_review.json',D04/'static_chrome_candidate07/candidate_manifest.json',smoke,package_file,*extra])
files.update(package_dir/n for n in ['SageNative13RamTest08.efi','SAGE-N13-RAMTEST08-NOFLASH.iso','readonly-efiboot.img'])
files.update(D04/'ram_test08_delivery'/n for n in ['transport_boundary_result.json','package_app.py','smoke_iso.py'])
manifest={'status':r['status'],'path_base':'installer_design04','efi_sha256':expected,'iso_sha256':sha(iso),'artifacts':[{'path':str(p.relative_to(D04)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)],'review_sha256':sha(review_path),'hardware_execution':False,'firmware_release_ready':False}
manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'status':'FROZEN_TX08_VOLATILE_TEST_ONLY','artifacts':len(manifest['artifacts']),'manifest_sha256':sha(manifest_path),'review_sha256':sha(review_path),'efi_sha256':expected,'iso_sha256':sha(iso)}))
