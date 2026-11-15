"""Independent read-only packaging review; emits only this agent's report."""
from pathlib import Path
import json,hashlib,sys,warnings
H=Path(__file__).resolve().parent;R=H.parents[3];P=H.parent/'packaging05'
sys.path.insert(0,str(R/'tools/vm-pydeps'));warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def binding(p):return {'path':str(p.relative_to(R)),'sha256':sha(p)}
tests=[]
for name in ['pe_composition_test.json','layout_validator_test.json','save_replay_test.json','fv_composition_test.json']:
 p=P/name;j=json.loads(p.read_text());checks=[]
 for b in j.get('bindings',[]):
  f=Path(b['path']);actual=sha(f)if f.is_file()else None
  checks.append({'path':str(f),'recorded':b['sha256'],'current':actual,'match':actual==b['sha256']})
 tests.append({**binding(p),'reported_status':j['status'],'case_count':len(j.get('cases',j.get('native_decoder_checks',[]))),'bindings':checks,'all_current':all(c['match']for c in checks)})
loaders=[]
for run in ['20261108_035132','20261108_035459']:
 d=P/'loader_runs'/run;j=json.loads((d/'result.json').read_text());build=json.loads((d/'build_manifest.json').read_text())
 boot=d/'boot.img';before=sha(boot)
 with PyFatFS(str(boot),read_only=True,utc=True)as fs:efi=fs.readbytes('/EFI/BOOT/BOOTX64.EFI')
 assert before==sha(boot)
 es=hashlib.sha256(efi).hexdigest();assert es==build['sha256']==j['efi_sha256']
 assert sha(d/'PACKAGING-ONLY.iso')==j['iso_before']==j['iso_after']
 assert sha(d/'debug.log')==j['debug_sha256']
 text=(d/'debug.log').read_text(encoding='ascii',errors='replace');assert text.count('PASS ')==j['checks'] and 'W890_PACKAGING_LOADER_PASS'in text and 'FAIL 'not in text
 loaders.append({'run':run,'result':binding(d/'result.json'),'manifest':binding(d/'build_manifest.json'),'boot_image':binding(boot),'iso':binding(d/'PACKAGING-ONLY.iso'),
  'embedded_boot_efi_sha256':es,'checks':j['checks'],'actual_scope':j['scope'],'functional_startimage_executed':False,'fixture_startimage_executed':not bool(build.get('functional_aggregate_load_only'))})
bootstrap=(H.parent/'integration05/bootstrap05.c').read_text()
report={'status':'INDEPENDENT_SOURCE_AND_RECORDED_EVIDENCE_REVIEW_NOT_RELEASE_APPROVAL','reviewed':[
 'merge_pe preserves original RVAs, section bytes except exact reviewed overlays, existing DIR64 data entries, and explicitly relocates approved RIP/CALL replay targets.',
 'bind_layout pins original/extension executable sections and extension readonly data, excludes relocated words while checking their base-adjusted values, and postfill checks the slot cannot change pinned spans.',
 'layout validates exact header identity after bounded ImageBase/CheckSum normalization; current source fixes symbol-count unsigned wrap by individual bound and subtraction.',
 'pack_fv changes only AMITSE file/required FV metadata, uses a legal PAD if relocated, preserves other FFS contents/offsets and outer carrier extent, and uses known-size LZMA.',
 'Actual original IA32 extraction-code tests prove two compressed streams; they do not execute complete firmware or establish dispatch order.',
 'Read-only FAT extraction independently confirms the exact EFI tested in both retained OVMF runs, independently of overwritten shared loader_build output.'
 ],'findings':[
 {'id':'L05_SYMBOL_COUNT_WRAP','state':'FIXED_IN_CURRENT_SOURCE_REPLAY_PENDING_IF_BINDINGS_DIFFER','severity':'low','file':'packaging05/layout.c','detail':'Previously sum-only export_count+trampoline_count could wrap. Current code bounds export_count and subtracts it before bounding trampoline_count. Normal generated manifests were within bounds.'},
 {'id':'EARLY_DISPATCH_PASSTHROUGH','state':'FIXED_IN_CURRENT_INTEGRATOR_SOURCE_REPLAY_REQUIRED','severity':'high','file':'write_sinks05/save_guard05.c / integration05/bootstrap05.c','detail':'Direct static replacement FD6C originally returned before prepare even for unrelated selectors. Current i05_dispatch validates mapped/static image and forwards non-FFFF001D selectors through exact original trampoline before readiness; protected defaults and fault-state forwarding remain denied. compose_candidate redirects FD6C to this wrapper.'},
 {'id':'EARLY_SAVE_CANCEL_TARGET','state':'FIXED_IN_CURRENT_INTEGRATOR_SOURCE_REPLAY_REQUIRED','severity':'high','file':'write_sinks05/save_thunk05.S / integration05/bootstrap05.c','detail':'Current i05_entry binds ws05_save_cancel=entry_base+202F4 after exact LoadedImage/layout validation and before original6480 entry, so pre-prepare denial has a fixed native cleanup target without granting permission.'},
 {'id':'BOOTSTRAP_EBS_REVOKE','state':'FIXED_IN_CURRENT_INTEGRATOR_SOURCE_REPLAY_REQUIRED','severity':'medium','file':'integration05/bootstrap05.c','detail':'Current bootstrap registers its own ExitBootServices event, sets bootstrap_ended/boot_vm.ended/service_state before revoking observer, runtime, management and write guards. anchor_live and early image-range forwarding reject after that terminal state.'}
 ],'source_bindings':[binding(P/n)for n in ['merge_pe.py','bind_layout.py','layout.c','layout.h','layout_slot.c','pack_fv.py','test_merge.py','test_layout.py','test_replay.py','test_fv.py','loader_lab.c','build_loader_lab.py','run_loader_lab.py']]+[binding(H/'review_packaging05.py')],
 'integrator_fix_bindings':[binding(H.parent/'integration05'/n)for n in ['bootstrap05.c','compose_candidate.py','build_aggregate.py']],
 'test_records':tests,'retained_real_ovmf_runs':loaders,
 'remaining_acceptance':['Final aggregate must be rebuilt after source changes and exact current hashes bound to rerun checks.','Functional bootstrap/owner/password/navigation/Save execution is separate from packaging LoadImage.','Actual ASUS whole-firmware dispatch, host startup integrity, BMC updater acceptance and recovery are not established here.'],
 'performed':{'read_only_artifact_verification':True,'modified_parent_files':False,'new_hardware_or_vm_run':False,'created_CAP_or_keys':False}}
(H/'packaging05_independent_review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'current_test_records':sum(x['all_current']for x in tests),'test_records':len(tests),'verified_loader_runs':len(loaders),'sha256':sha(H/'packaging05_independent_review.json')}))
