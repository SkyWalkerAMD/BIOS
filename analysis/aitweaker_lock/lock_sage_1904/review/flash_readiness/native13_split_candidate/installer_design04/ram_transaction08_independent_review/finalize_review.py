"""Freeze a bounded, offline TX08 review; never operate the target system."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;READY=HERE.parents[2]
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
TX=D04/'ram_transaction08';P14=D04/'provider14_chrome07';LAB=D04/'provider14_ovmf_lab';DEL=D04/'ram_test08_delivery'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8'))
EFI='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
ISO='44aa175e37bc367da4ded343df814ca0f3271391bc03cc53fc73371ebfd61dfe'
PROVIDER='495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630'
bindings={}
def bind(p,expected=None,size=None):
 p=Path(p).resolve();assert p.is_relative_to(ROOT)
 digest=sha(p)
 if expected is not None:assert digest==expected,(p,digest,expected)
 if size is not None:assert p.stat().st_size==size
 rel=str(p.relative_to(ROOT)).replace('\\','/')
 bindings[rel]={'path':rel,'bytes':p.stat().st_size,'sha256':digest}
 return bindings[rel]
def manifest(p,expected,base):
 bind(p,expected);obj=read(p)
 for row in obj['artifacts']:bind(base/row['path'],row['sha256'],row['bytes'])
 return len(obj['artifacts'])
def main():
 output=HERE/'independent_review.json';index=HERE/'independent_manifest.json'
 if '--verify-only' in sys.argv:
  obj=read(index)
  for row in obj['artifacts']:bind(ROOT/row['path'],row['sha256'],row['bytes'])
  print(json.dumps({'status':'PASS_FROZEN_REVIEW_BINDINGS','artifacts':len(obj['artifacts']),'review_sha256':sha(output),'manifest_sha256':sha(index)}));return
 assert not output.exists() and not index.exists()
 counts={
  'author_tx08':manifest(TX/'ram_candidate_manifest.json','7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96',D04),
  'author_p14':manifest(P14/'local_candidate_manifest.json','150ae9aaba738a2c70f3075d741f4875f0c9f26ce8006ca83eafd71c5e9e7019',D04),
  'independent_lab':manifest(LAB/'independent_manifest.json','ef2f79ff8d353bdf723eaca8f9a549b10116d3de0891beed4a1164a27b0b5c00',ROOT)}
 bind(LAB/'independent_review.json','81a76db8741b013ac1da6783c80ca0d78b2e5f1caccf2c5317ac40f8712c0912')
 bind(TX/'ram_candidate_review.json','7a3f431a088031ce9ccf9c6c82629e3294fff5031c9f5c54a54c84be6c8aec5e')
 build=read(TX/'app_build/app_build.json');assert build['efi_sha256']==EFI
 for row in build['sources']:bind(TX/row['path'],row['sha256'])
 for name,digest in build['objects'].items():bind(TX/'app_build'/name,digest)
 bind(TX/'app_build/SageNative13RamTest08.efi',EFI)
 bind(P14/'build/AiTweakerSplitProvider14.UNSIGNED.local.efi',PROVIDER)
 bind(DEL/'packages'/EFI[:16]/'SAGE-N13-RAMTEST08-NOFLASH.iso',ISO)
 # Preserve current compiled-source inputs in our own immutable review tree.
 for row in build['sources']:
  source=TX/row['path'];dest=HERE/'source_snapshot'/Path(row['path']).relative_to('source')
  dest.parent.mkdir(parents=True,exist_ok=True)
  if dest.exists():assert dest.read_bytes()==source.read_bytes()
  else:dest.write_bytes(source.read_bytes())
  bind(dest,row['sha256'])
 evidence=[]
 def leaf(name,p,checks=None,own=False,scope=None):
  obj=read(p);assert str(obj.get('status','')).startswith('PASS')
  if 'efi_sha256'in obj:assert obj['efi_sha256']==EFI
  if checks is not None:assert obj.get('checks',obj.get('cases'))==checks
  record={'name':name,'report':bind(p),'new_execution_by_this_reviewer':own}
  if checks is not None:record['checks']=checks
  if scope:record['scope']=scope
  evidence.append(record);return obj
 leaf('Exact complete-app entry and ending',HERE/'final_app_edges_e0793175f78b6488/result.json',20,True,
      'Actual full app PE; UEFI endpoints modeled. Original inventory code refuses incomplete fixture platform. No adapter substitution.')
 leaf('Exact pinned-object relink and independent embedded P14 asset audit',HERE/'link_and_assets_review.json',own=True,
      scope='Ten original object files relink byte-identically to the delivered EFI after standard PE checksum. Not an independent source compiler proof.')
 delivery=leaf('Raw ISO/FAT/PE and original OVMF QR pixels',HERE/'delivery_review.json',own=True,
      scope='Raw ElTorito/FAT parsing, eight PNG/PPM pixel pairs, two complete527B logs. No positive ASUS/native-installer inference.')
 for row in delivery['bindings']:bind(ROOT/row['path'],row['sha256'],row['bytes'])
 ops=leaf('Controller-operation source and existing local mocks',HERE/'operations_review.json',scope='Read-only review and strict hashes. No operations or mocks executed by this reviewer.')
 for row in ops['bindings']:bind(ROOT/row['path'],row['sha256'],row['bytes'])
 for name,file,count in [('Transaction','integrated_core_verification.json',75),('Platform','platform_verification.json',43),('Provider publication','platform_edges.json',37),('Native-global collector','globals_verification.json',23)]:
  leaf(name,TX/'app_build'/file,count,scope='Author actual complete-app machine-code suite with explicitly modeled UEFI/CPU or validator endpoints; report and test source bound.')
 ui=leaf('Independent full-app UI',TX/'ui_independent_review/ui_test_result.json',139,
         scope='Actual UI instructions; native SendForm, globals collector and firmware/provider methods explicitly modeled. Actual collector covered separately.')
 assert ui['actual_app_sha256']==EFI
 leaf('Per-service QR transport ending boundaries',DEL/'transport_boundary_result.json',99,
      scope='Compiled transport carrier, modeled UEFI/ending and QR encoder substitutes except one actual encoder route; not whole-app ending evidence.')
 validator=read(LAB/'tx08_validator_e0793175/latest_result.json')['result']
 assert validator['actual_app_sha256']==EFI and validator['provider_sha256']==PROVIDER and validator['checks']==85
 evidence.append({'name':'Actual loaded application validator in OVMF','report':bind(LAB/'tx08_validator_e0793175/latest_result.json'),'checks':85,'new_execution_by_this_reviewer':False,
  'scope':'Standard LoadImage loads exact app/P14; actual internal validator runs. Neither app nor P14 entry starts in this fixture.'})
 lab=read(LAB/'independent_review.json');assert lab['actual_app_sha256']==EFI and lab['actual_provider_sha256']==PROVIDER
 assert [r['assertions']for r in lab['actual_provider_two_process_test']['boot_assertions']]==[173,192]
 evidence.append({'name':'Actual P14 two-process OVMF password/storage/console/EBS','report':bind(LAB/'latest_result.json'),'assertions_per_process':[173,192],'new_execution_by_this_reviewer':False,
  'scope':'Actual provider and detached guard; native ASUS browser body replaced by declared fixture. Counts include repeated setup, not unique hardware cases.'})
 preserved=[]
 for p,digest in [
  (D04/'ram_transaction05/app_build/SageNative13RamTest05.efi','9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'),
  (D04/'readonly_browser_baseline06/build/SageNative13BrowserBaseline06.efi','2092c11abfc1cc9271357277aaac030424f8dd99c342ae1612f4c0cd3d82e169'),
  (D04/'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi','caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9')]:
  preserved.append(bind(p,digest))
 n12=READY/'native12_safety_review/implementation/build/integration_native12_review/W790E-SAGE-SE-1904-NATIVE12-INTERNAL-UNSIGNED-NOT-RELEASE-READY.review.bin'
 oldintegration=read(n12.parent/'integration_review.json');preserved.append(bind(n12))
 for p in [D04/'ram_transaction05_independent_review/original_startimage_error_cleanup.json',D04/'ram_transaction05_independent_review/original_startimage_tpl_restore.json']:
  bind(p)
 report={'status':'PASS_INDEPENDENT_LOCAL_REVIEW_FOR_STAGED_VOLATILE_TX08_TEST','utc':datetime.now(timezone.utc).isoformat(),
  'efi_sha256':EFI,'iso_sha256':ISO,'provider_sha256':PROVIDER,'guard_template_sha256':'2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa',
  'device_calls':0,'firmware_release_ready':False,'flash_approval':False,'confirmed_source_blockers_remaining_in_reviewed_scope':[],
  'manifest_counts_reverified':counts,'compiled_sources_verified':len(build['sources']),'linked_objects_verified':len(build['objects']),
  'review_findings':[
   {'source':'ram_transaction08/source/transaction.c','line':1,'finding':'Transaction implementation is byte-identical to frozen TX05; regenerated fixed12 plan targets the new exact07 guard. High-TPL validation has no BootServices call, unknown site bytes are not overwritten, and failed/ambiguous restoration remains resident CPU hold. The test demonstrates BSP service model only, not AP/SMM quiescence.'},
   {'source':'ram_transaction08/source/platform.c','line':233,'finding':'New globals collector validates fresh mapped original module header/LoadedImage identity, reads only six fixed RVAs (5x8B plus reset1B), logs values without following pointer-looking contents, and never treats them as an idle predicate. Ordinary map/metadata rejection propagates false; EBS/abnormal TPL holds.'},
   {'source':'ram_transaction08/source/session_ui.c','line':182,'finding':'Pre-globals rejection suppresses SendForm. A successful collector is followed by a second owned-state/provider/credential/store check. ActionRequest now starts standard NONE0; returned dangling owner or abnormal TPL stops before diagnostic services.'},
   {'source':'ram_transaction08/source/session_ui.c','line':199,'finding':'An ordinary post-globals failure still observes the private record and OC/MEM before UI returns false, preserving exact-owned cleanup eligibility. This is not an authorization of firmware writes or proof of all OEM effects.'},
   {'source':'ram_transaction08/source/platform.c','line':287,'finding':'Provider remains single-attempt with exact loaded object/five method RVAs and READY flags. Standard declared-header/VirtualSize/BSS identity plus17 DIR64 normalization is retained; final embedded P14 is byte-exact. The actual OVMF loaded-validator evidence addresses this exact new provider size.'},
   {'source':'ram_transaction08/source/platform.c','line':301,'finding':'All published app/provider/guard/state/context resources remain resident after normal rollback or partial StartImage failure. Cached validated provider span avoids freed LoadedImage dereference. No UEFI unload or unsafe forced native exit is added.'},
   {'source':'ram_transaction08/source/session_ui.c','line':217,'finding':'Sole controller SetVariable remains fixed-name/GUID deletion after exact observed owned valid128B record comparison. Existing unknown records are refused/preserved. Password contents and record digest are not logged.'},
   {'source':'ram_transaction08/source/transport/kvm.c','line':1,'finding':'Transport changes only family labels from TX05; ending checks remain at every modeled service boundary. Exact ISO transport and whole-app entry checks are separate evidence.'}],
  'test_evidence':evidence,
  'physical_stage_advice':[
   'No local blocker found for root-controlled initial Q and fresh runtime identity/permission/credential absence checks on the authorized maintained SAGE1904.',
   'Verify exact mode1 twelve-site rollback in a new complete snapshot before mode2; do not transfer prior TX05 hardware success across the new binary.',
   'After exact mode2 provider/guard READY snapshot, first M display -> one native ESC -> Q with no password input. This is the immediate diagnostic target.',
   'Independently review that actual return before password actions or B/original Setup. Unknown/no-safe-page denial may still prevent ESC; do not force native app/reset fields.',
   'If responsive, R verifies/deletes only exact owned private record and restores hooks, then snapshot. If unresponsive, reviewed one-shot BMC power-off plus separate recovery observations; HTTP ack and black pixels prove neither power state nor CPU hold.'
  ],
  'limitations':[
   'The narrow07 static SUBTITLE classification and ActionRequest0 correction are local changes; TX05 black-screen cause was not observed internally and is not retrospectively proven.',
   'C10 demonstrates original unhooked form render/ESC only. This new native render/input/password/alternative-entry behavior has no physical acceptance at review time.',
   'A known unknown-page/no-safe-Main denial can suppress input. No safe automatic unwind has been proved or introduced.',
   'Models and OVMF exclude complete original ASUS browser body, AP/SMM concurrency, full runtime mapping assurance and physical NVRAM behavior. Counts are separately scoped, not a coverage percentage or unique hardware total.',
   'OC/MEM before/after equality does not establish absence of every OEM variable write. Recovery private absence is current-state evidence, not universal historical no-write proof.',
   'This is a resident volatile diagnostic. It is not permanent every-boot protection, a signed/flash-ready BIOS, or evidence of complete backup/recovery availability.',
   'The independent relink binds existing objects to final bytes; it is not a second compiler validation of source semantics.'
  ],'preserved_predecessor_identities':preserved}
 output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');bind(output)
 # Capture our scripts, immutable source/operation snapshots and own leaf output.
 for p in HERE.rglob('*'):
  if p.is_file() and p!=index and '__pycache__'not in p.parts:bind(p)
 frozen={'path_base':'workspace_root','status':'FROZEN_INDEPENDENT_TX08_REVIEW_NOT_FIRMWARE_RELEASE','efi_sha256':EFI,'iso_sha256':ISO,'artifacts':sorted(bindings.values(),key=lambda r:r['path'])}
 index.write_text(json.dumps(frozen,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'status':report['status'],'artifacts':len(frozen['artifacts']),'review_sha256':sha(output),'manifest_sha256':sha(index)}))
if __name__=='__main__':main()
