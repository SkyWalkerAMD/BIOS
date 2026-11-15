"""Freeze diagnostic-only guard bytes and bounded local evidence."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=D04.parents[6]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mp=HERE/'candidate_manifest.json'
if '--verify' in sys.argv:
 m=json.loads(mp.read_text())
 for r in m['artifacts']:
  p=D04/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256'],r['path']
 print(json.dumps({'status':'PASS_FROZEN_DIAGNOSTIC09_BINDINGS','artifacts':len(m['artifacts']),'sha256':sha(mp)}));raise SystemExit
assert not mp.exists(),'Already frozen; use --verify'
build=json.loads((HERE/'build/split_build.json').read_text())
for n,h in build['sources'].items():assert sha(HERE/'source'/n)==h,n
assert sha(HERE/'build/guard_template.bin')==build['template_sha256']
tests=[]
for n,count in [('split_guard_regression.json',198),('chrome_verification.json',106),('diagnostic_verification.json',115)]:
 p=HERE/'build'/n;r=json.loads(p.read_text());assert r['checks']==count and r['status'].startswith('PASS'),n
 if n=='split_guard_regression.json':assert r['split_build_sha256']==sha(HERE/'build/split_build.json')
 elif n=='chrome_verification.json':assert r['new_build_sha256']==sha(HERE/'build/split_build.json')
 else:assert r['template_sha256']==build['template_sha256']and r['template_source_sha256']==sha(HERE/'source/gate.c')and r['test_source_sha256']==sha(HERE/'verify_diagnostic.py')
 tests.append({'path':str(p.relative_to(D04)),'sha256':sha(p),'checks':count,'scope':r['status']})
old=D04/'static_chrome_candidate07';assert sha(HERE/'source/policy_data.h')==sha(old/'source/policy_data.h')
assert sha(HERE/'source/native_chrome_data.h')==sha(old/'source/native_chrome_data.h')
contract={
 'status':'DIAGNOSTIC09_PRIVATE_STORAGE_AND_DISPLAY_CONTRACT',
 'public_provider_frame_context_binding_unchanged':True,
 'state_page_bytes':4096,'public_prefix_bytes':32,'diagnostic_offset':64,'diagnostic_bytes':576,'diagnostic_end_exclusive':640,
 'header_bytes':64,'record_bytes':256,'first_state_offset':128,'current_state_offset':384,
 'initialize_once_after_state_memset_before_any_detour':{'magic_offset':64,'magic':'0x3930474149444753','revision_offset':72,'revision':1,'bytes_offset':76,'bytes':576,'remaining_bytes_zero':True},
 'initialization_writes_not_authorization_inputs':True,
 'lifetime':'Uses existing exclusively allocated RW/non-X state page; no extra allocation, no reuse or free while any guard/provider remains resident.',
 'concurrency':'Nonblocking atomic32 CAS writer lock with acquire/release; flags always atomically accessed; failed write sets sticky DROPPED. First record is immutable; current request serial advances and matching completion clears pending. Any dropped/incomplete/overflow state makes current summary unavailable.',
 'display':'Six lines on existing UNCONFIGURED prompt only; no additional input mode, no forced return and no Q export.',
 'display_crc':'CRC32 over exactly100 little-endian bytes: three u64, nineteen u32 in displayed order. This is NOT a screenshot-verifiable checksum of the full256-byte record.',
 'display_fields':['request_serial_u64','prompt_count_u64','successful_unconfigured_ack_count_u64','first_hook','first_reason','first_detail','first_frame_kind','current_hook','current_reason','current_detail','current_classification','page_index','form_id','page_owner','record_valid_low32','frame_kind','control_type','control_vtable_rva','control_hii_class','control_owner','first_and_current_valid_bits','diagnostic_flags'],
 'unobserved_u32':'FFFFFFFF; validity distinguishes unavailable from legitimate signed-1.',
 'owner_detail':'For ownership failure only, high8 bits identify primary subject:1 page or2 control; low24 bits are failure stage.2 GetPackageListHandle/driver failure,3 ConfigAccess lookup/validation failure,4 null/live check. EFI status is in memory record only, not six-line display.',
 'forbidden_data':['Passwords','Password records','Salt/verifier bytes','Hashes of credentials or credential records','Unbounded stack/object traversal'],
 'semantics':'Guard classification/authorization still derives solely from preexisting inputs. Trace unavailable, malformed, busy, overflow or unwritable never grants, redirects differently, or changes password/session state.',
 'kind4_expected_fixture_only':{'hook':5,'reason':11,'detail':'02000003','frame_kind':4,'control_vtable':'0006D6F0','IFR_and_type_unobserved':True},
 'limitations':['Kind4 fixture is not a captured hardware trace.','Single unchanged screen after ESC cannot prove whether the key was consumed; a later higher request serial and acknowledgement count can provide bounded evidence.','No safe-page exit repair. No diagnostic-induced clearing of native reset flags.','No public provider ABI or original-module content identity relaxation.']}
(HERE/'integration_contract.json').write_text(json.dumps(contract,indent=2)+'\n')
review={
 'status':'FROZEN_DIAGNOSTIC_ONLY_GUARD09_NOT_INSTALLER_OR_GUI_ACCEPTANCE',
 'template_sha256':build['template_sha256'],'template_bytes':build['template_bytes'],
 'source_sha256':sha(HERE/'source/gate.c'),'reference_classifier_manifest_sha256':sha(old/'candidate_manifest.json'),
 'tests':tests,'author_checks':sum(x['checks']for x in tests),
 'corrected_during_development':['Initial record reused one control accumulator; the next-control owner failure inherited an earlier IFR. Final actual-byte two-control negative case requires all IFR validity/data absent.','Direct independent verify origin uses classification=-1, not a synthetic safe-page classification.','Owner failure detail carries primary subject/stage so the six-line output is actionable without another query.','Failed nonblocking completion can retain pending context; sticky loss now suppresses current-record validity.'],
 'fixture_label_correction':'Inherited07 chrome test page was Setup-owned despite its old foreign label. Its old safe Form1 regression remains limited. New115 differential cases explicitly verify foreign page ownership0.',
 'policy_delta':'None intended; exact native static kinds1/2/3/5 only. Kind4/unknown remain denied. Generated policy and native method/CRC tables are byte-identical to07.',
 'actual_differential_scope':'Eleven paired cases compare final09 to frozen07 authorization endpoints, provider flags, HII/provider service sequence/arguments and all non-stack/non-diagnostic writes. This is bounded testing, not a universal equivalence proof.',
 'store_model_limits':'Host concurrency tests are separately reviewed. Neither Unicorn nor host contention tests prove arbitrary firmware AP behavior.',
 'unimplemented':['Physical diagnostic09 execution','Full original ASUS browser/root-cause proof','Safe unwind when no safe native page exists','Formal flash/signature acceptance'],
 'previous_frozen_candidates_modified':False,'hardware_actions':False}
(HERE/'candidate_review.json').write_text(json.dumps(review,indent=2)+'\n')
files=set(HERE.glob('*.py'))|set(HERE.glob('*.json'))
files.update(p for sub in ['source','build']for p in(HERE/sub).iterdir()if p.is_file())
files.update([old/'candidate_manifest.json',old/'candidate_review.json'])
files.discard(mp)
m={'status':review['status'],'path_base':'installer_design04','artifacts':[{'path':str(p.relative_to(D04)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)]}
mp.write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({'status':review['status'],'template_sha256':build['template_sha256'],'artifacts':len(m['artifacts']),'manifest_sha256':sha(mp),'review_sha256':sha(HERE/'candidate_review.json')}))
