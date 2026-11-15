"""Independent read-only binding review of the EBS six-suite path retargeting.

Does not execute a test, load the DLL, invoke a linker, or change a candidate.
"""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[1]
ROOT = HERE.parents[4]
EBS = HERE / 'ebs_candidate'
DRIVER = CASE / 'driver'
OUT = EBS / 'full_regression'
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf-8'))
def info(p):
    return {'path': p.relative_to(ROOT).as_posix(), 'sha256': sha(p), 'bytes': p.stat().st_size}
candidate = load(EBS / 'build/build.json')
baseline = load(DRIVER / 'build/build.json')
context = load(OUT / 'build_context.json')
summary = load(OUT / 'summary.json')
PIN_DRIVER = '93237af8b9b59437f0135524d8283c4685f6f454e3050c0ed6dc5a6495387c80'
PIN_BASELINE = 'da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
PIN_SOURCE = '5346f3396367096938b971ba1b78552aad53075a9c3ee68a8778170aad7e67c9'
assert sha(OUT / 'summary.json') == '19a5ad0272eab0bce4cc72fa9275f18a91b805dca9099f8ffcb51c383f2ec0f4'
assert sha(EBS / 'run_full_regression.py') == summary['runner_sha256'] == 'ab57a4724b570666ba460eb1104a1a2054d3600163be8817bbdbef84f151d57d'
assert sha(EBS / 'build/build.json') == summary['candidate_build_manifest_sha256']
assert sha(OUT / 'build_context.json') == summary['build_context_sha256']
assert sha(EBS / 'build/AiTweakerLock1904.efi') == candidate['candidate_driver_sha256'] == summary['candidate_driver_sha256'] == PIN_DRIVER
assert sha(EBS / 'services.c') == candidate['candidate_source_sha256'] == PIN_SOURCE
assert sha(DRIVER / 'build/AiTweakerLock1904.efi') == candidate['baseline_driver_sha256'] == baseline['efi_sha256'] == PIN_BASELINE
assert all(sha(CASE / n) == digest for n, digest in candidate['object_sha256'].items())
assert all(sha(CASE / n) == digest for n, digest in baseline['sources'].items())
assert all(sha(ROOT / n) == digest for n, digest in baseline['external_sources'].items())
expected_sources = {n.replace('\\', '/'): digest for n, digest in baseline['sources'].items() if n.replace('\\', '/') != 'driver/services.c'}
expected_sources['review/flash_readiness/ebs_candidate/services.c'] = PIN_SOURCE
assert context['sources'] == expected_sources
assert context['external_sources'] == baseline['external_sources']
assert summary['hardware_acceptance_inherited'] is False

def path_only(text):
    return text.replace("HERE/'build/", "CANDIDATE/'build/").replace("HERE/'build'", "CANDIDATE/'build'")

expected_counts = {'verify_adapter.py': 36, 'verify_identity.py': 12, 'verify_entropy.py': 10, 'verify_hii_abi.py': 8, 'verify_policy.py': 6357, 'verify_history.py': 131}
results = []
assert len(summary['tests']) == len(expected_counts)
for test in summary['tests']:
    name = test['test']
    original_path = DRIVER / name
    adapted_path = OUT / name
    original = original_path.read_text(encoding='utf-8')
    expected = path_only(original)
    if name == 'verify_policy.py':
        expected = expected.replace("str(OUT/(x+'.obj'))", "str((CANDIDATE/'build' if x=='services' else HERE/'build')/(x+'.obj'))")
    if name == 'verify_history.py':
        expected = expected.replace("build=json.loads((CANDIDATE/'build/build.json').read_text(encoding='utf8'))", 'build=CANDIDATE_BUILD_CONTEXT')
        expected = expected.replace("assert sha(CANDIDATE/'build/AiTweakerLock1904.efi')==build['efi_sha256']==HARDWARE_DRIVER_SHA", "assert sha(CANDIDATE/'build/AiTweakerLock1904.efi')==build['candidate_driver_sha256']\nassert build['baseline_driver_sha256']==HARDWARE_DRIVER_SHA")
        expected = expected.replace("ns={'__file__':str(DRIVER/'verify_adapter.py')};", "prefix=ADAPT_PATHS(prefix)\nns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':CANDIDATE};")
    assert expected == adapted_path.read_text(encoding='utf-8'), name
    assert sha(original_path) == test['original_test_sha256']
    assert sha(adapted_path) == test['adapted_test_sha256']
    report_path = Path(test['report'])
    assert report_path.parent == EBS / 'build'
    assert sha(report_path) == test['report_sha256']
    report = load(report_path)
    assert report.get('status') == 'PASS' or report.get('passed') is True
    assert report.get('driver_sha256', report.get('driver_efi_sha256')) == PIN_DRIVER
    count = report.get('cases', report.get('assertions', report.get('checks')))
    count = len(count) if isinstance(count, list) else count
    assert count == test['checks_or_cases'] == expected_counts[name]
    results.append({'test': name, 'count': count, 'status': 'PASS_BINDING_ONLY', 'original': info(original_path), 'adapted': info(adapted_path), 'report': info(report_path), 'changes_exclusively_allowed_path_or_identity_context': True, 'behavior_assertions_and_fixtures_unchanged': True})

objects = ['entry', 'services', 'cpu_entropy', 'ui', 'policy', 'hii', 'platform', 'password_core', 'password_crypto', 'probe_core']
object_paths = [(EBS / 'build' if n == 'services' else DRIVER / 'build') / (n + '.obj') for n in objects]
assert {p.relative_to(CASE).as_posix(): sha(p) for p in object_paths} == {n.replace('\\', '/'): v for n, v in candidate['object_sha256'].items()}
dll_path = EBS / 'build/policy_test.dll'
assert sha(dll_path) == '587248730e4754fb280bf641fd2edf331d0b81466c21ab374c221c3837fb0048'
dll = pefile.PE(str(dll_path))
driver = pefile.PE(str(EBS / 'build/AiTweakerLock1904.efi'))
exports = {x.name.decode(): x.address for x in dll.DIRECTORY_ENTRY_EXPORT.symbols}
assert set(exports) == {'policy_ifr_insert', 'policy_form', 'policy_question', 'policy_inert_ifr', 'protection_for_variable'}
assert all(x.forwarder is None for x in dll.DIRECTORY_ENTRY_EXPORT.symbols)
assert dll.OPTIONAL_HEADER.AddressOfEntryPoint == 0
assert all(dll.OPTIONAL_HEADER.DATA_DIRECTORY[n].Size == 0 for n in [1, 9, 13])
dll.relocate_image(driver.OPTIONAL_HEADER.ImageBase)
di = driver.get_memory_mapped_image()
li = dll.get_memory_mapped_image()
sections = []
for sec in driver.sections:
    a, n = sec.VirtualAddress, sec.Misc_VirtualSize
    assert di[a:a + n] == li[a:a + n]
    sections.append({'section': sec.Name.decode().rstrip('\0'), 'candidate_bytes': n, 'candidate_section_sha256': hashlib.sha256(di[a:a + n]).hexdigest(), 'DLL_corresponding_bytes_match_after_imagebase_relocation': True})

history = load(EBS / 'build/history_regression.json')
assert history['hardware_history01_driver_sha256'] == PIN_BASELINE
assert history['driver_sha256'] == PIN_DRIVER
assert history['compiled_source_sha256'] == expected_sources
assert history['external_source_sha256'] == baseline['external_sources']
assert history['verification_source_sha256']['verify_adapter.py'] == sha(DRIVER / 'verify_adapter.py')
assert history['verification_source_sha256']['verify_history.py'] == sha(DRIVER / 'verify_history.py')
prefix = path_only((DRIVER / 'verify_adapter.py').read_text(encoding='utf-8').split('\nchecks=[]', 1)[0])
assert "CANDIDATE/'build/AiTweakerLock1904.efi'" in prefix and "CANDIDATE/'build/driver.map'" in prefix
exp02 = CASE / 'lab/asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin'
assert sha(exp02) == '95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e'

review = {
    'status': 'PASS_INDEPENDENT_EBS_FULL_REGRESSION_RETARGET_REVIEW',
    'review_date': '2026-11-03', 'reviewer': 'sage_original',
    'scope': 'Read-only runner, saved test diff, artifact and report binding review. No simulation repeated, DLL loaded, linker run, production/candidate edit, BMC action or deployment by this reviewer.',
    'blocking_findings': [],
    'candidate_driver_sha256': PIN_DRIVER, 'candidate_services_sha256': PIN_SOURCE,
    'baseline_driver_sha256': PIN_BASELINE, 'hardware_acceptance_inherited': False,
    'inputs': {'runner': info(EBS / 'run_full_regression.py'), 'summary': info(OUT / 'summary.json'), 'build_context': info(OUT / 'build_context.json'), 'candidate_manifest': info(EBS / 'build/build.json'), 'baseline_manifest': info(DRIVER / 'build/build.json'), 'candidate_EFI': info(EBS / 'build/AiTweakerLock1904.efi'), 'candidate_services': info(EBS / 'services.c'), 'EXP02': info(exp02)},
    'test_bindings': results,
    'runner_findings': [
        'Every saved adapted test exactly matches the original plus the independently enumerated allowed substitutions; no test behavior assertion or fixture was weakened or removed.',
        'Candidate driver and linker-map paths are used by every compiled suite. The history suite dynamically loads the original adapter prefix only after applying the same candidate-path rewrite and supplying CANDIDATE to its namespace.',
        'Preserving __file__ as the original path keeps official module/IFR/helper locations correct. sys.argv is explicitly reset without --baseline, so HII ABI uses the candidate branch. A new execution namespace is used per suite, failures propagate, and sys.argv is restored in finally.',
        'Report writes, policy DLL and policy fixture output are directed to the isolated candidate build folder. Original production test scripts are read only. Source hashes, object hashes and both baseline/candidate EFI identities are checked before execution.',
        'The history hardware identity assertion was split into current candidate identity and an explicitly separate baseline-history identity. It does not assert that the candidate passed the prior hardware test; summary hardware_acceptance_inherited is false and test limits disclaim new hardware acceptance.',
    ],
    'policy_DLL': {'artifact': info(dll_path), 'link_input_objects': [info(p) for p in object_paths], 'linker_mode': '/dll /noentry /nodefaultlib /machine:x64 /timestamp:0', 'only_replaced_object': 'services.obj from isolated EBS candidate', 'exports': {n: hex(v) for n, v in exports.items()}, 'entrypoint': 0, 'TLS_directory_bytes': 0, 'normal_import_directory_bytes': 0, 'delay_import_directory_bytes': 0, 'section_comparison': sections, 'host_call_scope': 'Only the five exported pure policy functions are called. policy_ifr_insert operates on caller buffers; policy/form/question/inert checks and protection_for_variable use static data and memory/string comparisons. Firmware entry, UI, native OEM code, privileged helpers and UEFI service methods are not invoked on the host.'},
    'nonblocking_metadata_finding': {'location': 'ebs_candidate/full_regression/verify_history.py report verification_source_sha256', 'finding': 'Because __file__ intentionally remains the original test path, history_regression.json verification_source_sha256 records original template hashes rather than the executed adapted test/prefix. The summary separately pins original_test_sha256 and adapted_test_sha256 correctly, and this independent report binds both. Do not treat the standalone history field as the adapted-source hash.', 'impact': 'Metadata ambiguity only; it does not change the compiled image exercised or the test assertions. For standalone future consumption, use summary.json and this review, or explicitly relabel/add adapted-source metadata.', 'adapted_adapter_prefix_sha256': hashlib.sha256(prefix.encode('utf-8')).hexdigest()},
    'preservation': {'production_EFI_is_da52': True, 'production_sources_match_baseline_manifest': True, 'candidate_services_and_EFI_unchanged': True, 'EXP02_still_95a95856': True, 'tests_or_linking_rerun_by_reviewer': False},
    'limits': ['This review confirms path retargeting and evidence binding, not completeness of the six existing suites or correctness of every EBS lifecycle path.', 'The six counts are different suites of assertions/cases; no hardware acceptance, OEM full-browser behavior, real persistent NVRAM or successful firmware flash is inherited.', 'The EBS-specific83 cases and OVMF handoff coverage are separate evidence and were not rerun or recounted here.', 'Existing first-install ordering and partial failure recovery limits remain unresolved by this runner. No formal firmware release is approved or performed by this report.'],
    'review_binder': info(Path(__file__).resolve()),
}
target = HERE / 'ebs_full_regression_review.json'
target.write_text(json.dumps(review, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': review['status'], 'report': info(target)}, indent=2))
