"""Retarget existing compiled tests to the isolated EBS candidate, without rebuilding it.

Only artifact/report paths and the old hardware-specific identity assertion are
adapted. Original test assertions and fixtures remain intact; no hardware result
is inherited by the newly linked image.
"""
from pathlib import Path
import contextlib
import hashlib
import io
import json
import sys

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[2]
DRIVER = CASE / 'driver'
OUT = HERE / 'full_regression'
OUT.mkdir(exist_ok=True)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

candidate = read(HERE / 'build/build.json')
baseline = read(DRIVER / 'build/build.json')
assert sha(HERE / 'build/AiTweakerLock1904.efi') == candidate['candidate_driver_sha256']
assert sha(DRIVER / 'build/AiTweakerLock1904.efi') == candidate['baseline_driver_sha256'] == baseline['efi_sha256']
assert sha(HERE / 'services.c') == candidate['candidate_source_sha256']
assert all(sha(CASE / name) == digest for name, digest in candidate['object_sha256'].items())
assert all(sha(CASE / name) == digest for name, digest in baseline['sources'].items())
sources = {name.replace('\\', '/'): digest for name, digest in baseline['sources'].items()}
del sources['driver/services.c']
sources['review/flash_readiness/ebs_candidate/services.c'] = candidate['candidate_source_sha256']
build_context = {**candidate, 'sources': sources, 'external_sources': baseline['external_sources']}
(OUT / 'build_context.json').write_text(json.dumps(build_context, indent=2) + '\n', encoding='utf-8')

def adapt_paths(source):
    return source.replace("HERE/'build/", "CANDIDATE/'build/").replace("HERE/'build'", "CANDIDATE/'build'")

tests = [
    ('verify_adapter.py', 'adapter_emulation.json'),
    ('verify_identity.py', 'identity_test.json'),
    ('verify_entropy.py', 'entropy_test.json'),
    ('verify_hii_abi.py', 'hii_abi_test.json'),
    ('verify_policy.py', 'policy_test.json'),
    ('verify_history.py', 'history_regression.json'),
]
results = []
for name, report_name in tests:
    path = DRIVER / name
    original = path.read_text(encoding='utf-8')
    source = adapt_paths(original)
    if name == 'verify_policy.py':
        old = "str(OUT/(x+'.obj'))"
        assert old in source
        source = source.replace(old, "str((CANDIDATE/'build' if x=='services' else HERE/'build')/(x+'.obj'))")
    if name == 'verify_history.py':
        old = "build=json.loads((CANDIDATE/'build/build.json').read_text(encoding='utf8'))"
        assert old in source
        source = source.replace(old, 'build=CANDIDATE_BUILD_CONTEXT')
        old = "assert sha(CANDIDATE/'build/AiTweakerLock1904.efi')==build['efi_sha256']==HARDWARE_DRIVER_SHA"
        assert old in source
        source = source.replace(old, "assert sha(CANDIDATE/'build/AiTweakerLock1904.efi')==build['candidate_driver_sha256']\nassert build['baseline_driver_sha256']==HARDWARE_DRIVER_SHA")
        old = "ns={'__file__':str(DRIVER/'verify_adapter.py')};"
        assert old in source
        source = source.replace(old, "prefix=ADAPT_PATHS(prefix)\nns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':CANDIDATE};")
    adapted = OUT / name
    adapted.write_text(source, encoding='utf-8')
    namespace = {'__file__': str(path), '__name__': '__main__', 'CANDIDATE': HERE,
                 'CANDIDATE_BUILD_CONTEXT': build_context, 'ADAPT_PATHS': adapt_paths}
    old_argv = sys.argv
    sys.argv = [str(path)]
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            exec(compile(source, str(adapted), 'exec'), namespace)
    finally:
        sys.argv = old_argv
    result_path = HERE / 'build' / report_name
    result = read(result_path)
    assert result.get('status') == 'PASS' or result.get('passed') is True
    assert result.get('driver_sha256', result.get('driver_efi_sha256')) == candidate['candidate_driver_sha256']
    count = result.get('cases', result.get('assertions', result.get('checks')))
    count = len(count) if isinstance(count, list) else count
    results.append({'test': name, 'checks_or_cases': count, 'status': 'PASS',
                    'original_test_sha256': sha(path), 'adapted_test_sha256': sha(adapted),
                    'report': str(result_path), 'report_sha256': sha(result_path)})
    print(json.dumps({'test': name, 'status': 'PASS', 'checks_or_cases': count}))
assert sha(DRIVER / 'build/AiTweakerLock1904.efi') == candidate['baseline_driver_sha256']
summary = {'status': 'PASS_SIX_EXISTING_COMPILED_REGRESSION_SUITES_ON_ISOLATED_CANDIDATE',
           'candidate_driver_sha256': candidate['candidate_driver_sha256'],
           'candidate_build_manifest_sha256': sha(HERE / 'build/build.json'),
           'build_context_sha256': sha(OUT / 'build_context.json'),
           'runner_sha256': sha(Path(__file__)), 'hardware_acceptance_inherited': False,
           'tests': results,
           'limits': ['These are the original six local regression suites, with their explicit firmware/UI stubs unchanged.',
                      'Not a full firmware boot, real NVRAM persistence test, complete OEM browser or hardware acceptance.',
                      'The EBS-specific 83 cases and OVMF handoff tests remain separately reported, not counted again here.',
                      'First-install ordering and failure recovery are not repaired by these path retargetings.']}
(OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': summary['status'], 'candidate_driver_sha256': candidate['candidate_driver_sha256']}))
