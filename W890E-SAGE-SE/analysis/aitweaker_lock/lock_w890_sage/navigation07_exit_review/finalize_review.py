"""Freeze the independent review without editing its frozen inputs."""
from pathlib import Path
import hashlib, json, sys
sys.dont_write_bytecode = True
H = Path(__file__).resolve().parent
B = H.parent
R = B.parents[2]
N = B / 'navigation07_exit'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p): return {'path': p.relative_to(R).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p)}
def load(p): return json.loads(p.read_text())
mf = N / 'component_manifest.json'
assert sha(mf) == '9eb0571832725a84601a7c6f33161553405af7899b6c761acbdda1296c8a5834'
m = load(mf)
for x in m['local_bindings'] + m['external_bindings']:
    assert bind(R / x['path']) == x
build = load(N / 'build/build.json')
for p, digest in build['sources'].items(): assert sha(R / p) == digest
test_rows = []
for name, script, count in [('tail_tests', 'verify_tail.py', 25), ('retry_tests', 'verify_retry.py', 2), ('caller_tests', 'verify_caller.py', 1)]:
    p = N / ('build/' + name + '.json'); j = load(p)
    assert j['component_sha256'] == m['component_sha256']
    assert j['source_sha256'] == sha(N / script)
    assert j['checks'] == count == len(j['cases']) and all(x['status'] == 'PASS' for x in j['cases'])
    if 'tail_fixture_sha256' in j: assert j['tail_fixture_sha256'] == sha(N / 'verify_tail.py')
    test_rows.append({'report': bind(p), 'cases': count, 'independently_rerun_all': False})
selected = load(H / 'selected_replay.json')
assert selected['component_sha256'] == m['component_sha256']
assert selected['review_script_sha256'] == sha(H / 'replay_selected.py')
finding = {
    'id': 'N07-REVIEW-01', 'classification': 'SCOPED_DEFENSIVE_CONTRACT_GAP',
    'source': bind(N / 'exit07.inc'), 'function': 'n07_fault_wait',
    'condition': 'Explicit non-normative fault injection calls the real no_end_boot during modeled RaiseTPL(31).',
    'actual_behavior': 'One cached RestoreTPL executes after revocation; return2 follows, without output, WaitForEvent, variable writes or GUI continuation.',
    'not_claimed': 'This does not establish that conforming RaiseTPL naturally dispatches EBS, nor an ordinary boot failure or authorization bypass.',
    'suggestion': 'In a new derivative, recheck recovery_services immediately after RaiseTPL and before RestoreTPL; separately audit inherited helpers if the same broad no-service-after-revocation guarantee is retained.',
    'frozen_input_unchanged': True,
    'author_response': 'Navigation author acknowledged the qualified observation and plans next-derivative hardening; nav07 remains frozen.'
}
report = {
    'status': 'INDEPENDENT_SCOPED_REVIEW_COMPLETE_PARTIAL_CANCELLATION_NOT_RELEASE',
    'reviewed_manifest': bind(mf), 'component': bind(N / 'build/W890NavigationExit07.TESTONLY.dll'),
    'validated_bindings': {'local': len(m['local_bindings']), 'external': len(m['external_bindings']), 'build_source_hashes': len(build['sources'])},
    'author_test_evidence': test_rows, 'independent_actual_pe_replay': bind(H / 'selected_replay.json'),
    'identity_findings': [
        'The exact inline CALL return, immutable consumer window, private live NO_LOOP frame/visit/epoch, actual stack anchor and repeated module/HII/native checks are required. No external owner=true authorizes cancellation.',
        'The original B8DC CALL, original prologue and new assembly are executed in the selected replay. BrowserLoop initialization/middle and surrounding objects remain explicit fixtures.',
        'The stack anchor is necessary inside the already private frame; it is not claimed as standalone physical ownership or resistance to arbitrary ring0 memory corruption.',
        'No cold installation, parser lifetime or foreign-HII authority follows from this test.'
    ],
    'state_and_abi_findings': [
        'At original1995F the only successful native request-state write is App+5A=0. Reset marker, current page, native input, exit protocol, bypass value and history metadata are preserved in the checked model.',
        'Saved RAX is replaced with App to reproduce the displaced original load. Other GPRs, all16 XMM registers, RSP/RBP and zero-compare flags are checked at196FF.',
        'The exact original input reset23378/read232DC executes to modeled fresh-event backend61FE4; complete render/input interaction is not executed.',
        'Before-write drift refuses mutation. After-RestoreTPL drift isolates the flow even if App+5A was already cleared; no rollback claim.',
        'The main dispatch rechecks service identity before RestoreTPL following cached validation failure/EBS. A separate fault-wait helper has the qualified hardening gap below.',
        'Raised BSP TPL is not AP/SMM exclusion and cannot make arbitrary external lifetime changes atomic.'
    ],
    'bypasses_and_release_limits': [
        'There is no normal-exit permission path, even for the bounded Main-only action4 proof; all covered valid exit requests are cancelled.',
        'Original196F7->19973 and initialization direct edges19240->19A76,1937E/19454->19994 bypass1995F. No claim of all-exit coverage.',
        'Later748C rejection is not adequate for GUI preservation because OEM/protocol/history/render teardown has already begun, and reset path ignores its result.',
        'Earlier save/default effects before App+5A are not undone by this cancellation.',
        'Foreign HII, complete teardown/callback/OEM/free/reset effects, whole BrowserLoop, real GUI, exact aggregate binding and hardware installation remain unproved.',
        'The FF25+pointer+NOP2 overlay is required by this candidate; a different aggregate branch encoding needs a separately verified layout contract.',
        'This is a TESTONLY DLL, not a flashable firmware or a release authorization.'
    ],
    'findings': [finding],
    'no_hardware_operations': True, 'no_frozen_inputs_modified': True
}
(H / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
readme = '''Independent review of navigation07_exit frozen manifest 9eb05718…5834.

All 48 local / 35 external bindings and all build source hashes match. The saved 25+2+1 actual-instruction reports bind this DLL and their current producers. Two selected positive/negative cases were independently executed with the declared original fixtures, and one extra non-normative fault injection reproduced a narrowly scoped RestoreTPL ordering gap in the fault-wait helper.

The new early guard can cancel its covered exit request before the tail teardown while retaining the checked native state and exact continuation ABI. It does not allow a normal exit, cover the direct bypass edges, prove the entire GUI, or make the firmware deployable. The original loop middle, outer objects, UEFI service model and input backend boundary remain explicit.

The fault-injection finding must not be reported as evidence that standard RaiseTPL dispatches EBS. The primary dispatch already checks the revocation boundary. Only a future derivative should change the frozen helper or wording.

See review.json and selected_replay.json for exact evidence and limits. No hardware, CAP generation or frozen input modification occurred.
'''
(H / 'README.txt').write_text(readme, encoding='utf-8')
external = [mf, N / 'build/W890NavigationExit07.TESTONLY.dll', B / 'hardware_delta07_review/component_manifest.json']
out = {'status': 'FROZEN_INDEPENDENT_SCOPED_REVIEW_NOT_RELEASE',
       'local_bindings': [bind(p) for p in sorted(H.iterdir()) if p.is_file() and p.name != 'component_manifest.json'],
       'external_bindings': [bind(p) for p in external]}
(H / 'component_manifest.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps({'report': bind(H / 'review.json'), 'manifest': bind(H / 'component_manifest.json')}))
