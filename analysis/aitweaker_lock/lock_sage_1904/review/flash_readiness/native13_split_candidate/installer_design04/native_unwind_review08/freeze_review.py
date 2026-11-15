from pathlib import Path
import argparse, hashlib, json

HERE = Path(__file__).resolve().parent
D04 = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
HW = ROOT / 'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
MANIFEST = HERE / 'independent_manifest.json'

def item(path):
    raw = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}

def verify():
    manifest = json.loads(MANIFEST.read_text(encoding='utf8'))
    for expected in manifest['artifacts']:
        assert item(ROOT / expected['path']) == expected, expected['path']
    print(json.dumps({'status': 'PASS', 'bindings': len(manifest['artifacts']),
                      'manifest_sha256': item(MANIFEST)['sha256'],
                      'review_sha256': item(HERE / 'independent_review.json')['sha256']}))

def freeze():
    assert not MANIFEST.exists(), 'Frozen review must not be overwritten'
    original = D04.parent / 'boot_context/AMITSE.original.efi'
    assert item(original)['sha256'] == '531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
    proof = D04 / 'guard_blackout_review01/native_exit_counterexample.json'
    assert item(proof)['sha256'] == 'a20ca3d778f7d8a0b4c755b0aa888d87c49b1bac5e26b60e5dbe93ffe7b192dd'
    proof_json = json.loads(proof.read_text(encoding='utf8'))
    assert proof_json['checks'] == 30
    log = HW / 'hardware-native13-browser-baseline06-1793713512938-ce806332/hardware-log.txt'
    assert item(log)['sha256'] == '520ea66fc0965f1268df8b0a7ca8f9d4a4d1bc6119676814092e79643e962cee'
    physical_review = D04 / 'readonly_browser_baseline06_independent_review/hardware_review01/returned_snapshot2_review.json'
    assert item(physical_review)['sha256'] == 'dd669c3995ac34d9a37b5a1b654758ad975f2a03bd09e90d0898fd226f22b2ad'
    design = D04 / 'ram_transaction08/integration_design.json'
    report = {
        'status': 'NO_PROVEN_GENERAL_AUTOMATIC_UNWIND_LIMITED_INTEGRATION_TEST_DESIGN_ACCEPTABLE',
        'scope': 'Independent local exact-native disassembly and frozen prior fragment-test review; no hardware, no native firmware execution, no candidate edits.',
        'module': item(original),
        'integration_design': item(design),
        'new_runtime_tests': 0,
        'prior_fragment_tests_referenced_not_rerun': {'checks': 30, 'report': item(proof),
            'limits': 'Actual reset and ActionRequest decision instructions, with GUI teardown122C, reset notification and firmware services explicitly modeled. Not complete native cleanup execution.'},
        'findings': [
            {'id': 'NATIVE_EXIT_HELPER_IS_NOT_A_SAFE_UNWIND',
             'rvas': ['33080', '33086', '33093', '33099', '148A4', '148C4'],
             'evidence': ['escape_handler.asm.txt', 'discard_exit_helper.asm.txt'],
             'meaning': 'Native33080 with external93028 nonzero only sets app+5A=1. With external93028 zero it calls148A4, whose accepted path ANDs pending-reset83580 and calls13A1C. Neither is an independently safe read-only refusal path; automatic invocation is not proposed.'},
            {'id': 'EXIT_FLAG_RUNS_CALLBACK_AND_CLEANUP',
             'rvas': ['E91E', 'E925', 'E929', 'E936', 'E93B', 'E52D'],
             'evidence': ['loop_tail.asm.txt'],
             'meaning': 'app+5A nonzero invokes49E5C before jumping to cleanupE52D. It does not directly return to SendForm caller. Page-close behavior49E5C is not proved inert.'},
            {'id': 'TWO_INDEPENDENT_RESET_DECISIONS',
             'rvas': ['E56C', 'E57C', 'E5D5', 'E5E9', '213B5', '21412'],
             'meaning': 'Inner cleanup may ResetSystem when83580 nonzero and93028 null. Outer SendForm independently may reset when83580 nonzero and93038 null. ACCESS_DENIED or ABORTED does not veto these decisions. No reset flags or RuntimeServices entries are changed.'},
            {'id': 'TEARDOWN_INVOKES_LIFECYCLE_CALLBACKS',
             'rvas': ['122C', 'DB1C', 'DB55', 'DC01', '291D8', '292F5', '29020', '2911D'],
             'evidence': ['gui_release.asm.txt', 'gui_release_tail.asm.txt', 'lifecycle_close.asm.txt', 'lifecycle_callback_dispatch.asm.txt'],
             'meaning': 'GUI teardown may retain/reset native application flags or destroy the app, close events, free objects and dispatch FORM_CLOSE callbacks through284B4. Earlier pending-reset zero is not a proof of invariance through these callbacks. Full transitive cleanup/callback semantics remain unproved.'},
            {'id': 'GENERIC_ESC_FORWARDING_IS_TOO_BROAD',
             'rvas': ['12168', '18C2C', '18C9F'],
             'evidence': ['app_input.asm.txt', 'hotkey_dispatch.asm.txt'],
             'meaning': 'Native app input iterates runtime hotkey objects and dispatches their stored callbacks. Passing an unknown page through original input is not an ESC-only safe path without proving those runtime objects and their callbacks.'},
            {'id': 'NO_SAFE_PAGE_REMAINS_A_LIVENESS_GAP',
             'meaning': 'The new static classifier narrows known subtitle compatibility only. Unknown/protected pages with no verified safe Main can still suppress render/input/poll and fail to return. This is not accepted completed refusal behavior and not evidence of an unlock bypass.'}
        ],
        'physical_comparison': {
            'log': item(log), 'independent_qr_review': item(physical_review),
            'observed': 'Same frozen991B HII package with no provider/detours: original ASUS form visible and single ESC returned. Seven QR pages4911B/CCF8A98C; status0/action0, nine unsupported lifecycle callbacks, private absent and selected text/header/sites/stores checks unchanged.',
            'globals_before_and_after': {'app': '5B064698', 'stage': 7, 'pages': '5B0F3018', 'records': '5B0F3018', 'external93028': 0, 'pending83580': 0},
            'limits': 'Only boundary observations; no observation of internal93028/93038 or reset flags throughout cleanup. Return menu had prior QR background remnants, so complete visual restoration is not accepted. No guard/password or general zero-OEM-write claim.'
        },
        'integration_design_assessment': {
            'accepted_local_direction': 'Frozen2aef strict classifier + exact P14/TX08 rebinding, ActionRequestNONE and six bounded read-only native globals. No automatic app+5A writes/reset flag edits/RT replacements or relaxed unknown-page policy.',
            'next_limited_physical_stage_if_separately_reviewed': 'Exact final candidate/ISO review first. One M display -> native ESC -> Q, without entering or setting any password and without B original Setup navigation. Capture the returned diagnostics and check initial/private absence, original identity/stores and empty owned chains before considering any later stage.',
            'failure_recovery': 'If native return is absent, root may use the separately authorized BMC power-off and subsequent fresh read-only identity/private-absence check. Do not claim poweroff recovers uncollected volatile trace or proves absence of all intermediate side effects.',
            'not_authorization': 'This is an offline design assessment, not approval of an unfrozen binary or a device operation.',
            'later_stage_separation': 'Password set/verify/clear, protected native entries/B, direct Del/F2 boot integration and no-safe-page unwinding require separate evidence; a first management-form return does not accept them.'
        },
        'remaining_safe_unwind_proof': [
            'Complete49E5C page-close and122C/DB1C/291D8 lifecycle paths, including reachable callbacks and event tables.',
            'All native reset/save decisions across inner and parent SendForm context for the actual refused state, with context lifetime and reentry preserved.',
            'A narrowly implemented denial path that does not clear OEM reset state, replace RT services, grant unknown-page input, fabricate returns or bypass protected-store writes.',
            'Exact-byte negative tests plus a justified hardware stage; current fragment models and boundary logs do not supply this proof.'
        ],
        'release_ready': False,
        'device_actions': 0,
        'frozen_inputs_modified': False
    }
    (HERE / 'independent_review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    references = [original, proof, D04/'guard_blackout_review01/verify_native_exit.py',
        D04/'guard_blackout_review01/diagnostic_design.json',
        D04/'guard_blackout_review01/native_cleanup.asm.txt',
        D04/'guard_blackout_review01/native_gui_teardown.asm.txt',
        D04/'guard_blackout_review01/sendform_complete.asm.txt',
        D04/'guard_blackout_review01/native_events.asm.txt', log, physical_review, design,
        D04/'static_chrome_candidate07_independent_review/independent_review.json',
        D04/'static_chrome_candidate07_independent_review/independent_manifest.json',
        HW/'hardware-native13-browser-baseline06-1793713512938-ce806332/manifest.json',
        HW/'screen-342-current.png', HW/'screen-343-current.png']
    local = [p for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p != MANIFEST]
    artifacts = {row['path']: row for row in map(item, local+references)}
    MANIFEST.write_text(json.dumps({'path_base': 'workspace_root', 'artifacts': sorted(artifacts.values(), key=lambda row: row['path'])}, indent=2)+'\n', encoding='utf8')
    verify()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    verify() if args.verify_only else freeze()
