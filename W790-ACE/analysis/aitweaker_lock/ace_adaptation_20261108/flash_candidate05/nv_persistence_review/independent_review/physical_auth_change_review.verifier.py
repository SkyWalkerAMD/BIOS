"""Validate local physical QR receipts without accessing BMC or secret state.

Draft by default. Optional later receipt paths are explicitly supplied; never
discover or read credential/session/operation files. Existing reviews/media are
read only. Stage2 counters are cumulative and are never added to preflight.
"""
from pathlib import Path
import argparse, datetime, hashlib, json, sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent; NV = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import read_image, assemble, parse_frame

BMC = NV.parent / 'bmc_nv05'
PIN = '71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98'
S1_SHA = 'a47b5a24e3cd978e895bac63e40cf2095d535098e752b474457cf481d2cfe54b'
S2_SHA = '8829b116128fb99722dfa9566fbc37904359a00ef6b020fd74746921f3ae6c91'
RECORD_SHA = 'c1d706f63848951af3c28e6378d719ea6ebd509adabb69a700060be84ae57379'
AUTH_SHA = '0aa17cac9c4f84c5216a6d8ba80fc86680956e299ca766d9e47d124865079e4b'
CHANGED_LOG_SHA = 'e5795ab4c662754d83181319007b85b6aab42c7d1f0efadd85079d1a3ec8f4c7'
CHANGED_RECORD_SHA = '367c4405567649660ddae1b10d937b5aa8849655ecb23740d583d9a312ede245'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
bindings = {}
def bind(p):
    p = Path(p).resolve(); digest = sha(p); bindings[str(p.relative_to(ROOT))] = digest; return digest
def load(p):
    bind(p); return json.loads(Path(p).read_text(encoding='utf8'))
def fields(raw):
    out = {}
    for line in raw.decode('ascii').replace('\r\n', '\n').splitlines():
        if '=' in line:
            k, v = line.split('=', 1); out.setdefault(k, []).append(v)
    return out
def one(f, key):
    assert len(f[key]) == 1, key
    return f[key][0]
def integer(f, key): return int(one(f, key), 0)

def receipt(folder, expected_stage, expected_sha=None):
    folder = Path(folder).resolve()
    # Scope constrained to the local hardware evidence collection named by root.
    assert folder.is_relative_to(BMC.resolve()), str(folder)
    m = load(folder / 'manifest.json'); log = folder / 'hardware-log.txt'
    raw = log.read_bytes(); digest = bind(log)
    if expected_sha: assert digest == expected_sha
    assert m['stage'] == expected_stage and digest == m['transport']['sha256']
    frames = []; shots = []
    for item in m['screenshots']:
        p = Path(item['file']).resolve(); assert p.is_relative_to(BMC.resolve())
        assert bind(p) == item['sha256']
        frame = read_image(p); parsed = parse_frame(frame); frames.append(frame)
        shots.append({'path': str(p.relative_to(ROOT)), 'sha256': item['sha256'], 'page': parsed['page']})
    decoded, transport = assemble(frames)
    assert decoded == raw and transport == m['transport']
    assert sorted(s['page'] for s in shots) == list(range(1, transport['pages'] + 1))
    build_path = NV / ('stage' + str(expected_stage)) / 'build/build.json'
    build = load(build_path)
    assert m['build_manifest_sha256'] == sha(build_path)
    for key in ['efi_sha256', 'iso_sha256', 'source_bundle_sha256']: assert m[key] == build[key]
    assert bind(Path(build['efi_path'])) == build['efi_sha256']
    assert bind(Path(build['iso_path'])) == build['iso_sha256']
    f = fields(raw)
    assert one(f, 'DriverSHA256') == PIN and one(f, 'SourceBundleSHA256') == build['source_bundle_sha256']
    assert integer(f, 'Stage') == expected_stage and integer(f, 'Failures') == 0 and integer(f, 'Fault') == 0
    assert one(f, 'Owner') == 'ISOLATED_CONSOLE_ADAPTER' and one(f, 'AMITSE_SendForm') == 'NOT_CALLED'
    if expected_stage == 2: assert one(f, 'Phase1ReceiptLogSHA256') == S1_SHA
    summary = {'folder': str(folder.relative_to(ROOT)), 'manifest_sha256': sha(folder / 'manifest.json'),
               'log_sha256': digest, 'transport': transport, 'screenshots': shots,
               'efi_sha256': build['efi_sha256'], 'iso_sha256': build['iso_sha256'],
               'independently_decoded_exact': True,
               'final_scalar_fields': {key: values[0] for key, values in f.items() if len(values) == 1},
               'logged_authentication_results': f.get('UnlockResult', []),
               'logged_unlocked_after': f.get('UnlockedAfter', []),
               'logged_management_results': {'SetOrChangeResult': f.get('SetOrChangeResult', []), 'ClearResult': f.get('ClearResult', [])},
               'within_session_unchanged_check_lines': raw.count(b'PASS OC/memory variable metadata and SHA256 unchanged\r\n'),
               'checks_are_cumulative_in_this_log': True}
    return summary, f

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cleanup-folder', type=Path)
parser.add_argument('--expected-cleanup-sha')
parser.add_argument('--absence-preflight-folder', type=Path)
parser.add_argument('--expected-absence-sha')
parser.add_argument('--output', type=Path, default=HERE / 'physical_evidence_draft.json')
args = parser.parse_args()
if bool(args.cleanup_folder) != bool(args.expected_cleanup_sha): parser.error('Cleanup requires explicit folder and log SHA together')
if bool(args.absence_preflight_folder) != bool(args.expected_absence_sha): parser.error('Absence requires explicit folder and log SHA together')

s1, f1 = receipt(BMC / 'stage1-receipt', 1, S1_SHA)
s2, f2 = receipt(BMC / 'stage2-preflight', 2, S2_SHA)
auth, fauth = receipt(BMC / 'stage2-auth-relock', 2, AUTH_SHA)
changed, fchanged = receipt(BMC / 'stage2-changed', 2, CHANGED_LOG_SHA)
for f in [f1, f2]:
    assert one(f, 'CredentialSHA256') == RECORD_SHA
    assert integer(f, 'CredentialGeneration') == 1 and integer(f, 'CredentialAttributes') == 3 and integer(f, 'CredentialBytes') == 128
assert integer(f1, 'Checks') == 14 and integer(f1, 'AcceptedWrites') == integer(f1, 'NativeSetAttempts') == 1
assert one(f1, 'Phase1Receipt') == 'COMMITTED_EXACT_READBACK'
assert integer(f1, 'CoreActive') == integer(f1, 'CoreUnlocked') == integer(f1, 'ConsoleOwnerActive') == 0
assert integer(f2, 'Checks') == 10 and integer(f2, 'AcceptedWrites') == integer(f2, 'NativeSetAttempts') == 0
assert integer(f2, 'CredentialMode') == integer(f2, 'CoreActive') == integer(f2, 'ConsoleOwnerActive') == 1
assert integer(f2, 'CoreUnlocked') == 0
auth_sequence = ['0x0000000000000000', '0x0000000000000000', '0x0000000000000001', '0x0000000000000001']
assert fauth['UnlockResult'] == fauth['UnlockedAfter'] == auth_sequence
for key, value in {'Checks': 23, 'NativeSetAttempts': 0, 'AcceptedWrites': 0, 'CoreUnlocked': 0,
                   'CredentialGeneration': 1, 'ConsoleSessions': 2, 'CoreActive': 1}.items():
    assert integer(fauth, key) == value, key
assert one(fauth, 'CredentialSHA256') == RECORD_SHA
assert fchanged['UnlockResult'] == fchanged['UnlockedAfter'] == auth_sequence
assert fchanged.get('SetOrChangeResult') == ['0x0000000000000001']
for key, value in {'Checks': 27, 'NativeSetAttempts': 1, 'AcceptedWrites': 1, 'CoreUnlocked': 0,
                   'CredentialGeneration': 2, 'CredentialAttributes': 3, 'CredentialBytes': 128}.items():
    assert integer(fchanged, key) == value, key
assert one(fchanged, 'CredentialSHA256') == CHANGED_RECORD_SHA

# These screenshots were manually inspected with view_image. Keep direct
# visual observations distinct from the operator's secret-slot/action labels.
visual_notes = {
    29: 'Password prompt contains one masked character before the intended test input; reported by operator as a carried menu key.',
    32: 'Password prompt again contains one masked character; the character value cannot be recovered from this screenshot.',
    35: 'Password prompt is visibly empty after operator Backspace correction, before the successful enrollment-password attempt.',
    57: 'Post-change password prompt is visibly empty before operator submission of the old password.',
    58: 'Post-change prompt shows masked input and Password was not accepted. No change was authorized.',
    60: 'Post-change password prompt is visibly empty before operator submission of the replacement password.',
    61: 'Maintenance menu is displayed after that submission; menu alone does not distinguish success from cancellation.'
}
visuals = []
for number, note in visual_notes.items():
    path = BMC / ('screen-' + str(number) + '-nv-console.png')
    visuals.append({'path': str(path.relative_to(ROOT)), 'sha256': bind(path), 'manually_viewed': True, 'observation': note})

off_path = BMC / 'power-1794111095994.json'; confirm_path = BMC / 'browser-read-20.json'; on_path = BMC / 'power-1794111344388.json'
off, confirm, on = [load(p) for p in [off_path, confirm_path, on_path]]
assert off['command'] == 5 and off['before']['data']['power_status'] == 1 and off['result']['status'] == 200
assert confirm['path'] == '/api/chassis-status' and confirm['status'] == 200 and confirm['data']['power_status'] == 0
assert on['command'] == 1 and on['before']['status'] == 200 and on['before']['data']['power_status'] == 0 and on['result']['status'] == 200
parse_time = lambda s: datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
interval = (parse_time(on['utc']) - parse_time(off['utc'])).total_seconds()
assert interval > 0

cleanup = None; absence = None
if args.cleanup_folder:
    cleanup, fc = receipt(args.cleanup_folder, 2, args.expected_cleanup_sha)
    for key, value in {'CredentialAttributes': 0, 'CredentialBytes': 0, 'OwnershipKnown': 0, 'CleanupDeleteAttempts': 1,
                       'CleanupRestoredAbsence': 1, 'CoreActive': 0, 'CoreUnlocked': 0, 'ConsoleOwnerActive': 0,
                       'CredentialMode': 2, 'CredentialGeneration': 3, 'AcceptedWrites': 2, 'NativeSetAttempts': 2,
                       'LastNativeSetStatus': 0, 'LastNativeGetStatus': 0x800000000000000e}.items():
        assert integer(fc, key) == value, key
    assert one(fc, 'CredentialSHA256') == '0' * 64
    assert fc.get('SetOrChangeResult') == ['0x0000000000000001']
    assert fc.get('ClearResult') == ['0x0000000000000001']
    assert fc.get('UnlockResult', [])[:4] == auth_sequence
    assert fc.get('UnlockResult', [])[4:6] == ['0x0000000000000000', '0x0000000000000001']
    assert cleanup['within_session_unchanged_check_lines'] > 0
if args.absence_preflight_folder:
    absence, fa = receipt(args.absence_preflight_folder, 1, args.expected_absence_sha)
    for key, value in {'CredentialMode': 0, 'CredentialBytes': 0, 'CredentialAttributes': 0,
                       'NativeSetAttempts': 0, 'AcceptedWrites': 0, 'CleanupDeleteAttempts': 0}.items():
        assert integer(fa, key) == value, key
    assert 'Phase1Receipt' not in fa

report = {'status': 'DRAFT_HOST_OFF_ON_RELOAD_VERIFIED_AWAITING_CLEANUP' if cleanup is None else
                    'PHYSICAL_CLEANUP_READBACK_VERIFIED_AWAITING_POST_CLEANUP_OFF_ON_BINDING',
          'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'scope': 'Dedicated password variable, isolated console owner, unchanged production05 password/services/UI objects.',
          'phase1': s1, 'phase2_off_on_preflight': s2, 'phase2_auth_and_new_session': auth,
          'phase2_changed': changed, 'cleanup': cleanup, 'later_absence_preflight': absence,
          'power_cycle': {'shutdown_request_utc': off['utc'], 'shutdown_request': 'ACPI orderly shutdown command5 accepted',
                          'off_confirmed_by_local_get': str(confirm_path.relative_to(ROOT)),
                          'power_on_request_utc': on['utc'], 'power_on_before_state': 'Off',
                          'request_to_request_seconds': interval, 'claim': 'Host Off -> On, not AC power removal',
                          'continuous_off_duration_measured': False},
          'verified_now': ['One exact gen1 128-byte credential committed by stage1 and read back successfully.',
                           'After confirmed host Off and subsequent On, stage2 loads the same hash without any new credential write.',
                           'The new console owner begins active but locked; no unlock grant persists across this host power cycle.',
                           'The stage2 authentication log records results 0,0,1,1 with zero native writes, followed by a new locked console session.',
                           'A successful management action commits one generation2 record with a changed hash, attrs3/128B, and leaves the owner locked.'],
          'pending': (['Final stage2 cleanup receipt'] if cleanup is None else []) +
                     ['Post-cleanup Off -> On evidence for durable absence',
                      'Final cumulative authentication outcomes must corroborate the observed post-change old/new password screen sequence.' if cleanup is None else
                      'No further console-authentication evidence required for the observed planned sequence.'],
          'ui_observations': visuals,
          'input_residual': {'disclosed': True, 'screens': [29, 32, 35],
                             'observation': 'One masked character was already present on two authentication prompts. Operator cleared it with Backspace and confirmed the empty prompt before the correct attempt.',
                             'attribution': 'Operator reports carry-over from the U menu key; screenshots prove presence/removal, not the exact injected byte or firmware source.',
                             'claim': 'This is retained as a KVM/input-path observation, not diagnosed as a password-core failure. The first negative attempt may include that extra character.'},
          'operator_action_labels': {'auth_0_0_1_1': ['wrong input', 'cancel', 'correct enrollment password', 'same-session grant reuse'],
                                     'post_change_screens_57_58_60_61': ['empty old-password prompt', 'old-password refusal', 'empty replacement-password prompt', 'return after replacement-password input'],
                                     'provenance': 'Parent supplied action/slot labels; reviewer did not access secret values. Numeric outcomes and state/hash changes are independently verified from QR logs.'},
          'oc_memory_claim': 'Each boot checks against its own in-memory baseline. Actual baseline hashes are not printed, so no cross-boot OC/memory equality is inferred.',
          'counting': 'Phase1 final14 and phase2 preflight10 are distinct receipts. Later phase2 counters/log lines are cumulative and are not added as new independent tests.',
          'limits': ['This is not AC power removal or a measured full discharge.',
                     'This is not permanent-DXE/native SendForm integration, complete Setup-save acceptance or whole-SPI/NVRAM rollback.',
                     'Parent performed live hardware operations. This reviewer reads only named local evidence and does not access BMC or runner memory.'],
          'input_bindings': bindings, 'script_sha256': sha(Path(__file__)), 'existing_reports_or_media_modified': False,
          'hardware_access_by_reviewer': False, 'credential_values_read': False}
assert all(sha(ROOT / path) == digest for path, digest in bindings.items())
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'sha256': sha(args.output), 'output': str(args.output), 'receipt_count': 4 + bool(cleanup) + bool(absence)}))
