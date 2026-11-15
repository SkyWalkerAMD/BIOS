"""Independently decode captured PNGs; never control a device or edit evidence."""
import hashlib
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
OWN = HERE.parent
CASE = OWN.parents[4]
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
DECODER = ROOT / 'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py'
WRAPPER = CASE / 'remote_172_20_2_162/read_native13_ram_test05_qr.py'
EXPECTED_EFI = '9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'
EXPECTED_ISO = 'aca8533281df2d2432881a28441143baf104bc3655bc3309620c76055251ae78'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def bound(p): return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}
def import_file(name, p):
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

def main():
    if len(sys.argv) not in (3, 4) or sys.argv[1] not in ('initial', 'mode1'):
        raise SystemExit('Usage: review_snapshot.py initial|mode1 CAPTURE_DIR [INITIAL_CAPTURE_DIR]')
    stage, capture = sys.argv[1], Path(sys.argv[2]).resolve()
    assert capture.is_relative_to(CASE / 'remote_172_20_2_162')
    assert sha(DECODER) == 'f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
    assert sha(WRAPPER) == 'a1cc79c0fc172f38990e8467acd96bcab801ca579322df1f7fbac2d027c395d0'
    decoder = import_file('independent_live_decoder', DECODER)
    wrapper = import_file('independent_live_wrapper', WRAPPER)
    manifest = json.loads((capture / 'manifest.json').read_text())
    for name, digest in manifest['files'].items():
        assert sha(capture / name) == digest, name
    pngs = sorted(capture.glob('page-[0-9][0-9].png'))
    assert pngs and len(pngs) == manifest['pages']
    frames, pages, attempts = [], [], []
    for p in pngs:
        raw = decoder.read_image(p)
        assert raw == p.with_suffix('.frame').read_bytes(), p.name
        part = decoder.parse_frame(raw)
        pages.append({**bound(p), 'frame': bound(p.with_suffix('.frame')),
                      'page': part['page'], 'offset': part['offset'], 'payload_bytes': len(part['data']),
                      'decoded_png_equals_saved_frame': True, 'page_crc_checked': True})
        frames.append(raw)
    for p in sorted((capture / 'attempts').glob('*.png')):
        raw = decoder.read_image(p)
        assert raw == p.with_suffix('.frame').read_bytes()
        info = decoder.parse_frame(raw)
        assert raw == frames[info['page']-1]
        attempts.append({**bound(p), 'same_as_accepted_page': info['page']})
    raw, meta = decoder.assemble(frames, require_inventory=False)
    snapshot = wrapper.validate(raw)
    assert raw == (capture / 'hardware-log.txt').read_bytes()
    for key in ('pages', 'bytes', 'crc32', 'sha256'):
        assert meta[key] == manifest[key], key
    assert snapshot == manifest['snapshot_id']
    text = raw.decode('ascii')
    lines = text.splitlines()
    for prefix in ('SNAPSHOT_ID=', 'MODE=', 'OPERATION_ID=', 'Warnings=', 'LOG_OVERFLOW=', 'LOG_COMPLETE='):
        assert sum(line.startswith(prefix) for line in lines) == 1, prefix
    def value(name):
        hits = [line.split('=', 1)[1] for line in lines if line.startswith(name + '=')]
        assert len(hits) == 1, name
        return hits[0]
    required_initial = [
        'WatchdogDisableStatus=0000000000000000',
        'PASS exact SAGE SE 1904 SMBIOS',
        'AMITSECount=0000000000000001', 'SetupCount=0000000000000001',
        'ENTRY_BOUND=EXACT_CORE_AMITSE_BOOT_CALL_RETURN',
        'OriginalSetupHiiMatches=0000000000000001',
        'OriginalWritableSupervisorCodePages=0000000000000008',
        'PASS complete initial original identity and boot context',
        'PASS initial private credential absent',
        'PASS initial complete OCMR snapshot read only',
        'PASS initial complete memory snapshot read only',
        'LOG_OVERFLOW=NO', 'LOG_COMPLETE=YES', 'Warnings=0000000000000000',
        'BROWSER_ABSENCE_PROOF=NO', 'BSP_TPL_TRANSACTION_PREMISE=YES',
    ]
    assert all(line in lines for line in required_initial)
    assert not any(line.startswith('FAIL ') for line in lines)
    assert int(value('EntryOuterReturnRVA'), 16) in (0x2d7d, 0x960c)
    assert all(0 < int(value(name), 16) < (1<<47) and int(value(name), 16) % 4096 == 0
               for name in ('AMITSEBase', 'SetupBase'))
    checks = ['All captured accepted and attempt PNGs independently decoded to exact saved frames.',
              'Each chunk CRC, pagination bounds, whole-log CRC/length/SHA and complete snapshot markers agree.',
              'Exact board/version, unique original modules/HII, pinned launch caller and eight writable supervisor code pages reported accepted.',
              'Watchdog disable, initial credential absence and complete two protected-store snapshots reported successful; no FAIL or warnings.']
    if stage == 'initial':
        assert snapshot == '0000000000000001'
        assert value('MODE') == value('OPERATION_ID') == '0000000000000000'
        assert not any(line.startswith('ACTION=') or line.startswith('InstallResult=') for line in lines)
        verdict = 'INITIAL_PHYSICAL_PREFLIGHT_PASSES_MODE1_PREREQUISITES'
        permits = 'Proceed only to the reviewed mode1 install/check/rollback action; this capture contains no transaction result.'
        mode1_pass = False
        mode2_condition = 'Not accepted by the initial snapshot alone; require mode1 exact restoration evidence first.'
    else:
        assert len(sys.argv) == 4
        initial = Path(sys.argv[3]).resolve()
        initial_raw = (initial / 'hardware-log.txt').read_bytes()
        assert hashlib.sha256(initial_raw).hexdigest() == '517ba5e82cf7ebed211cdbc47f222cb14a289ece6e28db964dabaa27d5afd2a4'
        old_journal = initial_raw.split(b'WatchdogDisableStatus=',1)[1].split(b'LOG_OVERFLOW=',1)[0]
        new_journal = raw.split(b'WatchdogDisableStatus=',1)[1].split(b'LOG_OVERFLOW=',1)[0]
        assert new_journal.startswith(old_journal)
        assert int(snapshot,16) > 1 and value('MODE') == '0000000000000001'
        assert value('OPERATION_ID') == '0000000000000001'
        required = [
            'Operation=0000000000000001', 'ACTION=INSTALL_CHECK_ROLLBACK',
            'PrepareResult=0000000000000000', 'InstallResult=0000000000000000',
            'ALL_12_ORIGINAL_SITES_RESTORED',
            'ALL_PUBLISHED_ALLOCATION_LIFETIMES=UNTIL_POWER_OFF',
            'PASS mode1 exact twelve-site restoration',
            'MODE1_PROVIDER_STARTED=NO', 'MODE1_PASSWORD_WRITES=NO',
            'MODE1_RESULT_DOES_NOT_ACCEPT_MODE2',
        ]
        assert all(lines.count(line) == 1 for line in required)
        assert not any('ProviderStartImageStatus=' in line or line == 'ACTION=START_PASSWORD_NATIVE_TEST' for line in lines)
        checks.extend(['Mode1 extends the exact initial journal without changing its contents.',
                       'Prepare and install returned TX_OK; the code-bound complete original-site rollback check reports success.',
                       'Provider was not started, mode1 password writes are explicitly absent, and no warnings/failure is present.'])
        verdict = 'MODE1_PHYSICAL_INSTALL_AND_EXACT_ROLLBACK_REPORTED_PASS'
        permits = 'Mode2 may proceed under its separate approved temporary-private-credential scope after returning to the resident menu; the application must freshly compare the original protected stores before installing again.'
        mode1_pass = True
        mode2_condition = 'Prerequisites satisfied for attempting mode2, not a password/UI result. Initial credential was absent; mode1 did not start the provider or write it. Fresh mode2 store comparison and later exact credential cleanup remain required.'
    local = json.loads((OWN / 'independent_review.json').read_text())
    assert local['efi_sha256'] == EXPECTED_EFI and local['iso_sha256'] == EXPECTED_ISO
    result = {
        'status': verdict, 'utc': datetime.now(timezone.utc).isoformat(),
        'capture': str(capture), 'stage': stage, 'snapshot_id': snapshot, **meta,
        'device_calls_by_reviewer': 0, 'source_evidence_modified': False,
        'candidate_efi_sha256': EXPECTED_EFI, 'candidate_iso_sha256': EXPECTED_ISO,
        'candidate_identity_scope': 'Candidate selection/boot hash is supplied by the parent controlled-session chain and frozen local package; the QR log itself does not contain a self-measured EFI/ISO SHA.',
        'checked_facts': checks, 'next_action_scope': permits,
        'mode1_result_accepted': mode1_pass, 'mode2_prerequisites': mode2_condition,
        'password_ui_accepted': False, 'permanent_direct_del_lock_accepted': False, 'firmware_flash_approved': False,
        'limits': [
            'This is an independent reconstruction and semantic audit of recorded hardware output, not an additional read of physical memory/registers.',
            'Eight page permissions and a recognized call frame do not prove absence of an already-active outer browser or quiescence of APs/SMM; the exact recorded BSP/TPL premise remains.',
            'Two complete protected-variable snapshots do not prove that every OEM NVRAM variable was untouched.',
            'Mode1 never establishes password persistence, UI correctness, cold-boot permanent protection, or firmware update/recovery readiness.',
            'If the app enters CPU hold, use the separately reviewed bounded ForceOff path; QR is unavailable in that state and power-off does not restore a private credential.',
        ],
        'accepted_pages': pages, 'attempt_images': attempts,
        'bindings': [bound(capture / 'manifest.json'), bound(capture / 'hardware-log.txt'), bound(DECODER), bound(WRAPPER), bound(OWN / 'independent_review.json'), bound(Path(__file__))],
    }
    output = HERE / (stage + '_' + snapshot + '_review.json')
    assert not output.exists(), 'Never overwrite a frozen hardware review; create a new stage/version if evidence changes.'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': verdict, 'report': str(output), 'sha256': sha(output), 'pages': meta['pages'], 'bytes': meta['bytes'], 'crc32': meta['crc32']}))

if __name__ == '__main__': main()
