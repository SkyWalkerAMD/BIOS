"""Review saved mode2/black-screen evidence, with no device interaction."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('frozen_snapshot_reviewer', HERE / 'review_snapshot.py')
R = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = R
spec.loader.exec_module(R)
HW = R.CASE / 'remote_172_20_2_162'
CAPTURE = HW / 'hardware-native13-ram-test05-1793710255493-6348c6d6'
PRIOR = HW / 'hardware-native13-ram-test05-1793710122082-b4174444'
sha, bound = R.sha, R.bound

def main():
    assert sha(R.DECODER) == 'f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
    decoder = R.import_file('incident_transport', R.DECODER)
    wrapper = R.import_file('incident_snapshot', R.WRAPPER)
    manifest = json.loads((CAPTURE / 'manifest.json').read_text())
    for name, digest in manifest['files'].items(): assert sha(CAPTURE / name) == digest
    frames, pages, attempts = [], [], []
    for p in sorted(CAPTURE.glob('page-[0-9][0-9].png')):
        frame = decoder.read_image(p)
        assert frame == p.with_suffix('.frame').read_bytes()
        info = decoder.parse_frame(frame)
        frames.append(frame)
        pages.append({**bound(p), 'frame': bound(p.with_suffix('.frame')), 'page': info['page'],
                      'offset': info['offset'], 'payload_bytes': len(info['data']), 'page_crc_checked': True})
    for p in sorted((CAPTURE / 'attempts').glob('*.png')):
        frame = decoder.read_image(p)
        info = decoder.parse_frame(frame)
        assert frame == p.with_suffix('.frame').read_bytes() == frames[info['page']-1]
        attempts.append(bound(p))
    raw, meta = decoder.assemble(frames, require_inventory=False)
    assert wrapper.validate(raw) == '0000000000000003'
    assert raw == (CAPTURE / 'hardware-log.txt').read_bytes()
    assert meta == {'pages': 3, 'bytes': 1901, 'crc32': '5086171C',
                    'sha256': '9777421d6aa15eb86fd9ba67a0fb76afb7796fa342a0309f6f13424e999d6fa9'}
    prior = (PRIOR / 'hardware-log.txt').read_bytes()
    assert hashlib.sha256(prior).hexdigest() == '07bd3c779114777b5b5ef50f8ed4030fc3712e6d8c8e3dda7fde1fb2dc88c6aa'
    old_body = prior.split(b'WatchdogDisableStatus=',1)[1].split(b'LOG_OVERFLOW=',1)[0]
    new_body = raw.split(b'WatchdogDisableStatus=',1)[1].split(b'LOG_OVERFLOW=',1)[0]
    assert new_body.startswith(old_body)
    lines = raw.decode('ascii').splitlines()
    assert 'MODE=0000000000000002' in lines and 'OPERATION_ID=0000000000000002' in lines
    assert not any(x.startswith('FAIL ') for x in lines)
    assert 'Warnings=0000000000000000' in lines
    operation = new_body[len(old_body):].decode('ascii').splitlines()
    expected = [
        'Operation=0000000000000002', 'ACTION=START_PASSWORD_NATIVE_TEST',
        'PASS complete OCMR values and attributes unchanged',
        'PASS complete memory values and attributes unchanged',
        'ProviderLoadImageStatus=0000000000000000',
        'PrepareResult=0000000000000000', 'InstallResult=0000000000000000',
        'ProviderStartImageStatus=0000000000000000', 'ProviderInitialFlags=0000000000000001',
        'PASS single resident provider attach',
    ]
    assert operation == expected
    assert 'ACTION=PASSWORD_MANAGEMENT' not in lines

    from PIL import Image
    visual = []
    for index in (310,311,312):
        p = HW / f'screen-{index}-current.png'
        with Image.open(p) as img:
            assert img.size == (1600,1200)
            crop = img.convert('RGB').crop((400,76,1200,676))
            assert crop.getextrema() == ((0,0),(0,0),(0,0))
            visual.append({**bound(p), 'screenshot_dimensions': list(img.size),
                           'visually_selected_kvm_rectangle': [400,76,1200,676],
                           'rectangle_dimensions': [800,600], 'all_480000_pixels_exact_rgb_zero': True})
    assert visual[-1]['sha256'] == '81535a5ce4f443d44f2f6bb19b3591ec30498b4c1b4ae60d6cdabc164a70eca6'
    key_path = HW / 'native-test09-key-1793710307009-155a60fe-result.json'
    key = json.loads(key_path.read_text())
    assert key['key'] == 'm' and key['key_sent'] is True and key['automatic_retry'] is False
    assert sha(HW / key['evidence']) == key['evidence_sha256']
    off_path = HW / 'ram-test09-off-1793710385549-d4ac21f1-result.json'
    off = json.loads(off_path.read_text())
    assert off['action'] == 'ForceOff' and off['status'] == 202 and off['automatic_retry'] is False
    assert off['powered_off_readback_pending'] is True
    assert off['evidence_sha256'] == visual[-1]['sha256']
    power_path = HW / 'manager-restart08-capability-1793710410787.json'
    power = json.loads(power_path.read_text())
    assert power['system']['status'] == 200 and power['system']['PowerState'] == 'Off'
    assert power['system']['BiosVersion'] == '1904'
    assert power['utc'] > off['utc']
    result = {
        'status': 'MODE2_ATTACH_REPORTED_PASS_MANAGEMENT_UI_BLACK_SCREEN_UNACCEPTED',
        'utc': datetime.now(timezone.utc).isoformat(), 'device_calls_by_reviewer': 0,
        'snapshot3': {**meta, 'snapshot_id': 3, 'mode': 2, 'operation_id': 2,
                      'prior_mode1_journal_preserved': True, 'new_operation_lines': expected},
        'accepted_narrow_result': 'The complete captured pre-M log reports successful provider LoadImage, 12-site prepare/install, StartImage and READY flags1. Both complete protected stores still matched the initial snapshots immediately before this attach. No warning is present in that pre-M snapshot.',
        'management_attempt': {
            'key_record': bound(key_path), 'utc': key['utc'], 'key': 'm', 'one_recorded_key_send': True,
            'observed_visuals': visual,
            'operator_report_separate_from_log': 'Parent reports one Escape after the black display and no password fixture creation, plaintext typing, enrollment or setting action. This is operator-session evidence, not a result encoded in snapshot3.',
            'application_management_return_log_available': False,
            'password_ui_accepted': False,
        },
        'power': {
            'forceoff_acceptance': bound(off_path), 'acceptance_utc': off['utc'], 'http_status': 202,
            'task_id': json.loads(off['body'])['Id'],
            'independent_later_redfish_readback': bound(power_path), 'readback_utc': power['utc'],
            'reported_power_state': 'Off', 'private_credential_cleanup_proven_by_poweroff': False,
        },
        'boundaries': [
            'Black KVM pixels do not identify CPU hold, processor exception, a browser hang, graphics-mode/rendering issue, or KVM transport behavior.',
            'The last complete QR precedes M. Its successful status cannot be extended to the management call, its return, cleanup, or any subsequent variable state.',
            'Absence of password typing does not by itself prove the OEM browser or provider performed zero variable writes. No post-M variable observation or complete log exists in this record.',
            'Power-off ends the RAM test execution but is not a credential deletion or proof of unchanged persistent firmware/configuration.',
            'A new read-only initial capture after restarting the original firmware is required to observe private credential absence and original module/target identity; that capture still cannot certify every SPI/NVRAM byte.',
            'Further M/password UI testing is not accepted by this evidence; diagnosis and a separately reviewed correction are needed before retrying the failed path.',
        ],
        'firmware_flash_approved': False, 'permanent_lock_accepted': False,
        'accepted_qr_pages': pages, 'qr_attempt_images': attempts,
        'bindings': [bound(CAPTURE/'manifest.json'), bound(CAPTURE/'hardware-log.txt'), bound(PRIOR/'hardware-log.txt'),
                     bound(R.DECODER), bound(R.WRAPPER), bound(HERE/'review_snapshot.py'), bound(Path(__file__))],
    }
    out = HERE / 'mode2_snapshot3_black_screen_review.json'
    assert not out.exists()
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'sha256': sha(out), 'capture_crc': meta['crc32'], 'later_redfish_off': power['utc']}))

if __name__ == '__main__': main()
