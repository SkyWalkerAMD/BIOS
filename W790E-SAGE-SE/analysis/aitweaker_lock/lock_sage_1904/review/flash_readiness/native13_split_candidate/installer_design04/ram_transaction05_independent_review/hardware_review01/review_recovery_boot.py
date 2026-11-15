"""Independent second-boot observation; does not reclassify the failed M call."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('frozen_capture_reader', HERE / 'review_snapshot.py')
R = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = R
spec.loader.exec_module(R)
HW = R.CASE / 'remote_172_20_2_162'
FIRST = HW / 'hardware-native13-ram-test05-1793709785752-8aced29c'
SECOND = HW / 'hardware-native13-ram-test05-1793710733660-6383ec06'
sha, bound = R.sha, R.bound

def main():
    assert sha(R.DECODER) == 'f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
    assert sha(R.WRAPPER) == 'a1cc79c0fc172f38990e8467acd96bcab801ca579322df1f7fbac2d027c395d0'
    dec = R.import_file('recovery_decoder', R.DECODER)
    wrap = R.import_file('recovery_wrapper', R.WRAPPER)
    manifest = json.loads((SECOND/'manifest.json').read_text())
    for name, digest in manifest['files'].items(): assert sha(SECOND/name) == digest
    frames, images, attempts = [], [], []
    for p in sorted(SECOND.glob('page-[0-9][0-9].png')):
        frame = dec.read_image(p)
        assert frame == p.with_suffix('.frame').read_bytes()
        old = FIRST/p.name
        assert sha(p) != sha(old)
        assert frame == old.with_suffix('.frame').read_bytes()
        frames.append(frame)
        images.append({**bound(p), 'original_png_sha256': sha(old),
                       'png_differs_from_first_boot': True, 'frame_identical_to_first_boot': True,
                       'frame': bound(p.with_suffix('.frame'))})
    for p in sorted((SECOND/'attempts').glob('*.png')):
        frame = dec.read_image(p)
        part = dec.parse_frame(frame)
        assert frame == p.with_suffix('.frame').read_bytes() == frames[part['page']-1]
        attempts.append(bound(p))
    raw, meta = dec.assemble(frames, require_inventory=False)
    assert wrap.validate(raw) == '0000000000000001'
    assert raw == (SECOND/'hardware-log.txt').read_bytes() == (FIRST/'hardware-log.txt').read_bytes()
    assert meta == {'pages': 2, 'bytes': 1168, 'crc32': '7DC729FE',
                    'sha256': '517ba5e82cf7ebed211cdbc47f222cb14a289ece6e28db964dabaa27d5afd2a4'}
    lines = raw.decode('ascii').splitlines()
    assert 'MODE=0000000000000000' in lines and 'OPERATION_ID=0000000000000000' in lines
    for line in ['PASS complete initial original identity and boot context', 'PASS initial private credential absent',
                 'PASS initial complete OCMR snapshot read only', 'PASS initial complete memory snapshot read only',
                 'Warnings=0000000000000000', 'LOG_OVERFLOW=NO', 'LOG_COMPLETE=YES']:
        assert line in lines
    assert not any(x.startswith('ACTION=') or x.startswith('FAIL ') for x in lines)
    key_path = HW/'native-test09-key-1793710722653-e7939e59-result.json'
    key = json.loads(key_path.read_text())
    assert key['key'] == 'q' and key['key_sent'] is True and key['observed_stage'] == 'SAGE_NATIVE13_RAM_TEST05_MAIN'
    assert sha(HW/key['evidence']) == key['evidence_sha256']
    off_path = HW/'inventory-poweroff-1793710780318.json'
    off = json.loads(off_path.read_text())
    assert off['result']['status'] == 200 and off['result']['data']['power_command'] == 0
    assert off['diagnostic']['total'] == 1168 and off['diagnostic']['crc'] == int('7DC729FE',16)
    readback_path = HW/'manager-restart08-capability-1793710805928.json'
    readback = json.loads(readback_path.read_text())
    assert readback['system']['status'] == 200 and readback['system']['PowerState'] == 'Off'
    assert readback['power']['status'] == 200 and readback['power']['data']['power_status'] == 0
    assert readback['utc'] > off['utc'] and readback['system']['BiosVersion'] == '1904'
    result = {
        'status': 'SECOND_BOOT_ORIGINAL_IDENTITY_AND_CURRENT_PRIVATE_ABSENCE_OBSERVED',
        'utc': datetime.now(timezone.utc).isoformat(), 'device_calls_by_reviewer': 0,
        'capture': str(SECOND), 'boot_instance': 'Second controlled boot after the M black-screen incident',
        'snapshot_id_within_this_boot': 1, 'mode': 0, 'operation_id': 0, **meta,
        'new_images_same_deterministic_log': images, 'attempt_images': attempts,
        'freshness_scope': 'New PNG files differ from first-boot PNGs, while decoded payloads are byte-identical. Distinct boot identity comes from the parent controlled reboot/BIOS314/F8/Q session chain; snapshot ID1 is local to this app boot and is not a global nonce.',
        'observations': [
            'The saved BIOS Main screen314 visibly shows Aptio Setup/AMI and BIOS Version1904 X64 after the earlier black-screen power-off.',
            'The new application initial log contains no installation or UI action. It reports complete original-module/12-window/boot-context identity accepted again and no warning.',
            'The private credential size-only query reports EFI_NOT_FOUND in the new boot: no residual private credential is observed at this point.',
            'Both protected OCMR/memory stores could be read completely again. These lines do not encode their values or cross-boot comparison hashes.',
            'A Q-only key action is separately recorded before the new capture. The parent reports no1/2/M in this second boot.',
        ],
        'power_off': {'request': bound(off_path), 'request_utc': off['utc'], 'native_command_ack_status': 200,
                      'later_readback': bound(readback_path), 'readback_utc': readback['utc'],
                      'redfish_power_state': 'Off', 'native_power_status': 0,
                      'cd_active_sessions_at_this_readback': readback['media']['cd_active_sessions'],
                      'media_detach_not_established_by_this_record': True},
        'not_established': [
            'No zero-write claim for the failed M call: current absence does not reconstruct every earlier variable transition.',
            'No all-SPI or all-NVRAM unchanged claim. The original loaded-code identity and selected windows are much narrower than a complete flash backup/comparison.',
            'No across-boot byte comparison of OCMR/memory values. Their old snapshots were volatile, and the log prints only read success.',
            'No successful password dialog, enrollment, authentication, cleanup flow, permanent direct-Del lock or firmware flash acceptance.',
            'The earlier M black screen remains a failed/unaccepted management path and must not be relabeled passed by this recovery observation.',
        ],
        'bindings': [bound(SECOND/'manifest.json'), bound(SECOND/'hardware-log.txt'), bound(FIRST/'hardware-log.txt'),
                     bound(HW/'screen-314-current.png'), bound(HW/'screen-314-current.json'), bound(key_path),
                     bound(R.DECODER), bound(R.WRAPPER), bound(Path(__file__))],
    }
    out = HERE/'second_boot_recovery_review.json'
    assert not out.exists()
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':result['status'],'sha256':sha(out),'off_readback_utc':readback['utc']}))

if __name__ == '__main__': main()
