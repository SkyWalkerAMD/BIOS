"""Close the curated evidence index only after observed host/session cleanup."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HW = HERE / 'bmc_hardware03'


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def ref(path):
    return {'path': path.relative_to(ROOT).as_posix(),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def values(text, key):
    return [int(v, 16) for v in re.findall(r'^' + re.escape(key) + r'=0x([0-9A-F]+)\r?$', text, re.M)]


def log_record(folder, revision, driver):
    path = HW / folder / 'hardware-log.txt'
    data = path.read_bytes()
    text = data.decode('utf8')
    manifest_path = path.with_name('manifest.json')
    manifest = read(manifest_path)
    assert 'ACE1904-' + revision + '-RAM' in text
    assert 'DriverSHA256=' + driver in text and 'PROBE_COMPLETE' in text
    assert manifest['sha256'] == ref(path)['sha256'] and manifest['bytes'] == len(data)
    assert manifest['crc32'] == f'{zlib.crc32(data):08X}'
    counters = {k: values(text, k)[-1] for k in ['Checks', 'Failures', 'BlockedSetVariableCalls']}
    assert counters['Failures'] == 0
    return {'label': folder, **ref(path), 'decoded_manifest': ref(manifest_path), 'counters': counters}, text


def main():
    index_path = HW / 'hardware_evidence_index.json'
    index = read(index_path)
    assert not index['collection_closed'], 'Existing closed collection is immutable'
    completion_path = HW / 'cleanup-completion.json'
    completion = read(completion_path)
    state_path = HW / 'cleanup-host-state.json'
    state = read(state_path)
    assert completion['status'] in {'COMPLETED', 'COMPLETED_WITH_BOOT_RECORD_RESIDUAL'}
    assert completion['browser_process_exit_code'] == 0
    assert completion['logout_http_status'] == 200 and completion['keepalive_stopped']
    assert state['initial_power'] == state['final_power'] == 'Off'
    assert state['virtual_media_detached'] and state['chassis_power_status'] == 0
    if not state['boot_unchanged']:
        assert completion['status'] == 'COMPLETED_WITH_BOOT_RECORD_RESIDUAL'
        before, after = state['initial_boot'], state['final_boot']
        assert [v for v in after['BootOrder'] if v != 'Boot0008'] == before['BootOrder']
        assert set(after['BootOrder']) - set(before['BootOrder']) == {'Boot0008'}
        assert all(after[k] == before[k] for k in before if k != 'BootOrder')
    for revision, folders in [
        ('INTEGRATED03', ['integrated03-preflight', 'integrated03-before-reset']),
        ('INTEGRATED04', ['integrated04-preflight', 'integrated04-final']),
    ]:
        observation_path = HW / ('hardware-observations-' + revision.lower() + '.json')
        observation = read(observation_path)
        assert observation['status'].startswith('PASS')
        if revision == 'INTEGRATED04':
            assert observation['finalized'] is True
        driver = observation['driver_sha256']
        summary_path = HERE / ('lock_1904_' + revision.lower()) / 'ram_validation/delivery_summary.json'
        summary = read(summary_path)
        assert summary['production_driver_sha256'] == driver
        assert summary['iso_sha256'] == observation['iso_sha256']
        logs = []
        for folder in folders:
            entry, final_text = log_record(folder, revision, driver)
            logs.append(entry)
        screens = []
        for screen in observation['screens']:
            assert screen['visually_reviewed_with_view_image'] is True
            path = ROOT / screen['path']
            assert ref(path)['sha256'] == screen['sha256']
            screens.append({'number': screen['screen_number'], **ref(path), 'visually_reviewed': True})
        observations = [{'case': item['result'], 'screens': item['screens'], 'result': 'PASS'}
                        for item in observation['interactive_observations']]
        final = logs[-1]['counters']
        active = values(final_text, 'Credential.active_after_return')
        unlocked = values(final_text, 'Credential.unlocked_after_return')
        statuses = values(final_text, 'SendForm.status')
        requests = values(final_text, 'SendForm.request')
        assert active and not any(active + unlocked + statuses + requests)
        run = next(row for row in index['runs'] if row['revision'] == revision)
        run.update(status='OBSERVED', driver_sha256=driver, iso_sha256=observation['iso_sha256'],
                   ram_delivery_summary=ref(summary_path), observation_source=ref(observation_path),
                   logs=logs, screenshots=screens, observations=observations,
                   final_counters={'checks': final['Checks'], 'failures': final['Failures'],
                                   'blocked_runtime_set_variable_calls': final['BlockedSetVariableCalls'],
                                   'sendform_returns': len(statuses), 'sendform_status': statuses,
                                   'sendform_request': requests, 'credential_mode_after_return': values(final_text, 'Credential.mode'),
                                   'active_after_return': active, 'unlocked_after_return': unlocked,
                                   'three_named_variables_unchanged': True},
                   notes=['Physical native Setup navigation and password management observed with RAM-only credentials.',
                          'Actual nonvolatile password persistence and real Save/Reset behavior were not tested.'],
                   limits=observation['limits'])
    cleanup_screens = [ROOT / p for p in completion['reviewed_screenshot_paths']]
    index['cleanup'] = {'status': 'COMPLETED' if state['boot_unchanged'] else 'NOT_VERIFIED',
                        'evidence': [ref(state_path), ref(completion_path)] + [ref(p) for p in cleanup_screens],
                        'note': completion['report_note'], 'initial_power_restored': True,
                        'media_detached': True, 'browser_logged_out_and_closed': True,
                        'exact_boot_order_restored': state['boot_unchanged']}
    index['collection_closed'] = True
    index['closed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'status': 'CLOSED_REVIEWED_HARDWARE_EVIDENCE', **ref(index_path)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
