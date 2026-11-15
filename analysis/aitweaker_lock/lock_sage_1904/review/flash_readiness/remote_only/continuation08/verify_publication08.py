"""Verify C08 publication identities and scope using local files only."""
from pathlib import Path
import hashlib, importlib.util, json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[1]
CASE = READY.parents[1]


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    report = read(READY/'acceptance_status.json')
    c08 = read(HERE/'validation08_result.json')
    c07_path = READY/'remote_only/continuation07/validation07_result.json'
    c07_sha = '38f97a4d61c7d33b114179ef0896f45cd46ae6b6d10a2c092ce3acc8aa610dfc'
    assert report['latest_remote_validation'] == c08
    assert report['latest_completed_validation_round'] == 8
    assert report['active_continuation'] == 'continuation08'
    assert report['current_work'] == 'local_native_installer_development'
    assert not any(report[k] for k in ['release_ready', 'task_complete', 'production_release_completed',
                                      'firmware_upload_performed', 'firmware_flashing_performed'])
    assert c08['diagnostic_session_complete'] and not c08['task_complete']
    assert c08['raw_QR_pages_verified'] == 16 and c08['completed_diagnostic_captures'] == 1
    assert c08['failed_or_interrupted_boot_attempts_without_new_diagnostic_result'] == 3
    assert c08['binding_count_is_not_unique_file_count']
    assert sum(x['file_bindings_rechecked'] for x in c08['frozen_manifest_bindings'].values()) == 538
    assert len(c08['frozen_manifest_bindings']) == 6
    assert len(report['three_major_gaps_zh']) == 3
    assert sha(c07_path) == c07_sha == c08['prior_continuation07_preserved']['sha256']
    assert report['prior_remote_validation07'] == read(c07_path)
    assert report['prior_remote_validation06'] == read(READY/'remote_only/continuation06/validation06_result.json')

    for name, item in report['evidence'].items():
        path = (READY/name).resolve()
        assert path.is_relative_to(READY.resolve()), name
        assert sha(path) == item['sha256'], name
    spec = importlib.util.spec_from_file_location('publication08_checks', READY/'publish_readiness.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.verify_bound_tree({k: v for k, v in c08.items() if k != 'evidence_links'})
    assert c08['internal_image_unchanged']['sha256'] == report['latest_internal_image_sha256'] == 'b1223ca05cf9630382e5fc014457d3c6343aaf7d970b58e5769950200f65ac02'
    assert c08['standard_bmc_restarts']['count'] == 2
    assert c08['helper05_normal_disconnect']['F7_attempts'] == 1
    assert not c08['helper05_normal_disconnect']['server_slot_clear_acknowledgement']
    assert not c08['helper05_normal_disconnect']['writeback_verified']
    assert c08['cd_recovery']['new_READ12_request_response_counts'] == [24, 24]
    assert not c08['cd_recovery']['unique_root_cause_established']
    assert not c08['cd_recovery']['HD_geometry_fixed']
    cleanup = c08['cleanup']
    assert cleanup['SD_restored'] and not cleanup['active_Self_restored']
    assert cleanup['active_and_SD_override_disabled'] and cleanup['BootNext_null_in_both_views']
    assert cleanup['host_off_at_readback'] and cleanup['CD_HD_idle_at_readback']
    assert cleanup['logout_HTTP_status'] == 200 and cleanup['controller_exit_code_reported_by_operator'] == 0
    assert not cleanup['all_firmware_NVRAM_bytes_unchanged_claimed']
    assert cleanup['as_of_utc'] == '2026-11-03T11:26:51.151Z'
    assert c08['native_installer_work']['ongoing']
    assert not c08['native_installer_work']['native_installer_hardware_pass']
    assert not c08['native_installer_work']['separate_split_candidate_validation_transferred_to_N12']
    for path in [CASE/'requirements.json', CASE.parent/'requirements.json']:
        status = read(path)['production_release_work']
        assert not status['release_ready'] and not status['flashing_performed'] and not status['task_complete']
        assert status['latest_completed_validation_round'] == 8
        assert status['active_continuation'] == 'continuation08'
        assert status['current_work'] == 'local_native_installer_development'
    outputs = [HERE/'validation08_result.json', HERE/'publish_validation08.py', HERE/'verify_publication08.py',
               READY/'publish_readiness.py', READY/'acceptance_status.json', READY/'检查报告.html']
    result = {
        'status': 'PASS_LOCAL_PUBLICATION_CONSISTENCY_AND_BINDINGS',
        'evidence_links_verified': len(report['evidence']), 'raw_QR_pages': 16,
        'frozen_manifest_references': 538, 'binding_count_is_not_unique_file_count': True,
        'diagnostic_session_complete': True, 'task_complete': False,
        'current_work': 'local_native_installer_development', 'release_ready': False,
        'cleanup_is_timestamped_with_active_Self_difference': True,
        'prior_C07_preserved': True, 'N12_image_preserved': True,
        'native_install_or_password_hardware_acceptance': False,
        'files': {path.relative_to(READY).as_posix(): sha(path) for path in outputs},
        'requirements': [{'path': str(path), 'sha256': sha(path)} for path in [CASE/'requirements.json', CASE.parent/'requirements.json']],
    }
    (HERE/'publication08_check.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    print(json.dumps({k: result[k] for k in ['status', 'evidence_links_verified', 'release_ready', 'task_complete']}))


if __name__ == '__main__':
    main()
