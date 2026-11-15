"""Independent offline C08 Linux retry/P04 attempt review.

Reads parent-collected evidence only. Does not import the live helper or any
browser/power/media operation, connect to the target, or alter a frozen file.
Writes only this review directory. This is not final round cleanup evidence.
"""
from pathlib import Path
import hashlib, json, re, sys

HERE = Path(__file__).resolve().parent
C08 = HERE.parent
READY = C08.parents[1]
SAGE = C08.parents[3]
HW = SAGE / 'remote_172_20_2_162'
CLIENT = READY / 'remote_only/media_writeback_client01'
P04 = READY / 'native13_split_candidate/installer_design04/prerequisite_probe04'
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/kvm-pydeps'))
from PIL import Image
import zxingcpp

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf8'))
bound = lambda p: {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}


def main():
    paths = {
        'linux2_helper_result': CLIENT / 'runs/20261103_103442/result.json',
        'linux2_sd_boot_once': HW / 'boot-once-1793702121988.json',
        'linux2_active_power_on': HW / 'power-on-1793702126043.json',
        'linux2_screen': HW / 'screen-267-current.png',
        'linux2_screen_metadata': HW / 'screen-267-current.json',
        'linux2_orderly_shutdown': HW / 'power-1793702301223.json',
        'linux2_browser_input_after_shutdown': HW / 'browser-selected-iso08-1793702316238.json',
        'linux2_override_restore': HW / 'media-override-restored08-1793702665655.json',
        'before_p04_cleanup': HW / 'media-cleanup-1793702775667.json',
        'p04_sd_boot_once': HW / 'boot-once-1793702819465.json',
        'p04_active_power_on': HW / 'power-on-1793702822825.json',
        'p04_screen': HW / 'screen-268-current.png',
        'p04_screen_metadata': HW / 'screen-268-current.json',
        'p04_orderly_shutdown': HW / 'power-1793703180928.json',
        'p04_later_off_readback': HW / 'browser-read-269.json',
        'p04_parent_preflight_review': C08 / 'prerequisite04_parent_review.json',
        'helper_source': CLIENT / 'live_writeback04.py',
        'helper_session_source': CLIENT / 'observed_session03.py',
        'helper_bounds_source': CLIENT / 'review_legacy_data/bounded_legacy.py',
        'helper_backend_source': CLIENT / 'hdmedia_offline.py',
        'helper_auth_source': CLIENT / 'observed_auth_adapter.py',
        'helper_launch_source': HW / 'operations/hdmedia_writeback04_session.mjs',
        'boot_override_source': HW / 'operations/redfish_boot.mjs',
        'power_on_source': HW / 'operations/power_on.mjs',
        'power_shutdown_source': HW / 'operations/power_control.mjs',
        'cleanup_readback_source': HW / 'operations/record_media_cleanup.mjs',
        'p04_capture_source': HW / 'operations/capture_native13_prerequisite04.mjs',
        'p04_decoder_source': HW / 'read_native13_prerequisite04_qr.py',
        'p04_candidate_manifest': P04 / 'prerequisite04_manifest.json',
        'p04_independent_manifest': P04.parent / 'prereq04_independent_review/review_manifest.json',
        'p04_known_good_ovmf_qr_control': P04 / 'ovmf/20261103_193613/qr-01.png',
        'linux2_pinned_loader_manifest': READY / 'remote_only/linux_capacity_candidate01/loader/loader_manifest.json',
    }
    inputs = {key: bound(path) for key, path in paths.items()}
    helper = load(paths['linux2_helper_result'])
    assert helper['script_sha256'] == inputs['helper_source']['sha256'] == '1f83f12403636e9764f3cc90350880b6bfa7b15ea0610e220a1106b5e0bd4f43'
    source = paths['helper_source'].read_text(encoding='utf8')
    for rel, expected in re.findall(r"'([^']+\.py)'\s*:\s*'([0-9a-f]{64})'", source):
        assert sha(CLIENT / rel) == expected, rel
    assert helper['status'] == 'SESSION_ENDED_WITHOUT_PROTOCOL_ERROR' and helper['end_reason'] == 'parent_stop'
    assert helper['authenticated'] and helper['image_opened'] and helper['socket_closed'] and helper['image_closed']
    assert helper['frames'] == 18 and helper['opcode_counts'] == {'F1': 1, 'F3': 17}
    assert helper['capacity_sends'] == [] and helper['action_counts'] == {'control': 17}
    backend = {key: helper[key] for key in ['backend_read_calls', 'backend_write_calls', 'backend_flush_calls', 'backend_written_bytes']}
    assert all(value == 0 for value in backend.values())
    assert helper['final_image_bytes'] == 16777216 and helper['final_image_sha256'] == 'df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
    backend_source = paths['helper_backend_source'].read_text(encoding='utf8')
    assert "PINNED_SHA256 = '" + helper['final_image_sha256'] + "'" in backend_source
    selected = load(paths['linux2_browser_input_after_shutdown'])
    assert selected['files_count'] == len(selected['files']) == 1
    file = selected['files'][0]
    assert file['size'] == file['array_buffer_bytes'] == 32571392
    assert file['sha256'] == '4e70bb0abfc285849301a6829b1ac51cae914d65025e135b971b06dd47d25d18'
    assert selected['label'] == 'Stop Media'

    endpoint_discrepancies = []
    for label in ['linux2', 'p04']:
        once = load(paths[label + '_sd_boot_once']); power = load(paths[label + '_active_power_on'])
        assert once['status'] == 204 and once['requested'] == {'BootSourceOverrideEnabled': 'Once', 'BootSourceOverrideTarget': 'Cd', 'BootSourceOverrideMode': 'UEFI'}
        for key, value in once['requested'].items(): assert once['after'][key] == value
        assert power['status'] == 202 and power['before_power'] == 'Off' and power['action'] == 'On'
        assert power['before_boot']['BootSourceOverrideEnabled'] == 'Disabled'
        assert power['before_boot']['BootSourceOverrideTarget'] == 'Cd' and power['before_boot']['BootSourceOverrideMode'] == 'UEFI'
        assert power['before_boot']['BootOrder'] == once['after']['BootOrder'] == once['before']['BootOrder']
        shutdown = load(paths[label + '_orderly_shutdown'])
        assert shutdown['command'] == 5 and shutdown['result']['status'] == 200 and shutdown['before']['data']['power_status'] == 1
        endpoint_discrepancies.append({'attempt': label, 'sd_result_utc': once['utc'], 'sd_enabled': 'Once', 'active_read_in_power_on_record_utc': power['utc'], 'active_enabled': 'Disabled', 'same_target': 'Cd', 'same_mode': 'UEFI'})
    assert "args.settings?'/redfish/v1/Systems/Self/SD':'/redfish/v1/Systems/Self'" in paths['boot_override_source'].read_text(encoding='utf8')
    assert "client.get('/redfish/v1/Systems/Self'" in paths['power_on_source'].read_text(encoding='utf8')
    restore = load(paths['linux2_override_restore'])
    assert restore['baseline_sha256'] == inputs['linux2_sd_boot_once']['sha256'] and restore['verified'] and not restore['boot_order_patch_sent']
    assert restore['requested'] == {'BootSourceOverrideEnabled': 'Disabled', 'BootSourceOverrideTarget': 'None', 'BootSourceOverrideMode': 'Legacy'}
    for key, value in restore['requested'].items(): assert restore['after'][key] == value
    cleanup = load(paths['before_p04_cleanup'])
    assert all(cleanup['verified'].values()) and not cleanup['owned_helper_running']
    off = load(paths['p04_later_off_readback']); assert off['status'] == 200 and off['data']['power_status'] == 0
    parent = load(paths['p04_parent_preflight_review'])
    for key, source_key in [('capture_operation', 'p04_capture_source'), ('decoder', 'p04_decoder_source')]:
        assert parent[key]['sha256'] == inputs[source_key]['sha256']
    assert parent['same_iso_smoke']['pages'] == 6 and parent['same_iso_smoke']['bytes'] == 4071
    # The test control is explicitly OVMF evidence, not a physical P04 capture.
    scans = []
    for key in ['linux2_screen', 'p04_screen', 'p04_known_good_ovmf_qr_control']:
        with Image.open(paths[key]) as image:
            found = zxingcpp.read_barcodes(image.convert('RGB'), formats=zxingcpp.BarcodeFormat.QRCode)
        p3 = [bytes(x.bytes) for x in found if bytes(x.bytes).startswith(b'AITWK-P3-KVM\n')]
        if key.endswith('control'):
            assert len(p3) == 1 and b'T=4071;C=3A6F8B03;P=1/6;' in p3[0]
        else:
            assert not p3 and not found
        scans.append({'input': key, 'qr_count': len(found), 'p3_frame_count': len(p3), 'positive_control': key.endswith('control')})

    report = {
        'status': 'NO_NEW_DIAGNOSTIC_EXECUTION_EVIDENCE_IN_REVIEWED_LINUX2_AND_P04_ATTEMPTS',
        'scope': 'Independent offline review of fixed local records and original screenshots for two bounded C08 attempts. No live controller, target, firmware, power, boot or media operation was invoked.',
        'inputs': inputs,
        'linux_retry02': {
            'helper_started_utc': helper['started_utc'], 'power_on_record_utc': load(paths['linux2_active_power_on'])['utc'],
            'visual_observation': ['Rocky Linux 8.10 (Green Obsidian)', 'Kernel 4.18.0-553.el8_10.x86_64', 'K6D-008 login prompt', 'sr0 READ/media I/O errors and sdb unable to read RDB block 0', 'Virtual CD viewer says boot.iso (1 KB) / Stop Media'],
            'browser_input_verified_after_shutdown': {'utc': selected['utc'], **file, 'scope': 'Local browser File/ArrayBuffer bytes only; neither the 1 KB UI label nor this local hash proves what the BMC delivered to the host.'},
            'helper_frames': helper['frames'], 'helper_opcode_counts': helper['opcode_counts'], 'capacity_sends': [], 'backend_calls': backend,
            'helper_end_reason': helper['end_reason'], 'helper_finished_utc': helper['finished_utc'],
            'recorded_final_image_sha256': helper['final_image_sha256'], 'recorded_final_image_matches_open_time_pin': True,
            'orderly_shutdown_requested_utc': load(paths['linux2_orderly_shutdown'])['utc'],
            'later_override_restore_utc': restore['utc'], 'later_cleanup_utc': cleanup['utc'],
            'new_host_capacity_result_available': False, 'successful_file_writeback_proven': False,
            'conclusion': 'The observed system is installed Rocky, not the frozen custom Linux 6.12 diagnostic. No new target READ CAPACITY result or successful test-file writeback was obtained. Helper counters apply only to its pinned disposable image; they do not describe all installed-OS disk activity.'
        },
        'prerequisite04_attempt': {
            'intended_artifact_iso_sha256': '852ed9fdbf39cad8764bf0b1cf21c2b3fb1b95f939c9536e13ad22dbf943307c',
            'prior_media_cleanup_verified': cleanup['verified'], 'power_on_record_utc': load(paths['p04_active_power_on'])['utc'],
            'visual_observation': ['Rocky Linux 8.10 (Green Obsidian)', 'Kernel 4.18.0-553.el8_10.x86_64', 'K6D-008 login prompt', 'Virtual CD viewer names SAGE-N13-OWNED-PREREQUISITE04.iso (1 KB) / Stop Media'],
            'valid_physical_prerequisite_log_in_reviewed_attempt': False, 'native_owned_memory_service_result_available': False,
            'orderly_shutdown_requested_utc': load(paths['p04_orderly_shutdown'])['utc'],
            'later_off_readback': {'embedded_utc': None, 'status': off['status'], 'power_status': off['data']['power_status'], 'scope': 'Historical readback following this attempt; this report does not claim current machine state.'},
            'conclusion': 'The provided terminal screenshot contains no P04 program or QR result. Local preflight/OVMF approval remains valid evidence for that local scope; it does not turn this attempted physical boot into a P04 pass.'
        },
        'boot_view_difference': {'observations': endpoint_discrepancies,
                                 'conclusion': 'The SD settings resource read back Once/Cd/UEFI while the active Self resource recorded Disabled/Cd/UEFI before each power-on request.',
                                 'limit': 'The resources have different roles. This discrepancy is a diagnostic clue, not proof of the exact time an override changed, why it changed, or why installed Rocky appeared.'},
        'qr_scanner_checks': scans,
        'manual_visual_review': {'method': 'Original PNG files opened with view_image; no OCR-only interpretation or altered images.', 'files': [inputs['linux2_screen'], inputs['p04_screen']]},
        'not_proven': [
            'That neither diagnostic could ever have executed at any unobserved instant; the reviewed evidence establishes no execution result and the shown terminal state only.',
            'Successful post-restart correction of virtual-HD geometry, new capacity data, or successful file writeback.',
            'The identity of screenshot sdb, local-disk damage, or any successful storage write inferred from READ errors.',
            'The exact cause of fallback/selection of installed Rocky, BMC media byte delivery, or capsule/firmware behavior.',
            'A complete C08 final cleanup/logout/controller exit. Later F7 helper work and final cleanup require separate records.',
            'Native password lock, initial Del entry interception, original-page permission writes, firmware flashing, or recovery readiness.'
        ],
        'publication_state': 'ATTEMPT_REVIEW_FOR_PARENT_APPROVAL_ONLY_MAIN_PUBLISHER_UNCHANGED',
        'release_ready': False,
    }
    (HERE / 'attempts_review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    summary = '''C08 的 Linux 第二次尝试和 P04 尝试都没有取得新的诊断执行结果。两张原始截图均显示已安装的 Rocky Linux 8.10、4.18.0-553 内核和登录提示；P04 截图上方虽显示所选 ISO 名称，仍没有 P04 页面或二维码。终态截图不能证明所有未观察时刻发生过什么，因此报告使用“没有执行结果证据”，不使用绝对的“从未执行”。

Linux 第二次尝试的自有 HD helper 完成认证，只记录 1 个 F1 和 17 个 F3 控制帧，没有容量响应，也没有后端数据读、写或 flush。记录的最终 16 MiB 临时镜像散列等于打开时要求的固定散列。这些计数仅覆盖该 helper，不能扩展为已安装操作系统的所有存储活动。截图中的 sr0/sdb 读错误也不能据此证明磁盘身份、盘损坏或成功写入。

该次尝试关机后，浏览器输入文件的 32,571,392 字节及散列与冻结 Linux ISO 相符；1 KB 的界面标签不能代表真实文件长度。本地输入散列也不等于证明 BMC 已向主机正确交付全部内容。P04 的本地构建与 OVMF 通过结果保留，但尚未取得此次实机自有内存服务的结果。

两次 SD 设置资源均读回 Once/Cd/UEFI，而随后 power-on 中的 active Self 资源记录 Disabled/Cd/UEFI。这是两个资源视图的差异，可以作为后续诊断线索，尚不能确定启动回退的根因。

已记录 Linux 第二次尝试后的临时启动项恢复、媒体清理，以及 P04 后的 ACPI 有序关机请求和后续 Off 回读。它们都是相应时间的历史证据；C08 后续 F7 helper 与最终清理需另行绑定。当前文件只供父任务审查，没有修改主发布报告，也没有连接设备。
'''
    (HERE / 'attempts_summary.txt').write_text(summary, encoding='utf8')
    own = [bound(HERE / name) for name in ['review_attempts.py', 'attempts_review.json', 'attempts_summary.txt']]
    manifest = {'status': 'FROZEN_BOUNDED_ATTEMPT_REVIEW_NOT_FINAL_C08_PUBLICATION', 'inputs': list(inputs.values()), 'artifacts': own,
                'review_sha256': sha(HERE / 'attempts_review.json')}
    (HERE / 'attempts_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'status': report['status'], 'input_bindings': len(inputs), 'review_sha256': sha(HERE / 'attempts_review.json'), 'manifest_sha256': sha(HERE / 'attempts_manifest.json')}, indent=2))


if __name__ == '__main__':
    main()
