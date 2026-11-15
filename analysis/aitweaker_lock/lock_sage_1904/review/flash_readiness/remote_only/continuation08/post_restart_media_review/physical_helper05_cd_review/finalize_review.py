"""Freeze/recheck local evidence only. Never imports or calls a remote operation."""
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
REMOTE = SAGE / 'review/flash_readiness/remote_only'
HW = SAGE / 'remote_172_20_2_162'
C08 = REMOTE / 'continuation08'
P04 = SAGE / 'review/flash_readiness/native13_split_candidate/installer_design04/prerequisite_probe04'
CLIENT = REMOTE / 'media_writeback_client01'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def binding(path):
    path = path.resolve()
    assert path.is_relative_to(ROOT.resolve()), path
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def checked(path, digest):
    assert sha(path) == digest, str(path)


def stamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def dump(path, value):
    with path.open('x', encoding='utf8', newline='\n') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def verify():
    m = read(HERE / 'manifest.json')
    for row in m['inputs'] + m['artifacts']:
        p = Path(row['path']).resolve()
        assert p.is_relative_to(ROOT.resolve())
        assert p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], p
    assert sha(HERE / 'physical_review.json') == m['review_sha256']
    r = read(HERE / 'physical_review.json')
    assert r['release_ready'] is False and r['publication08_complete'] is False
    assert r['helper05']['protocol_ack_validated'] is False
    assert r['helper05']['server_slots_cleared_verified'] is False
    assert r['second_bmc_restart']['settings_override_all_three_unchanged'] is False
    out = {'status': 'PASS_FROZEN_PHYSICAL_SUPPLEMENT_RECHECK', 'input_bindings': len(m['inputs']),
           'artifact_bindings': len(m['artifacts']), 'review_sha256': m['review_sha256'],
           'manifest_sha256': sha(HERE / 'manifest.json')}
    print(json.dumps(out))


def main():
    if '--verify-only' in sys.argv:
        verify()
        return
    assert not (HERE / 'manifest.json').exists(), 'Already frozen; use --verify-only'
    inputs = {
        'observer_source': HW / 'operations/observe_cd08.mjs',
        'observer_author_test_source': C08 / 'test_cd_observer.mjs',
        'observer_author_test_result': C08 / 'cd_observer_tests.json',
        'original_h5_cd_review': REMOTE / 'cd_capacity_review08/cd_capacity_review.json',
        'original_h5_cd_manifest': REMOTE / 'cd_capacity_review08/manifest.json',
        'cd_trace': HW / 'cd-observer08-1793703687797.jsonl',
        'cd_trace_summary': HW / 'cd-observer08-1793703687797.jsonl.json',
        'setup_reset_source': HW / 'operations/reset_setup08.mjs',
        'setup_reset_intent': HW / 'setup-reset08-1793703821707-intent.json',
        'setup_reset_result': HW / 'setup-reset08-1793703821707.json',
        'bootmenu_poweroff_source': HW / 'operations/power_off_bootmenu08.mjs',
        'bootmenu_poweroff_intent': HW / 'bootmenu-off08-1793704005484-intent.json',
        'bootmenu_poweroff_result': HW / 'bootmenu-off08-1793704005484.json',
        'helper_source': CLIENT / 'live_writeback05.py',
        'helper_owning_operation': HW / 'operations/hdmedia_writeback05_session.mjs',
        'helper_result': CLIENT / 'runs/20261103_110804_helper05/result.json',
        'helper_offline_independent_review': HERE.parent / 'helper05_independent/independent_review.json',
        'helper_offline_independent_manifest': HERE.parent / 'helper05_independent/manifest.json',
        'cleanup_source': HW / 'operations/record_media_cleanup.mjs',
        'cleanup_before_helper': HW / 'media-cleanup-1793704071595.json',
        'cleanup_after_helper': HW / 'media-cleanup-1793704126043.json',
        'disposable_image': REMOTE / 'media_writeback_review/blank_test/WRITEBACK02.img',
        'p04_iso': P04 / 'build/SAGE-N13-OWNED-PREREQUISITE04.iso',
        'p04_candidate_manifest': P04 / 'prerequisite04_manifest.json',
        'restart_source': HW / 'operations/restart_manager08.mjs',
        'restart_readback_source': HW / 'operations/read_manager_restart08.mjs',
        'restart_before_readback': HW / 'manager-restart08-capability-1793704023580.json',
        'restart_intent': HW / 'manager-restart08-1793704149205-intent.json',
        'restart_result': HW / 'manager-restart08-1793704149205-result.json',
        'restart_reachability': C08 / 'restart_reachability_1793704130137.json',
        'restart_after_readback': HW / 'manager-restart08-capability-1793704391712.json',
    }
    for stem in ['screen-276-current', 'screen-277-setup-before-reset08', 'screen-279-boot-watch', 'screen-280-bootmenu-before-off08']:
        for extension in ['json', 'png']:
            inputs[stem + '_' + extension] = HW / (stem + '.' + extension)
    expected = {
        'observer_source': '56791daa59378c410b11b1755a06b52df8a75988459ac5c287c40f3badcd410b',
        'original_h5_cd_review': '1d278acbec06dc1d359e2ac5c3c11f69529faa51132871a0287a9e2b5eed7768',
        'original_h5_cd_manifest': 'ee899987590cc87e02814187fcd0a1ba583de320c332dc367bcdd53d249e5dd3',
        'helper_source': '5dffcd939577ad7faf460a9bbd9ebf2065ebf1d9664b9a8ac41ef7d296c07e75',
        'helper_owning_operation': '381a1fa3d2bbe49d4d29f7671f35a5fd03077ab22889e0860ae4d50bbcff7af3',
        'helper_result': '419b7c79b6c8e61bbd317d21b6ccbc0cee545c327895b5f7b0d3cadda789b94e',
        'helper_offline_independent_review': '0c303d66a874214970e89a65805ad80eb26255712b04dcbf68ba2b96db5dd0d1',
        'helper_offline_independent_manifest': '3a9816aeac692f5d2772e2079952500bb7b2358c8d60e6eebcb05ac85ae12f94',
        'disposable_image': 'df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6',
        'p04_iso': '852ed9fdbf39cad8764bf0b1cf21c2b3fb1b95f939c9536e13ad22dbf943307c',
        'p04_candidate_manifest': '1c70adb50d8e17c2672b091c4bc0ab8fa201a5035b3bfda1a67e017fb3033ba9',
        'screen-279-boot-watch_png': '0938ca55a1944c204a5cd0a5bad22b121294e481587f52932190ae53e2afddfd',
    }
    for key, digest in expected.items():
        checked(inputs[key], digest)
    cd_native_manifest = read(inputs['original_h5_cd_manifest'])
    cd_native_rows = cd_native_manifest['artifacts'] + cd_native_manifest['external_inputs']
    assert len(cd_native_rows) == 31
    for row in cd_native_rows:
        path = (ROOT / row['path']).resolve()
        assert path.is_relative_to(ROOT.resolve()) and path.stat().st_size == row['size']
        checked(path, row['sha256'])
    source_tests = read(inputs['observer_author_test_result'])
    assert source_tests['status'] == 'PASS' and len(source_tests['cases']) == 6
    assert source_tests['source_sha256'] == expected['observer_source']
    own_tests = read(HERE / 'observer_tests.json')
    assert own_tests['case_count'] == len(own_tests['cases']) == 12
    assert all(x['status'] == 'PASS' for x in own_tests['cases'])
    assert own_tests['source_sha256'] == expected['observer_source']
    trace = [json.loads(x) for x in inputs['cd_trace'].read_text(encoding='utf8').splitlines() if x.strip()]
    summary = read(inputs['cd_trace_summary'])
    assert summary['packets'] == len(trace) == 34 and summary['sockets'] == 1 and summary['truncated'] is False
    assert all(stamp(a['utc']) <= stamp(b['utc']) for a, b in zip(trace, trace[1:]))
    assert stamp(summary['started_utc']) <= stamp(trace[0]['utc']) <= stamp(trace[-1]['utc']) <= stamp(summary['finished_utc'])
    assert trace[0]['event'] == 'socket' and trace[-1]['event'] == 'closed'
    assert trace[-1]['pending_sent_bytes'] == trace[-1]['pending_received_bytes'] == 0
    assert all('unparsed' not in row for row in trace)
    frames = [x for x in trace if 'opcode' in x]
    assert len(frames) == 32
    counts = dict(sorted(Counter(x['direction'] + ':' + x['opcode'] for x in frames).items()))
    assert counts == {'received:25': 1, 'received:f1': 1, 'received:f3': 13,
                      'sent:25': 1, 'sent:f2': 1, 'sent:f3': 13, 'sent:f7': 1, 'sent:f8': 1}
    assert not any(x['opcode'] in ['28', 'a8'] for x in frames)
    auth = [x for x in frames if x['opcode'] == 'f1']
    assert len(auth) == 1 and auth[0]['connection_status'] == 1
    caps = [x for x in frames if 'capacity8' in x]
    assert len(caps) == 1 and caps[0]['capacity8'] == '0000201f00000800'
    assert caps[0]['direction'] == 'sent' and caps[0]['status'] == [0, 0, 0, 0]
    capacity = bytes.fromhex(caps[0]['capacity8'])
    cd_last = int.from_bytes(capacity[:4], 'big')
    cd_block = int.from_bytes(capacity[4:], 'big')
    assert (cd_last + 1) * cd_block == inputs['p04_iso'].stat().st_size == 16842752
    reset = read(inputs['setup_reset_result'])
    assert reset['status'] == 202 and reset['action'] == 'ForceRestart'
    assert reset['evidence_sha256'] == sha(inputs['screen-276-current_png']) == sha(inputs['screen-277-setup-before-reset08_png'])
    off = read(inputs['bootmenu_poweroff_result'])
    assert off['status'] == 202 and off['action'] == 'ForceOff'
    assert off['evidence_sha256'] == expected['screen-279-boot-watch_png']
    h = read(inputs['helper_result'])
    assert h['script_sha256'] == expected['helper_source'] and h['helper_version'] == '05_F7_NORMAL_STOP'
    assert h['authenticated'] is True and h['image_opened'] is True
    assert h['socket_closed'] is True and h['image_closed'] is True
    assert h['opcode_counts'] == {'F1': 1, '00': 1, '1A': 1, '25': 1}
    assert h['frames'] == 4 and h['legacy_commands'] == 3 and h['action_counts'] == {'control': 3}
    assert h['unhandled_buffer_bytes_at_stop'] == 0
    assert all(h[x] == 0 for x in ['backend_read_calls', 'backend_write_calls', 'backend_flush_calls', 'backend_written_bytes', 'reserved_write_bytes'])
    assert h['final_image_bytes'] == inputs['disposable_image'].stat().st_size == 16777216
    assert h['final_image_sha256'] == expected['disposable_image']
    assert len(h['capacity_sends']) == 1
    hd = h['capacity_sends'][0]
    assert hd['capacity8_hex'] == '00007fff00000200' and hd['sendall_returned'] and hd['expected_capacity_bytes_match']
    d = h['normal_disconnect']
    assert d['reason'] == 'parent_stop' and d['attempts'] == 1 and d['frame_bytes'] == 62 and d['opcode'] == 'F7'
    assert d['sendall_returned'] is True and d['peer_eof_observed'] is True
    assert d['protocol_ack_validated'] is False and d['server_slots_cleared_verified'] is False
    assert d['drained_bytes'] == 0 and d['drain_elapsed_seconds'] == 0.04759
    assert d['status'] == 'SENT_PEER_EOF_OBSERVED' and h['end_reason'] == 'parent_stop'
    before_cleanup = read(inputs['cleanup_before_helper'])
    after_cleanup = read(inputs['cleanup_after_helper'])
    for row in [before_cleanup, after_cleanup]:
        assert all(v is True for v in row['verified'].values())
        assert row['power']['status'] == 200 and row['power']['data']['power_status'] == 0
        assert row['media']['status'] == 200 and row['hd_active_sessions'] == row['cd_active_sessions'] == 128
        assert row['media_button'] == 'Start Media' and row['owned_helper_running'] is False
    assert stamp(before_cleanup['utc']) < stamp(h['started_utc']) < stamp(d['sent_utc']) < stamp(h['finished_utc']) < stamp(after_cleanup['utc'])
    ri = read(inputs['restart_intent'])
    rr = read(inputs['restart_result'])
    assert ri['request'] == {'ResetType': 'ForceRestart'} and ri['automatic_retries'] == 0
    assert rr['intent_sha256'] == sha(inputs['restart_intent'])
    assert rr['http_status'] == 202 and rr['post_attempts'] == 1 and rr['task_location'] == '/redfish/v1/TaskService/Tasks/20'
    reach = read(inputs['restart_reachability'])
    assert reach['observed_down_then_up'] and reach['stop_reason'] == 'down_then_up'
    first_down = next(x for x in reach['samples'] if x['up'] is False)
    recovery = next(x for x in reach['samples'] if x['up'] is True and stamp(x['utc']) > stamp(first_down['utc']))
    assert first_down['utc'] == '2026-11-03T11:09:24.065Z' and recovery['utc'] == '2026-11-03T11:11:19.469Z'
    assert recovery['http_status'] == 200 and recovery['certificate_matches'] is True
    rb = read(inputs['restart_before_readback'])
    ra = read(inputs['restart_after_readback'])
    keys = ['BootSourceOverrideEnabled', 'BootSourceOverrideMode', 'BootSourceOverrideTarget']
    triplet = lambda x: {k: x[k] for k in keys}
    sb = triplet(rb['settings']['Boot']); sa = triplet(ra['settings']['Boot'])
    ab = triplet(rb['system']['Boot']); aa = triplet(ra['system']['Boot'])
    assert list(sb.values()) == ['Disabled', 'Legacy', 'None']
    assert list(sa.values()) == ['Disabled', 'UEFI', 'Cd']
    assert list(ab.values()) == list(aa.values()) == ['Disabled', 'UEFI', 'Cd']
    order = rb['settings']['Boot']['BootOrder']
    assert len(order) == 6 and len(set(order)) == 6
    assert ra['settings']['Boot']['BootOrder'] == ra['system']['Boot']['BootOrder'] == rb['system']['Boot']['BootOrder'] == order
    assert ri['before']['settings_boot']['BootOrder'] == order
    for row in [rb, ra]:
        assert row['system']['PowerState'] == 'Off' and row['power']['data']['power_status'] == 0
        assert row['settings']['Boot']['BootNext'] is None and row['system']['Boot']['BootNext'] is None
    assert stamp(after_cleanup['utc']) < stamp(ri['utc']) < stamp(first_down['utc']) < stamp(recovery['utc']) < stamp(ra['utc'])
    report = {
        'status': 'REVIEWED_HISTORICAL_CD_WINDOW_HELPER05_AND_SECOND_BMC_RESTART',
        'reviewed_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Offline review of already saved records only. Not a new hardware operation, not current machine state, and not final C08 cleanup.',
        'inputs': {k: binding(v) for k, v in inputs.items()},
        'cd_observer': {
            'window_start_utc': summary['started_utc'], 'window_end_utc': summary['finished_utc'],
            'metadata_events': len(trace), 'protocol_frames': len(frames), 'sockets': 1,
            'truncated': False, 'incomplete_bytes_at_close': 0, 'counts': counts,
            'connection_status': 1, 'capacity8_hex': caps[0]['capacity8'], 'last_lba': cd_last,
            'block_bytes': cd_block, 'capacity_bytes': (cd_last + 1) * cd_block,
            'matches_pinned_p04_iso_length': True, 'read10_seen': False, 'read12_seen': False,
            'cd_f7_sent_utc': next(x['utc'] for x in frames if x['opcode'] == 'f7'),
            'cd_socket_closed_utc': trace[-1]['utc'],
            'source_review': 'Passive event listeners only; all framed opcodes are recorded. CDBs and the exact eight-byte RC10 response are whitelisted; auth/session/file/read bodies are excluded. Limits are ten minutes, 4096 events, 262144 bytes per frame/chunk and 524288 buffered bytes per direction.',
            'author_local_cases': 6, 'independent_local_cases': 12,
            'case_count_caveat': 'Overlapping tests, not a count of unique coverage. Independent fixtures are EventEmitters, never remote sessions.',
            'original_h5_cross_review_bindings_verified': len(cd_native_rows),
            'original_h5_cross_review': 'The separately frozen original-code review identifies the startup opcode25 sent by WebSocketProxy after F1 and the worker READ12 opcodeA8. Its eight synthetic ARM branch cases were read and bound here, not independently rerun; they do not prove live BMC backend state.',
            'interpretation': 'The browser-to-BMC session reports a capacity response matching the ISO length. The initial RC10 can be proxy startup work, not a host-issued query. No READ(10) or READ(12) is observed in this bounded complete trace. This is not proof of host optical enumeration, sector reads or EFI execution.'
        },
        'screen_review': {
            'method': 'Original saved PNGs viewed directly; no image modification or inferred OCR-only conclusion.',
            'screen_276_and_277': 'Byte-identical original Aptio Setup Exit page. This page itself does not display BIOS release 1904; the operation readback supplies the release check.',
            'screen_279': 'Boot menu has four PXE entries, Rocky Linux and UEFI OS entries on the Samsung 240 GB disk, and Enter Setup. No CD entry is visible. Browser media label names P04 ISO and Stop Media.',
            'screen_280': 'Same boot menu remains visible immediately before recorded ForceOff; browser media label now says Start Media with no chosen file.',
            'p04_execution_evidence_in_these_screens': False,
            'limits': 'No visible CD entry does not identify its cause or prove every unobserved moment. The displayed 1 KB/2 KB media label is not the ISO file length.'
        },
        'helper05': {
            'started_utc': h['started_utc'], 'finished_utc': h['finished_utc'],
            'source_sha256': h['script_sha256'], 'authenticated': True,
            'frames': 4, 'opcode_counts': h['opcode_counts'],
            'capacity_response_utc': hd['utc'], 'capacity8_hex': hd['capacity8_hex'],
            'capacity_bytes': 16777216, 'host_new_capacity_observation': False,
            'normal_f7_sent_utc': d['sent_utc'], 'normal_f7_attempts': 1,
            'sendall_returned': True, 'peer_eof_observed': True, 'drain_elapsed_seconds': d['drain_elapsed_seconds'],
            'protocol_ack_validated': False, 'server_slots_cleared_verified': False,
            'backend_read_calls': 0, 'backend_write_calls': 0, 'backend_flush_calls': 0,
            'backend_written_bytes': 0, 'image_bytes': h['final_image_bytes'],
            'image_sha256_at_completion_and_local_review': h['final_image_sha256'],
            'socket_closed': True, 'image_closed': True,
            'interpretation': 'The exact pinned helper recorded one normal F7 send and peer EOF after 0.04759 s, then socket/image closure. This confirms its transport observation only; it does not establish an acknowledged slot clear, corrected geometry, file writeback or backup.'
        },
        'cleanup_at_that_time': {
            'before_utc': before_cleanup['utc'], 'after_utc': after_cleanup['utc'],
            'reported_verified': after_cleanup['verified'], 'media_flags': {'HD': 128, 'CD': 128},
            'interpretation': 'Readback shows native host Off, browser CD detached, helper ownership cleared, and both media flags at the reviewed idle value at 11:08:46. These flags are not an independent inspection of internal media-slot backing storage, and do not assert state after later actions.'
        },
        'second_bmc_restart': {
            'intent_utc': ri['utc'], 'accepted_utc': rr['finished_utc'], 'http_status': 202,
            'task_location': rr['task_location'], 'post_attempts': 1,
            'first_failed_public_https_sample_utc': first_down['utc'], 'first_recovered_public_https_sample_utc': recovery['utc'],
            'post_restart_readback_utc': ra['utc'], 'host_off_in_both_readbacks': True,
            'boot_order_six_entries_unchanged': True, 'boot_order': order,
            'settings_override_before': sb, 'settings_override_after': sa,
            'active_override_before': ab, 'active_override_after': aa,
            'settings_override_all_three_unchanged': False,
            'settings_override_enabled_remained_disabled': True,
            'interpretation': 'The standard BMC restart was accepted and public HTTPS was later observed down then recovered. Host Off and six-entry BootOrder agree in before/after readbacks. The SD shadow mode/target changed from Legacy/None to UEFI/Cd while Enabled stayed Disabled; all-three-field restoration did not persist. The cause is unproven, and later restoration is a separate record.'
        },
        'no_claims': ['No new P04 execution or native password/entry hardware result from this evidence.',
                      'No proven HD geometry repair, successful writeback, SPI backup, flash trust or recovery path.',
                      'No inference that F7 or BMC restart caused or fixed the missing CD boot entry.',
                      'No claim about the current host/media/SD state after the final bound timestamp.'],
        'reviewer_remote_operations': 0, 'publication08_complete': False, 'release_ready': False,
    }
    dump(HERE / 'physical_review.json', report)
    text = (
        '这份补充只核对已保存的历史证据，未连接 BMC，也不是 C08 最终清理记录。\n\n'
        'CD 观察窗口为 11:01:27–11:06:40 UTC：34 个元数据事件中有 32 帧，未截断。认证状态为 1，容量响应 0000201f00000800 换算为 16,842,752 字节，与冻结 P04 ISO 长度一致；窗口内未观察到 READ(10) 或 READ(12)。原厂 H5 代码交叉审查表明，最初的 RC10 可由代理启动流程主动发出，不能当成主机发出的查询。原图 279 的启动菜单没有 CD 条目，只有四个 PXE、Rocky Linux、UEFI OS 和 Enter Setup。这些证据没有建立 P04 实机执行结果，也未确定缺少光驱条目的原因。\n\n'
        '11:08:04–11:08:14 的 helper05 只处理控制命令，读、写、flush 均为 0。它发送一次正常 F7 后，0.04759 秒内观察到对端 EOF，随后关闭 socket/image；本地 16 MiB 测试镜像仍为原哈希。sendall 返回、EOF 和内部槽位清除是不同证据，protocol_ack_validated 与 server_slots_cleared_verified 仍为 false。正确的 HD 容量响应只是客户端发送值，不是主机端重新读到的容量。\n\n'
        '11:08:46 的清理回读显示当时主机 Off、CD 已脱离、自己持有的 helper 已解除、HD/CD 标志为已审核的空闲值 128。随后第二次标准 BMC 重启获 202/Task20，公共 HTTPS 在 11:09:24 首次失败、11:11:19 首次恢复。11:13:11 的回读仍为主机 Off、六项 BootOrder 不变，但 SD 的 Mode/Target 从 Legacy/None 变为 UEFI/Cd，Enabled 保持 Disabled。因此不能宣称三个恢复字段在 BMC 重启后都保持；原因尚未证明。之后的恢复和当前状态另行记录。\n\n'
        '观察器源码与父任务六项测试已核对，本地再用原模块完成 12 项纯 EventEmitter 测试，包括 READ12 opcode、分片、合帧、认证/数据体排除、错误方向隔离、容量长度约束和数量/时间上限。这些测试有重叠，不累加称作独立覆盖。\n\n'
        '仍缺原生独立密码/入口拦截实测、正确 HD 几何与 SPI 备份，以及实际刷写信任和恢复验证。release_ready=false；最终 publication08 尚待父任务完成本轮清理。\n'
    )
    with (HERE / 'README.txt').open('x', encoding='utf8', newline='\n') as stream:
        stream.write(text)
    artifact_paths = sorted(p for p in HERE.rglob('*') if p.is_file() and p.name != 'manifest.json')
    manifest = {'status': 'FROZEN_HISTORICAL_SUPPLEMENT_NOT_C08_FINAL',
                'inputs': [binding(p) for p in inputs.values()],
                'artifacts': [binding(p) for p in artifact_paths],
                'review_sha256': sha(HERE / 'physical_review.json'),
                'scope': 'Bindings, not unique coverage. Recheck the disposable image separately after any later use. No changes to previous frozen reports.'}
    dump(HERE / 'manifest.json', manifest)
    verify()


if __name__ == '__main__':
    main()
