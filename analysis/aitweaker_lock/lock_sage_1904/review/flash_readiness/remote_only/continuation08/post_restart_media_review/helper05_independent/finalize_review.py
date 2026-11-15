"""Freeze independent helper05 source/evidence review; no target operations."""
from pathlib import Path
import argparse, hashlib, json, zipfile

HERE = Path(__file__).resolve().parent
REMOTE = HERE.parents[2]
AUTHOR = REMOTE / 'media_disconnect_client05_review'
ROOT = next(p for p in HERE.parents if (p / 'tools').is_dir())
SOURCE_SHA = '5dffcd939577ad7faf460a9bbd9ebf2065ebf1d9664b9a8ac41ef7d296c07e75'
OP_SHA = '381a1fa3d2bbe49d4d29f7671f35a5fd03077ab22889e0860ae4d50bbcff7af3'
AUTHOR_MANIFEST_SHA = 'cec421f0d500840f7e36635417dc319ed9c01973dcad5d5718ff07abdd3479ee'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf8'))
bound = lambda p: {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}


def check(row, base):
    path = Path(row['path']); path = (path if path.is_absolute() else base / path).resolve()
    assert path.is_relative_to(ROOT.resolve())
    assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], path


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--verify-only', action='store_true'); args = parser.parse_args()
    manifest = AUTHOR / 'manifest.json'; review = AUTHOR / 'helper05_review.json'
    assert sha(manifest) == AUTHOR_MANIFEST_SHA
    authored = load(review); rows = load(manifest)['files']
    assert len(rows) == 41 and len(authored['inputs']) == 15
    for row in rows: check(row, AUTHOR)
    for row in authored['inputs']: check(row, AUTHOR)
    for row in authored['frozen_prior_inputs_unchanged']: check(row, AUTHOR)
    if args.verify_only:
        own = load(HERE / 'manifest.json')
        for row in own['files']: check(row, HERE)
        print(json.dumps({'status': 'PASS_FROZEN_HELPER05_INDEPENDENT_REVIEW_RECHECK', 'author_local_bindings': 41, 'external_bindings': 15, 'independent_artifacts': len(own['files']), 'manifest_sha256': sha(HERE / 'manifest.json')}))
        return
    source = Path(authored['inputs'][0]['path']); operation = Path(authored['inputs'][1]['path'])
    assert sha(source) == SOURCE_SHA and sha(operation) == OP_SHA
    with zipfile.ZipFile(REMOTE / 'media_writeback_review/JViewer.jar') as jar:
        for name, expected in authored['vendor_java_class_sha256'].items():
            assert hashlib.sha256(jar.read(name)).hexdigest() == expected
    tests = {}
    result_hashes = {row['sha256'] for row in rows if row['path'].endswith('result.json')}
    for name, count in [('helper_tests.json', 31), ('session_tests.json', 18), ('arm_f7_tests.json', 4)]:
        path = AUTHOR / name; report = load(path)
        assert report['status'] == 'PASS' and report['cases'] == len(report['results']) == count
        assert all(row['status'] == 'PASS' for row in report['results'])
        assert report['helper_sha256'] == SOURCE_SHA
        assert sha(path) == authored['tests'][name]['sha256']
        tests[name] = {'source_result': bound(path), 'cases': count}
        if name == 'helper_tests.json':
            for case in report['results']:
                if 'result' in case:
                    assert case['result']['protocol_ack_validated'] is False and case['result']['server_slots_cleared_verified'] is False
                if 'result_sha256' in case:
                    assert case['result_sha256'] in result_hashes
                    timeline = case['timeline']
                    sends = [i for i, event in enumerate(timeline) if event == ['send', 247]]
                    if sends:
                        assert len(sends) == 1
                        assert sends[0] < next(i for i, event in enumerate(timeline) if event[0] == 'socket_close')
                        assert sends[0] < next(i for i, event in enumerate(timeline) if event[0] == 'image_close')
        if name == 'session_tests.json': assert report['operation_sha256'] == OP_SHA
        if name == 'arm_f7_tests.json':
            assert all(case['network_or_device_operations_executed'] == 0 for case in report['results'])
    independent = load(HERE / 'independent_stop_tests.json')
    assert independent['helper_sha256'] == SOURCE_SHA and independent['cases'] == 15
    assert all(row['passed'] for row in independent['results']) and independent['network_constructors_reached'] == 0
    source_text = source.read_text(encoding='utf8')
    assert "report['normal_disconnect'] = graceful_disconnect(sock, engine, report['end_reason'])" in source_text
    op_text = operation.read_text(encoding='utf8')
    assert "const HELPER_SHA256='" + SOURCE_SHA + "'" in op_text and 'windowsHide:true' in op_text
    report = {
        'status': 'PASS_INDEPENDENT_OFFLINE_REVIEW_HELPER05_NORMAL_DISCONNECT',
        'source': bound(source), 'owning_operation': bound(operation),
        'author_manifest': bound(manifest), 'author_review': bound(review),
        'author_local_bindings_verified': 41, 'external_input_bindings_verified': 15,
        'prior_unchanged_bindings_verified': len(authored['frozen_prior_inputs_unchanged']),
        'vendor_jar_class_hashes_verified': 4,
        'author_tests_reviewed': tests, 'author_tests_total': 53,
        'independent_stop_function_tests': bound(HERE / 'independent_stop_tests.json'), 'independent_cases': 15,
        'unresolved_blocking_findings_for_reviewed_scope': [],
        'reviewed_normal_path': [
            'Only parent_stop or lifetime_limit can attempt normal F7, and only for the exact active owned engine with instance 0, active session and open image.',
            'A fresh zeroed writer generates the public 62-byte vendor-compatible F7 control command. Retained authentication key/token/old response data is not copied.',
            'Exactly one send attempt, inside the TLS context before its automatic close. Send timeout is 1 second.',
            'After sendall succeeds, receive-only observation is bounded by 2 seconds and 16384 bytes; received bytes are counted and discarded, without image I/O or replies.',
            'TLS socket closes on scope exit, then engine/image closure and final local report run. Abnormal/auth/peer/server stops do not retry or initiate a reconnect.'
        ],
        'operation_review': [
            'Start requires observed host Off, CD detached, idle HD/CD, a unique authorized cookie, fresh token, and the exact helper hash; Off and CD detached are rechecked immediately before spawn.',
            'The helper path is fixed and runs in a hidden child. Credentials travel through stdin, not argv or saved result fields.',
            'Only the operation that owns helper05 version/hash can stop it. It sends STOP, waits at most 10 seconds for the child, and refuses to claim closure while exitCode remains null.',
            'Process closure, finished report, F7 send success, and actual BMC media cleanup are separate observations. The operator must inspect nested normal_disconnect plus fresh standard readbacks.'
        ],
        'redaction_review': [
            'Persisted frame records are whitelisted metadata; payload, authentication key, token and other-user IP are omitted.',
            'Disconnect failures log only exception type. Pinned Reject paths use fixed public messages.',
            'Independent ACK-shaped and secret-bearing drain data did not become logs or acknowledgement claims; deliberate old writer/auth contamination did not alter the fixed F7 frame.'
        ],
        'interpretation_limits': [
            'sendall returning proves only that local sendall returned; peer EOF proves only transport closure. protocol_ack_validated and server_slots_cleared_verified remain false in every disconnect path.',
            'The outer SESSION_ENDED_WITHOUT_PROTOCOL_ERROR can coexist with nested SEND_OR_DRAIN_IO_FAILURE. Read the nested result; the outer label is not a cleanup-success flag.',
            'Reviewed future workflow is a bounded own-helper start/stop while host Off and CD detached, with idle-media preconditions and subsequent standard readbacks. The stop branch itself does not query the host; maintaining that workflow boundary is the parent operator responsibility.',
            'Original ARM receiver/dispatch and Java serialization evidence is locally checked; NBD/gadget/thread/socket/device boundaries in the ARM tests are stubs. It does not prove this BMC actually clears a backing slot.',
            'No real TLS session, BMC request, image backend write or device action occurred in this independent review. Nothing here establishes geometry correction, optical boot recovery, file writeback, backup or flash readiness.'
        ],
        'live_result': None, 'device_operations_by_reviewer': 0, 'publication08_complete': False,
    }
    (HERE / 'independent_review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    (HERE / 'README.txt').write_text('''Helper05 正常 F7 断开流程的独立离线审查通过，限定范围没有未解决阻断问题。

已核验作者冻结的 41 项本地、15 项外部输入、5 项旧文件绑定和 4 个原厂 JAR 类。审阅作者 31+18+4 共 53 项测试，另独立执行 15 项停止函数测试；覆盖范围有重叠，不能相加作为覆盖率。独立测试禁止网络构造器，实际连接次数为 0。

F7 在 TLS 关闭前最多发送一次；发送限时 1 秒，随后最多接收观察 2 秒或 16384 字节。停止期间不处理镜像读写、不回复、不重连。新控制帧没有带入旧认证 key、token 或旧响应数据；异常只记录类型，收到的数据不写入日志。

sendall 返回、对端 EOF、进程退出和 BMC 后端清理成功不是同一个结果。ACK 与槽位清理确认字段始终为 false；外层 SESSION_ENDED_WITHOUT_PROTOCOL_ERROR 也可能伴随内层发送/接收失败，必须检查 normal_disconnect。实际 NBD/gadget 清理仍需父任务在受审状态下运行并读取标准状态，不能从离线 ARM/Java 夹具推断已清理。

本次审查支持的后续流程是主机 Off、CD 已断开时启动并停止自有 helper，随后核对新结果与标准媒体状态。start 会检查这些门槛；stop 本身不查询主机电源，需由父任务保持流程边界。本审查没有连接设备，也未改变 C07、主 publisher 或任何冻结候选。
''', encoding='utf8')
    own = {'status': 'FROZEN_INDEPENDENT_HELPER05_REVIEW', 'author_manifest_sha256': AUTHOR_MANIFEST_SHA,
           'review_sha256': sha(HERE / 'independent_review.json'),
           'files': [bound(path) for path in sorted(HERE.iterdir()) if path.is_file() and path.name != 'manifest.json']}
    (HERE / 'manifest.json').write_text(json.dumps(own, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'status': report['status'], 'independent_artifacts': len(own['files']), 'review_sha256': sha(HERE / 'independent_review.json'), 'manifest_sha256': sha(HERE / 'manifest.json')}, indent=2))


if __name__ == '__main__': main()
