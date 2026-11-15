"""Build a new EXP02 release from verified inputs. Never flash or access a BMC.

The exact HISTORY01-tested production driver is required. Hardware RAM tests,
OVMF persistence tests and an integrated ASUS image have distinct claims.
Existing releases are immutable; --check-only performs no output writes.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import html
import json
import re
import struct
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RELEASE = 'EXP02'
TARGET = 'ASUS Pro WS W790E-SAGE SE BIOS 1904'
SOURCE_SHA = 'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
DRIVER_SHA = 'da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
HISTORY_ISO_SHA = '217eb8a427883a0feddd0ae119329b5d68577040d71b05b9e327aedff4e3f81f'
HARDWARE_LOG_SHA = '041df80c8a06a8d00885db5427df0b5bf9d5a0fb8839ec22aa4b2d7111411b75'
MODULE_SHA = {
    'Setup': '719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d',
    'AMITSE': '531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1',
}
SOURCE = HERE.parent/'official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
CANDIDATE = HERE/'lab/asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin'
REMOTE = HERE/'remote_172_20_2_162'
CAPTURE = REMOTE/'hardware-p4-1793666523615'
OUT = ROOT/'W790E-SAGE-SE-1904-AiTweaker密码BIOS-EXP02-UNSIGNED'
NAME = 'Pro-WS-W790E-SAGE-SE-1904-AiTweakerLock-EXP02-UNSIGNED.CAP'
DELIVERY = HERE/'bios_delivery_exp02.json'
FRAME = re.compile(rb'AITWK-P3-KVM\nT=([0-9]+);C=([0-9A-F]{8});P=([0-9]+)/([0-9]+);O=([0-9]+);N=([0-9]+);D=([0-9A-F]{8})\n\n')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False)+'\n').encode('utf8')


def safe_path(root, relative):
    root = Path(root).resolve()
    path = (root/relative).resolve()
    require(path.is_relative_to(root) and path != root, f'Path outside evidence root: {relative}')
    return path


def new_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(content)


def checked_archive(path, members):
    """members maps archive names to immutable bytes or existing file paths."""
    require(not Path(path).exists(), f'Refusing to overwrite archive: {path}')
    expected = {}
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, value in sorted(members.items()):
            require(name and not name.startswith('/') and '\\' not in name and '..' not in name.split('/'), f'Invalid ZIP member: {name}')
            data = value if isinstance(value, bytes) else Path(value).read_bytes()
            expected[name] = hashlib.sha256(data).hexdigest()
            archive.writestr(name, data)
    with zipfile.ZipFile(path) as archive:
        require(archive.testzip() is None, 'ZIP CRC failure')
        require(set(archive.namelist()) == set(expected), 'ZIP inventory mismatch')
        for name, digest in expected.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == digest, f'ZIP content mismatch: {name}')


def compare_coff_object(hardware_path, current_path, expected_hardware_sha):
    """Only standard AMD64 COFF FileHeader.TimeDateStamp may differ.

    No section, relocation, symbol, string-table or other header byte is ignored.
    The original archived object still has to match its raw hardware-build hash.
    """
    hardware, current = hardware_path.read_bytes(), current_path.read_bytes()
    require(hashlib.sha256(hardware).hexdigest() == expected_hardware_sha, f'Hardware object archive changed: {hardware_path.name}')
    for data in [hardware, current]:
        require(len(data) >= 20, 'Truncated COFF object')
        machine, sections, _, _, _, optional_size, _ = struct.unpack_from('<HHIIIHH', data)
        require(machine == 0x8664 and optional_size == 0 and 0 < sections <= 4096 and 20+40*sections <= len(data), 'Expected ordinary AMD64 COFF object')
    require(len(hardware) == len(current) and hardware[:4] == current[:4] and hardware[8:] == current[8:], f'Hardware executable/object content differs: {current_path.name}')
    normalized = hardware[:4]+bytes(4)+hardware[8:]
    return {
        'hardware_raw_sha256': expected_hardware_sha,
        'production_raw_sha256': hashlib.sha256(current).hexdigest(),
        'sha256_with_only_coff_timestamp_zeroed': hashlib.sha256(normalized).hexdigest(),
        'hardware_coff_timestamp': int.from_bytes(hardware[4:8], 'little'),
        'production_coff_timestamp': int.from_bytes(current[4:8], 'little'),
        'only_permitted_difference': 'AMD64 COFF FileHeader.TimeDateStamp, bytes [4,8)',
        'all_other_bytes_identical': True,
    }


def verify_hardware(driver_sha):
    notes_path = REMOTE/'history01_hardware_notes.json'
    notes, cleanup = read(notes_path), read(REMOTE/'cleanup.json')
    binding = notes['build_binding']
    require(notes['build_identifier'] == 'HISTORY01', 'Wrong hardware test revision')
    require(binding['candidate_driver_sha256'] == driver_sha == DRIVER_SHA, 'Hardware/production driver mismatch')
    require(binding['iso_sha256'] == HISTORY_ISO_SHA, 'Wrong hardware test ISO')
    media = REMOTE/'ram_test_history01'
    require(sha(media/'AiTweaker-SAGE-P5-History01-RAM-Test.iso') == HISTORY_ISO_SHA, 'Hardware ISO changed')
    require(sha(media/'build.json') == binding['build_manifest_sha256'], 'Hardware build record changed')
    ram_build = read(media/'build.json')
    require(ram_build['candidate_driver_sha256'] == driver_sha, 'Hardware candidate identity mismatch')
    require(sha(media/'candidate-relinked.efi') == driver_sha, 'Hardware candidate relink mismatch')
    require(sha(media/'BOOTX64.EFI') == binding['efi_sha256'] == ram_build['efi_sha256'], 'Hardware application changed')
    require(sha(media/'source-snapshot.zip') == binding['source_archive_sha256'] == ram_build['source_archive_sha256'], 'Hardware source archive changed')
    expected_objects = {'services', 'cpu_entropy', 'ui', 'policy', 'hii', 'platform',
                        'password_core', 'password_crypto', 'probe_core'}
    require(set(ram_build['linked_objects']) == expected_objects, 'Hardware linked-object inventory changed')
    object_bindings = {}
    for name, digest in ram_build['linked_objects'].items():
        archived = media/('candidate_objects' if name == 'platform' else 'production_objects')/(name+'.obj')
        object_bindings[name] = compare_coff_object(archived, HERE/'driver/build'/(name+'.obj'), digest)
    entry_binding = compare_coff_object(media/'production_objects/entry.obj', HERE/'driver/build/entry.obj', ram_build['production_objects']['entry'])
    harness_sources = {}
    for name in ['ram_lock_test.c', 'kvm.c', 'target_detect.h']:
        digest = ram_build['source_hashes'][name]
        require(sha(media/'source'/name) == digest, f'HISTORY01 harness source changed: {name}')
        harness_sources[name] = digest
    production_build = read(HERE/'driver/build/build.json')
    source_bindings = {}
    for name, digest in production_build['sources'].items():
        relative = Path(name).as_posix()
        archived_name = 'history_candidate/platform.c' if relative == 'driver/platform.c' else 'production/'+relative
        require(ram_build['source_hashes'][archived_name] == digest and sha(safe_path(media/'source', archived_name)) == digest, f'Hardware compiled-source mismatch: {name}')
        source_bindings[relative] = {'sha256': digest, 'hardware_source': archived_name}
    for name, digest in production_build['external_sources'].items():
        archived_name = 'p3/'+Path(name).name
        require(ram_build['source_hashes'][archived_name] == digest and sha(safe_path(media/'source', archived_name)) == digest, f'Hardware external source mismatch: {name}')
        source_bindings[Path(name).as_posix()] = {'sha256': digest, 'hardware_source': archived_name}
    manifest = read(CAPTURE/'manifest.json')
    require(manifest['pages'] == 8 and manifest['bytes'] == 5856 and manifest['crc32'] == '9F2B8F75', 'Wrong final capture')
    expected_files = {'hardware-log.txt'} | {f'page-{n:02d}.{suffix}' for n in range(1, 9) for suffix in ['frame', 'png']}
    require(set(manifest['files']) == expected_files, 'Unexpected capture inventory')
    for name, digest in manifest['files'].items():
        require(sha(safe_path(CAPTURE, name)) == digest, f'Capture file changed: {name}')
    pieces = []
    for page in range(1, 9):
        raw = (CAPTURE/f'page-{page:02d}.frame').read_bytes()
        match = FRAME.match(raw)
        require(match is not None, 'Malformed QR frame')
        total, crc, number, pages, offset, size, chunk_crc = match.groups()
        data = raw[match.end():]
        require((int(total), int(number), int(pages), int(offset)) == (5856, page, 8, (page-1)*768), 'QR page bounds mismatch')
        require(int(size) == len(data) == min(768, 5856-int(offset)), 'QR page length mismatch')
        require(int(crc, 16) == 0x9F2B8F75 and zlib.crc32(data) == int(chunk_crc, 16), 'QR CRC mismatch')
        pieces.append(data)
    log = b''.join(pieces)
    require(log == (CAPTURE/'hardware-log.txt').read_bytes() and hashlib.sha256(log).hexdigest() == HARDWARE_LOG_SHA, 'Final hardware log mismatch')
    require(zlib.crc32(log) == 0x9F2B8F75 and manifest['sha256'] == HARDWARE_LOG_SHA, 'Whole-log integrity mismatch')
    lines = log.decode('ascii').splitlines()
    require('Build=HISTORY01' in lines and 'CandidateDriverSHA256='+driver_sha in lines, 'Live build identifier mismatch')
    require('ExitChoice=SHUTDOWN' in lines and lines[-1] == 'PROBE_COMPLETE', 'Incomplete final log')
    counters = {key: int(next(line.split('=', 1)[1] for line in lines if line.startswith(key+'=')), 16)
                for key in ['Checks', 'Failures', 'BlockedSetVariableCalls']}
    require(counters == {'Checks': 50, 'Failures': 0, 'BlockedSetVariableCalls': 98}, 'Hardware counters mismatch')
    require(sum(line.startswith('PASS ') for line in lines) == 50 and not any(line.startswith('FAIL ') for line in lines), 'Hardware check lines mismatch')
    require(lines.count('PASS variable metadata and SHA256 unchanged') == 30, 'Variable comparison count mismatch')
    require(len(notes['sendform_returns']) == 8 and all(row[k] == 0 for row in notes['sendform_returns'] for k in ['status', 'action_request', 'active_after_return', 'unlocked_after_return']), 'Unexpected hardware browser return')
    require(notes['conclusions']['all_cancellations_return_to_Main'] is False, 'Cancellation limitation missing')
    require(notes['conclusions']['persistent_lock_or_flash_readiness_established'] is False, 'Hardware scope overstated')
    require(notes['conclusions']['baseline_history_defect_retest'].startswith('PASS') and notes['conclusions']['ram_password_enroll_unlock_session_relock_and_clear'].startswith('PASS'), 'Hardware review reports a functional failure')
    noted_log = next(row for row in notes['logs'] if row['sha256'] == HARDWARE_LOG_SHA)
    require(noted_log['checks'] == 50 and noted_log['failures'] == 0 and noted_log['blocked_setvariable_calls'] == 98, 'Independent review counters mismatch')
    for name, digest in notes['screenshot_sha256'].items():
        require(name.startswith('screen-') and name.endswith('.png'), 'Unexpected hardware evidence kind')
        require(sha(safe_path(REMOTE, name)) == digest, f'Hardware screenshot changed: {name}')
    require(cleanup['status'] == 'REMOTE_TEST_SESSION_CLOSED' and cleanup['final_power_state'] == 'Off', 'Hardware cleanup incomplete')
    require(cleanup['virtual_media_detached'] is True and cleanup['boot_override_disabled'] is True, 'Temporary media or override remains')
    require(cleanup['flash_performed'] is False and cleanup['persistent_password_created'] is False, 'Wrong hardware test scope')
    require(cleanup['original_boot_relative_order_preserved'] is True, 'Original boot order changed')
    original = cleanup['original_boot_order']
    require([item for item in cleanup['final_reported_boot_order'] if item in original] == original, 'Boot order summary inconsistent')
    # Deliberately exclude controller identifiers, raw HTTP/session evidence and
    # arbitrary remote-directory files from both releases.
    clean = {key: cleanup[key] for key in [
        'status', 'recorded_utc', 'original_power_state', 'final_power_state',
        'power_evidence_note', 'virtual_media_detached', 'credential_cleanup',
        'persistent_password_created', 'flash_performed', 'boot_override_disabled',
        'original_boot_relative_order_preserved', 'boot_order_byte_identical',
        'original_boot_order', 'final_reported_boot_order', 'boot_note']}
    clean['source_sha256'] = sha(REMOTE/'cleanup.json')
    clean['source_export'] = 'Selected audit fields only; no controller or HTTP session records.'
    summary = {
        'build': 'HISTORY01', 'driver_sha256': driver_sha, 'iso_sha256': HISTORY_ISO_SHA,
        'scope': 'RAM-only password and native FormBrowser2 invocation; no modified firmware was flashed.',
        'final_log_sha256': HARDWARE_LOG_SHA, 'qr_pages': 8, 'bytes': 5856, 'crc32': '9F2B8F75',
        'automatic_checks': 50, 'automatic_failures': 0, 'blocked_setvariable_calls': 98,
        'selected_variable_comparisons': 30, 'comparison_rounds': 10,
        'history_path_retest': notes['conclusions']['baseline_history_defect_retest'],
        'alternate_cancel_behavior': 'Favorites, ASUS Profile, Overclocking Presets and Memory Presets initial-entry cancel exits SendForm to the test menu, rather than remaining on Main.',
        'all_cancel_paths_return_to_Main': False,
        'asus_persistent_storage_tested': False, 'asus_direct_del_dispatch_tested': False,
        'firmware_flash_tested': False, 'notes_sha256': sha(notes_path),
        'hardware_to_production_object_binding': object_bindings,
        'candidate_relink_entry_binding': entry_binding,
        'hardware_to_production_source_binding': source_bindings,
        'hardware_harness_source_sha256': harness_sources,
        'binding_scope': 'Nine linked objects match every byte except the specifically parsed COFF compilation timestamp. Archived raw hashes and matching source hashes are retained; reconstructed complete candidate EFI exactly matches the production driver. RAM harness replaces persistence callbacks and does not execute production entry dispatch.',
    }
    return notes, summary, clean


def validate_release():
    driver = HERE/'driver/build/AiTweakerLock1904.efi'
    driver_sha, cap_sha = sha(driver), sha(CANDIDATE)
    require(driver_sha == DRIVER_SHA, 'EXP02 must use the exact HISTORY01-tested driver')
    require(sha(SOURCE) == SOURCE_SHA and SOURCE.stat().st_size == CANDIDATE.stat().st_size == 0x4001000, 'Original/candidate size or identity mismatch')
    with SOURCE.open('rb') as a, CANDIDATE.open('rb') as b:
        require(a.read(4096) == b.read(4096), 'Original capsule header was not preserved')
    require(cap_sha != SOURCE_SHA, 'Candidate is unchanged original firmware')
    for name, digest in MODULE_SHA.items():
        require(sha(HERE/f'analysis/modules/{name}.efi') == digest, f'Wrong {name} module')
    build_path = HERE/'driver/build/build.json'
    build = read(build_path)
    require(build['board'] == 'Pro WS W790E-SAGE SE' and build['bios'] == '1904' and build['efi_sha256'] == driver_sha, 'Production build identity mismatch')
    for name, digest in build['sources'].items():
        require(sha(safe_path(HERE, name)) == digest, f'Compiled source changed: {name}')
    for name, digest in build['external_sources'].items():
        require(sha(safe_path(ROOT, name)) == digest, f'External compiled source changed: {name}')
    reports = {name: HERE/path for name, path in {
        'firmware_structure': 'lab/asus_review_exp02/verification.json',
        'policy': 'driver/build/policy_test.json', 'adapter': 'driver/build/adapter_emulation.json',
        'history_regression': 'driver/build/history_regression.json',
        'entropy': 'driver/build/entropy_test.json', 'hii_abi': 'driver/build/hii_abi_test.json',
        'target_identity': 'driver/build/identity_test.json', 'uefi_integration': 'driver/build/vm_integration.json',
    }.items()}
    evidence = {name: read(path) for name, path in reports.items()}
    for name, report in evidence.items():
        require(report.get('driver_sha256', report.get('driver_efi_sha256')) == driver_sha, f'Stale driver-bound report: {name}')
        require(report.get('status') == 'PASS' or report.get('all_passed') is True or report.get('passed') is True, f'Failed report: {name}')
    firmware = evidence['firmware_structure']
    require(firmware['candidate_sha256'] == cap_sha and firmware['inserted_driver_pe32_exact_match'] is True, 'Integrated driver identity mismatch')
    require(firmware['source_capsule_unchanged'] is True and firmware['contains_original_signature_without_resigning'] is True, 'Incorrect source/signature assertion')
    require(firmware['hardware_boot_and_capsule_acceptance_verified'] is False, 'Firmware report overstates hardware validation')
    candidate_manifest = read(CANDIDATE.with_suffix('.json'))
    require(candidate_manifest['fixture_only'] is False and candidate_manifest['driver_sha256'] == driver_sha and candidate_manifest['candidate_sha256'] == cap_sha, 'Wrong firmware manifest')
    require(candidate_manifest['source_capsule_sha256'] == SOURCE_SHA and candidate_manifest['capsule_signature_valid'] is False, 'Incorrect capsule signing scope')
    require(evidence['adapter']['amitse_sha256'] == MODULE_SHA['AMITSE'], 'Adapter tested wrong AMITSE')
    history = evidence['history_regression']
    require(history['checks'] == history['cases'] == len(history['check_names']) == 131, 'Incomplete history regression')
    require(history['hardware_history01_driver_sha256'] == driver_sha and history['original_amitse_sha256'] == MODULE_SHA['AMITSE'] and history['original_setup_sha256'] == MODULE_SHA['Setup'], 'History regression identity mismatch')
    require(history['build_manifest_sha256'] == sha(build_path) and history['linker_map_sha256'] == sha(HERE/'driver/build/driver.map'), 'History regression build binding mismatch')
    require(history['compiled_source_sha256'] == build['sources'], 'History regression source set mismatch')
    require(history['external_source_sha256'] == build['external_sources'], 'History external source set mismatch')
    for name, digest in history['verification_source_sha256'].items():
        require(sha(safe_path(HERE/'driver', name)) == digest, f'History verifier changed: {name}')
    native, core, policy = read(HERE/'lab/native_hooks_result.json'), read(HERE/'core/test_report.json'), read(HERE/'driver/policy.json')
    require(native['all_passed'] is True and native['module_sha256'] == MODULE_SHA['AMITSE'], 'Native hook evidence mismatch')
    require(core['status'] == 'PASS', 'Password core failed')
    for name, digest in core['sources'].items():
        require(sha(safe_path(HERE/'core', name)) == digest, f'Core source changed: {name}')
    require(sha(HERE/'core/verify_core.py') == core['test_source_sha256'], 'Core verifier changed')
    require(policy['form_count'] == 28 and policy['question_count'] == 1992 and policy['source_ifr_sha256'] == sha(HERE/'analysis/modules/Setup_IFR.json'), 'SAGE policy identity mismatch')
    vm, binding = evidence['uefi_integration'], read(HERE/'driver/build/vm_build.json')
    require(vm['fixture_sha256'] == sha(HERE/'driver/build/VM-INTEGRATION-ONLY.EFI') == binding['fixture_sha256'], 'VM fixture mismatch')
    require(binding['driver_sha256'] == driver_sha and binding['production_build_sha256'] == sha(build_path), 'VM production binding mismatch')
    require(vm['fixture_build_manifest_sha256'] == sha(HERE/'driver/build/vm_build.json'), 'VM report binding changed')
    for name, key in [('vm_fixture.c', 'fixture_source_sha256'), ('build_vm.py', 'build_script_sha256')]:
        require(sha(HERE/'driver'/name) == binding[key], f'VM source changed: {name}')
    require(binding['hii_source_sha256'] == MODULE_SHA['Setup'] and binding['generated_hii_sha256'] == sha(HERE/'driver/build/vm_hii_data.h'), 'VM HII binding mismatch')
    for name, digest in binding['shared_objects'].items():
        require(sha(safe_path(HERE/'driver/build', name)) == digest, f'VM shared object changed: {name}')
    require(len(vm['groups']) == 2 and {g['readonly_iso'] for g in vm['groups']} == {False, True}, 'VM medium coverage incomplete')
    boots = [boot for group in vm['groups'] for boot in group['boots']]
    require(len(boots) == 6 and all(boot['passed'] for boot in boots) and sum(boot['checks'] for boot in boots) >= 368, 'Six persistence boots did not pass')
    matches = [path.parent for path in (HERE/'driver/vm_runs').glob('*/result.json') if sha(path) == sha(reports['uefi_integration'])]
    require(len(matches) == 1, 'Cannot identify unique current VM evidence run')
    vm_run = matches[0]
    for group in vm['groups']:
        require([boot['phase'] for boot in group['boots']] == [0, 1, 2], 'VM persistence phases incomplete')
        group_path = vm_run/('readonly_iso' if group['readonly_iso'] else 'fat')
        for boot in group['boots']:
            run = group_path/('boot'+str(boot['phase']))
            require(read(run/'result.json') == boot and sha(run/'debug.log') == boot['debug_sha256'], 'VM raw evidence mismatch')
        require(sha(group_path/'vars.fd') == group['boots'][-1]['nvram_sha256'], 'VM final variable store mismatch')
        medium = group_path/('integration.iso' if group['readonly_iso'] else 'boot.img')
        require(sha(medium) == group['medium_sha256_after'], 'VM medium changed after test')
        if group['readonly_iso']:
            require(group['medium_sha256_before'] == group['medium_sha256_after'], 'Read-only VM ISO changed')
    require(vm['firmware_sha256'] == sha(HERE/'lab/build/OVMF-ACTUAL-1904.fd'), 'VM firmware changed')
    notes, hardware, cleanup = verify_hardware(driver_sha)
    audit_path = HERE/'review/exp02_integration_audit.json'
    require(audit_path.is_file(), 'EXP02 requires the completed integration audit')
    audit = read(audit_path)
    require(audit['normal_input_blocking_defects_confirmed'] == [] and audit['release_conclusion']['can_continue_exact_history01_exp02_packaging'] is True, 'Integration audit contains a packaging blocker')
    for name, digest in audit['source_sha256'].items():
        require(sha(safe_path(HERE, name)) == digest, f'Integration-audited source changed: {name}')
    counts = {
        '密码核心断言': core['assertions'], '策略与 IFR 检查': evidence['policy']['assertions'],
        '导航适配用例': evidence['adapter']['cases'], '历史返回回归检查': history['checks'],
        '原厂指令片段用例': len(native['cases']), '取熵用例': len(evidence['entropy']['checks']),
        'HII 回调 ABI 用例': len(evidence['hii_abi']['cases']), '型号版本识别用例': len(evidence['target_identity']['cases']),
        'UEFI 虚拟机冷启动': len(boots), 'UEFI 集成检查': sum(boot['checks'] for boot in boots),
        '实机 RAM 自动检查': hardware['automatic_checks'], '实机 RAM 自动失败': hardware['automatic_failures'],
        '静态保护表单': policy['form_count'], '静态保护问题 ID': policy['question_count'],
    }
    return dict(driver_sha=driver_sha, cap_sha=cap_sha, build=build, reports=reports,
                evidence=evidence, counts=counts, vm_run=vm_run, notes=notes,
                hardware=hardware, cleanup=cleanup, audit_path=audit_path)


def description(ctx):
    return f'''{TARGET} — Ai Tweaker 独立密码 BIOS {RELEASE} / UNSIGNED

本版本已完成 BIOS 映像制作与驱动固件内集成，永久密码存储代码已实现。
EXP02 合入 HISTORY01 历史返回修复：首次 Ai Tweaker 拒绝后，Main → Security → Esc 能正常返回。
最终驱动与完成免刷 RAM 实测的 HISTORY01 候选逐字节相同。
尚未将本映像刷入 ASUS 实机；原厂签名不再认证修改后的内容，不能宣布可直接刷写。
本包及制作脚本不执行刷写，不附带自动刷写工具。

适用范围与功能
仅适用 Pro WS W790E-SAGE SE / 1904；不适用 W790-ACE、W890E-SAGE SE 或 2003。
1904 是原厂基础版本，EXP02 是修改包版本，不改写原厂版本字段。
Security 新增 Ai Tweaker Password / Clear Ai Tweaker Password。
自行设置 8–128 个可打印 ASCII 字符；不预置密码，不保存明文。
每个 BIOS 会话首次进入受保护页面验证，同一会话已解锁时复用；新会话重新锁定。
修改或清除需要当前密码；清除还需确认，随后关闭保护。未设置时保持锁定并允许到 Security 设置。
加盐验证记录存于独立 NV+BootServices 变量；驱动嵌入 DXE 固件卷，设计上不依赖光驱工具启动。

验证统计
''' + '\n'.join(f'{key}：{value}' for key, value in ctx['counts'].items()) + f'''

验证范围
1. 固件结构：UEFIExtract 独立提取通过，嵌入驱动与最终 EFI 一致；原厂其他文件按结构报告保留。
2. OVMF：生产存储/密码/UI/HII等对象在 FAT 与只读 ISO 上各完成三次启动，验证虚拟变量存储延续。
   这些测试并非整套华硕 BIOS 模拟，也不能替代 ASUS 硬件的 NVRAM 验收。
3. 本机型免刷 RAM 实测：设密、错误拒绝、正确解锁、同会话复用、新会话重锁、清除及历史返回通过观察。
   最终日志 50 项自动检查、0 失败、98 次 SetVariable 调用被拒绝；三个选定变量共十轮比较一致。
   自动检查计数不等于覆盖所有 UI；UI 流程和限制单列在硬件证据中。
   HISTORY01 本轮 UI 未另行重做改密；自动自检包含改密，原 EXP01 UI 改密作为历史证据另列。

已知行为差异
免刷程序把 Favorites、ASUS Profile、Overclocking Presets 或 Memory Presets 直接作为初始页时，
取消密码会安全结束当前 SendForm 调用并回到测试菜单。不能写成所有取消都返回 Main。
原生历史不足等条件下采用保守退出；实际各次退出原因未写入日志。

实机收尾
原机 Off，测试后恢复 Off；虚拟光驱已卸载，临时启动覆盖已禁用。
原有启动项相对顺序保留。固件枚举出 Boot0007 虚拟光驱项，因此 BootOrder 并非逐字节未变；
未手动删除该项，其在下次不挂载启动后的保留情况尚未验证。
实测只使用 RAM 密码，没有写入本修改固件，也没有在 ASUS NVRAM 创建持久密码。

仍未验收
修改 BIOS 的实机刷写接受、完整冷启动、ASUS 固件自动调度、直接 Del/F2 进入后的锁行为，
以及 ASUS 实体 NVRAM 跨重启保存、完整图形/EZ/搜索入口、默认值恢复和训练流程仍未实机验收。
全局变量写守卫与正常开机、训练及授权保存是否兼容，尚需真实固件启动路径验证。
真实图形 BIOS 的一次可见访问是否恰好对应一次外层 browser_loop 也未确认；多次外层调用可能重复提示。
集成代码采用一次性挂钩尝试；部分安装失败时保留写保护，回滚恢复操作未逐项确认成功。
因此故障后可能需要重启才能恢复可用管理界面，具体残留挂钩状态仍有限制；详见 integration_audit.json。
EZ Flash/BMC/FlashBack 接受条件、原机备份与可恢复方式尚未核实，不能将本包标为可直接刷写正式版。
UNSIGNED 表示未对修改载荷重新取得有效签名；文件仍保留原始 4096 字节签名封装头。
密码锁不提供对 SPI 直接写入者的防护；忘记密码的恢复流程尚未实机验证。

文件校验
BIOS：{NAME}
CAP 字节数：{CANDIDATE.stat().st_size}
CAP SHA-256：{ctx['cap_sha']}
驱动 SHA-256：{ctx['driver_sha']}
官方原始 CAP SHA-256：{SOURCE_SHA}
manifest.json / SHA256SUMS.txt 核对本包文件；源码与验证归档使用 EXP02-UNSIGNED 独立文件名。
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    ctx = validate_release()
    if args.check_only:
        print(json.dumps({'status': 'INPUTS_VERIFIED_NO_OUTPUT_WRITES', 'driver_sha256': ctx['driver_sha'], 'capsule_sha256': ctx['cap_sha'], 'counts': ctx['counts']}, ensure_ascii=False, indent=2))
        return
    archive_path = OUT.with_suffix('.zip')
    require(not OUT.exists() and not archive_path.exists() and not DELIVERY.exists(), 'EXP02 output already exists; refusing release reuse')
    members = {NAME: CANDIDATE, '说明-先读.txt': description(ctx).encode('utf8')}
    for name, path in ctx['reports'].items():
        members['验证/'+name+'.json'] = path
    for name, path in {
        'firmware_build.json': CANDIDATE.with_suffix('.json'),
        'production_build.json': HERE/'driver/build/build.json',
        'password_core.json': HERE/'core/test_report.json',
        'native_hooks.json': HERE/'lab/native_hooks_result.json',
        'sage_policy.json': HERE/'driver/policy.json',
        'vm_build_binding.json': HERE/'driver/build/vm_build.json',
        'official_source.json': HERE/'analysis/original_identity.json',
        'history01_hardware_notes.json': REMOTE/'history01_hardware_notes.json',
        'hardware_final_log.txt': CAPTURE/'hardware-log.txt',
        'hardware_capture_manifest.json': CAPTURE/'manifest.json',
        'alternate_cancel_diagnosis.json': HERE/'navigation/direct_entry_exit_diagnosis.json',
    }.items():
        members['验证/'+name] = path
    members['验证/hardware_summary.json'] = json_bytes(ctx['hardware'])
    members['验证/cleanup_summary.json'] = json_bytes(ctx['cleanup'])
    members['验证/integration_audit.json'] = ctx['audit_path']
    page = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SAGE SE 1904 EXP02 验证</title><style>body{max-width:980px;margin:40px auto;padding:0 24px;font:16px/1.7 system-ui,sans-serif;color:#182638;background:#f5f7fa}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:28px;background:white;border:1px solid #d6dfe9}</style><body><pre>'+html.escape(description(ctx))+'</pre></body></html>'
    members['验证报告.html'] = page.encode('utf8')
    OUT.mkdir()
    for name, value in members.items():
        new_file(OUT/name, value if isinstance(value, bytes) else value.read_bytes())
    manifest = {
        'release': RELEASE, 'target': TARGET, 'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'status': 'BIOS_IMAGE_COMPLETED_INTEGRATED_UNSIGNED_NOT_FLASH_VALIDATED',
        'bios_file': NAME, 'capsule_sha256': ctx['cap_sha'], 'driver_sha256': ctx['driver_sha'],
        'source_capsule_sha256': SOURCE_SHA, 'module_sha256': MODULE_SHA,
        'driver_embedded_in_dxe_firmware_volume': True, 'history01_fix_integrated': True,
        'persistent_credential_storage_implemented': True, 'ovmf_six_persistence_boots_passed': True,
        'signature_status': 'ORIGINAL_SIGNATURE_NOT_VALID_FOR_MODIFIED_PAYLOAD',
        'hardware_password_test_scope': 'HISTORY01_RAM_ONLY_NATIVE_FORMBROWSER2',
        'hardware_ram_password_tested': True, 'hardware_ram_driver_sha256': ctx['driver_sha'],
        'automatic_asus_dispatch_verified': False, 'asus_direct_del_lock_verified': False,
        'asus_persistent_credential_storage_verified': False, 'firmware_flashing_performed': False,
        'persistent_hardware_deployment_complete': False, 'direct_flashing_ready': False,
        'hardware_summary': ctx['hardware'], 'cleanup_summary': ctx['cleanup'], 'test_counts': ctx['counts'],
        'files': {name: {'bytes': (OUT/name).stat().st_size, 'sha256': sha(OUT/name)} for name in sorted(members)},
    }
    new_file(OUT/'manifest.json', json_bytes(manifest))
    members['manifest.json'] = OUT/'manifest.json'
    sums = ''.join(f'{sha(OUT/name)}  {name}\n' for name in sorted(members))
    new_file(OUT/'SHA256SUMS.txt', sums.encode('utf8'))
    members['SHA256SUMS.txt'] = OUT/'SHA256SUMS.txt'
    checked_archive(archive_path, {name: OUT/name for name in members})
    require(sha(SOURCE) == SOURCE_SHA and sha(OUT/NAME) == ctx['cap_sha'], 'Final firmware digest mismatch')
    delivery = {'release': RELEASE, 'status': manifest['status'], 'directory': str(OUT), 'capsule': str(OUT/NAME),
                'capsule_sha256': ctx['cap_sha'], 'driver_sha256': ctx['driver_sha'],
                'zip': str(archive_path), 'zip_sha256': sha(archive_path), 'zip_bytes': archive_path.stat().st_size,
                'manifest_sha256': sha(OUT/'manifest.json'), 'files_verified': len(members),
                'hardware_ram_tested': True, 'flashing_performed': False, 'direct_flashing_ready': False}
    new_file(DELIVERY, json_bytes(delivery))
    print(json.dumps(delivery, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
