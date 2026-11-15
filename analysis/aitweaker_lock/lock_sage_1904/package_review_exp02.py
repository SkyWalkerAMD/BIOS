"""Archive EXP02 sources and selected evidence, with no BMC session material.

Run package_bios_exp02.py first. Explicit inventories prevent old release state,
credentials, controller scripts or raw HTTP/browser records from being copied.
--check-only validates the input and inventory without creating an archive.
"""
from pathlib import Path
import argparse
import datetime
import json

import package_bios_exp02 as release

HERE, ROOT = release.HERE, release.ROOT
ARCHIVE = ROOT/'W790E-SAGE-SE-1904-AiTweaker-源码与验证-EXP02-UNSIGNED.zip'
DELIVERY = HERE/'review_delivery_exp02.json'


def inventory(ctx):
    members = {}

    def add(path, name=None):
        path = Path(path).resolve()
        release.require(path.is_file(), f'Missing selected evidence: {path}')
        release.require(path.is_relative_to(ROOT), f'Selected evidence outside workspace: {path}')
        name = name or path.relative_to(HERE).as_posix()
        release.require(name not in members, f'Duplicate archive member: {name}')
        members[name] = path

    # Only source extensions in the two production source directories. Build
    # outputs and JSON state are selected separately below, never recursively.
    for folder in ['core', 'driver']:
        for path in sorted((HERE/folder).iterdir()):
            if path.is_file() and path.suffix in {'.c', '.h', '.py'}:
                add(path)
    for relative in [
        'package_bios_exp02.py', 'package_review_exp02.py', 'bios_delivery_exp02.json',
        'core/test_report.json', 'core/build_report.json', 'driver/policy.json',
        'driver/build/build.json', 'driver/build/driver.map', 'driver/build/AiTweakerLock1904.efi',
        'driver/build/vm_build.json', 'driver/build/VM-INTEGRATION-ONLY.EFI',
        'driver/build/vm_hii_data.h', 'driver/build/vm_fixture.map',
        'lab/build_asus_review.py', 'lab/verify_asus_review.py', 'lab/inject_ovmf.py',
        'lab/native_hooks.py', 'lab/native_hooks_result.json',
        'analysis/original_identity.json', 'analysis/module_metadata.json',
        'analysis/policy_comparison.json', 'analysis/container_layout.json', 'analysis/forms_1904.json',
        'analysis/modules/Setup.efi', 'analysis/modules/AMITSE.efi', 'analysis/modules/Setup_IFR.json',
        'navigation/disasm.py', 'navigation/map_native.py', 'navigation/map_globals.py',
        'navigation/verify_full_routines.py', 'navigation/verify_sendform.py',
        'navigation/anchor_mapping.json', 'navigation/global_mapping.json',
        'navigation/routine_equivalence.json', 'navigation/sendform_mapping.json',
        'navigation/diagnose_direct_entry_exit.py', 'navigation/direct_entry_exit_diagnosis.json',
    ]:
        add(HERE/relative)
    for path in ctx['reports'].values():
        add(path)
    add(release.CANDIDATE.with_suffix('.json'))
    # Preserve the native history investigation under an explicitly historical
    # prefix. Its older driver status is not current EXP02 acceptance evidence.
    for relative in [
        'navigation/history_finding.json', 'navigation/history_regression.json',
        'navigation/reproduce_history.py', 'navigation/history_candidate/platform.patch',
        'navigation/history_candidate/history_candidate_result.json',
    ]:
        add(HERE/relative, 'history_provenance/'+relative)
    for stem in [
        'HISTORY-push10220', 'HISTORY-pop1012c', 'HISTORY-page-dd6c',
        'STATE-app12168', 'STATE-page16c20', 'STATE-send20ee4',
        'FOCUS-poll34b2c', 'FOCUS-loop-e1b8', 'FOCUS-dispatch626c', 'SAGE-dispatch626c',
    ]:
        for suffix in ['.c', '.json']:
            path = HERE/'navigation/rea'/(stem+suffix)
            if path.is_file():
                add(path)
    # The hardware app links all production objects except entry. Include the
    # exact current production objects plus entry, with their source binding.
    for name in ['entry', 'services', 'cpu_entropy', 'ui', 'policy', 'hii', 'platform',
                 'password_core', 'password_crypto', 'probe_core']:
        add(HERE/'driver/build'/(name+'.obj'))
    # Only the one VM run already bound to the current vm_integration.json.
    add(ctx['vm_run']/'result.json')
    for group in ['fat', 'readonly_iso']:
        for phase in range(3):
            for name in ['result.json', 'debug.log', 'serial.log', 'stdout.log', 'stderr.log', 'command.json']:
                add(ctx['vm_run']/group/('boot'+str(phase))/name)
    for name, digest in ctx['build']['external_sources'].items():
        path = release.safe_path(ROOT, name)
        release.require(release.sha(path) == digest, f'External source changed: {name}')
        add(path, 'external/'+path.relative_to(ROOT).as_posix())
    # Shared local parsers/VM image builder are needed to understand the build
    # scripts. Full tool installations and firmware ROMs are intentionally not
    # duplicated; original CAP provenance remains in original_identity.json.
    for relative in [
        'analysis/aitweaker_lock/inspect_setup.py',
        'analysis/aitweaker_lock/uefi_vm_20261015/disk_images.py',
    ]:
        add(ROOT/relative, 'external/'+relative)
    remote = release.REMOTE
    add(remote/'history01_hardware_notes.json')
    # Local RAM harness/builder files do not connect to the controller. Explicit
    # names exclude bmc_browser.mjs and every identity/browser/session dump.
    for name in [
        'ram_lock_test.c', 'build_test_common.py', 'build_ram_history01.py',
        'verify_ram_history01_boot.py', 'verify_ram_history01_safety.py',
        'verify_ram_boot.py', 'verify_ram_safety.py',
    ]:
        add(remote/name)
    for name in ['build.json', 'delivery.json', 'vm_validation.json', 'safety_validation.json']:
        add(remote/'ram_test_history01'/name)
    for name in ctx['hardware']['hardware_to_production_object_binding']:
        add(remote/'ram_test_history01'/('candidate_objects' if name == 'platform' else 'production_objects')/(name+'.obj'))
    add(remote/'ram_test_history01/production_objects/entry.obj')
    for item in ctx['hardware']['hardware_to_production_source_binding'].values():
        add(remote/'ram_test_history01/source'/item['hardware_source'])
    for name in ctx['hardware']['hardware_harness_source_sha256']:
        add(remote/'ram_test_history01/source'/name)
    for name in ['candidate-relinked.efi', 'BOOTX64.EFI']:
        add(remote/'ram_test_history01'/name)
    for name in release.read(release.CAPTURE/'manifest.json')['files']:
        add(release.safe_path(release.CAPTURE, name))
    add(release.CAPTURE/'manifest.json')
    for name, digest in ctx['notes']['screenshot_sha256'].items():
        path = release.safe_path(remote, name)
        release.require(release.sha(path) == digest, 'Hardware screenshot identity changed')
        add(path)
    # Include the earlier two-page HISTORY01 self-test capture named in the
    # verified notes, while excluding unrelated baseline and BMC HTTP logs.
    first_log = ctx['notes']['logs'][0]
    initial = release.safe_path(remote, first_log['log']).parent
    release.require(release.sha(initial/'hardware-log.txt') == first_log['sha256'], 'HISTORY01 self-test log changed')
    initial_manifest = release.read(initial/'manifest.json')
    allowed = {'hardware-log.txt', 'page-01.frame', 'page-02.frame', 'page-01.png', 'page-02.png'}
    release.require(set(initial_manifest['files']) == allowed, 'Unexpected initial capture inventory')
    for name, digest in initial_manifest['files'].items():
        path = release.safe_path(initial, name)
        release.require(release.sha(path) == digest, 'Initial capture hash mismatch')
        add(path)
    add(initial/'manifest.json')
    add(ctx['audit_path'])
    # Include the new release's actual README/manifest, never root requirements,
    # old bios_delivery.json/review_delivery.json, or EXP01 package scripts.
    for name in ['manifest.json', '说明-先读.txt', '验证报告.html', 'SHA256SUMS.txt']:
        add(release.OUT/name, 'release/'+name)
    members['hardware/cleanup_summary.json'] = release.json_bytes(ctx['cleanup'])
    members['hardware/history01_summary.json'] = release.json_bytes(ctx['hardware'])
    return members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    ctx = release.validate_release()
    delivery = release.read(release.DELIVERY)
    release.require(delivery['release'] == 'EXP02' and delivery['driver_sha256'] == ctx['driver_sha'] and delivery['capsule_sha256'] == ctx['cap_sha'], 'Wrong EXP02 delivery record')
    release.require(Path(delivery['capsule']).resolve() == (release.OUT/release.NAME).resolve(), 'Unexpected capsule delivery path')
    release.require(release.sha(release.OUT/release.NAME) == ctx['cap_sha'] and release.sha(Path(delivery['zip'])) == delivery['zip_sha256'], 'Released BIOS files changed')
    release.require(release.sha(release.OUT/'manifest.json') == delivery['manifest_sha256'], 'Released manifest changed')
    published = release.read(release.OUT/'manifest.json')
    for name, item in published['files'].items():
        path = release.safe_path(release.OUT, name)
        release.require(path.stat().st_size == item['bytes'] and release.sha(path) == item['sha256'], f'Release file changed: {name}')
    members = inventory(ctx)
    manifest = {
        'target': release.TARGET, 'release': 'EXP02-UNSIGNED',
        'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Current production source/build/evidence, HISTORY01 native-history provenance and RAM hardware evidence. Firmware image completed and integrated; no ASUS flash, persistent hardware storage or direct Del dispatch acceptance claim.',
        'driver_sha256': ctx['driver_sha'], 'capsule_sha256': ctx['cap_sha'],
        'original_capsule_sha256': release.SOURCE_SHA,
        'hardware_ram_tested': True, 'firmware_flashing_performed': False,
        'asus_persistent_storage_tested': False, 'asus_direct_del_dispatch_tested': False,
        'historical_context_prefix': 'history_provenance/',
        'historical_context_note': 'Older baseline/candidate observations explain the repair; driver/build/history_regression.json and current reports are the EXP02 acceptance evidence.',
        'excluded': ['BMC credentials', 'controller scripts', 'raw HTTP/browser/session records',
                     'requirements.json', 'old delivery JSON', 'EXP01 release files', 'firmware flashing tools'],
        'files': {},
    }
    for name, value in sorted(members.items()):
        data = value if isinstance(value, bytes) else value.read_bytes()
        manifest['files'][name] = {'bytes': len(data), 'sha256': release.hashlib.sha256(data).hexdigest()}
    if args.check_only:
        print(json.dumps({'status': 'SOURCE_INVENTORY_VERIFIED_NO_OUTPUT_WRITES', 'files': len(members),
                          'driver_sha256': ctx['driver_sha'], 'capsule_sha256': ctx['cap_sha']}, indent=2))
        return
    release.require(not ARCHIVE.exists() and not DELIVERY.exists(), 'EXP02 source archive already exists; refusing overwrite')
    members['REVIEW-MANIFEST.json'] = release.json_bytes(manifest)
    members['说明.txt'] = (
        'SAGE SE 1904 / EXP02-UNSIGNED 源码与验证归档。此归档不是启动盘或刷写工具。\n'
        '最终密码驱动已集成到独立 BIOS 实验包；本归档提供当前源码、131项历史回归、6次UEFI存储测试和HISTORY01免刷RAM实测证据。\n'
        'ASUS硬件未刷写本修改固件，未验收实体持久保存及直接Del/F2自动调度；原厂签名对修改载荷无效，不能称为可直接刷写正式版。\n'
        '四个其他初始入口取消密码会退出当前SendForm至工具菜单，不代表所有取消都回Main。\n'
        'history_provenance/明确保存旧版问题与候选修复的历史证据；当前通过报告以driver/build和lab/asus_review_exp02为准。\n'
        '完整硬件操作收尾见hardware/cleanup_summary.json；仅导出审核字段，不含BMC凭据或原始HTTP会话。\n'
        '外部共享源码保留external/下工作区相对路径；构建仍需原工作区布局、Zig、Python依赖、UEFIExtract、REA/Ghidra及QEMU工具。\n'
        '原版CAP按analysis/original_identity.json取得并核验；本归档不重复携带原版固件或工具安装。\n'
    ).encode('utf8')
    release.checked_archive(ARCHIVE, members)
    result = {'release': 'EXP02', 'status': 'SOURCE_AND_SCOPED_EVIDENCE_ARCHIVE_VERIFIED',
              'archive': str(ARCHIVE), 'bytes': ARCHIVE.stat().st_size, 'sha256': release.sha(ARCHIVE),
              'driver_sha256': ctx['driver_sha'], 'capsule_sha256': ctx['cap_sha'],
              'verified_files': len(members), 'flashing_performed': False}
    release.new_file(DELIVERY, release.json_bytes(result))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
