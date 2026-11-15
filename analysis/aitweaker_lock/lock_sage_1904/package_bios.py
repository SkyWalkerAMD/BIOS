"""Package only a fully checked, exact SAGE SE 1904 experimental image.

No remote calls, signing, firmware update, or device access. An existing release
name can never silently be reused for a different firmware payload.
"""
from pathlib import Path
import datetime
import hashlib
import html
import json
import shutil
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RELEASE = 'EXP01'
TARGET = 'ASUS Pro WS W790E-SAGE SE BIOS 1904'
SOURCE_SHA = 'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3'
MODULE_SHA = {
    'Setup': '719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d',
    'AMITSE': '531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1',
}
SOURCE = HERE.parent/'official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
OUT = ROOT/f'W790E-SAGE-SE-1904-AiTweaker密码BIOS-{RELEASE}'
NAME = f'Pro-WS-W790E-SAGE-SE-1904-AiTweakerLock-{RELEASE}-UNSIGNED.CAP'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding='utf8'))

def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n', encoding='utf8')

def archive_checked(path, root, files):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in files:
            z.write(p, p.relative_to(root).as_posix())
    with zipfile.ZipFile(path) as z:
        assert z.testzip() is None
        for p in files:
            assert hashlib.sha256(z.read(p.relative_to(root).as_posix())).hexdigest() == sha(p)

def main():
    candidate = HERE/'lab/asus_review/W790E-SAGE-SE-1904-lock.review.bin'
    driver = HERE/'driver/build/AiTweakerLock1904.efi'
    cap_sha, driver_sha = sha(candidate), sha(driver)
    assert sha(SOURCE) == SOURCE_SHA
    assert SOURCE.stat().st_size == candidate.stat().st_size == 0x4001000
    assert SOURCE.read_bytes()[:4096] == candidate.read_bytes()[:4096]
    assert cap_sha != SOURCE_SHA
    for name, digest in MODULE_SHA.items():
        assert sha(HERE/f'analysis/modules/{name}.efi') == digest
    build = read(HERE/'driver/build/build.json')
    assert build['board'] == 'Pro WS W790E-SAGE SE' and build['efi_sha256'] == driver_sha
    for name, digest in build['sources'].items():
        assert sha(HERE/name) == digest, name
    for name, digest in build['external_sources'].items():
        assert sha(ROOT/name) == digest, name
    reports = {
        'firmware_structure': HERE/'lab/asus_review/verification.json',
        'policy': HERE/'driver/build/policy_test.json',
        'adapter': HERE/'driver/build/adapter_emulation.json',
        'entropy': HERE/'driver/build/entropy_test.json',
        'hii_abi': HERE/'driver/build/hii_abi_test.json',
        'target_identity': HERE/'driver/build/identity_test.json',
        'uefi_integration': HERE/'driver/build/vm_integration.json',
    }
    evidence = {name: read(path) for name, path in reports.items()}
    for name, r in evidence.items():
        assert r.get('driver_sha256', r.get('driver_efi_sha256')) == driver_sha, name
        assert r.get('status') == 'PASS' or r.get('passed') is True or r.get('all_passed') is True, name
    assert evidence['firmware_structure']['candidate_sha256'] == cap_sha
    candidate_manifest=read(candidate.with_suffix('.json'))
    assert candidate_manifest['fixture_only'] is False and candidate_manifest['driver_sha256']==driver_sha
    assert evidence['adapter']['amitse_sha256'] == MODULE_SHA['AMITSE']
    native = read(HERE/'lab/native_hooks_result.json')
    assert native['all_passed'] and native['module_sha256'] == MODULE_SHA['AMITSE']
    core = read(HERE/'core/test_report.json')
    assert core['status'] == 'PASS'
    for name, digest in core['sources'].items():
        assert sha(HERE/'core'/name) == digest
    assert sha(HERE/'core/verify_core.py') == core['test_source_sha256']
    policy = read(HERE/'driver/policy.json')
    assert policy['form_count'] == 28 and policy['question_count'] == 1992
    assert policy['source_ifr_sha256'] == sha(HERE/'analysis/modules/Setup_IFR.json')
    vm = evidence['uefi_integration']
    assert vm['fixture_sha256'] == sha(HERE/'driver/build/VM-INTEGRATION-ONLY.EFI')
    binding=read(HERE/'driver/build/vm_build.json')
    assert binding['driver_sha256']==driver_sha and binding['fixture_sha256']==vm['fixture_sha256']
    assert vm['fixture_build_manifest_sha256']==sha(HERE/'driver/build/vm_build.json')
    assert binding['production_build_sha256']==sha(HERE/'driver/build/build.json')
    assert binding['fixture_source_sha256']==sha(HERE/'driver/vm_fixture.c')
    assert binding['build_script_sha256']==sha(HERE/'driver/build_vm.py')
    assert binding['hii_source_sha256']==MODULE_SHA['Setup']
    assert binding['generated_hii_sha256']==sha(HERE/'driver/build/vm_hii_data.h')
    for name,digest in binding['shared_objects'].items():assert sha(HERE/'driver/build'/name)==digest
    boots = [b for g in vm['groups'] for b in g['boots']]
    assert len(boots) == 6 and all(b['passed'] for b in boots)
    assert sum(b['checks'] for b in boots) >= 368
    identity = read(HERE/'remote_172_20_2_162/identity_summary.json')
    assert identity['identity_matches_requested_target'] and identity['device_write_operations'] == 0
    navigation = read(HERE/'navigation/adaptation_summary.json')
    assert navigation['status'] == 'PASS'
    assert navigation['module_sha256'] == MODULE_SHA

    OUT.mkdir(exist_ok=True)
    cap = OUT/NAME
    if cap.exists():
        assert sha(cap) == cap_sha, 'Release name already binds different firmware bytes'
    else:
        shutil.copyfile(candidate, cap)
    verify = OUT/'验证'
    verify.mkdir(exist_ok=True)
    for name, path in reports.items():
        shutil.copyfile(path, verify/(name+'.json'))
    for source, name in [
        (HERE/'lab/native_hooks_result.json', 'native_hooks.json'),
        (HERE/'core/test_report.json', 'password_core.json'),
        (HERE/'navigation/adaptation_summary.json', 'navigation_adaptation.json'),
        (HERE/'driver/policy.json', 'sage_policy.json'),
        (HERE/'driver/build/vm_build.json', 'vm_build_binding.json'),
        (HERE/'remote_172_20_2_162/identity_summary.json', '带外身份核验.json'),
        (HERE/'analysis/original_identity.json', 'official_source.json'),
    ]:
        shutil.copyfile(source, verify/name)

    checks = {
        '密码核心断言': core['assertions'],
        '策略与原厂 IFR 检查': evidence['policy']['assertions'],
        '导航适配用例': evidence['adapter']['cases'],
        '原厂指令片段用例': len(native['cases']),
        '取熵用例': len(evidence['entropy']['checks']),
        'HII 回调 ABI 用例': len(evidence['hii_abi']['cases']),
        '型号与版本识别用例': len(evidence['target_identity']['cases']),
        'UEFI 虚拟机冷启动': len(boots),
        'UEFI 集成检查': sum(b['checks'] for b in boots),
        '静态保护表单': policy['form_count'],
        '静态保护问题 ID': policy['question_count'],
    }
    readme = f'''{TARGET} — Ai Tweaker 独立密码 BIOS {RELEASE}

本包为实验映像：已集成驱动并通过所列离线检查，尚未完成实机刷写和启动验收。
原厂签名不再适用于修改后的内容，不能据此认定 EZ Flash / BMC / FlashBack 会接受。
尚未写入修改固件；带外库存报告原版 1904、主机关机。本轮只读取身份，没有开机、重启、挂载或刷写。

适用范围
仅适用于 Pro WS W790E-SAGE SE、BIOS 1904。
不适用于 W790-ACE、W890E-SAGE SE 或 SAGE SE 2003。
1904 是原厂基础版本；{RELEASE} 是修改包版本，不改写原厂版本字段。

功能设计与操作
在 BIOS 的 Security 页面新增 Ai Tweaker Password 与 Clear Ai Tweaker Password。
用户自行设置 8–128 个可打印 ASCII 字符；不预置密码，不保存明文。
每个 BIOS 会话首次进入 Ai Tweaker 或受保护入口时验证；同一会话内解锁后无需重复。
重新进入 BIOS 恢复锁定；修改/清除必须验证当前密码，清除后关闭保护。
首次尚未设置密码时保持锁定，可在 Security 设置。忘记密码的恢复流程尚未实机验证。
独立 NV+BootServices 变量保存加盐验证记录；驱动已放入固件，不依赖光驱工具启动。
保护范围包含 Ai Tweaker 子页、收藏夹与配置档相关入口；动态控件还会按变量来源检查。

验证统计
''' + '\n'.join(f'{name}：{count}' for name, count in checks.items()) + f'''
独立 UEFIExtract 结构校验：PASS；提取到的密码驱动与最终编译文件逐字节一致。
所有统计对应本型号、本次编译。ACE 的历史实机结果没有算入本包验证。
OVMF 测试执行生产存储/密码/UI/HII对象及非匹配主板拒绝路径；它不是整套华硕固件模拟。
Unicorn 导航测试执行原厂指令片段与实际适配代码，固件服务和完整浏览器仍有明确桩替代。

未完成事项
完整修改 BIOS 的实机启动、ASUS 固件内自动调度、直接 Del/F2 进入后的行为，
完整图形/EZ/搜索入口、实体 NVRAM 跨重启，以及恢复默认值和训练流程尚未实机验收。
更新器接受条件、原机可恢复备份和固件恢复方式尚未核实。
BMC 库存确认型号与1904；尚未取得这台机器运行中的 Setup/AMITSE 指纹。
因此本文件不能标为可直接刷写的正式版；本包不附带自动刷写工具。
本锁也不是针对具有 SPI 直接写入能力的攻击者的防护机制。

文件与校验
BIOS：{NAME}
CAP 字节数：{cap.stat().st_size}
CAP SHA-256：{cap_sha}
驱动 SHA-256：{driver_sha}
官方原始 CAP SHA-256：{SOURCE_SHA}
包内 manifest.json 与 SHA256SUMS.txt 可核对所有发布文件。
'''
    (OUT/'说明-先读.txt').write_text(readme, encoding='utf8')
    page = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SAGE SE 1904 密码 BIOS 验证</title><style>body{max-width:980px;margin:40px auto;padding:0 24px;background:#f5f7fa;color:#182638;font:16px/1.7 system-ui,sans-serif}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:white;padding:28px;border:1px solid #d6dfe9;border-radius:12px}a{color:#155bb5}</style><body><pre>'''+html.escape(readme)+'''</pre><p>官方原版来源：<a href="https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w790e-sage-se/helpdesk_bios/">ASUS SAGE SE BIOS 支持页</a></p></body></html>'''
    (OUT/'验证报告.html').write_text(page, encoding='utf8')
    files = sorted(p for p in OUT.rglob('*') if p.is_file() and p.name not in {'manifest.json', 'SHA256SUMS.txt'})
    manifest = {
        'release': RELEASE, 'target': TARGET,
        'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'status': 'EXPERIMENTAL_MODIFIED_BIOS_NOT_FLASH_VALIDATED',
        'bios_file': NAME, 'capsule_sha256': cap_sha, 'driver_sha256': driver_sha,
        'source_capsule_sha256': SOURCE_SHA, 'module_sha256': MODULE_SHA,
        'driver_embedded_in_dxe_firmware_volume': True,
        'persistent_credential_storage_implemented': True,
        'signature_status': 'ORIGINAL_SIGNATURE_NOT_VALID_FOR_MODIFIED_PAYLOAD',
        'hardware_password_tested': False, 'automatic_asus_dispatch_verified': False,
        'firmware_flashing_performed': False, 'persistent_hardware_deployment_complete': False,
        'bmc_read_only_identity_verified': True, 'test_counts': checks,
        'files': {p.relative_to(OUT).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in files},
    }
    save(OUT/'manifest.json', manifest)
    files.append(OUT/'manifest.json')
    (OUT/'SHA256SUMS.txt').write_text(''.join(f'{sha(p)}  {p.relative_to(OUT).as_posix()}\n' for p in sorted(files)), encoding='utf8')
    files.append(OUT/'SHA256SUMS.txt')
    archive = OUT.with_suffix('.zip')
    archive_checked(archive, OUT, files)
    assert sha(SOURCE) == SOURCE_SHA
    delivery = {'status': manifest['status'], 'directory': str(OUT), 'capsule': str(cap),
                'capsule_sha256': cap_sha, 'driver_sha256': driver_sha,
                'zip': str(archive), 'zip_sha256': sha(archive), 'zip_bytes': archive.stat().st_size,
                'files_verified': len(files), 'flashing_performed': False}
    save(HERE/'bios_delivery.json', delivery)
    requirements = read(HERE/'requirements.json')
    requirements.update({'status': manifest['status'], 'experimental_bios_release': delivery,
                         'persistent_hardware_deployment_complete': False})
    save(HERE/'requirements.json', requirements)
    print(json.dumps(delivery, indent=2))

if __name__ == '__main__':
    main()
