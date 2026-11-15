"""Package a frozen, explicit allowlist. Local reads only; no firmware execution."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIVE = ROOT / 'analysis/hero_ipmi_continued_live_20261108'
INV = ROOT / 'analysis/hero_inventory_20261108'
FIX = ROOT / 'analysis/hero_ipmi_sectionfix_20261108'
STAGE = HERE / 'package'
ZIP = HERE / 'HERO-INVENTORY-20261108-实测与候选.zip'
EXPECTED_CAP = '66420b42a5251a1209cac9865d3a1d8d5f1e03e512b4b9ce98ba0d29b81be131'
CAP_NAME = 'HERO-3107-IPMI-SECTIONFIX-LATEST-UNSIGNED.CAP'
items: dict[str, dict] = {}
checks: dict[str, object] = {}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def readj(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def valid_name(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(name) and '\\' not in name and not p.is_absolute() and '..' not in p.parts and ':' not in name


def add(source: Path, dest: str):
    assert valid_name(dest) and dest not in items, dest
    resolved = source.resolve(strict=True)
    assert resolved.is_relative_to(ROOT) and resolved.is_file(), source
    data = resolved.read_bytes()
    items[dest] = dict(source=resolved.relative_to(ROOT).as_posix(), bytes=len(data), sha256=sha(data))


def generated(dest: str, data: bytes):
    assert valid_name(dest) and dest not in items, dest
    path = STAGE / dest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    items[dest] = dict(source=None, bytes=len(data), sha256=sha(data))


def audit_credentials(name: str, data: bytes) -> list[str]:
    # Report only the file and rule, never a matched secret. No blanket token-word ban:
    # token limits, public certificate pins and protocol documentation are valid sources.
    patterns = {
        'private_key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
        'http_auth_value': rb'(?im)^\s*(?:Authorization|Proxy-Authorization)\s*:\s*(?:Basic|Bearer)\s+[A-Za-z0-9+/=_-]{8,}',
        'http_cookie_value': rb'(?im)^\s*(?:Cookie|Set-Cookie)\s*:\s*[^\r\n\s]{4,}',
        'json_auth_value': rb'(?i)"(?:password|passwd|cookie|cookies|access_token|refresh_token|x-auth-token)"\s*:\s*"[^"\r\n]+"',
    }
    return [f'{name}: {rule}' for rule, pattern in patterns.items() if re.search(pattern, data)]


def inspect_frozen_zip(path: Path) -> dict:
    value = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(value)) as z:
        names = z.namelist()
        assert len(names) == len(set(names))
        assert all(valid_name(n) for n in names), path
        assert z.testzip() is None, path
        assert all(not re.search(r'(?i)(?:^|/)(?:sessions?|cookies?|commands|responses|browser)(?:/|\.)', n) for n in names)
        manifest = json.loads(z.read('package-manifest.json'))
        for member, expected in manifest.items():
            member = member.replace('\\', '/')
            b = z.read(member)
            if isinstance(expected, str):
                assert sha(b) == expected, (path.name, member)
            else:
                assert sha(b) == expected['sha256'] and len(b) == expected['bytes'], (path.name, member)
        hits = []
        for member in names:
            hits.extend(audit_credentials(path.name + '/' + member, z.read(member)))
        assert not hits, hits
        return dict(name=path.name, bytes=len(value), sha256=sha(value), members=len(names),
                    zip_crc_valid=True, internal_manifest_entries_verified=len(manifest), credentials_rule_hits=0)


def main():
    assert not ZIP.exists() and not STAGE.exists(), 'Use a fresh delivery folder; never overwrite a delivery.'
    STAGE.mkdir()
    result = readj(LIVE / 'inventory-result-verification.json')
    assert result['verified'] and result['warm_host_restart_persistence_verified']
    assert not result['automatic_firmware_upload_implemented']
    add(LIVE / '本轮结果与使用说明-20261108.txt', '01-实测记录/本轮结果与使用说明-20261108.txt')
    add(LIVE / 'inventory-result-verification.json', '01-实测记录/inventory-result-verification.json')

    logs = ['hero71-i3b-preflight', 'hero71-i3b-system-cpu', 'hero71-i3d-inventory-complete',
            'hero71-i3d-diagnostic', 'hero71-fv-sections-i2c']
    log_checks = []
    for name in logs:
        p = LIVE / (name + '.TXT')
        m = LIVE / 'captures' / name / 'manifest.json'
        b, meta = p.read_bytes(), readj(m)
        assert len(b) == meta['bytes'] and sha(b) == meta['sha256']
        assert f'{zlib.crc32(b):08X}' == meta['crc32'].upper()
        assert meta['pages'] == len(meta['screens'])
        add(p, f'01-实测记录/完整日志/{p.name}')
        add(m, f'01-实测记录/QR清单/{name}-manifest.json')
        log_checks.append(dict(name=p.name, pages=meta['pages'], bytes=len(b), crc32=meta['crc32'], sha256=sha(b)))
    checks['five_complete_logs_match_qr_manifests'] = log_checks

    expected_reads = {c['readback']['file']: c['readback']['sha256'] for c in result['readback_checks']}
    assert len(expected_reads) == 8
    for i in range(1853, 1861):
        name = f'responses/999-{i:06d}-get.json'
        p = LIVE / name
        assert sha(p.read_bytes()) == expected_reads[name]
        assert readj(p)['result']['status'] == 200
        add(p, '01-实测记录/最终8份只读响应/' + p.name)
    checks['final_readback_count'] = 8
    checks['final_readback_hashes_match_result_record'] = True

    cache = readj(LIVE / 'cpu-collection-cache-validation.json')
    add(LIVE / 'cpu-collection-cache-validation.json', '01-实测记录/单项CPU缓存验证/cpu-collection-cache-validation.json')
    for evidence in cache['evidence']:
        p = LIVE / 'responses' / evidence['response']
        assert sha(p.read_bytes()) == evidence['sha256']
        assert readj(p)['result']['status'] == evidence['status']
        add(p, '01-实测记录/单项CPU缓存验证/' + p.name)
    checks['cache_evidence_hashes_match'] = True

    screens = ['inventory-i3d-system.png', 'inventory-i3d-processor.png', 'inventory-i3d-memory.png',
               'restore-network-save-review.png', 'network-stack-restored.png', 'restore-centos-selection.png', 'centos-final.png']
    for name in screens:
        add(LIVE / 'screens' / name, '01-实测记录/关键截图/' + name)
    assert sha((LIVE / 'screens/centos-final.png').read_bytes()) == result['host_final_screen_sha256']
    checks['visually_reviewed_key_screenshots'] = screens

    frozen = [ROOT / 'analysis/hero_inventory_publish_i3d_20261108/HERO-INVENTORY-I3D-CONTINUATION.zip',
              ROOT / 'analysis/hero_fw_i2c_20261108/HERO-FW-ID-I2C-PACKAGE.zip']
    checks['frozen_nested_packages'] = [inspect_frozen_zip(p) for p in frozen]
    for p in frozen:
        add(p, '02-冻结工具/' + p.name)

    # Preserve relative source hierarchy so offline test fixtures can be located.
    source_root = '03-离线源码与测试/'
    handoff_checks = []
    for lib, extras in [('dynamic_catalog', ['freeze_handoff.py', '接口与集成缺口.txt', 'build/build.json']),
                        ('cache_refresh', [])]:
        base = INV / lib
        handoff = readj(base / 'handoff.json')
        chosen = set(handoff['files']) | set(extras) | {'handoff.json'}
        for name, expected in handoff['files'].items():
            b = (base / name).read_bytes()
            assert len(b) == expected['bytes'] and sha(b) == expected['sha256'], (lib, name)
        for name in sorted(chosen):
            p = base / name
            add(p, source_root + p.relative_to(ROOT).as_posix())
        handoff_checks.append(dict(library=lib, hash_verified_entries=len(handoff['files']),
                                   native_unit_tests=handoff['native_unit_tests'],
                                   hardware_execution_performed_by_packager=False))
    checks['frozen_library_handoffs'] = handoff_checks
    helpers = ['smbios_inventory.py', 'test_smbios_inventory.py']
    payload_names = ['system.patch.json', 'DevType1_CPU0.post.json'] + [f'DevType2_DIMM{i}.post.json' for i in range(4)]
    for name in helpers:
        p = INV / name
        add(p, source_root + p.relative_to(ROOT).as_posix())
    for name in payload_names:
        p = INV / 'hero71-legacy' / name
        add(p, source_root + p.relative_to(ROOT).as_posix())
    for name in ['hero71-smbios-i1.TXT', 'responses/697-get.json', 'responses/701-get.json', 'responses/702-get.json',
                 'responses/996-evaluate.json', 'responses/998-get.json']:
        p = LIVE / name
        add(p, source_root + p.relative_to(ROOT).as_posix())
    checks['extra_fixture_scope'] = 'One complete SMBIOS capture and exact offline test fixtures; not current final readback evidence.'

    pc = INV / 'pcie_storage_analysis'
    for name in ['PCIe与存储库存适配评估-20261108.txt', 'field-matrix.json', 'field-matrix.txt', 'gap-checklist.json',
                 'decode_readonly.py', 'test_decode_readonly.py', 'decoder-tests.json', 'decoder-tests.txt',
                 'hero71-smbios-pcie.json', 'evidence-index.json', 'source-manifest.json']:
        add(pc / name, '04-PCIe与存储-离线评估/' + name)
    dtest = readj(pc / 'decoder-tests.json')
    assert dtest['tests'] == 19 and dtest['failures'] == 0 and dtest['errors'] == 0
    assert sha((pc / 'decode_readonly.py').read_bytes()) == dtest['source_sha256']
    checks['pcie_storage_decoder_frozen_result_matches_source'] = True

    cap = FIX / 'candidate-latest' / CAP_NAME
    report = readj(FIX / 'candidate-latest/build-report.json')
    independent = readj(INV / 'container_review/independent-sectionfix-review.json')
    latest = next(v for v in independent['variants'] if v['variant'] == 'latest')
    assert sha(cap.read_bytes()) == EXPECTED_CAP == report['candidate_sha256'] == latest['candidate_sha256']
    assert report['bytes'] == cap.stat().st_size
    assert independent['passed'] and latest['offline_checks_passed']
    assert not report['automatic_inventory_included'] and not report['flashed'] and not report['hardware_boot_validated']
    add(cap, '固件候选-未刷写/' + CAP_NAME)
    for p in [FIX / 'candidate-latest/build-report.json', FIX / 'candidate-latest' / (CAP_NAME + '.report.txt'),
              FIX / 'packaging-tests.json', FIX / 'parser-warning-comparison.json', FIX / 'test_packaging.py',
              FIX / 'build_sectionfix.py', INV / 'container_review/independent-sectionfix-review.json',
              INV / 'container_review/verify_sectionfix.py']:
        add(p, '固件候选-未刷写/静态复核/' + p.name)
    follow = ROOT / 'analysis/hero_ipmi_r2_followup_20261108/dispatch-audit'
    for name in ['I3d实采与节串问题结论.txt', 'i2c-live-validation.json', 'i3d-capture-validation.json',
                 'section-validation-machine-code.json', 'section-stream-validation.asm']:
        add(follow / name, '固件候选-未刷写/故障定位证据/' + name)
    checks['candidate_cap_matches_two_independent_reports'] = dict(sha256=EXPECTED_CAP, bytes=cap.stat().st_size,
                 flashed=False, hardware_boot_validated=False, automatic_inventory_included=False)

    generated('00-请先阅读.txt', '''HERO .71 库存阶段交付：实测结果与未刷写固件候选
日期：2026-11-08

已完成并有完整证据的结果
.71 的 System、1 个 CPU 和 4 个内存槽库存已由 UEFI 工具发布并逐项读回；2 个已安装内存和 2 个空槽分别保留真实状态。
CPU 型号为 i9-14900KS，24 核 32 线程；已安装内存共 64 GiB，实际运行速率 4800 MT/s。
System、CPU、内存及处理器摘要经主机热重启后仍正确。主机最后已恢复 Network Stack Disabled，并启动回原 CentOS。
详细限制、未实现字段和实测过程，以 01-实测记录/本轮结果与使用说明-20261108.txt 为准。

必须区分
这些库存结果来自已经运行过的 UEFI 工具，不代表开机自动库存驱动已经完成。
固件候选-未刷写 目录仅包含 SECTIONFIX latest 候选：修复 R2/P6 模块封装末尾 2 字节问题，未增加自动库存上报驱动。
候选尚未实机刷写、尚未验证启动与驻留功能，也未获得 ASUS 重新签名；不能将它视为本轮实机验收通过的正式版。
本包不自动执行工具或刷写。冻结 I3d 工具只适用于原来的 .71 身份及证书，不能当作通用主板工具使用。
BMC 自身重启及整机 AC 断电后的持久性尚未验证；PCIe/Storage 只有离线适配评估。

文件导航
01-实测记录：原始结果说明；5 份完整日志与对应 QR 清单；最终 8 份只读响应；单项 CPU 缓存证据；7 张关键截图。
02-冻结工具：原封不动的 I3d 库存续传包与 I2c 只读诊断包，内部保留各自说明、源码、测试及校验清单。
03-离线源码与测试：动态 SMBIOS 库存生成器、单项缓存刷新模块、交付说明、已有测试结果和少量明确的测试输入。
04-PCIe与存储-离线评估：报告、字段矩阵、缺口及只读解析器的离线测试。未包含原厂全部提取文件；source-manifest/evidence-index 是原工作区证据索引。
固件候选-未刷写：唯一 CAP 候选及构建、独立复核、真实故障定位证据。
校验：内容清单、SHA256SUMS 和打包前证据核对结果。

验证和使用
ZIP 外的 ZIP逐文件SHA256.json 列出每个压缩包成员的 SHA256，包含内部清单本身；ZIP回读验证.json 记录整体 ZIP 的 SHA256、大小和回读结果。
ZIP 内的 校验/内容清单.json 与 SHA256SUMS.txt 覆盖全部业务内容，排除两个清单自身以避免自引用。
解压后可运行 python verify_package.py，仅校验本地文件；也可对原 ZIP 运行 python verify_package.py <ZIP路径>。
不要只凭截图或界面默认的 0 值推断未采集的硬件参数。

打包范围
只采用明确的文件白名单。未纳入凭据、Cookie、登录会话、浏览器控制脚本、全部响应目录或不完整旧日志。
保留本机 UUID、内存序列号、网络地址等硬件追溯信息；关键截图中的已登录用户名显示不用于登录。
未纳入后续 Dashboard 分析。原始源码、报告、日志和冻结工具均按原字节保留。
'''.encode('utf-8'))
    generated('03-离线源码与测试/复核说明.txt', '''离线源码与测试说明
dynamic_catalog 和 cache_refresh 的 handoff.json 是原冻结交付依据，已逐文件复核其 SHA256。
动态库：24 项原生测试、400 个固定种子损坏样本、8 个读边界测试；6 份 .71 真实 payload 与冻结版逐字节一致。
缓存库：27 项原生测试、12 个响应边界测试；当前只是独立库，尚未集成进 I3d 或 BIOS。
本次打包不重新运行上述功能测试，也不运行任何硬件代码；保留已有结果及对应源码供复核。
同目录 analysis 层次保留原始源码与测试输入位置；编译器、Python 外部依赖及工具链未随包分发。
原脚本使用 tools/zig-x86_64-windows-0.14.1/zig.exe；需要在相同工作区布局下另行提供工具链才能重新构建。
historical 697、701、702 是缓存边界测试的准确样本；当前最终结果只以 01-实测记录/最终8份只读响应 为准。
hero71-smbios-i1.TXT 是完整的早期 SMBIOS 输入，用于还原真实硬件字段，不是新的本轮硬件采集。
所有文件保留原字节，原报告中的相对路径均指向原工作区；没有为了打包改写原文。
'''.encode('utf-8'))
    generated('固件候选-未刷写/00-候选状态说明.txt', f'''本目录仅保存未刷写候选，不是实机验收通过的正式版。
文件：{CAP_NAME}
SHA256：{EXPECTED_CAP}
大小：{cap.stat().st_size} 字节
范围：R2/P6 FFS 最后节之后多计入的 2 字节填充；驱动 PE、DEPEX、UI 内容保持不变。
离线检查已通过；尚未实机刷写和启动验证，未重新获得 ASUS 签名。
没有开机自动 System/CPU/Memory 库存上报驱动。本轮库存已写入的事实来自独立 UEFI 工具，不能用于证明此 CAP 功能已通过。
静态复核报告还涉及 observed 对照版本；本交付只含 latest 候选，避免把两个候选混用。
'''.encode('utf-8'))

    verifier = r'''"""Local hash verification only. Does not execute packaged binaries or contact a host."""
from pathlib import Path, PurePosixPath
import hashlib, json, sys, zipfile

def safe(name):
    p=PurePosixPath(name)
    return bool(name) and not p.is_absolute() and '..' not in p.parts and ':' not in name and '\\' not in name

def check(read):
    m=json.loads(read('校验/内容清单.json'))
    for row in m['files']:
        assert safe(row['path']), row['path']
        data=read(row['path'])
        assert len(data)==row['bytes'], row['path']
        assert hashlib.sha256(data).hexdigest()==row['sha256'], row['path']
    print('PASS:',len(m['files']),'content files; no binaries executed.')

if len(sys.argv)==2:
    with zipfile.ZipFile(sys.argv[1]) as z:
        names=z.namelist()
        assert len(names)==len(set(names)) and all(safe(n) for n in names)
        assert z.testzip() is None
        check(z.read)
elif len(sys.argv)==1:
    root=Path(__file__).resolve().parent
    def read(name):
        path=(root/name).resolve(strict=True)
        assert path.is_relative_to(root),name
        return path.read_bytes()
    check(read)
else:
    raise SystemExit('Usage: python verify_package.py [package.zip]')
'''
    generated('verify_package.py', verifier.encode('utf-8'))

    # Actual staging always copies original bytes; no report/source mutation.
    for name, info in items.items():
        if info['source'] is not None:
            p = STAGE / name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / info['source'], p)
        data = (STAGE / name).read_bytes()
        assert len(data) == info['bytes'] and sha(data) == info['sha256'], name

    hits = []
    for name in items:
        hits.extend(audit_credentials(name, (STAGE / name).read_bytes()))
    assert not hits, hits
    checks['credential_rule_hits'] = 0
    checks['selection_mode'] = 'explicit allowlist, no response/screenshot directory recursion'
    checks['original_files_changed'] = False
    checks['hardware_or_network_operations'] = 0
    checks['new_dashboard_analysis_included'] = False
    generated('校验/证据核对结果.json', json_bytes(checks))

    rows = [dict(path=name, **info) for name, info in sorted(items.items())]
    manifest = dict(format=1, self_reference_exclusions=['校验/内容清单.json', '校验/SHA256SUMS.txt'], files=rows)
    for name, data in [('校验/内容清单.json', json_bytes(manifest)),
                       ('校验/SHA256SUMS.txt', ''.join(f"{row['sha256']}  {row['path']}\n" for row in rows).encode('utf-8'))]:
        p = STAGE / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    with zipfile.ZipFile(ZIP, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(STAGE.rglob('*')):
            if p.is_file():
                z.write(p, p.relative_to(STAGE).as_posix())

    zip_rows = []
    with zipfile.ZipFile(ZIP) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and all(valid_name(n) for n in names)
        assert len(names) == len(items) + 2
        assert z.testzip() is None
        for name in names:
            data = z.read(name)
            staged = (STAGE / name).read_bytes()
            assert data == staged and sha(data) == sha(staged), name
            if name in items and items[name]['source'] is not None:
                assert data == (ROOT / items[name]['source']).read_bytes(), name
            zip_rows.append(dict(path=name, bytes=len(data), sha256=sha(data)))
    zip_sha = sha(ZIP.read_bytes())
    (HERE / 'ZIP逐文件SHA256.json').write_bytes(json_bytes(dict(zip=ZIP.name, zip_sha256=zip_sha, files=zip_rows)))
    (HERE / 'ZIP逐文件SHA256.txt').write_text(''.join(f"{row['sha256']}  {row['path']}\n" for row in zip_rows), encoding='utf-8')
    summary = dict(zip=ZIP.name, bytes=ZIP.stat().st_size, sha256=zip_sha, members=len(zip_rows),
                   total_uncompressed_bytes=sum(row['bytes'] for row in zip_rows),
                   all_members_zip_crc_valid=True, all_members_reopened_and_sha256_verified=True,
                   all_source_backed_members_byte_identical_to_unchanged_sources=True,
                   full_log_count=5, final_readonly_responses=8, cpu_cache_evidence_responses=3,
                   screenshots=7, frozen_nested_packages_verified=checks['frozen_nested_packages'],
                   credential_rule_hits=0, hardware_or_network_operations=0,
                   candidate=dict(file=CAP_NAME, sha256=EXPECTED_CAP, flashed=False,
                                  automatic_inventory_included=False, official_asus_release=False),
                   new_dashboard_analysis_included=False)
    (HERE / 'ZIP回读验证.json').write_bytes(json_bytes(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
