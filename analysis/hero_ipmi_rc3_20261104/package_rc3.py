"""Curated field package with three clearly separated CAP choices and hashes.

No wildcard collection of the workspace, remote sessions or login artifacts.
No flashing or device access. Existing RC2/R2 artifacts are never overwritten.
"""
from pathlib import Path
import hashlib, json, re, zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PACKAGE = HERE/'FIELD-PACKAGE'
ZIP = ROOT/'analysis/HERO-3107-IPMI-P5-R2-RC3-FLASHBACK-20261104.zip'
P5 = ROOT/'analysis/hero_ipmi_p5'
R2 = ROOT/'analysis/hero_ipmi_r2'
REVIEW = ROOT/'analysis/hero_ipmi_p5_rea_review_20261103'
RC3_SHA = '8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'
RC2_SHA = '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
OFFICIAL_SHA = 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
ISO_SHA = '7472d8c85396c701de4295c4a21e86c7562824ba023185a611d5bb08f8721920'
APP_SHA = '9b09356be91c7865b745146b1316669df21270c10e27fd0c425a88491afd2281'

def sha(b): return hashlib.sha256(b).hexdigest()
def read(path): return json.loads(path.read_text(encoding='utf-8'))

def main():
    checks = [('container-verification.json','passed'),('authentication-verification.json','passed_expected_results'),
        ('runtime-verification.json','passed'),('review/integration-review.json','passed_static_checks'),
        ('collector/app-verification.json','all_passed'),('collector/vm-verification.json','all_passed')]
    for name, key in checks:
        assert read(HERE/name)[key], name
    assert read(HERE/'runtime-verification.json')['candidate_sha256'] == RC3_SHA
    assert read(HERE/'collector/app-verification.json')['app_sha256'] == APP_SHA
    PACKAGE.mkdir(exist_ok=True)
    staged = {}

    def put(source, destination, expected=None):
        assert source.is_file(), source
        name = Path(destination).as_posix()
        assert name not in staged and not name.startswith('/') and '..' not in Path(name).parts
        data = source.read_bytes()
        if expected: assert sha(data) == expected, source
        target = PACKAGE/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
        staged[name] = dict(path=name,bytes=len(data),sha256=sha(data),source=str(source.relative_to(ROOT)))

    def write(destination, content):
        name=Path(destination).as_posix()
        assert name not in staged
        data=content.encode('utf-8')
        target=PACKAGE/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
        staged[name]=dict(path=name,bytes=len(data),sha256=sha(data),source='generated field instructions')

    put(HERE/'firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP','01-RC3-FLASHBACK/MZ790H.CAP',RC3_SHA)
    put(REVIEW/'rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP','90-PREVIOUS-RC2/MZ790H.CAP',RC2_SHA)
    put(ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP','91-OFFICIAL-3107/MZ790H.CAP',OFFICIAL_SHA)
    put(HERE/'刷写与验收说明.txt','刷写与验收说明.txt')
    put(HERE/'collector/HERO-RC3-AUTO-LOG.iso','02-AUTO-LOG/HERO-RC3-AUTO-LOG.iso',ISO_SHA)
    put(HERE/'collector/使用说明.txt','02-AUTO-LOG/使用说明.txt')
    for source in sorted((HERE/'collector/USB').rglob('*')):
        if source.is_file():
            put(source,'02-AUTO-LOG/USB/'+source.relative_to(HERE/'collector/USB').as_posix(),
                APP_SHA if source.name=='BOOTX64.EFI' else None)
    for name in ['build.json','container-verification.json','authentication-verification.json','runtime-verification.json',
        'review/integration-review.json','review/integration-review.txt','collector/build.json','collector/app-verification.json',
        'collector/vm-verification.json','collector/source-provenance.json']:
        put(HERE/name,'04-EVIDENCE/RC3/'+name)
    for source in sorted(HERE.glob('*-r2.txt'))+sorted(HERE.glob('*-p5.txt'))+sorted(HERE.glob('boot-*.txt')):
        put(source,'04-EVIDENCE/RC3/runtime-replays/'+source.name)
    for mode in ('iso_readonly','usb'):
        for name in ('capture-only-no-core.png','serial.log','result.json'):
            put(HERE/'collector/vm'/mode/name,'04-EVIDENCE/RC3/collector/vm/'+mode+'/'+name)
    put(HERE/'firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP.report.txt','04-EVIDENCE/RC3/UEFIExtract-report.txt')
    for name in ('verification.json','entry-verification.json','static-analysis.json','build.json'):
        put(R2/name,'04-EVIDENCE/PRIOR-R2/'+name)
    for name in ('live-verification.json','R2-success-full.TXT','R2-reload-summary.TXT'):
        put(ROOT/'analysis/hero_ipmi_r2_live_20261102'/name,'04-EVIDENCE/PRIOR-R2/live/'+name)
    for name in ('field-result.json','P5-field-log.txt','transactions.json','实机验证补充记录.txt'):
        put(ROOT/'analysis/hero_ipmi_p5_field_20261104'/name,'04-EVIDENCE/PRIOR-RC2-FIELD/'+name)
    for name in ('policy-tests.json','publisher-tests.json','native-verification.json'):
        put(P5/name,'04-EVIDENCE/PRIOR-P5/'+name)
    for name in ('sensor-comparison.json','传感器差异复核.txt'):
        put(ROOT/'analysis/hero_ipmi_sensor_gap_20261104'/name,'04-EVIDENCE/SENSOR-COMPARISON/'+name)

    # Existing matching REA evidence is reused, not presented as a new session.
    rea = [
        (R2/'reference/index.json','R2-reference-index.json'),
        (R2/'reference/rea/baseline/responses/002-initialization.json','creator-initialization.json'),
        (R2/'reference/rea/seeded/responses/002-ipmi-publish.json','creator-publisher.json'),
        (REVIEW/'review-index.json','P5-RC2-review-index.json'),
        (REVIEW/'driver-loopback/responses/002-entry.json','P5-entry.json'),
        (REVIEW/'driver-loopback/responses/003-core.json','P5-core.json'),
        (REVIEW/'driver-seeded/responses/002-timer.json','P5-timer.json'),
        (REVIEW/'dxe/responses/005-lzma-constructor.json','HERO-DXE-LZMA.json')]
    for source, name in rea: put(source,'04-EVIDENCE/REUSED-REA/'+name)

    for name in ('build_rc3.py','verify_container.py','verify_runtime.py','verify_authentication.py','package_rc3.py'):
        put(HERE/name,'05-SOURCE/RC3/'+name)
    put(HERE/'review/review_rc3_integration.py','05-SOURCE/RC3/review_rc3_integration.py')
    for folder, label in [(P5,'P5'),(R2,'R2'),(HERE/'collector','COLLECTOR')]:
        for source in sorted((folder/'source').rglob('*')):
            if source.is_file(): put(source,'05-SOURCE/'+label+'/source/'+source.relative_to(folder/'source').as_posix())
        put(folder/'build.py','05-SOURCE/'+label+'/build.py')
    for name in ('verify.py','verify_entry.py','decode_captures.py'):
        put(R2/name,'05-SOURCE/R2/'+name)
    for name in ('verify_app.py','run_vm.py','prepare_source.py','launcher.map'):
        put(HERE/'collector'/name,'05-SOURCE/COLLECTOR/'+name)
    for name in ('container_review.py','container_review_rc2.py'):
        put(REVIEW/name,'05-SOURCE/DEPENDENCIES/'+name)
    put(P5/'build_candidate.py','05-SOURCE/DEPENDENCIES/build_candidate.py')
    put(ROOT/'analysis/hero_ipmi_flash_validation_20261104/capsule/verify_hero_capsule.py','05-SOURCE/DEPENDENCIES/verify_hero_capsule.py')
    put(R2/'driver.map','05-SOURCE/R2/driver.map')
    put(P5/'driver.map','05-SOURCE/P5/driver.map')
    put(ROOT/'tools/rea-runtime/node_modules/rea-agents/skills/reverse-engineer-anything/SKILL.md','05-SOURCE/REA-SKILL.md')
    write('05-SOURCE/说明.txt',
        '源码/脚本为本次审计快照，保持原工作区路径引用。完整重跑还需要原工作区中的工具链、\n'
        'Unicorn/pefile/PyCDlib 依赖、记录的测试夹具和原始固件。本包不是独立工具链安装包。\n'
        '本次固件没有重编译 P5/R2 核心，CAP 中两者与已验证版本逐字节相同；只重编译只读日志应用。\n'
        'PRIOR 和 REUSED-REA 为历史证据，不代表 RC3 的新实机验证。\n')

    ledger = dict(date='2026-11-04', candidate_sha256=RC3_SHA, status='OFFLINE_VERIFIED_FIELD_CANDIDATE',
        new_hardware_test=False, remote_bmc_access=False,
        assumed_wiring='New .71 BMC_HEADER connected, per user instruction; not independently observed',
        findings=[
            dict(id='RC3-C1',result='passed_offline',claim='Add R2 in original inner DXE FV; keep existing P5/Setup/SPF bytes and offsets.',evidence=['RC3/container-verification.json','RC3/review/integration-review.json']),
            dict(id='RC3-C2',result='passed_replay',claim='Extracted P5/R2 code shares serialized BMC/PCI state successfully in three schedules; six boot skip/guard cases pass.',evidence=['RC3/runtime-verification.json']),
            dict(id='RC3-C3',result='passed_scoped',claim='Capture application never calls run/enable/unlock or loads a driver; 11 machine-code tests and 2 bounded OVMF boot cases pass.',evidence=['RC3/collector/app-verification.json','RC3/collector/vm-verification.json']),
            dict(id='RC3-C4',result='confirmed_limitation',claim='Vendor certificate preserved; modified firmware signature invalid. RC3 flashing acceptance not established.',evidence=['RC3/authentication-verification.json']),
            dict(id='RC3-H1',result='prior_hardware',claim='User reports RC2 FlashBack and native automatic pages plus OS boot on new HERO .71; exact flashed file readback not available.',evidence=['PRIOR-RC2-FIELD/field-result.json']),
            dict(id='RC3-H2',result='prior_hardware',claim='Same R2 code manually initialized old HERO .182: eight motherboard readings observed, fan/pump availability unresolved.',evidence=['PRIOR-R2/live/live-verification.json']),
            dict(id='RC3-H3',result='pending_hardware',claim='Combined RC3 automatic ReadyToBoot initialization, FlashBack acceptance, boot stability and actual recovery remain to be tested onsite.',evidence=[])],
        rea_reuse=dict(new_session_opened=False, rationale='Unchanged native inputs retain the prior matching REA evidence; new assembly is independently parsed and extracted code is executed in replay.',
            skill='05-SOURCE/REA-SKILL.md', evidence_ids=[
                'ev_8ce483e5979ae86bf3333a571a02a5ed1de064e519e893c26a6e52013370b050',
                'ev_e1dd50026ebb1e0070f283c60b4a7839e026266095c860b687494260fbb665a4'],
            index='REUSED-REA/P5-RC2-review-index.json'),
        remaining=['New hardware acceptance and sensor correctness','Cold/warm boot and recovery',
            'Editable LAN/watchdog/SEL settings, fan/pump mapping, LEDs and in-band driver type'],
        specification_links=['https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html',
            'https://www.asus.com/support/faq/1038568/'])
    write('04-EVIDENCE/RC3-FINDING-LEDGER.json',json.dumps(ledger,ensure_ascii=False,indent=2)+'\n')
    write('00-先读我.txt',
        'HERO 3107 IPMI RC3 / P5 原生菜单 + R2 自动传感器初始化\n\n'
        '本次刷写：01-RC3-FLASHBACK/MZ790H.CAP\n'
        '先结束压力测试，按“刷写与验收说明.txt”通过背板 USB BIOS FlashBack 操作。\n'
        '不要把 90/91 目录的同名恢复文件当成本次 RC3，也不要使用 EZ Flash。\n'
        '刷后先启动系统，再检查主板温度/电压。数量不必等于旧机的25个 Normal Sensors。\n'
        '02-AUTO-LOG 是本次仅采集自动运行日志的 ISO/USB 工具，勿混用旧手动初始化工具。\n\n'
        '01 = 当前 RC3（新增自动 R2）；90 = 前版 RC2（已有实机成功反馈）；91 = 官方3107。\n'
        'RC3 结构/代码回放检查通过，实机自动运行与恢复尚待现场验收，仍为定制候选版。\n'
        'P5 菜单继续只读；本次不包含网络/看门狗/SEL写设置、LED、风扇水泵适配。\n\n'
        'RC3 SHA-256：'+RC3_SHA+'\n'
        '所有包内文件的 SHA-256 在 SHA256SUMS.txt；文件清单含来源与大小。\n')
    # All data is curated above; no BMC sessions, credentials, token stores or
    # network-control scripts are selected. Refuse stale/unselected leftovers.
    actual={p.relative_to(PACKAGE).as_posix() for p in PACKAGE.rglob('*') if p.is_file()}
    assert actual <= set(staged)|{'MANIFEST.json','SHA256SUMS.txt'}, actual-set(staged)
    for name in staged:
        if Path(name).suffix.lower() in {'.txt','.json','.py','.c','.h','.md'}:
            text=(PACKAGE/name).read_text(encoding='utf-8')
            assert not re.search(r'(?i)"(?:password|passwd|auth_token|x-auth-token)"\s*:\s*"[^"\s]+"',text), name
    manifest=dict(version='HERO 3107 IPMI P5 + R2 RC3',candidate_sha256=RC3_SHA,
        hardware_verified=False, files=[staged[n] for n in sorted(staged)])
    (PACKAGE/'MANIFEST.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    checksums=''.join(staged[n]['sha256']+'  '+n+'\n' for n in sorted(staged))
    checksums += sha((PACKAGE/'MANIFEST.json').read_bytes())+'  MANIFEST.json\n'
    (PACKAGE/'SHA256SUMS.txt').write_text(checksums,encoding='utf-8')
    with zipfile.ZipFile(ZIP,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for p in sorted(PACKAGE.rglob('*')):
            if p.is_file(): archive.write(p,p.relative_to(PACKAGE).as_posix())
    with zipfile.ZipFile(ZIP) as archive:
        assert archive.testzip() is None
        assert len(archive.namelist()) == len(staged)+2
        assert len(set(archive.namelist())) == len(archive.namelist())
        for name,row in staged.items():
            data=archive.read(name)
            assert len(data)==row['bytes'] and sha(data)==row['sha256'], name
        assert sorted(n for n in archive.namelist() if n.upper().endswith('.CAP')) == [
            '01-RC3-FLASHBACK/MZ790H.CAP','90-PREVIOUS-RC2/MZ790H.CAP','91-OFFICIAL-3107/MZ790H.CAP']
        usb=[n for n in archive.namelist() if n.startswith('02-AUTO-LOG/USB/')]
        assert sorted(usb)==['02-AUTO-LOG/USB/EFI/BOOT/BOOTX64.EFI','02-AUTO-LOG/USB/HERO_RC3.TAG']
    report=dict(package=str(ZIP),bytes=ZIP.stat().st_size,sha256=sha(ZIP.read_bytes()),
        candidate_sha256=RC3_SHA,manifest_files=len(staged),archive_members=len(staged)+2,
        zip_crc_and_all_manifest_hashes_passed=True,three_caps_verified_separately=True,
        no_old_manual_diagnostic_media=True,no_known_login_credentials=True,
        new_hardware_flash_or_bmc_access=False)
    (HERE/'delivery.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__ == '__main__': main()
