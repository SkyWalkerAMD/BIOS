"""Publish source/static data and evidence, never a failed flash/boot package."""
from pathlib import Path
import hashlib
import json
import zipfile

OUT = Path(__file__).resolve().parent
A = OUT.parent
P2 = A/'hero_ipmi_p2'
P3 = A/'hero_ipmi_p3'
L2 = A/'hero_ipmi_p2_live_20261103'
L3 = A/'hero_ipmi_p3_live_20261103'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def response(name):
    d = json.loads((L3/'responses'/name).read_text())
    assert d['ok']
    return d['result']

def main():
    assert json.loads((OUT/'native-verification.json').read_text())['passed']
    for p in (P2,P3):
        build = json.loads((p/'build.json').read_text())
        for rel,digest in build['sources'].items():
            assert sha((p/'source'/rel).read_bytes()) == digest
        for name in ('native-tests.json','policy-tests.json','tse-guard-tests.json'):
            data = json.loads((p/name).read_text())
            assert data['passed'], name
    assert 'Start Media' in response('065-unmount.json')['text']
    assert 'volatile test removed' in response('066-reset-cleanup.json')['reset']
    assert response('070-logout.json')['url'].endswith('/#login')
    assert response('071-stop.json')['stopping']
    logs = {}
    for name in ('P3-new-package','P3-registered-and-linked'):
        data = (L3/(name+'.txt')).read_bytes()
        meta = json.loads((L3/(name+'.json')).read_text())
        assert sha(data) == meta['sha256']
        logs[name] = dict(bytes=len(data),sha256=sha(data))
    findings = dict(target='HERO BIOS 3107 / BMC 1.3.13',native_menu_usable=False,
        registration=dict(before_cache_packages=5,after_cache_packages=6,
                          before_pages=319,after_pages=324,independent_ipmi_pages=5,
                          cached_forms_crc32='A41847FD',log='P3-registered-and-linked.txt'),
        linked_test=dict(native_advanced_controls_preserved=38,
                         replacement_forms_bytes=326030,replacement_crc32='AE2BA886',
                         observed='After A then N, Boot screen no longer responded to Right/Left/Down.'),
        independent_only_test=dict(native_setup_update_called=False,
                         observed='D,P,N returned to Boot; Left reached Monitor; next Left toward Advanced froze the Monitor frame; Right also did not respond.',
                         evidence_screens=['061-key-N.png','062-key-ArrowLeft.png',
                                           '063-key-ArrowLeft.png','064-key-ArrowRight.png']),
        interpretation=['The late NEW-package path also fails when entering Advanced, without modifying the original Setup forms.',
                        'Five cache entries are evidence of registration, not successful GUI rendering.',
                        'A native GUI dynamic-layout problem is a working hypothesis; the faulting CPU instruction was not captured.'],
        cleanup=dict(iso_unmounted=True,host_reset_cleared_volatile_changes=True,
                     original_advanced_verified='screens/069-key-ArrowRight.png',logout_verified=True),
        logs=logs,configuration_writes=False,firmware_flash=False,creator_modified=False)
    (P3/'live-findings.json').write_text(json.dumps(findings,indent=2)+'\n')
    report = '''Z790 HERO 原生 IPMI 栏目适配：P2/P3 实机与 P4 离线进展
日期：2026-11-03
目标：ROG MAXIMUS Z790 HERO，实际 BIOS 3107，BMC 1.3.13。

结论
原生 IPMI 栏目尚未在 HERO 实机跑通，配置写入尚未实现。
当前读数后端已验证；本轮继续解决的是原生 BIOS 菜单整合。
P4 是匹配的原生菜单资源和 Setup 资源组件，尚不是完整可刷 BIOS。

已确认的功能
BMC 自检、Device ID、BMC 固件版本、IPMI 版本、看门狗状态、
LAN 地址来源/IP/掩码/网关/MAC、SEL 状态及前 16 条原始事件记录。
本轮后端使用标准只读命令；临时启用的 PCI Memory 位已按日志恢复。
没有执行 BMC 设置写入、清空事件日志、启动看门狗或 BIOS 刷写。

P2 实机：找到了一个明确的菜单索引问题
原始页面数 319；更新后为 320。
Advanced 从索引 35 移到了 319，但新增 IPMI 页面没有被加入缓存。
新增入口指向索引 320，已经超出有效页面范围 0..319。
REA 对 30318/310c8 的分析与此一致：替换包的复用路径不追加不存在的表单，
而控件数量变化会让原页面分配新索引。
原始菜单已恢复并读回核对，再重启清除全部内存测试内容。

P3 实机：独立页面注册成功，但原生显示仍失败
5 个 IPMI 页面通过独立 NEW 包进入缓存，页面总数 324，缓存内容校验一致。
此处验证的是注册成功，不是页面显示成功。
第一组测试用 REF3 连接 Advanced，保持原 38 个控件数量；返回后界面停顿。
第二组只注册独立页面，没有更新原 Setup 表单：返回 Boot 后可进入 Monitor，
继续进入 Advanced 时仍停顿。说明此前的无效索引并非唯一问题。
尚未取得停顿位置的 CPU 指令，因此不能将某个反编译分支说成已证实的全部根因。

P4 离线：改为构建菜单初始化时使用的配套资源
1. 在 HERO 自身的 Setup 表单中加入 5 页及 Advanced > IPMI 入口。
2. 同步构建 AMITSESetupData 页表：299 -> 304，Advanced 控件数 38 -> 39。
3. 原有 8,882 个控件逐项核对；8,334 个原 IFR 引用、6,268 个条件目标核对一致。
4. 6,804 个受插入位置影响的 IFR 指针同步调整；47 个新增只读控件及 5 条跳转通过校验。
5. 10 个语言包保留原始字符串，新增相同 ID 的 96 个字符串，新增内容目前为英文。
6. Setup 的 HII 资源重打包后校验正确，可执行代码、入口点和重定位条目保持原样。
这些检查证明离线资源一致，不能替代 HERO 的原生菜单运行验证。

P4 尚未完成的部分
现有只读 BMC 后端与 P4 静态字符串的实时绑定；启动阶段的驱动装配和整包固件校验；
原生页面打开/返回的实机验证；网络配置、看门狗策略、SEL 策略的保存与回读。
MLED/BMC_LED 同步、BMC 硬件版本和 In-Band 类型仍需各自适配。
没有把 ProArt 的 ServerSetup 变量偏移直接写到 HERO，也没有移植其默认写入/复位回调。

当前实机状态
P3 测试 ISO 已卸载，主机已重启移除内存测试内容；截图 069 确认原生 Advanced 正常。
BMC 已退出到登录页，私有浏览器已关闭。Creator 参考机未作更改。

交付说明
源码证据包不包含可启动 ISO、EFI、FFS 或 CAP。
P4 的 Setup-P4-RESOURCE-REVIEW.efi 仅为本地资源重打包审查组件，
不能作为启动程序、刷写文件或已经完成适配的固件使用。
'''
    report_path = OUT/'原生IPMI栏目适配进展-P2-P4-20261103.txt'
    report_path.write_text(report,encoding='utf-8')
    dest = A/'HERO-3107-IPMI-P2-P4-SOURCE-EVIDENCE.zip'
    files = {}
    def add(p, name):
        assert p.is_file() and p.suffix.lower() not in ('.efi','.ffs','.cap','.iso','.obj','.dll','.lib','.pyc')
        assert name not in files
        files[name] = p.read_bytes()
    add(report_path,'阅读说明.txt')
    for root in (P2,P3):
        tag = root.name.rsplit('_',1)[-1].upper()
        for p in (root/'source').rglob('*'):
            if p.is_file(): add(p,tag+'/source/'+p.relative_to(root/'source').as_posix())
        for name in ('build.py','build.json','generate_forms.py','test_native.py','test_policy.py',
                     'test_tse_guard.py','native-tests.json','policy-tests.json','tse-guard-tests.json',
                     'live-findings.json','decode_captures.py'):
            add(root/name,tag+'/'+name)
    for name in ('build_native_payload.py','verify_native_payload.py','package_progress.py',
                 'Setup-HII-P4.bin','Setup-forms-P4.bin','AMITSESetupData-P4.bin',
                 'native-payload.json','native-verification.json','resource-code-reference-audit.json'):
        add(OUT/name,'P4/'+name)
    for root in (L2,L3):
        tag = 'P2' if root == L2 else 'P3'
        for p in root.glob(tag+'-*.txt'): add(p,'evidence/'+tag+'/'+p.name)
        for p in root.glob(tag+'-*.json'): add(p,'evidence/'+tag+'/'+p.name)
    for name in ('030-key-A.png','049-key-N.png','050-key-ArrowRight.png','051-key-ArrowLeft.png',
                 '052-key-ArrowDown.png','061-key-N.png','062-key-ArrowLeft.png',
                 '063-key-ArrowLeft.png','064-key-ArrowRight.png','069-key-ArrowRight.png'):
        add(L3/'screens'/name,'evidence/P3/screens/'+name)
    for p in (P3/'reference/rea').glob('FUN_*.c'):
        add(p,'reference/rea/'+p.name)
    add(A/'hero_ipmi_p1b/reference/HERO-3107-AMITSESetupData.bin','reference/HERO-3107-AMITSESetupData.bin')
    add(P3/'reference/HERO-3107-forms.bin','reference/HERO-3107-forms.bin')
    manifest = {name:dict(bytes=len(b),sha256=sha(b)) for name,b in files.items()}
    files['manifest.json'] = (json.dumps(manifest,indent=2)+'\n').encode()
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,b in files.items(): z.writestr(name,b)
    with zipfile.ZipFile(dest) as z:
        assert z.testzip() is None and set(z.namelist()) == set(files)
        for name,b in files.items(): assert z.read(name) == b
    summary = dict(path=dest.as_posix(),bytes=dest.stat().st_size,
                   sha256=sha(dest.read_bytes()),files=len(files),bootable_payloads_included=False)
    (OUT/'delivery.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2))

if __name__ == '__main__':
    main()
