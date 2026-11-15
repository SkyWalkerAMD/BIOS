"""Ship both original P2 USB file output and the new read-only P3 KVM ISO."""
from pathlib import Path
import base64,datetime,hashlib,html,json,shutil,zipfile
OUT=Path(__file__).resolve().parent;BASE=OUT.parent;ROOT=OUT.parents[2]
RELEASE=BASE/'delivery_dual_mode_20261102'
ZIP=BASE/'AiTweaker-实机采集工具包-USB与KVM.zip'
P2_SHA='a16b2e7e0af6aa48cd375a3a3fbd77e58f60a50edd929751fcfe6951d6df64b5'
P2_ZIP_SHA='c06fafc804b6cedc74003459c49d18da53db7618d21edf72391dcfc2ac43ae64'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def write(p,value):Path(p).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def main():
    build=read(OUT/'build.json');capture=read(OUT/'capture_verification.json');inventory=read(OUT/'inventory_verification.json')
    vm=[read(p) for p in sorted((OUT/'vm').glob('*/result.json'))]
    assert len(vm)==3 and all(r['passed'] for r in vm)
    assert capture['passed'] and capture['count']==26 and inventory['passed'] and inventory['count']==27
    assert build['parser_source_unchanged'] and build['profile_source_unchanged']
    assert all(x['efi_sha256']==build['efi_sha256'] for x in [capture,inventory]+vm)
    assert sha(OUT/'BOOTX64.EFI')==build['efi_sha256'] and sha(OUT/'AiTweaker-P3-KVM.iso')==build['iso_sha256']
    assert all(x['iso_sha256_before']==x['iso_sha256_after']==build['iso_sha256'] for x in vm)
    assert any(x.get('idle_seconds',0)>=330 for x in vm)
    p2=BASE/'probe_p2/USB/EFI/BOOT/BOOTX64.EFI';oldzip=BASE/'AiTweaker-P2-免刷写诊断.zip'
    assert sha(p2)==P2_SHA and sha(oldzip)==P2_ZIP_SHA
    original_root=ROOT/'analysis/workstation_20261008';original=read(original_root/'packages.json');original_checks=[]
    for tag in ('W790_SAGE_2003','W790_ACE_2003','W890_SAGE_0603'):
        p=original[tag];assert sha(ROOT/p['source'])==p['zip_sha256'] and sha(original_root/p['cap'])==p['cap_sha256']
        original_checks.append({'board':tag,'zip_sha256':p['zip_sha256'],'cap_sha256':p['cap_sha256'],'unchanged':True})
    for name in ('USB/EFI/BOOT','KVM','资料/P3源码','资料/P3验证'):(RELEASE/name).mkdir(parents=True,exist_ok=True)
    shutil.copyfile(p2,RELEASE/'USB/EFI/BOOT/BOOTX64.EFI')
    shutil.copyfile(BASE/'probe_p2/USB/AITWEAKER-PROBE.TAG',RELEASE/'USB/AITWEAKER-PROBE.TAG')
    shutil.copyfile(OUT/'AiTweaker-P3-KVM.iso',RELEASE/'KVM/AiTweaker-P3-KVM.iso')
    iso_sha=build['iso_sha256']
    guide=f'''Ai Tweaker 实机采集工具包：USB 文件日志 + KVM 虚拟光驱
日期：2026-11-02

本包保留两种入口；两者都是诊断工具。Ai Tweaker 独立密码锁尚未实现，无修改版 CAP。
目标版本：Pro WS W790E-SAGE SE 2003 / Pro WS W790-ACE 2003 / Pro WS W890E-SAGE SE 0603。
三款实机均尚未验证。采集的 PARTIAL 日志也有价值；无需输入任何 BIOS 密码。

选择方式
USB/：原版 P2。可写 FAT32 U 盘启动，在启动 U 盘根目录保存 AITWK-xxx.TXT。
KVM/AiTweaker-P3-KVM.iso：新增 P3。供 BMC/IPMI 虚拟光驱挂载，显示完整日志的分段二维码。
只用虚拟光驱和远程画面时，选择 ISO 入口；此入口不在光盘或本地硬盘上保存 TXT 文件。

方式一：原有 U 盘 TXT 日志（保持原版 P2 不变）
1. 把 USB 文件夹里面的内容复制到可写 FAT32 U 盘根目录：
   /EFI/BOOT/BOOTX64.EFI
   /AITWEAKER-PROBE.TAG
   两者必须配套；不要覆盖其他用途的 EFI 启动文件。不需要重新格式化已有可用 U 盘。
2. 启动菜单选择该 U 盘的 UEFI 项。显示 Saved 后约 3 秒返回固件。
3. 取回 AITWK-000.TXT、AITWK-001.TXT 等，附主板型号和实际 BIOS 版本。
4. 旧日志可以保留，P2 使用下一个编号；000—999 全部占用时停止。
   写满或写入失败可能留下空文件/不完整文件；没有 Saved 就不能认定保存成功。

方式二：BMC/IPMI 虚拟光驱 + 远程 KVM（适用于当前远程环境）
1. 解压本包，在 BMC 虚拟介质功能中挂载 KVM/AiTweaker-P3-KVM.iso 本身。
   挂载对象是 ISO 文件，不是本 ZIP，也不是把 EFI 文件随意压成 ISO。
2. 启动菜单选择虚拟 CD/DVD 的 UEFI 项。工具自动采集后停留在 QR PAGE 1/N。
3. 保存当前远程 KVM 原始截图，优先 PNG，保留完整二维码、白色边框和页码。
   避免缩小画面或反复压缩。直接截图即可，不需要手机扫描二维码。
4. 按 N 或 Enter 到下一页，每页截一张，直到 PAGE N/N。P 返回上一页。
   按实际总页数收齐；不同机器的截图分别放文件夹，标注型号、实际 BIOS 版本和本次运行。
5. 全部截图发回后，可以按页码拼接、逐段和整份 CRC 校验，还原完整 TXT 日志。
   也可使用资料中的 decode_captures.py；依赖 Pillow 12.0.0 与 zxing-cpp 3.1.1。
6. 收齐截图再按 Esc 退出。日志仅保留在当前运行内存中，退出或重启后不能从 ISO 找回。
   程序不会自动跳过二维码页。虚拟机已验证停留 330 秒后仍可继续操作。

键盘操作
N / Enter / 空格 / 右方向键 / PageDown：下一页；末页保持不动。
P / 左方向键 / PageUp：上一页；首页保持不动。
Home / End：首页 / 末页。
T：文字页，供人工核查；Q：返回二维码。切换模式从该模式第 1 页开始。
Esc：退出并返回固件。
若远程画面未显示二维码，可按 T 尝试文字输出；保留画面和提示供分析。
二维码用于精确还原字节，文字截图不承诺自动精确还原。

结果与边界
COLLECTION_STATUS=PARTIAL：部分接口不可用或版本未识别，仍可提交。
COLLECTION_STATUS=COMPLETE：本次读取未记录警告，不等同于密码锁或实机兼容验证通过。
PROBE_COMPLETE：日志生成流程结束。二维码是日志数据，不是网站链接。
页内及整份 CRC 用于传输完整性检查，不认证主板身份；仍需注明型号和版本。
P2 仅主动向带正确标记的自身启动卷新建日志；P3 不主动写磁盘、NVRAM 或 SPI。
P3 临时关闭 UEFI 启动看门狗以便截图，不改变持久化 BIOS 设置或 BMC 配置。
固件本身启动时可能维护自己的启动变量，这与诊断程序的行为不同。
两种 EFI 都未签名；若 Secure Boot 策略拒绝启动，请记录提示。本包不会改变该策略。
本包用于 UEFI 启动，不要交给 EZ Flash 或 USB BIOS FlashBack。

已完成验证
P2：沿用原诊断版本，已完成 16 项 QEMU/OVMF 启动和 FAT 读写场景；程序和原 ZIP 均未改。
P3：3 次真实 OVMF 光盘启动：SATA 1280x800、USB 1024x768、USB 640x480。
     每次均从截图还原 4 页、3020 字节的虚拟机日志，与程序控制台输出逐字节一致。
     翻页、边界、文字/二维码切换和退出通过；640x480 场景额外停留 330 秒。
     26 组原生编码/还原检查覆盖 1—65536 字节边界、漏页、混页、冲突重复页、坏校验和图像压缩。
     三套原 ASUS 模块分别 9 项，共 27 项 EFI 模拟检查通过；这些 UEFI 服务是合成的。
以上不等于在三款 ASUS 工作站实机或实际 BMC 视频链路上验证通过。
原三份 BIOS ZIP/CAP 均未改变。无刷写、无密码锁安装。

完整性
原 P2 EFI SHA-256：{P2_SHA}
P3 EFI SHA-256：{build['efi_sha256']}
P3 ISO SHA-256：{iso_sha}
本包每个文件的哈希见 SHA256SUMS.txt；完整技术证据见资料目录。

源码说明
P3 的接口采集和解析逻辑沿用 P2；新增显示、键盘交互、二维码分段和看门狗处理。
二维码编码使用 Project Nayuki QR-Code-generator v1.8.0，MIT 许可保留在源码内。
构建脚本依赖原工作区、Zig 0.14.1 和 tools 中的 Python 依赖，源码材料不是独立 SDK。
参考：https://www.nayuki.io/page/qr-code-generator-library
      https://clalancette.github.io/pycdlib/example-creating-bootable-iso.html
      https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/GraphicsOutput.h
'''
    (RELEASE/'使用说明.txt').write_text(guide,encoding='utf-8')
    summary={'date':'2026-11-02','status':'DUAL_MODE_DIAGNOSTIC_READY_AWAITING_PHYSICAL_TEST',
      'modes':{'USB_P2':{'path':'USB/EFI/BOOT/BOOTX64.EFI','sha256':P2_SHA,'output':'new AITWK-xxx.TXT on marked boot volume','unchanged':True},
               'KVM_P3':{'path':'KVM/AiTweaker-P3-KVM.iso','sha256':iso_sha,'efi_sha256':build['efi_sha256'],'output':'QR screenshots reconstructed to exact log bytes'}},
      'p2_original_zip_sha256':P2_ZIP_SHA,'p3_capture_checks':capture['count'],'p3_inventory_cases':inventory['count'],
      'p3_vm_runs':vm,'original_bios_unchanged':original_checks,'hardware_validation_performed':False,
      'password_lock_implemented':False,'modified_cap_created':False,'p2_previous_vm_cases':16,
      'limits':['Generic OVMF is not ASUS firmware','Physical BMC keyboard/video/media not tested','Unsigned EFI; Secure Boot enforcement not tested',
                'CRC detects transmission errors, not board identity or malicious forgery','Text pages are manual fallback, not exact QR reconstruction']}
    write(OUT/'delivery.json',summary);write(RELEASE/'资料/P3验证/交付摘要.json',summary)
    for p in (OUT/'source').rglob('*'):
        if p.is_file():
            dest=RELEASE/'资料/P3源码/source'/p.relative_to(OUT/'source');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
    for name in ('prepare_source.py','build.py','decode_captures.py','verify_capture.py','verify_inventory.py','verify_vm.py','package_dual.py'):
        shutil.copyfile(OUT/name,RELEASE/'资料/P3源码'/name)
    for name in ('build.json','capture_verification.json','inventory_verification.json','inventory_provenance.json'):
        shutil.copyfile(OUT/name,RELEASE/'资料/P3验证'/name)
    for r in vm:
        folder=OUT/r['folder'];dest=RELEASE/'资料/P3验证'/folder.name;dest.mkdir(exist_ok=True)
        for p in folder.iterdir():
            if p.suffix.lower() in ('.json','.jsonl','.log','.txt','.png'):shutil.copyfile(p,dest/p.name)
    shutil.copyfile(BASE/'AiTweaker-P2-UEFI虚拟机测试报告.txt',RELEASE/'资料/AiTweaker-P2-UEFI虚拟机测试报告.txt')
    # The historical HTML links to its full workspace evidence tree; ship its
    # self-contained text report here, leaving the original HTML untouched.
    stale=RELEASE/'资料/AiTweaker-P2-UEFI虚拟机测试报告.html'
    if stale.is_file():
        assert stale.resolve().is_relative_to(RELEASE.resolve());stale.unlink()
    screenshot=base64.b64encode((OUT/'vm/usb_640x480_idle330/qr-001.png').read_bytes()).decode('ascii')
    report='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ai Tweaker 双模式采集工具</title>
<style>body{background:#f4f6fa;color:#172539;font:16px/1.7 system-ui,"Microsoft YaHei",sans-serif;margin:0}main{max-width:1000px;margin:auto;padding:36px 24px}h1{font-size:30px;line-height:1.4}h2{font-size:21px}table{border-collapse:collapse;width:100%;background:white}th,td{padding:14px;text-align:left;vertical-align:top;border-bottom:1px solid #d6e0eb}th{background:#e8eef6}.note{background:#e7effb;border-left:4px solid #3f70ac;padding:14px 18px}img{max-width:100%;border:1px solid #ccd5df;border-radius:8px}pre{background:white;padding:18px;white-space:pre-wrap;word-break:break-all;font:14px/1.7 Consolas,monospace}summary{cursor:pointer;font-weight:600}code{word-break:break-all}</style><main>
<p>2026-11-02 · 两种采集方式同时保留</p><h1>U 盘保存 TXT，虚拟光驱通过截图取回日志</h1>
<table><tr><th>入口</th><th>适用环境</th><th>交回的资料</th></tr><tr><td><strong>USB / 原版 P2</strong></td><td>可写 FAT32 U 盘</td><td>AITWK-xxx.TXT</td></tr><tr><td><strong>KVM / P3 ISO</strong></td><td>BMC/IPMI 虚拟光驱 + 远程画面</td><td>每一页二维码的清晰截图</td></tr></table>
<p class="note">原 P2 字节未改，原有文件日志流程保留。新增 ISO 自动采集后停留等待截图；N/Enter 下一页，P 上一页，收齐后 Esc 退出。两个入口都是诊断程序，Ai Tweaker 密码锁尚未实现。</p>
<h2>光盘版实际运行截图：640×480</h2><p>以下为虚拟机截图示例。你的实际页数以画面上的 PAGE 1/N 为准，截图时保留二维码白边和页码。</p>
'''+f'<img alt="P3 光盘版在 640x480 虚拟 KVM 中显示第一页二维码" src="data:image/png;base64,{screenshot}">'+'''
<h2>验证结果</h2><p>3 个真实 OVMF 光盘启动配置均通过，12 页二维码完整还原为各次 3020 字节的日志，且与程序输出逐字节一致。包含 330 秒停留、翻页、文字模式及退出。另有 26 组编码/还原检查、三套 ASUS 模块的 27 项 EFI 模拟检查通过。</p>
<p>这些是通用虚拟机和合成服务测试，尚未验证实际主板、BMC 视频压缩和启动策略。P2 继续沿用已有 16 项虚拟机启动与文件读写结果。</p>
<details><summary>完整使用说明、测试边界与哈希</summary><pre>'''+html.escape(guide)+'''</pre></details></main></html>'''
    (RELEASE/'使用说明与验证报告.html').write_text(report,encoding='utf-8')
    (BASE/'AiTweaker-双模式采集说明.html').write_text(report,encoding='utf-8')
    (BASE/'AiTweaker-双模式采集说明.txt').write_text(guide,encoding='utf-8')
    (RELEASE/'KVM/AiTweaker-P3-KVM.iso.sha256').write_text(iso_sha+'  AiTweaker-P3-KVM.iso\n',encoding='utf-8')
    files=sorted(p for p in RELEASE.rglob('*') if p.is_file() and p.name!='SHA256SUMS.txt')
    manifest=''.join(sha(p)+'  '+p.relative_to(RELEASE).as_posix()+'\n' for p in files)
    (RELEASE/'SHA256SUMS.txt').write_text(manifest,encoding='utf-8')
    with zipfile.ZipFile(ZIP,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(p for p in RELEASE.rglob('*') if p.is_file()):z.write(p,p.relative_to(RELEASE).as_posix())
    with zipfile.ZipFile(ZIP) as z:
        assert z.testzip() is None
        for line in z.read('SHA256SUMS.txt').decode('utf-8').splitlines():
            digest,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==digest
        assert hashlib.sha256(z.read('USB/EFI/BOOT/BOOTX64.EFI')).hexdigest()==P2_SHA
        assert z.read('USB/AITWEAKER-PROBE.TAG')==b'AITWEAKER-PROBE-P2\r\n'
        assert hashlib.sha256(z.read('KVM/AiTweaker-P3-KVM.iso')).hexdigest()==iso_sha
        assert not any(n.lower().endswith('.cap') for n in z.namelist())
    (BASE/(ZIP.name+'.sha256')).write_text(sha(ZIP)+'  '+ZIP.name+'\n',encoding='utf-8')
    delivery=read(BASE/'delivery.json');delivery['status']='DUAL_MODE_DIAGNOSTIC_READY_AWAITING_HARDWARE'
    delivery['dual_mode_collection']={'date':'2026-11-02','package':ZIP.name,'package_sha256':sha(ZIP),
      'usb_p2_unchanged':True,'kvm_p3_iso':'delivery_dual_mode_20261102/KVM/AiTweaker-P3-KVM.iso',
      'kvm_p3_iso_sha256':iso_sha,'report':'AiTweaker-双模式采集说明.html','p3_vm_runs':3,
      'p3_capture_checks':26,'p3_inventory_cases':27,'hardware_validation_performed':False}
    write(BASE/'delivery.json',delivery)
    requirements=read(BASE/'requirements.json')
    requirements['latest_diagnostic_release']='P2_USB_AND_P3_KVM'
    requirements['collection_modes']=['P2: TXT on marked writable boot volume','P3 KVM: read-only ISO, QR screenshots to exact TXT']
    requirements['next_required_external_evidence']='P2 TXT logs or all P3 QR screenshots, labeled with board and actual BIOS version; later UI testing remains necessary.'
    assert requirements['implementation_status']=='NOT_IMPLEMENTED_IN_FIRMWARE';write(BASE/'requirements.json',requirements)
    final={'zip':str(ZIP),'bytes':ZIP.stat().st_size,'sha256':sha(ZIP),'iso':str(RELEASE/'KVM/AiTweaker-P3-KVM.iso'),
      'p2_unchanged':True,'original_bios_unchanged':True,'p3_vm_runs':3,'p3_capture_checks':26,'p3_inventory_cases':27}
    write(OUT/'release_verification.json',final);print(json.dumps(final,indent=2,ensure_ascii=False))
if __name__=='__main__':main()
