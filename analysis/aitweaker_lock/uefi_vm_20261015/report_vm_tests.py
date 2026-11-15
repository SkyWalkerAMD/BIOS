"""Create an evidence-based VM report without changing the released probe."""
from pathlib import Path
import base64,datetime,hashlib,html,json,subprocess,zipfile
from disk_images import OUT,ROOT,sha
from run_vm_tests import QEMU,CODE,VARS,P2,P2_SHA,CASES,json_write

BASE=OUT.parent
REPORT='AiTweaker-P2-UEFI虚拟机测试报告'
MATERIALS='AiTweaker-P2-UEFI虚拟机测试材料.zip'
ZIP_SHA='c06fafc804b6cedc74003459c49d18da53db7618d21edf72391dcfc2ac43ae64'
LABELS=[
 'GPT + FAT32 + SATA 启动、保存、读回',
 '沿用上一轮磁盘与变量存储内容，再次冷启动',
 '一次 UEFI 启动中连续执行 P2 三次',
 'MBR + FAT32 + USB xHCI 启动',
 '无分区表 FAT32 + USB xHCI 启动',
 'MBR + FAT16 + SATA 兼容性',
 '缺少标记文件时拒绝保存',
 'P1 旧标记文件与 P2 程序混用时拒绝保存',
 '只读 USB 磁盘拒绝写入，整盘哈希不变',
 'FAT 数据簇全部用尽时返回错误',
 '已有 AITWK-000.TXT 时改用 001',
 '000—999 全部存在时停止、不覆盖',
 '仅第二块磁盘有标记时不转移写入目标',
 '两块磁盘都有标记时仅写启动盘',
 '原 P2 作为 BOOTX64.EFI，由固件直接从 SATA 启动',
 '原 P2 作为 BOOTX64.EFI，由固件直接从 USB 启动',
]

def main():
    results=json.loads((OUT/'results.json').read_text(encoding='utf-8'))
    assert len(results)==len(CASES)==16 and all(results[c['id']]['passed'] for c in CASES)
    assert sha(P2)==P2_SHA and sha(BASE/'AiTweaker-P2-免刷写诊断.zip')==ZIP_SHA
    original_root=ROOT/'analysis/workstation_20261008'
    original=json.loads((original_root/'packages.json').read_text(encoding='utf-8'))
    original_checks=[]
    for tag in ('W790_SAGE_2003','W790_ACE_2003','W890_SAGE_0603'):
        p=original[tag];zp=ROOT/p['source'];cap=original_root/p['cap']
        assert sha(zp)==p['zip_sha256'] and sha(cap)==p['cap_sha256']
        original_checks.append({'board':tag,'zip_sha256':sha(zp),'cap_sha256':sha(cap),'unchanged':True})
    version=subprocess.check_output([str(QEMU),'--version'],text=True,creationflags=subprocess.CREATE_NO_WINDOW).strip()
    complete=sum(log['complete'] for r in results.values() for log in r['new_logs'])
    readbacks=sum(len(r.get('uefi_readbacks_verified',[])) for r in results.values())
    positive=sum(not c.get('status') for c in CASES)
    sources=[
      ('QEMU 官方下载入口','https://www.qemu.org/download/'),
      ('官方入口列出的 Windows 构建发行目录','https://qemu.weilnetz.de/w64/'),
      ('下载文件的发布者 SHA-512','https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.sha512'),
      ('QEMU 启动参数文档','https://www.qemu.org/docs/master/system/invocation.html'),
      ('TianoCore OVMF 运行与调试说明','https://github.com/tianocore/edk2/blob/master/OvmfPkg/README'),
      ('pyfatfs 1.1.0','https://pypi.org/project/pyfatfs/1.1.0/'),
    ]
    summary={
      'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'status':'PASS_GENERIC_UEFI_BOOT_AND_FAT_IO',
      'scenarios_passed':16,'scenarios_total':16,'positive_scenarios':positive,'negative_scenarios':16-positive,
      'p2_invocations':sum(c.get('repeat',1) for c in CASES),'complete_new_logs':complete,
      'uefi_readbacks_verified':readbacks,'direct_firmware_boot_cases':2,
      'p2_efi_sha256':P2_SHA,'released_p2_zip_sha256':ZIP_SHA,'released_p2_unchanged':True,
      'qemu_version':version,'qemu_exe_sha256':sha(QEMU),'firmware_code_sha256':sha(CODE),
      'firmware_vars_template_sha256':sha(VARS),'firmware_code_bytes':CODE.stat().st_size,
      'firmware_vars_template_bytes':VARS.stat().st_size,
      'firmware':'QEMU-bundled generic OVMF, edk2-x86_64-code.fd + edk2-i386-vars.fd',
      'machine':'q35 / TCG / cpu=max / 1 CPU / 512 MiB RAM / network disabled',
      'secure_boot_enforcement_tested':False,'asus_bios_booted_in_vm':False,
      'hardware_validation_performed':False,'password_lock_implemented_in_firmware':False,
      'modified_cap_created':False,'physical_disks_used':False,'usb_passthrough_used':False,
      'full_volume_result':'EFI_DEVICE_ERROR, one zero-byte new log may remain; existing files preserved',
      'cold_boot_method':'Copy exact post-run disk and OVMF variable-store bytes to next isolated case and start a fresh QEMU process',
      'originals':original_checks,'sources':[{'title':t,'url':u} for t,u in sources],
      'resolved_test_setup_issues':[
        {'attempt':'cases/01_gpt_sata','issue':'Windows raw backend requires image size aligned to 4096 bytes',
         'resolution':'Aligned GPT whole-disk size; subsequent real EFI run passed'},
        {'attempt':'cases/09_readonly','issue':'QEMU ide-hd requires a writable backend',
         'resolution':'Used USB mass storage for the read-only boot case; real EFI run passed'},
      ],
      'result_file':'uefi_vm_20261015/results.json','report':REPORT+'.html',
    }
    json_write(OUT/'summary.json',summary)
    rows=[];text_rows=[]
    for case,label in zip(CASES,LABELS):
        r=results[case['id']];logs=', '.join(f"{x['name']} ({x['bytes']} B)" for x in r['new_logs']) or '无新日志'
        status='返回预期错误' if case.get('status') else '成功'
        detail='；'.join((status,logs))
        link='uefi_vm_20261015/'+r['folder'].replace('\\','/')+'/result.json'
        rows.append(f'<tr><td>{case["id"][:2]}</td><td>{html.escape(label)}</td><td class="ok">通过</td><td>{html.escape(detail)}</td><td><a href="{link}">记录</a></td></tr>')
        text_rows.append(f'{case["id"][:2]}. 通过 | {label} | {detail}')
    text_report=f'''Ai Tweaker P2 · UEFI 虚拟机启动与文件读写测试
日期：2026-10-15

结果：16 / 16 个场景达到预期。共运行原版 P2 {summary['p2_invocations']} 次，生成 {complete} 份完整新日志，
核对 {readbacks} 次真实 UEFI 文件读回。正常场景 {positive} 项，预期失败场景 {16-positive} 项。
本轮执行 QEMU/OVMF 的真实 UEFI 固件、驱动和文件服务；没有使用前几轮 Unicorn 的替代 UEFI 服务。

结论范围
这是 P2 免刷写诊断程序的启动与文件读写验证。Ai Tweaker 独立密码锁尚未实现，未生成修改版 CAP。
虚拟机运行通用 OVMF；没有启动三份 ASUS BIOS，没有模拟三款工作站主板的完整硬件。
三份原始 BIOS ZIP / CAP，以及 P2 的 EFI 和诊断 ZIP 哈希均未改变。
这为上机运行 P2 采集日志增加了证据，不能作为密码锁、实机兼容或刷写成功的证明。

测试矩阵
{chr(10).join(text_rows)}

关键观察
1. 通过真实 LoadImage / StartImage 加载原 P2；UEFI 启动器只记录返回码、读回日志并退出虚拟机。
   另有两项直接把原 P2 放在 EFI/BOOT/BOOTX64.EFI，由固件从 SATA / USB 启动；未插入测试启动器。
2. 正常日志以 PROBE_COMPLETE 结束；OVMF 缺少 ASUS Setup / AMITSE / PostManager，故全部显示
   COLLECTION_STATUS=PARTIAL。这符合通用平台预期，并不证明 ASUS 专有接口可用。
3. 读回对照使用 UEFI File.Read 的字节长度和 CRC32，再由宿主机读取 FAT 镜像核对。
   所有场景均检查已有文件的 SHA-256，两个 FAT 副本一致；两块盘场景的第二块盘整盘哈希不变。
4. 冷启动复用上一轮关机后的磁盘与 OVMF 变量存储内容，完整复制后用新 QEMU 进程启动；旧日志未变，生成 001。
5. 磁盘写满会留下 AITWK-000.TXT 空文件，同时返回 EFI_DEVICE_ERROR，控制台没有 Saved。
   此空文件不是有效采集结果；有效结果必须确认保存完成与日志结尾。
6. 只读磁盘返回 EFI_DEVICE_ERROR，整盘 SHA-256 不变。1000 个文件名全部占用时也返回错误，没有覆盖。
7. OVMF 自身启动时会写入隔离的虚拟变量存储。它与 P2 不直接写 NVRAM 的行为是不同层面的观察，
   本报告不把虚拟变量文件的变化归因于 P2，也不声称本轮对每次运行时服务调用做了跟踪。

环境与边界
{version}
q35 / TCG 软件模拟；1 CPU；512 MiB；无网络适配器；仅使用本工作区普通磁盘镜像文件。
UEFI：随 QEMU 包分发的 edk2-x86_64-code.fd，匹配 edk2-i386-vars.fd，每个场景独立变量存储。
FAT：64 MiB FAT16 / FAT32；GPT、MBR、无分区表；SATA、USB xHCI。
未验证：Secure Boot 强制验签、真实 U 盘与 USB 控制器、意外断电、三块主板固件内部接口、Ai Tweaker 密码流程。
P2 未签名，实际固件可能拒绝启动；本轮没有修改任何真实机器的启动策略。
这轮没有注入物理介质 I/O / Flush 故障；此前软件服务模拟覆盖不等同于真实控制器故障覆盖。

配置修正留痕
最初 GPT 镜像长度未满足 Windows QEMU 的 4 KiB 对齐要求，修正后通过。
QEMU 的 ide-hd 拒绝只读后端，因此只读场景改用支持该方式的 USB 存储设备，随后通过。
这两次均在 P2 执行前失败，原始记录保留；不计为通过的 P2 测试。

复查与重跑
工作目录：{ROOT}
脚本：analysis/aitweaker_lock/uefi_vm_20261015/run_vm_tests.py
重跑全部：python analysis/aitweaker_lock/uefi_vm_20261015/run_vm_tests.py --retry
重跑单项：python analysis/aitweaker_lock/uefi_vm_20261015/run_vm_tests.py --case 16_direct_usb --retry
默认复用已有通过记录；--retry 新建 attempt 目录，保留旧证据。应使用当前配置的 Python 3.14。
材料 ZIP 含报告、源代码、结果、串口/调试/QMP 记录和截图；不含 EFI 可执行文件、CAP、磁盘镜像或 QEMU 工具。
当前工作区保留工具与镜像以便复现；材料 ZIP 不是独立运行工具包。
VMRUNNER.EFI 仅作虚拟机测试工具，不属于给实机使用的 P2 USB 内容。

完整性
P2 EFI SHA-256：{P2_SHA}
P2 原诊断 ZIP SHA-256：{ZIP_SHA}
QEMU EXE SHA-256：{summary['qemu_exe_sha256']}
OVMF CODE SHA-256：{summary['firmware_code_sha256']}
OVMF VARS 模板 SHA-256：{summary['firmware_vars_template_sha256']}
下载包完整 SHA-512 已与发行站点公布值核对，见 download_provenance.json。

参考
'''+''.join(f'{t}：{u}\n' for t,u in sources)
    (BASE/(REPORT+'.txt')).write_text(text_report,encoding='utf-8')
    def embedded(case_id):
        p=OUT/results[case_id]['folder']/'screen.png'
        return 'data:image/png;base64,'+base64.b64encode(p.read_bytes()).decode('ascii')
    report_html='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ai Tweaker P2 · UEFI 虚拟机测试</title><style>
body{margin:0;background:#f4f6fa;color:#172539;font:16px/1.7 system-ui,"Microsoft YaHei",sans-serif}main{max-width:1120px;margin:auto;padding:40px 24px}h1{font-size:30px;line-height:1.4}h2{font-size:21px;margin-top:32px}p{max-width:96ch}a{color:#145ab1}small{color:#506078}.cards{display:flex;gap:16px;flex-wrap:wrap}.card{background:white;border:1px solid #d8e1eb;border-radius:12px;padding:18px 24px;flex:1;min-width:180px}.num{font-size:30px;font-weight:700;color:#116347}.note{background:#e8effb;border-left:4px solid #4572b5;padding:16px 20px;border-radius:4px}.warn{background:#fff2dc;border-left-color:#b57c1e}table{border-collapse:collapse;width:100%;font-size:14px;background:white}td,th{padding:10px 12px;text-align:left;border-bottom:1px solid #dfe5ec;vertical-align:top}th{background:#e9eef5}.ok{color:#116347;white-space:nowrap;font-weight:650}.scroll{overflow-x:auto}img{max-width:100%;border-radius:8px;border:1px solid #b8c3ce}pre{white-space:pre-wrap;word-break:break-all;background:#fff;padding:20px;border:1px solid #d8e1eb;font:14px/1.7 Consolas,monospace}details{margin:20px 0}summary{cursor:pointer;font-weight:600}.foot{font-size:14px;color:#506078}code{word-break:break-all}</style><main>
<small>2026-10-15 · 实际 QEMU / OVMF 运行证据</small><h1>Ai Tweaker P2：UEFI 启动与文件读写已验证</h1>
<p>原版 P2 在通用 UEFI 虚拟机中完成启动、保存日志和读回核对。异常场景按预期拒绝保存，已有文件保持完整。</p>
'''+f'''<div class="cards"><div class="card"><div class="num">16 / 16</div>场景达到预期</div><div class="card"><div class="num">{summary['p2_invocations']}</div>次原版 P2 执行</div><div class="card"><div class="num">{complete}</div>份完整新日志</div><div class="card"><div class="num">{readbacks}</div>次 UEFI 文件读回核对</div></div>
<p class="note"><strong>结论范围：</strong>这验证了免刷写诊断程序的启动与文件读写。Ai Tweaker 独立密码锁仍未实现，三块 ASUS 主板的实机兼容仍未验证。本轮没有运行 ASUS BIOS，也没有生成修改版 CAP。</p>
<h2>场景与结果</h2><div class="scroll"><table><thead><tr><th>编号</th><th>场景</th><th>结果</th><th>观察</th><th>证据</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<p class="note warn"><strong>写满时的实际行为：</strong>可能留下一个 0 字节日志；P2 返回错误并且没有显示 Saved。空文件不能当作成功采集结果。其余已有文件的内容保持完整。</p>
<h2>原 P2 直接从虚拟 USB 启动</h2><p>此场景没有测试启动器。固件直接执行原版 <code>EFI/BOOT/BOOTX64.EFI</code>，日志已实际写入 FAT 镜像。</p><img alt="原 P2 在 OVMF 中从 USB 启动并保存日志的真实截图" src="{embedded('16_direct_usb')}">
<h2>UEFI 启动器加载与读回验证</h2><p>其余场景使用专用于虚拟机的启动器，通过真实 LoadImage / StartImage 执行原 P2，再用 File.Read 读回日志。字节长度、CRC32 与宿主读取的文件一致，原 P2 字节未修改。</p><img alt="VMRUNNER 通过真实 UEFI 服务加载 P2 的运行截图" src="{embedded('01_gpt_sata')}">
<p>日志的 <code>COLLECTION_STATUS=PARTIAL</code> 符合预期：通用 OVMF 不含 ASUS 的 Setup、AMITSE 和 PostManager 接口。完整日志均含 <code>PROBE_COMPLETE</code> 结尾。</p>
<h2>仍需实机确认</h2><p>真实主板的启动策略、USB 驱动、ASUS 专有接口与正常返回。Secure Boot 强制验签、意外断电和物理介质故障未在本轮验证；密码设置、首次进入提示与会话解锁也尚未在固件中实现。</p>
<p>虚拟机仅使用工作区内的普通磁盘镜像，没有接入物理磁盘或 USB 设备，没有网络适配器。OVMF 自身会更新隔离的虚拟变量存储。</p>
<details><summary>完整方法、配置修正记录、哈希与重跑说明</summary><pre>{html.escape(text_report)}</pre></details>
<p><a href="uefi_vm_20261015/results.json">机器可读结果</a> · <a href="uefi_vm_20261015/summary.json">环境与完整性摘要</a> · <a href="{REPORT}.txt">纯文本报告</a> · <a href="{MATERIALS}">测试材料 ZIP</a></p>
<p class="foot">资料来源：'''+ ' · '.join(f'<a href="{html.escape(u)}">{html.escape(t)}</a>' for t,u in sources)+'''</p></main></html>'''
    (BASE/(REPORT+'.html')).write_text(report_html,encoding='utf-8')
    # Evidence archive intentionally excludes runnable EFI and disk images.
    selected=[OUT/name for name in ('run_vm_tests.py','disk_images.py','vm_runner.c','build_runner.py',
              'download_qemu.py','report_vm_tests.py','runner_build.json','download_provenance.json','results.json','summary.json')]
    selected += [BASE/(REPORT+ext) for ext in ('.html','.txt')]
    for folder in (OUT/'cases').iterdir():
        if folder.is_dir():selected += [p for p in folder.iterdir() if p.suffix.lower() in ('.json','.jsonl','.txt','.log','.png')]
    entries={p.relative_to(BASE).as_posix():p.read_bytes() for p in selected}
    entries['SHA256SUMS.txt']=''.join(f'{hashlib.sha256(b).hexdigest()}  {name}\n' for name,b in sorted(entries.items())).encode('utf-8')
    archive=BASE/MATERIALS
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted(entries.items()):z.writestr(name,data)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for line in z.read('SHA256SUMS.txt').decode('utf-8').splitlines():
            digest,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==digest
        assert not any(Path(n).suffix.lower() in ('.efi','.cap','.img','.fd') for n in z.namelist())
    (BASE/(MATERIALS+'.sha256')).write_text(sha(archive)+'  '+MATERIALS+'\n',encoding='utf-8')
    delivery=json.loads((BASE/'delivery.json').read_text(encoding='utf-8'))
    delivery['status']='UEFI_VM_BOOT_AND_FAT_IO_PASS_AWAITING_HARDWARE_DIAGNOSTIC'
    delivery['uefi_vm_validation']={'date':'2026-10-15','passed':16,'total':16,'p2_invocations':summary['p2_invocations'],
      'report':REPORT+'.html','materials_zip':MATERIALS,'materials_zip_sha256':sha(archive),
      'results':'uefi_vm_20261015/results.json','platform':'Generic QEMU/OVMF; ASUS firmware not booted',
      'password_lock_implemented_in_firmware':False,'hardware_validation_performed':False}
    json_write(BASE/'delivery.json',delivery)
    requirements=json.loads((BASE/'requirements.json').read_text(encoding='utf-8'))
    requirements['generic_uefi_vm_status']='16_SCENARIOS_PASS_BOOT_AND_FAT_IO_ONLY'
    requirements['generic_uefi_vm_results']='uefi_vm_20261015/results.json'
    assert requirements['implementation_status']=='NOT_IMPLEMENTED_IN_FIRMWARE'
    json_write(BASE/'requirements.json',requirements)
    print(json.dumps({'scenarios':'16/16','p2_invocations':summary['p2_invocations'],'complete_new_logs':complete,
      'readbacks':readbacks,'report':str(BASE/(REPORT+'.html')),'materials_bytes':archive.stat().st_size,
      'materials_sha256':sha(archive),'originals_unchanged':True,'p2_unchanged':True},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
