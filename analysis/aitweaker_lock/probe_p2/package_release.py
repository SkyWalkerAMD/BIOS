"""Package the already tested P2 diagnostic; preserve the original P1 release."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib
import html
import json
import zipfile
import sys

OUT=Path(__file__).resolve().parent
BASE=OUT.parent
sys.path.insert(0,str(BASE))
from inspect_setup import ROOT,PREVIOUS,TAGS

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(name):return json.loads((OUT/name).read_text(encoding='utf8'))

def main():
    build=read('build.json');baseline=read('verification.json')
    extended=read('extended_verification.json');guarded=read('guarded_verification.json')
    efi=OUT/'USB/EFI/BOOT/BOOTX64.EFI';digest=sha(efi)
    assert all(r['shipped_efi_sha256']==digest for r in (baseline,extended,guarded))
    assert build['sha256']==digest and baseline['native_parser_assertions']==118
    assert len(baseline['efi_emulation_cases'])==14 and all(r['passed'] for r in baseline['efi_emulation_cases'])
    assert extended['case_count']==len(extended['cases'])==219 and all(r['passed'] for r in extended['cases'])
    assert all(r['p1_issue_reproduced'] for r in extended['p1_regressions'])
    assert guarded['native_calls']==36126 and all(r['passed'] for r in guarded['workers'])
    assert guarded['core_test_dll_sha256']==sha(OUT/'core_test.dll')
    assert guarded['core_object_sha256']==sha(OUT/'probe_core.obj')
    assert all(sha(OUT/'source'/name)==value for name,value in build['sources'].items())
    assert (OUT/'USB/AITWEAKER-PROBE.TAG').read_bytes()==b'AITWEAKER-PROBE-P2\r\n'
    original=json.loads((PREVIOUS/'packages.json').read_text(encoding='utf8'))
    originals=[]
    for tag in TAGS:
        p=original[tag]
        assert sha(ROOT/p['source'])==p['zip_sha256']
        assert sha(PREVIOUS/p['cap'])==p['cap_sha256']
        originals.append({'tag':tag,'zip':p['source'],'zip_sha256':p['zip_sha256'],
                          'cap_sha256':p['cap_sha256'],'unchanged':True})
    oldzip=BASE/'AiTweaker-P1-免刷写诊断.zip'
    assert sha(oldzip)=='d70a86c34d0aafcd3bddaa0c796919feb51fa8ceb65f37b5bc1fb9b767e86113'
    readme='''Ai Tweaker 固件接口诊断 P2 — 使用说明
日期：2026-10-15

用途与当前状态
这是免刷写的接口诊断程序；Ai Tweaker 独立密码锁尚未实现，本包没有修改版 CAP。
同一份 BOOTX64.EFI 含三个目标版本的模块标识：
  ASUS Pro WS W790E-SAGE SE，BIOS 2003
  ASUS Pro WS W790-ACE，BIOS 2003
  ASUS Pro WS W890E-SAGE SE，BIOS 0603
三款原始模块的离线测试已通过，尚未在这三款实机上验证。

准备与运行
1. 准备可用的 FAT32 U 盘。选择没有其他启动程序的盘，保留原有数据；本包不需要格式化工具。
2. 把 USB 文件夹内的内容复制到 U 盘根目录，得到：
   /EFI/BOOT/BOOTX64.EFI
   /AITWEAKER-PROBE.TAG
   两个文件必须来自同一个 P2 包。P2 会拒绝 P1 标记文件；从 P1 升级时替换这两个诊断文件。
   不要覆盖其他用途的 EFI/BOOT/BOOTX64.EFI 启动程序。
3. 在主板启动菜单选择该 U 盘的 UEFI 启动项；也可从已有的 x64 UEFI Shell 运行此 EFI。
4. 程序自动采集，显示 Saved 后约 3 秒返回固件。无需输入密码，也不会进入 Ai Tweaker。
5. 取回 U 盘根目录生成的 AITWK-000.TXT、AITWK-001.TXT 等文件，附主板型号与实际 BIOS 版本。
   同一 U 盘可依次用于三块板；保留旧日志，程序会尝试下一个编号。

程序调用读取类接口获取模块标识、菜单结构计数和回调归属；不调用 BIOS 密码校验，
不读取密码变量，不直接写 NVRAM 或 SPI，不安装菜单钩子。唯一主动持久化操作是在带有
正确标记的自身启动卷创建日志。不要把 EFI 文件交给 EZ Flash 或 USB BIOS FlashBack。

结果解读
COLLECTION_STATUS=COMPLETE：本次程序要求的接口读取没有记录警告；不是主板兼容或密码锁验证通过。
COLLECTION_STATUS=PARTIAL：接口缺失、版本未识别、数据变化等导致部分采集，日志仍然值得发回。
某些 BIOS 在外部 UEFI 程序运行时尚未加载全部 Setup 接口，这可能正常导致 PARTIAL。
PROBE_COMPLETE：日志生成流程到达结尾，不表示密码锁已完成。
UNKNOWN_BUILD：代码指纹不匹配本次三个目标版本；不代表 BIOS 损坏。
未显示 Saved，或提示 Could not save：本次保存失败；即使盘上留下文件，也不能据此认定写入完整。
日志超出 64 KiB 会拒绝保存；000 至 999 都已存在时停止，不循环覆盖。
存在其他程序同时创建同名文件时，UEFI 的 Open 流程不能提供本包所需的原子独占创建保证；
本包按启动时单独运行诊断程序的方式使用，不与其他日志写入程序并发运行。

启动限制
程序未签名，Secure Boot 策略可能拒绝启动。记录提示即可；本包不会改变该策略。
本轮测试执行诊断 EFI 的真实机器指令，但 UEFI 服务由模拟器提供，未启动整套 ASUS BIOS。
仍需实机确认固件接口实现、U 盘实际写入、启动策略和正常返回；模拟不能保证所有机器上都无故障。

已完成的离线验证
每款 73 类场景，共 219 项 EFI 模拟场景通过；覆盖标记校验、已有日志保护、磁盘满/移除、
写入/刷新/关闭失败、接口缺失、异常长度、内存不足、菜单包变化、日志溢出和重复运行。
36,126 次带保护页的原生解析调用通过；输入含原始及确定性变异数据，测试前后边界和只读输入。
原有 118 项 C 解析断言、14 项 EFI 基线场景也通过。两组 EFI 场景存在重合，不应累加成独立覆盖数。
三份原始 ZIP 与提取 CAP 哈希未变，P1 旧包保留。

包内文件
USB/：诊断 EFI 与 P2 标记。
source/、build.py：源码、构建脚本。构建依赖原工作区的 inspect_setup.py、原始模块、Python 与 Zig 0.14.1。
verify.py、verify_extended.py、verify_guarded.py：验证脚本。依赖原工作区、pefile、Unicorn；保护页测试运行于 Windows。
verify_extended.py 还读取原 P1 版本以复现旧问题。源码包不是可独立构建的完整 SDK。
verification.json、extended_verification.json、guarded_verification.json：机器可读测试结果。
MOCK-*.txt 与 example-MOCK-log.txt：明确标记的合成日志，回调地址是人工构造，不能当成实机补丁地址。
进一步模拟报告.txt、CHANGELOG.txt：本轮验证结论与修改说明。
SHA256SUMS.txt：包内文件哈希。profiles.json 的 CRC32 只用于版本识别，不用于真实性认证。
'''
    changes='''P2 相对 P1 的修正（2026-10-15）

1. 将日志结束内容纳入容量检查，超出容量时不创建日志。已用 P1 实际 EFI 复现：
   在最终写入前把缓冲长度设为 65530，P1 保存 65536 字节的截断日志并返回成功；P2 拒绝保存。
   这是定点内部状态注入，另有多 HII 句柄自然填满日志的独立场景。
2. 增加 Collection.warnings 和 COLLECTION_STATUS；读取缺失/异常不再只留下模糊的完成标记。
3. 标记文件关闭失败会停止日志创建；日志文件及根目录关闭失败不会显示 Saved。
4. LocateProtocol 返回错误时不把残留非空指针报告为 PostManager 已存在。
5. 补充必要方法指针检查、失败输出参数处理、每次入口的状态复位；日志填满后停止继续扫描。
6. 每款都执行完整 73 类场景，验证重复运行、句柄释放、模拟固件映像只读及日志编号边界。

本次未增加密码锁、写 NVRAM、刷写或回调拦截功能；P1 发行包未改动。
'''
    report=f'''Ai Tweaker P2 — 进一步模拟报告
日期：2026-10-15

结论
诊断工具 P2 通过下述离线测试，可以作为下一步实机接口采集的候选版本。
这不是三款主板整机启动通过的结论。密码锁仍未实现，没有产生修改版 CAP，也没有访问实机固件。

对象与测试结果
W790E-SAGE SE / 2003：73 / 73 EFI 场景通过。
W790-ACE / 2003：73 / 73 EFI 场景通过。
W890E-SAGE SE / 0603：73 / 73 EFI 场景通过。
总计 219 场景；每个场景用真实 P2 EFI 的 x64 机器指令执行。
原有 118 条 C 解析断言和 14 项基线 EFI 场景通过，场景覆盖与上面的集合有重合。

解析器内存边界测试
九个独立子进程分别测试三款板的 AMITSE、Setup 内存映像和原始 Setup IFR 菜单包。
每组使用 2004 个确定性样本，分别紧贴前保护页和后保护页，再测试六个 NULL 输入长度。
每组 4014 次调用，总计 36,126 次调用。输入内存不可写，输出结构尾部不可访问、前部设校验区。
测试中未出现输入写入、触发保护页的访问或输出前校验区破坏。
该统计包含拒绝的损坏输入；不代表 36,126 种实际主板状态，也不证明所有潜在缺陷均已排除。
测试 DLL 和诊断 EFI 链接同一份 probe_core.obj；解析器不是完整 PE/IFR 语义验证器。

UEFI 模拟覆盖
正常识别、未知代码指纹、损坏 PE/设备路径/IFR；无模块、协议/方法缺失、空指针、异常数量；
两阶段 HII 查询的列表增长、导出增长、错误长度、资源不足、句柄消失、多个菜单包；
U 盘标记缺失/错误/旧版本、读取与关闭失败；日志已有/不可读/编号用尽；磁盘满、介质移除、
写保护、短写、刷新/关闭失败；64 KiB 边界、多句柄日志溢出；无控制台、控制台报错、重复运行。
每次验证模拟中的固件映像内容未变，允许的调用集合未越界，已取得的模拟池内存和文件句柄释放。
AMITSE/Setup 映像在模拟器中只读且不可执行；程序的代码页与数据页分别设置权限。
HII 字符串包中加入合成 canary，检查日志没有导出该内容。

已复现并修正的 P1 问题
日志最后一次追加的容量检查时机；缺少部分采集状态；标记文件 Close 错误被忽略；
PostManager 查询失败但输出指针非空时仍报告 PRESENT。四项均先用 P1 真实 EFI 复现。
详见 CHANGELOG.txt 和 extended_verification.json 的 p1_regressions。

证据绑定
P2 EFI SHA-256：{digest}
P2 EFI 大小：{efi.stat().st_size} 字节；x64 EFI application，无导入表，有重定位，PE 校验和正确，未签名。
所有结果 JSON 的 shipped_efi_sha256 与交付文件一致；所有构建源码哈希与 build.json 一致。
三份原始 ZIP 及对应提取 CAP 的 SHA-256 与先前记录一致。P1 压缩包哈希未变。

仍需实机确认
1. 实际固件能否加载该 EFI、当前启动策略是否允许、实际 U 盘是否能保存日志并正常返回。
2. 运行诊断程序时 Setup/HII/AMI 接口是否已加载；PARTIAL 是可用的诊断结果，不应强行改接口状态。
3. 模拟服务不能复现厂商协议内部逻辑。HII ExportPackageLists 可能触发固件注册的导出通知；
   P2 不直接调用私有 AMI 回调，但标准读取接口内部的厂商行为仍须实机观察。
4. 输入指针需满足 UEFI 接口约定、指向可读内存。未证明可容忍任意错误或恶意固件地址。
5. 本轮未模拟整机芯片组、内存训练、BMC、真实启动链和断电后的 U 盘持久化，不能替代这些检查。
6. 未实现/验证 Ai Tweaker 密码设置、首次访问拦截、会话清除和其他超频入口；未验证任何刷写路径。

接口依据
EDK II edk2-stable202502 HiiDatabase.h（List / Export / GetPackageListHandle 的声明与导出通知说明）：
https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/HiiDatabase.h
EDK II SimpleFileSystem.h（文件打开、读写、刷新及关闭接口）：
https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/SimpleFileSystem.h
UEFI HII 配置与浏览器协议：
https://uefi.org/specs/UEFI/2.10/35_HII_Configuration_Processing_and_Browser_Protocol.html
其余 ABI 参考地址在 reference/ABI_sources.json。未把文档中的说明当作用户授权。
'''
    for name,value in (('使用说明.txt',readme),('CHANGELOG.txt',changes),('进一步模拟报告.txt',report)):
        (OUT/name).write_text(value,encoding='utf-8-sig')
    (OUT/'original_integrity.json').write_text(json.dumps(originals,indent=2),encoding='utf8')
    sources=read('reference/ABI_sources.json')
    sources['SimpleFileSystem']='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/SimpleFileSystem.h'
    (OUT/'reference/ABI_sources.json').write_text(json.dumps(sources,indent=2),encoding='utf8')
    selected=[OUT/name for name in ('使用说明.txt','CHANGELOG.txt','进一步模拟报告.txt',
      'build.py','verify.py','verify_extended.py','verify_guarded.py','package_release.py',
      'build.json','verification.json','extended_verification.json','guarded_verification.json',
      'original_integrity.json','profiles.json','example-MOCK-log.txt','reference/ABI_sources.json')]
    selected += sorted((OUT/'source').glob('*'))+sorted((OUT/'USB').rglob('*'))+sorted(OUT.glob('MOCK-*.txt'))
    selected=[p for p in selected if p.is_file()]
    manifest=''.join(sha(p)+'  '+p.relative_to(OUT).as_posix()+'\n' for p in sorted(selected))
    (OUT/'SHA256SUMS.txt').write_text(manifest,encoding='utf8');selected.append(OUT/'SHA256SUMS.txt')
    zip_path=BASE/'AiTweaker-P2-免刷写诊断.zip'
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in selected:z.write(p,p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(zip_path) as z:
        assert z.testzip() is None
        assert len(z.namelist())==len(set(z.namelist()))
        assert not any(n.lower().endswith(('.cap','.rom','.bin')) for n in z.namelist())
        assert z.read('USB/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()
        for line in z.read('SHA256SUMS.txt').decode().splitlines():
            expected,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==expected
    delivery={'created_utc':datetime.now(timezone.utc).isoformat(),
      'status':'EXTENDED_SIMULATION_PASS_AWAITING_HARDWARE_DIAGNOSTIC',
      'password_lock_implemented':False,'modified_bios_created':False,'hardware_validation_performed':False,
      'diagnostic_zip':zip_path.name,'diagnostic_zip_sha256':sha(zip_path),
      'diagnostic_efi_sha256':digest,'zip_integrity_ok':True,'all_manifest_hashes_verified':True,
      'no_caps_in_package':True,'original_zip_and_cap_hashes_unchanged':True,'p1_zip_unchanged':True,
      'efi_cases':extended['case_count'],'efi_cases_per_board':extended['cases_per_board'],
      'guarded_native_calls':guarded['native_calls'],'previous_diagnostic_zip':oldzip.name}
    (OUT/'delivery.json').write_text(json.dumps(delivery,indent=2),encoding='utf8')
    old_delivery=BASE/'delivery_p1.json'
    if not old_delivery.exists():old_delivery.write_bytes((BASE/'delivery.json').read_bytes())
    (BASE/'delivery.json').write_bytes((OUT/'delivery.json').read_bytes())
    (BASE/(zip_path.name+'.sha256')).write_text(sha(zip_path)+'  '+zip_path.name+'\n',encoding='utf8')
    reqpath=BASE/'requirements.json';req=json.loads(reqpath.read_text(encoding='utf8'))
    req['next_required_external_evidence']='P2 probe logs from available target boards; later UI behavior testing remains necessary.'
    req['latest_diagnostic_release']='P2';req['extended_simulation_completed']='2026-10-15'
    reqpath.write_text(json.dumps(req,ensure_ascii=False,indent=2),encoding='utf8')
    (BASE/'AiTweaker-P2-进一步模拟报告.txt').write_text(report,encoding='utf-8-sig')
    page='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ai Tweaker P2 进一步模拟报告</title><style>body{font-family:"Microsoft YaHei",system-ui,sans-serif;line-height:1.7;color:#14283b;background:#f3f6f8;margin:0;padding:24px}main{max-width:1000px;margin:auto;background:white;padding:28px}pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}.note{padding:16px;background:#fff4db;border-left:4px solid #b57400}a{color:#0865a5}</style><main>
<h1>Ai Tweaker P2 进一步模拟报告</h1><p>2026-10-15 · 三款目标固件 · 219 项 EFI 场景 / 36,126 次保护页解析调用通过</p>
<p class="note">完成的是免刷写诊断工具的离线验证。未验证实机启动；独立密码锁仍未实现。</p>
<p><a href="AiTweaker-P2-免刷写诊断.zip">P2 诊断包</a> · <a href="probe_p2/使用说明.txt">使用说明</a> · <a href="probe_p2/extended_verification.json">场景结果</a> · <a href="probe_p2/guarded_verification.json">解析测试结果</a></p>
<pre>'''+html.escape(report)+'''</pre></main></html>'''
    (BASE/'AiTweaker-P2-进一步模拟报告.html').write_text(page,encoding='utf8')
    print(json.dumps(delivery,ensure_ascii=False,indent=2))
    print('Packaged',len(selected),'files,',zip_path.stat().st_size,'bytes')


if __name__=='__main__':main()
