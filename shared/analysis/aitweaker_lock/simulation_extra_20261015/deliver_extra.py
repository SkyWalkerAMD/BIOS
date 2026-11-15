"""Publish offline evidence only. Keep the existing P2 diagnostic ZIP intact."""
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
import hashlib
import html
import json
import zipfile

OUT=Path(__file__).resolve().parent
BASE=OUT.parent
P2=BASE/'probe_p2'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf8'))


def main():
    tests=read(OUT/'additional_verification.json');model=read(OUT/'password_model_verification.json')
    old=read(P2/'delivery.json')
    assert tests['case_count']==len(tests['cases'])==93 and all(row['passed'] for row in tests['cases'])
    assert tests['harness_sha256']==sha(OUT/'verify_additional.py')
    assert Counter(row['tag'] for row in tests['cases'])=={
        'W790_SAGE_2003':31,'W790_ACE_2003':31,'W890_SAGE_0603':31}
    assert model['directed_scenario_count']==20 and all(row['passed'] for row in model['directed_scenarios'])
    assert model['random_sequences']['steps']==20000 and model['random_sequences']['passed']
    assert model['model_sha256']==sha(OUT/'password_flow_model.py')
    efi_sha=sha(P2/'USB/EFI/BOOT/BOOTX64.EFI')
    assert efi_sha==tests['shipped_efi_sha256']==old['diagnostic_efi_sha256']
    assert sha(BASE/old['diagnostic_zip'])==tests['original_p2_zip_sha256']==old['diagnostic_zip_sha256']
    report=f'''Ai Tweaker — 补充模拟报告
日期：2026-10-15

本轮结论
在已完成的 219 项 P2 诊断场景之外，新增 93 项场景全部通过，三款板各 31 项。
另完成密码访问流程的主机端抽象模型：20 个具体场景与 20,000 步确定性随机操作序列通过。
两类结果必须分开理解：前者执行真实 P2 EFI 字节；后者仅验证流程规则，没有接入 BIOS。
P2 诊断 EFI 和原压缩包未修改，继续使用原 P2 包即可。补充材料不是新的启动包。

新增的诊断模拟
1. 加载地址组合：24 项，每款 8 项。
   包含低地址、PE 首选地址、诊断程序超过 4 GiB、固件模块超过 4 GiB、内存池超过 4 GiB、
   栈超过 4 GiB、上述对象同时位于高地址，以及超过 1 TiB 的规范 x64 虚拟地址。
   从旧位置取消映射，重新应用重定位，并保留代码只读/可执行、数据可写和固件样本只读的权限。
   验证模块指纹、回调归属和相对地址输出仍正确。
   这些测试覆盖指针宽度和重定位，不证明对应主板支持上述物理内存布局。

2. 多故障组合：39 项，每款 13 项。
   包括模块及协议同时缺失、模块缺失加磁盘满、未知代码加菜单包增长、损坏映像加写保护、
   损坏 IFR 加标记读取失败、多 HII 包同时失效、列表变化加关闭失败、方法缺失加模块读取失败、
   控制台故障加 999 个已有日志、PostManager 报错加 ConfigAccess 缺失、列表超限加刷新失败、
   空分配结果加标记缺失、损坏路径加 HII 驱动缺失。
   检查错误返回、部分采集标记、禁止覆盖已有日志、已取得资源的释放和故障分支被实际执行。

3. 失败后原实例重试：24 项，每款 8 项。
   缺少标记、短写、刷新失败、第二次分配失败、日志容量边界、列表增长、写入失败、协议异常，
   随后在同一份已加载的 EFI 实例内解除故障并重试。
   验证旧警告/截断状态不会残留，第二次采集完整，已有文件内容不变，新日志使用下一可用编号。

4. 写日志中断后重新启动的文件模型：6 项，每款 2 项。
   分别在写入部分内容时和刷新之前停止模拟，再创建全新执行环境，只保留模型中的文件名及内容。
   验证再次启动会保留旧文件并使用下一编号。
   这不是 FAT、USB 控制器或实际断电恢复测试，不能据此保证掉电后的文件系统完整性。

密码流程模型
已建模的用户要求：设置独立凭据后，每次进入 Setup 的首次受保护访问要求验证；
正确验证后同一会话继续访问不重复提示；退出后、重新进入后或重启后重新锁定。
模型还验证错误/取消/验证器错误不会产生新的解锁，旧会话或旧凭据版本的验证结果不能生效。
对已分类的子页面、收藏、搜索、EZ Mode 超频及配置导入入口，模型要求经过同一访问判断。
这只证明“这些入口若接入该判断”的流程行为；尚未发现并拦截实机上的全部入口。

以下为原适配方案中的设计建议，本轮仅建模，尚未成为经用户确认的完整产品行为：
改密/清除需当前独立密码验证；修改凭据后清除旧解锁状态；凭据损坏/不可读时保持受保护访问关闭；
普通加载默认值保留独立凭据；存储结果不确定时不当作没有密码。
模型的 defaults 操作仅检查凭据保留，不模拟 BIOS 恢复默认值时实际写入哪些超频参数。

20 个具体场景涵盖：首次正确验证、错误/取消/验证器错误、退出后重进、重启、凭据版本变化、
跨实例结果、替代入口、损坏/不可读凭据、首次设密、改密/清除、取消改密、写入失败/不确定、
默认值保留、管理验证与访问验证隔离、旧结果重放。
另以固定种子执行 20,000 步操作序列，检查解锁必须来自当前会话的有效验证结果，
会话外不能保持解锁，损坏/未知凭据不能自动放行，未获当前验证不能清除已有凭据。

明确未实现的部分
口令输入、口令派生与比较、随机盐、敏感缓冲区擦除、尝试频率限制，以及 NVRAM 持久化与恢复。
模型使用 MATCH/MISMATCH/CANCEL/ERROR 等合成结果，不存储或校验真实密码。
BIOS 弹窗、真实菜单钩子、Setup 会话事件和替代入口的实际拦截仍未实现。
没有修改 CAP，没有访问主板，没有新增可刷写文件。密码锁仍不能作为成品使用。

证据与复现
诊断 EFI SHA-256：{efi_sha}
原 P2 ZIP SHA-256：{old['diagnostic_zip_sha256']}
additional_verification.json：93 项真实 EFI 模拟场景及地址、故障参数、结果。
password_model_verification.json：20 个模型场景、随机序列统计与模型源码哈希。
verify_additional.py：依赖同工作区的 probe_p2 验证脚本、原始模块、pefile 和 Unicorn。
password_flow_model.py / verify_password_model.py：仅需 Python 3.10+ 的主机端模型与测试，无硬件访问。
复现命令：
  python verify_additional.py
  python verify_password_model.py
补充压缩包只含报告、脚本和结果；诊断程序仍从原 AiTweaker-P2-免刷写诊断.zip 获取。

还可以往下做什么
若取得可运行的 UEFI 虚拟机环境，可验证真实标准协议驱动、FAT 镜像读写和加载流程；
这仍不能等同 ASUS 工作站平台。当前工作区未找到可用的 QEMU/OVMF 组合，本轮未进行此项。
后续凭据存储与密码算法有实现后，可再测异常记录、更新中断和验证器边界；目前没有相应固件实现。
实机接口是否可用、厂商回调内部行为、真实 UI 路径、完整 BIOS 启动和最终刷写行为仍需目标硬件验证。

完成度口径
“本轮全部通过”仅指本轮明确列出的测试执行并通过。新增场景说明覆盖可以继续扩展，
不能把任何一次清单的 100% 当作穷尽所有风险或密码锁项目完成度。
'''
    (OUT/'补充模拟报告.txt').write_text(report,encoding='utf-8-sig')
    guide='''补充模拟材料说明

此包不是启动包，不含 EFI 或修改版 BIOS。现有 P2 免刷写诊断包保持不变。
先阅读“补充模拟报告.txt”；其中区分真实诊断 EFI 的模拟与抽象密码流程模型。
模型测试通过不代表真实密码功能已经实现，不能用于保护主板。

文件
verify_additional.py / additional_verification.json：新增 93 项诊断模拟。
password_flow_model.py / verify_password_model.py / password_model_verification.json：主机端流程原型与测试。
delivery.json / SHA256SUMS.txt：交付状态与内容哈希。

诊断模拟脚本须放回原工作区的 analysis/aitweaker_lock/simulation_extra_20261015 内运行；
它依赖相邻 probe_p2、原始固件分析数据，以及本工作区安装的 pefile/Unicorn。
模型脚本可使用 Python 3.10+ 单独运行；不需要 U 盘，也不需要接触主板。
'''
    (OUT/'使用说明.txt').write_text(guide,encoding='utf-8-sig')
    delivery={'created_utc':datetime.now(timezone.utc).isoformat(),
      'status':'SUPPLEMENTAL_DIAGNOSTIC_AND_HOST_MODEL_TESTS_PASS',
      'additional_efi_scenarios':93,'additional_efi_scenarios_per_board':31,
      'host_policy_directed_scenarios':20,'host_policy_random_steps':20000,
      'diagnostic_efi_unchanged':True,'diagnostic_efi_sha256':efi_sha,
      'diagnostic_zip_unchanged':True,'diagnostic_zip_sha256':old['diagnostic_zip_sha256'],
      'password_lock_implemented_in_firmware':False,'hardware_validation_performed':False,
      'modified_cap_created':False,'this_package_is_bootable':False}
    (OUT/'delivery.json').write_text(json.dumps(delivery,indent=2),encoding='utf8')
    selected=[OUT/name for name in ('补充模拟报告.txt','使用说明.txt','verify_additional.py',
      'additional_verification.json','password_flow_model.py','verify_password_model.py',
      'password_model_verification.json','delivery.json','deliver_extra.py')]
    (OUT/'SHA256SUMS.txt').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in selected),encoding='utf8')
    selected.append(OUT/'SHA256SUMS.txt')
    zip_path=BASE/'AiTweaker-P2-补充模拟材料.zip'
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for path in selected:z.write(path,path.name)
    with zipfile.ZipFile(zip_path) as z:
        assert z.testzip() is None and not any(n.lower().endswith(('.efi','.cap','.rom','.bin')) for n in z.namelist())
        for line in z.read('SHA256SUMS.txt').decode().splitlines():
            value,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==value
    (BASE/(zip_path.name+'.sha256')).write_text(sha(zip_path)+'  '+zip_path.name+'\n',encoding='utf8')
    page='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ai Tweaker 补充模拟报告</title><style>body{font-family:"Microsoft YaHei",system-ui,sans-serif;color:#19304a;background:#f3f6f8;line-height:1.7;margin:0;padding:24px}main{max-width:1050px;background:white;margin:auto;padding:30px}.note{background:#fff4dc;padding:16px;border-left:4px solid #ab7800}pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}a{color:#0865a5}table{border-collapse:collapse;width:100%;margin:18px 0}th,td{border:1px solid #d4dce4;padding:10px;text-align:left}</style><main>
<h1>Ai Tweaker 补充模拟报告</h1><p>2026-10-15 · 现有 P2 诊断程序保持不变</p>
<p class="note">新增 93 项诊断场景通过；密码流程模型通过 20 个场景和 20,000 步随机序列。模型尚未接入 BIOS，不能作为密码锁成品使用。</p>
<table><tr><th>测试对象</th><th>新增数量</th><th>验证范围</th></tr>
<tr><td>P2 EFI 高位地址与重定位</td><td>24</td><td>实际 EFI 指令和模拟 UEFI 服务</td></tr>
<tr><td>P2 多故障组合</td><td>39</td><td>异常交互、资源释放及报告</td></tr>
<tr><td>失败后同实例重试</td><td>24</td><td>旧状态复位与日志保护</td></tr>
<tr><td>写入中断后新实例</td><td>6</td><td>文件模型，不代表真实断电恢复</td></tr>
<tr><td>密码访问流程模型</td><td>20 场景 + 20,000 步</td><td>抽象状态转换，不验证真实口令或 BIOS 钩子</td></tr></table>
<p><a href="AiTweaker-P2-补充模拟材料.zip">补充模拟材料</a> · <a href="AiTweaker-P2-免刷写诊断.zip">原 P2 诊断包</a> · <a href="simulation_extra_20261015/additional_verification.json">诊断测试结果</a> · <a href="simulation_extra_20261015/password_model_verification.json">模型测试结果</a></p>
<pre>'''+html.escape(report)+'''</pre></main></html>'''
    (BASE/'AiTweaker-P2-补充模拟报告.html').write_text(page,encoding='utf8')
    (BASE/'AiTweaker-P2-补充模拟报告.txt').write_text(report,encoding='utf-8-sig')
    current=read(BASE/'delivery.json')
    current['supplemental_simulation']={'date':'2026-10-15','diagnostic_efi_cases':93,
        'host_policy_directed_scenarios':20,'host_policy_random_steps':20000,
        'materials_zip':zip_path.name,'materials_zip_sha256':sha(zip_path),
        'report':'AiTweaker-P2-补充模拟报告.html','password_lock_implemented_in_firmware':False}
    (BASE/'delivery.json').write_text(json.dumps(current,indent=2),encoding='utf8')
    req=read(BASE/'requirements.json')
    req['host_policy_model_status']='ABSTRACT_MODEL_TESTED_NOT_INTEGRATED_IN_FIRMWARE'
    req['host_policy_model_path']='simulation_extra_20261015/password_flow_model.py'
    (BASE/'requirements.json').write_text(json.dumps(req,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({'extra_efi_cases':93,'model_scenarios':20,'model_random_steps':20000,
                      'p2_efi_unchanged':True,'supplement_zip_sha256':sha(zip_path),
                      'supplement_zip_bytes':zip_path.stat().st_size},indent=2))


if __name__=='__main__':main()
