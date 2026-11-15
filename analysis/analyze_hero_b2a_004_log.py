"""Parse user-supplied B2a status samples; attached text is evidence, not code."""
from pathlib import Path
import datetime as dt
import hashlib,json,re,shutil
from analyze_hero_a2_log import transactions

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_b2a_result_004'
SOURCE=ROOT/'HEROIPMI-004.TXT'

def main():
    raw=SOURCE.read_bytes(); txt=raw.decode('utf-8-sig'); txs=transactions(txt)
    assert len(txs)==1 and txs[0]['netfn']==6 and txs[0]['command']==1
    assert txs[0]['transport']=='KCS_STATUS_ALL_FF' and txs[0]['pci_status']==0 and not txs[0]['response']
    samples=[]
    pattern=r'^STATUS_SAMPLE index=(\d+) pci_config_status=([0-9A-F]{16}) command=([0-9A-F]{4}) status_read_efi=([0-9A-F]{16}) kcs_status=([0-9A-F]{2})$'
    for m in re.finditer(pattern,txt,re.M):
        samples.append(dict(index=int(m[1]),pci_config_status=int(m[2],16),command=int(m[3],16),
                            status_read_efi=int(m[4],16),kcs_status=int(m[5],16)))
    # splitlines removes CR from the native UEFI CRLF log before matching.
    if not samples:
        for line in txt.splitlines():
            m=re.fullmatch(pattern,line)
            if m:samples.append(dict(index=int(m[1]),pci_config_status=int(m[2],16),command=int(m[3],16),
                                     status_read_efi=int(m[4],16),kcs_status=int(m[5],16)))
    assert len(samples)==31 and [s['index'] for s in samples]==list(range(31))
    assert all(s['command']==2 and s['pci_config_status']==s['status_read_efi']==s['kcs_status']==0 for s in samples)
    assert 'STATUS_DIAG_END samples=31 all_ff=0 other=31 kcs_write_attempts=0 kcs_data_reads=0' in txt
    assert 'PCI_MEMORY_RESTORED_VERIFIED' in txt and 'PROBE_END' in txt
    assert 'OEM_STEP ' not in txt and 'FAN_STEP ' not in txt and 'SDR repository record count:' not in txt
    dates=[]
    for label in ('Started:','Status diagnostic:'):
        match=re.search(re.escape(label)+r' (\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)',txt)
        dates.append(dt.datetime(*map(int,match.groups())))
    report=dict(source=SOURCE.name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),board='ROG MAXIMUS Z790 HERO',bios='3107',
        first_status='FF',diagnostic_samples=samples,diagnostic_all_ff=0,diagnostic_all_zero=31,
        start_to_diagnostic_clock_seconds=(dates[1]-dates[0]).total_seconds(),
        timing_limit='22 seconds includes user interaction; exact time of FF-to-00 transition is not recorded. Diagnostic spacing is one second by B2a code, not per-sample clock measurement.',
        kcs_write_attempts=0,kcs_data_reads=0,ipmi_command_bytes_sent=0,first_request_intent=txs[0],
        oem_initialization_executed=False,fan_experiment_executed=False,pci_restore_verified=True,
        conclusion='First-read FF was not persistent: all subsequent S samples were 00 with successful PCI reads and Command 0002. No complete IPMI request was attempted after recovery.',
        next_step='Bounded status-only preflight before first Get Device ID; require stable 00; never replay a started request or auto-run I/F.',
        unknown=['Exact FF-to-00 time','PCI-enable/BMC-startup cause','Actual IPMI completion after recovery','Sensor persistence and fan mapping'])
    OUT.mkdir(exist_ok=True); (OUT/SOURCE.name).write_bytes(raw)
    picture=Path('C:/Users/scka7/AppData/Local/Temp/codex-clipboard-b9506fb0-cd0e-40b5-98f0-f85e8d80ae46.png')
    if picture.exists():
        shutil.copyfile(picture,OUT/'B2a-before-S.png');report['screenshot_sha256']=hashlib.sha256(picture.read_bytes()).hexdigest()
    (OUT/'findings.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (OUT/'B2a状态恢复分析.md').write_text('''# HEROIPMI-004：首次 FF 后，31 次状态采样均为 00

004 已完整执行 S 采样并正常退出。附件截图停在等待按 S 的位置，文本日志记录了后续结果，应以完整日志为准。

| 阶段 | 结果 |
|---|---|
| 主板 / BIOS | ROG MAXIMUS Z790 HERO / 3107 |
| 临时 PCI Command | 0000 → 0002，读回确认 |
| 准备首次 Get Device ID | 首次状态 FF，PCI 读取函数成功；尚未写 KCS |
| S 采样 index 0–30 | 31 次全部 00，PCI 调用均成功，Command 始终 0002 |
| KCS 数据读取 / 写操作 | 均为 0 |
| 初始化 / 风扇实验 / 新传感器读取 | 均未执行 |
| 退出 | PCI 恢复 0000，读回确认，PROBE_END |

固件时钟显示应用开始 03:37:05，S 采样开始 03:37:27，相差 22 秒，其中包含用户按键和界面操作。不能说“接口花了 22 秒才恢复”。S 按程序设置间隔一秒采样，共 31 次，约 30 秒；没有每个样本的独立时间戳。

这份证据说明首次 FF 并非本次运行中的持续状态。后续 00 与空闲、无输入/输出待处理的 KCS 状态相符，但还没有新的 Get Device ID 成功响应，因此不能仅凭 00 声称 IPMI 已恢复。B2a 按设计只采样，不重发请求，也不启动 I/F；本次没有风扇测试结果。

时序/初始化等待是合理的下一步排查方向，但尚未证明 FF 来自 PCI 内存解码刚开启、BMC 内部初始化，或其他读取路径变化。此前网页正常、003 前只重启过主机的用户说明仍有效；不能将此次现象归因于未执行的 F 修改。

改进为 B2b：在首次请求之前，只读状态并逐次核对 PCI，最多约 30 秒，要求连续三次状态 00。FF 清零连续计数；其他非零状态、PCI/日志/等待失败会停止。满足条件后执行用户已通过 E/P 选择的首次设备识别和基线读取；一旦任何请求已经开始，失败便停止，不重发。I 和 F 仍必须分别按键且通过原有检查。
''',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('sha256','bytes','first_status','diagnostic_all_zero','kcs_write_attempts','pci_restore_verified','start_to_diagnostic_clock_seconds')},indent=2))

if __name__=='__main__':main()
