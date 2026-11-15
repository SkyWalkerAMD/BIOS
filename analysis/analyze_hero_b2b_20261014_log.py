"""Record the new Downloads log separately from the old A1 HEROIPMI-000.TXT."""
from pathlib import Path
import hashlib, json, re

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path('C:/Users/scka7/Downloads/HEROIPMI-000.TXT')
OUT = ROOT/'analysis/hero_ipmi_b2b_result_20261014'

def main():
    data = SOURCE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == 'e8deb8fca92e27fffc884db5f64f66c56326d2cd8140df5656286113933dbf2e'
    text = data.decode('ascii')
    assert 'HERO IPMI FAN B2b' in text and 'BIOS: 3107' in text
    samples = re.findall(r'READINESS_SAMPLE[^\r\n]+', text)
    assert len(samples) == 1 and 'kcs_status=C1' in samples[0]
    assert 'READINESS_STOPPED_NO_REQUEST samples=1 all_ff=0 kcs_write_attempts=0 kcs_data_reads=0' in text
    assert not re.search(r'^(TX |RX |OEM_STEP |FAN_STEP |SDR_SCAN_COMPLETE)', text, re.M)
    assert 'PCI_MEMORY_RESTORED_VERIFIED' in text and 'PROBE_END' in text
    OUT.mkdir(exist_ok=True)
    (OUT/'HEROIPMI-000.TXT').write_bytes(data)
    findings = dict(source=str(SOURCE), sha256=digest, bytes=len(data),
        program='B2b', board='ROG MAXIMUS Z790 HERO', bios='3107',
        firmware_local_start='2026-10-14 08:20:15', first_sample='2026-10-14 08:20:23',
        kcs_status='C1', state_bits=3, state='ERROR', ibf=0, obf=1, samples=1,
        kcs_write_attempts=0, kcs_data_reads=0, ipmi_requests_sent=0,
        pci_memory_enable_verified=True, pci_memory_restore_verified=True,
        probe_end=True, fan_experiment_executed=False, new_sensor_readings=False,
        user_report={'bmc_restarted_before_run':True, 'bmc_web_accessible':True},
        limitation='One status sample; duration and cause of error state are unknown. Not an IPMI completion code.',
        proposed_next='Separately keyed, once-only standard KCS GET_STATUS/ABORT after persistent startup error; log every handshake phase.')
    (OUT/'findings.json').write_text(json.dumps(findings,indent=2,ensure_ascii=False),encoding='utf-8')
    (OUT/'B2b实测分析.md').write_text('''# B2b 实测：启动时 KCS 状态 C1

来源为 2026-10-14 上传的 Downloads/HEROIPMI-000.TXT，与工作区旧的同名 A1 日志不同。本目录保留原始字节，未覆盖旧日志。

HERO BIOS 3107，扩展卡 0000:04:01.0，1A03:2402 revision 01，BAR1 74100000。PCI Command 从 0000 临时设为 0002，读回成功。

首次准备状态为 C1：state=ERROR，IBF=0，OBF=1。读取 PCI/状态的 EFI 调用均成功。B2b 按设计遇到非零且非 FF 的状态立即停止，因此只有一个样本；并非等待 30 秒后超时。C1 来自 KCS 状态寄存器，不是 IPMI completion code，也不是已经取出的接口错误码。没有数据寄存器读取，没有 KCS 写入，没有 Get Device ID、I 或 F，没有新传感器数据。退出时 PCI Command 恢复为 0000 且读回确认，日志正常结束。

用户补充：运行前重启过 BMC，BMC 网页可以打开。网页正常不能证明主机侧 KCS 可用；现有证据也不能确定该错误状态由 BMC 重启、之前的软件或其他原因造成，更不能认定它一直持续。此次未运行 F。

下一步 B2c 将在启动只读观察中要求连续三个 C0/C1，才提供单独的 K 选项。按 K 后重新核对平台、PCI 和状态，至多执行一次标准 GET_STATUS/ABORT 握手，保存此前残留输出字节和握手返回的错误状态字节。该操作会终止这个 KCS 通道上的未完成交换；它不是 BMC 重启，不修改固件，不自动执行 I/F。只有握手结束并重新观察到稳定空闲才继续首次 Get Device ID。实现是否能恢复这张扩展卡仍需新实机日志确认。

状态位依据：[Linux v6.12 KCS 定义](https://github.com/torvalds/linux/blob/v6.12/drivers/char/ipmi/ipmi_kcs_sm.c#L164-L172)。恢复握手依据：[IPMI v2.0 rev 1.1，第 9.18 节](https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf)及[Linux 错误处理](https://github.com/torvalds/linux/blob/v6.12/drivers/char/ipmi/ipmi_kcs_sm.c#L421-L467)。连续三次、单次按键和不重放为本工具选择的边界，不是规范对所有驱动的要求。
''',encoding='utf-8')
    print(json.dumps(findings,indent=2,ensure_ascii=False))

if __name__ == '__main__': main()
