"""Analyze real B2 failure evidence and replay its first-read failure offline."""
from pathlib import Path
import hashlib,json,re
from analyze_hero_a2_log import transactions
import verify_hero_ipmi_fan_b2 as b2

ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'HEROIPMI-003.TXT'
OUT=ROOT/'analysis/hero_ipmi_b2_result_003'

def main():
    raw=SOURCE.read_bytes();text=raw.decode('utf-8-sig');txs=transactions(text)
    assert len(txs)==1 and txs[0]['netfn']==6 and txs[0]['command']==1
    assert txs[0]['transport']=='PCI_IO_ERROR' and txs[0]['pci_status']==0 and txs[0]['response']==''
    assert 'RX transport=PCI_IO_ERROR status=FF pci_io=0000000000000000 bytes=' in text
    assert 'BIOS: 3107' in text and 'PCI_MEMORY_RESTORED_VERIFIED' in text and 'PROBE_END' in text
    assert 'FAN_STEP ' not in text and 'OEM_STEP ' not in text
    cfg=bytes.fromhex(re.search(r'PCI_CONFIG_00_3F ([0-9A-F ]+)',text)[1])
    assert cfg==b2.REAL_CONFIG
    exe=ROOT/'analysis/hero_ipmi_fan_b2/USB/EFI/BOOT/BOOTX64.EFI'
    assert hashlib.sha256(exe.read_bytes()).hexdigest()=='583e448281041868a0d61b172c4cc588714d0275dac77d644e53281aefbb0fd2'
    m=b2.Machine('real_3107');m.dev=b2.Device('status_ff');m.keys=list('eqq');m.run()
    assert not m.dev.writes and not m.dev.packets
    assert m.pci_writes==[(0,2),(2,0)] and m.config[4:8]==cfg[4:8]
    assert 'RX transport=PCI_IO_ERROR status=FF pci_io=0000000000000000 bytes=' in m.log.decode()
    report=dict(source=SOURCE.name,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),
        board='ROG MAXIMUS Z790 HERO',bios='3107',pci_config_identical_to_real_A2=True,
        first_request_intent=txs[0],kcs_status='FF',pci_memory_read_efi_status='EFI_SUCCESS',
        root_cause='NOT_ESTABLISHED: only one KCS status sample, no current BMC identity/SDR reading',
        user_report={'bmc_web_available_at_test':True,'previous_B2_run_before_003':False,
                     'host_reboot_before_003':True,'source':'Two user replies in this turn',
                     'causality':'Reboot preceded observation; causal link not established'},
        oem_requests=0,fan_test_started=False,bmc_command_bytes_sent=0,
        bmc_command_bytes_evidence='Source control flow plus offline replay of exact shipped B2 executable; no hardware bus trace',
        temporary_pci_command_changes=['0000->0002','0002->0000'],pci_restore_readback_confirmed=True,
        offline_replay=dict(status='PASS_MOCK_ONLY',kcs_write_attempts=len(m.dev.writes),complete_packets=len(m.dev.packets),pci_writes=m.pci_writes),
        not_proven=['BMC restart/unready cause','persistent MMIO mapping/bridge cause','cause attributable to host reboot',
                    'any fan mapping or sensor result from this run'])
    OUT.mkdir(exist_ok=True);(OUT/SOURCE.name).write_bytes(raw)
    (OUT/'findings.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (OUT/'example-MOCK-first-status-FF.txt').write_bytes(b'OFFLINE REPLAY OF FIRST-STATUS-FF FAILURE / NOT A HARDWARE LOG\r\n'+m.log)
    (OUT/'B2连接中止分析.md').write_text('''# HEROIPMI-003：B2 在通信入口中止

本次尚未开始 BMC 身份、传感器目录或风扇实验。唯一一条 TX 行是“准备执行 Get Device ID”的日志；发送前第一次读取 KCS 状态得到 FF，程序立即退出传输函数，没有写入 KCS 的启动字节或 IPMI 请求字节。

| 项目 | 结果 |
|---|---|
| BIOS / PCI 位置 | HERO 3107，0000:04:01.0 |
| PCI 配置前 64 字节 | 与 A2 实机成功日志完全一致 |
| BAR1 / 长度 | 74100000 / 40000 |
| 临时内存解码 | 0000 → 0002，读回确认 |
| 首次读取位置 | BAR1 + E8C，即 74100E8C |
| PCI 读取函数状态 | EFI_SUCCESS（0000000000000000） |
| 读到的 KCS 状态值 | FF |
| OEM 初始化 / F 实验 | 均未进入 |
| 退出恢复 | 0002 → 0000，读回确认，PROBE_END |

旧版把“读取函数报错”和“函数成功但值为 FF”都标成 PCI_IO_ERROR，这是诊断标签不足，不能据此认定 PCI 协议调用失败。已使用交付 B2 的实际 EFI 机器码做同条件离线回放：0 次 KCS 写操作、0 个发出的完整请求，两次 PCI Command 修改及恢复符合日志。

用户补充：生成日志时 BMC 网页能正常打开；003 之前没有运行过 B2，只重启过一次主机以进入 BIOS 运行程序。因此没有“此前 B2 已执行 F 修改”的证据，按用户说明可排除该情形。重启先于此次异常，但不能据此认定重启就是原因。

网页可达说明网络管理服务可用，但不能据此确认主机侧 KCS/PCI 入口也可用。本次只采到一个状态字节，尚不能区分短暂的主机接口未就绪、接口状态异常与 PCI/MMIO 路径问题，也不能证明扩展卡损坏。前次 B1 的温度/电压有效读数仍是成立的历史实测，但本次没有新的读数可评估持续性；同样不能判定 B2 的候选 RPM 映射成功或失败。

B2a 将错误分类分开，并在首次状态 FF 且尚无任何 KCS 写操作时提供一次 S：只采样状态和 PCI 配置约 30 秒，不读取 KCS 数据寄存器、不写 KCS、不自动重发 Get Device ID，不发送初始化/风扇命令。采样后退出，恢复 PCI；是否恢复通信需按日志判断。
''',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('source','sha256','bytes','fan_test_started','bmc_command_bytes_sent','offline_replay')},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
