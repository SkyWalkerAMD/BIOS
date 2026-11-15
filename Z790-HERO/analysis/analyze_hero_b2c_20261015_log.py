"""Analyze the actual B2c log; do not run its text or touch target hardware."""
from pathlib import Path
from collections import Counter
import hashlib, json, re
from analyze_hero_a2_log import transactions, decode_sdr, decode_reading, TARGETS

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT/'.codex-remote-attachments/01a0bede-5434-7821-8837-27b89c9e5cb9/fd859183-4096-43ce-82e7-a5649f8a949d/1-HEROIPMI-000.TXT'
OUT = ROOT/'analysis/hero_ipmi_b2c_result_20261015'


def main():
    raw = SOURCE.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == 'f78c02fbfe358459a2fd4354ef7ac2dd06c4e81e310bac1893ad2197b5c761a1'
    text = raw.decode('ascii')
    lines = text.splitlines()
    assert 'HERO IPMI FAN B2c' in text and 'BIOS: 3107' in text
    txs = transactions(text)
    counts = Counter((t['netfn'], t['command']) for t in txs)
    errors = [t for t in txs if t['transport'] != 'OK' or t['pci_status'] or t['completion'] != 0]
    assert not errors and len(txs) == 163
    assert counts == {(6,1):1, (10,32):2, (10,35):82, (4,45):78}
    identity = next(t['response'] for t in txs if (t['netfn'],t['command']) == (6,1))
    a2 = json.loads((ROOT/'analysis/hero_ipmi_a2_result/findings.json').read_text(encoding='utf-8'))
    assert bytes.fromhex(identity) == bytes.fromhex(a2['bmc']['raw_device_id'])

    ready = [dict(index=int(m[1]), status=m[2], consecutive_idle=int(m[3])) for m in
        re.finditer(r'READINESS_SAMPLE index=(\d+).*kcs_status=([0-9A-F]{2}) consecutive_idle=(\d+)',text)]
    assert [s['status'] for s in ready] == ['C1']*3 + ['00']*3
    states = [dict(phase=m[1], status=m[2], polls_left=int(m[3])) for m in
        re.finditer(r'KCS_RECOVERY_STATUS phase=(\w+) value=([0-9A-F]{2}) polls_left=(\d+)',text)]
    assert [s['status'] for s in states] == ['C1','C0','89','89','88','41','40','01','00']
    writes = [dict(phase=m[1], register=m[2], value=m[3]) for m in re.finditer(
        r'KCS_RECOVERY_WRITE_INTENT phase=(\w+) register=(\w+) value=([0-9A-F]{2})',text)]
    assert [(w['register'],w['value']) for w in writes] == [('COMMAND','60'),('DATA','00'),('DATA','68')]
    results = re.findall(r'KCS_RECOVERY_WRITE_RESULT phase=(\w+) pci_io=([0-9A-F]{16})',text)
    assert len(results) == 3 and all(int(status,16) == 0 for _,status in results)
    reads = [dict(phase=m[1], pci_status=int(m[2],16), value=m[3]) for m in re.finditer(
        r'KCS_RECOVERY_DATA phase=(\w+) pci_io=([0-9A-F]{16}) value=([0-9A-F]{2})',text)]
    assert [(r['phase'],r['value']) for r in reads] == [
        ('PREEXISTING_OUTPUT','00'),('WRITE_DUMMY','00'),('ERROR_CODE','01'),('FINAL_DUMMY','00')]
    assert all(r['pci_status'] == 0 for r in reads)
    assert text.count('KCS_RECOVERY_BEGIN:') == text.count('KCS_RECOVERY_HANDSHAKE_COMPLETE;') == 1
    assert 'kcs_write_attempts=3 kcs_data_reads=4' in text

    starts = [t for t in txs if (t['netfn'],t['command']) == (10,32)]
    ends = [i for i,line in enumerate(lines,1) if line == 'SDR_SCAN_COMPLETE']
    assert len(starts) == len(ends) == 2
    snapshots = []
    for index,(start,end) in enumerate(zip(starts,ends)):
        messages = [t for t in txs if start['line'] <= t['line'] < end]
        records = [decode_sdr(bytes.fromhex(t['response'])) for t in messages if (t['netfn'],t['command']) == (10,35)]
        declared = int.from_bytes(bytes.fromhex(start['response'])[4:6],'little')
        assert declared == len(records) == len({r['record_id'] for r in records}) == 41
        assert all(a['next_record'] == b['record_id'] for a,b in zip(records,records[1:]))
        assert records[-1]['next_record'] == 0xffff
        sensors = {r['sensor']:r for r in records if 'sensor' in r}
        assert len(sensors) == 39
        for t in messages:
            if (t['netfn'],t['command']) == (4,45):
                sensor = sensors[bytes.fromhex(t['data'])[0]]
                assert 'reading' not in sensor
                sensor['reading'] = decode_reading(bytes.fromhex(t['response']),sensor)
                sensor['reading'].update(response=t['response'], log_line=t['rx_line'])
        assert all('reading' in s for s in sensors.values())
        present = [f'{sid:02X}' for sid in TARGETS if sid in sensors]
        assert not present
        version = sensors[0xfb]['reading']
        assert version['reported'] and version['state_bits'] == 0x10
        timestamp = next(line for line in reversed(lines[:start['line']])
                         if line.startswith(('Readiness complete:', 'Rescan:')))
        snapshots.append(dict(index=index,phase=('baseline','baseline_rescan')[index],
            preceding_clock_line=timestamp,record_count=declared,sensor_count=len(sensors),
            target_ids_present=present,version_error_asserted=True,
            reported_count=sum(s['reading']['reported'] for s in sensors.values()),
            line_start=start['line'],line_end=end,records=records))
    definitions = [[{k:v for k,v in r.items() if k != 'reading'} for r in s['records']]
                   for s in snapshots]
    assert definitions[0] == definitions[1]
    no_oem = not any(t['netfn'] == 0x30 for t in txs)
    assert no_oem and 'OEM_STEP ' not in text and 'FAN_STEP ' not in text
    init_prompt = [i for i,line in enumerate(lines,1) if line.startswith('I = send the candidate OEM sequence ONCE')]
    fan_block = [i for i,line in enumerate(lines,1) if line == 'FAN_GATE_CLOSED: requires initialized B1 state and disabled CHA_FAN1.']
    assert init_prompt == [337,344,596] and fan_block == [341]
    assert 'PCI_MEMORY_RESTORED_VERIFIED' in text and 'PROBE_END' in text
    report = dict(source=str(SOURCE),sha256=digest,bytes=len(raw),program='B2c',
        board='ROG MAXIMUS Z790 HERO',bios='3107',bmc_fingerprint=identity,
        command_count=len(txs),command_counts={f'{n:02X}/{c:02X}':v for (n,c),v in counts.items()},errors=errors,
        recovery=dict(real_hardware=True,attempts=1,handshake_complete=True,
            readiness_samples=ready,status_trace=states,writes=writes,data_reads=reads,
            pending_output='00',interface_error_code='01',
            cause='Not established; error 01 reports abort and does not identify the original cause'),
        snapshots=snapshots,init_prompt_lines=init_prompt,blocked_f_attempt_lines=fan_block,
        oem_initialization_executed=False,fan_experiment_executed=False,
        pci_memory_restore_verified=True,probe_end=True,
        next_step='Use existing B2c: E/P, K only if offered, letter I when offered; then F only when offered; after F wait about 30 s and R; Q to save and exit.',
        not_proven=['Cause or timing of loss of the earlier initialized sensor state',
            'Fan mapping or valid mainboard RPM','BMC Web sensor display',
            'Automatic startup initialization or BIOS/DXE integration'],transactions=txs)
    OUT.mkdir(exist_ok=True)
    (OUT/'HEROIPMI-B2c-20261015-000.TXT').write_bytes(raw)
    (OUT/'findings.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    (OUT/'B2c实测结果.md').write_text(f'''# B2c 实测结果：通信恢复已确认，等待执行 I

2026-10-15 上传日志，{len(raw):,} 字节，SHA-256 `{digest}`。原文件保存在本目录，没有覆盖其他同名日志或历史测试包。

## 已确认的结果

| 项目 | 实机结果 |
|---|---|
| 主板 / BIOS | ROG MAXIMUS Z790 HERO / 3107 |
| 启动状态 | 连续三个 C1；按 K 前仍为 C1 |
| KCS 恢复 | 一次 60 → 00 → 68 握手，3 次写入均成功 |
| 握手返回 | 残留输出 00；接口错误状态字节 01；最终回到 00 |
| 恢复后 | 三个连续 00；Get Device ID 成功，身份与 A2 完全一致 |
| 标准 IPMI 请求 | 163 次，传输、PCI 调用及完成码全部成功 |
| 两次目录扫描 | 各 41 条 SDR、39 个传感器；候选主板目标各 0/16 |
| VERSION_ERR | 两次均为有效置位，response `14 2D 00 00 C0 10 80` |
| I 初始化 | 提示可用，但本次未执行，无 OEM 请求 |
| F 风扇实验 | 一次尝试在检查阶段被拒绝，没有发送任何 F 指令 |
| 退出 | PCI Command 0000 → 0002 → 0000，恢复读回确认 |

恢复时 89/88 的 bit 3 是 Command/Data 标志，本版已正确处理。01 是 GET_STATUS/ABORT 取得的接口状态字节，含义为 Aborted By Command；不能由此追溯最初 C1 的来源，也不能把残留字节 00 当作这个错误码。

163 次标准请求包括 Get Device ID 1 次、SDR 仓库信息 2 次、记录读取 82 次、传感器读取 78 次。两次目录中的 39 个传感器不包含约定的 16 个主板目标，不能把卡自身/PSU 等项目计为 HERO 目标监控成功。

第 337 行已有 I 选项，第 341 行是 `initialize_fan()` 检查失败的提示，随后只执行了 R。没有 `OEM_STEP`、`FAN_STEP` 或 netfn 30 请求。因此阻塞 F 的直接条件是尚未完成当前会话需要的初始化，不是一次已经发出的风扇指令失败。

当前状态与以前 A2 / B1 初始化前一致。以前 B1 初始化后的主板目录此刻已不在当前目录中，但两次实测间发生的操作没有完整记录，不能单凭本日志确定何时或为何失去这些状态。

## 下一次使用同一个 B2c

1. E/P 读取；只有提示 K 时才按 K。
2. 看到 `I = send the candidate OEM sequence ONCE` 后，按键盘字母 **I**（i 的大写，不是数字 1 或字母 L）。无需回车。
3. 等待 `OEM_SEQUENCE_ACCEPTED acknowledged=4/4` 及初始化后扫描；仅当程序提供 F 选项时按 F。如果初始化报错或不提供 F，保留日志。
4. F 完成后等待约 30 秒，按 R 再读取。检查 BMC 网页的 MB_CHA_FAN1，记录实际读数。
5. Q 结束记录，日志关闭后再 Q 返回启动菜单。提供本次新日志。

I 会重新执行此前 B1 验证过的四条候选初始化；F 会修改单项转速映射并启用该传感器扫描。Q 不回滚 BMC 修改。无需更换 B2c、降级 BIOS 或重新刷写固件。

**本次新增里程碑是实机 KCS 错误恢复及恢复后的正常通信。风扇映射、有效 RPM 和自动 BIOS 集成仍待验证。**

协议依据：[IPMI v2.0 rev 1.1，9.10 / 9.18 节](https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf)、[Linux v6.12 KCS 状态定义及错误处理](https://github.com/torvalds/linux/blob/v6.12/drivers/char/ipmi/ipmi_kcs_sm.c)。
''',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('sha256','command_count','command_counts','init_prompt_lines','blocked_f_attempt_lines','oem_initialization_executed','fan_experiment_executed','pci_memory_restore_verified')},indent=2,ensure_ascii=False))

if __name__ == '__main__': main()
