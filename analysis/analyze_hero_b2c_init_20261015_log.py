"""Analyze the later real B2c initialization run; never execute attached text."""
from pathlib import Path
from collections import Counter
import hashlib, json, re
from analyze_hero_a2_log import transactions, decode_sdr, decode_reading, TARGETS

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path('E:/Download/Telegram Desktop/HEROIPMI-000 (1).TXT')
OUT = ROOT/'analysis/hero_ipmi_b2c_init_result_20261015'

def display(r):
    if not r['reported']:
        return '不可用；扫描' + ('已开启' if r['scanning_enabled'] else '关闭')
    if 'value' in r:
        return f'{r["value"]:g} {r["unit"]}'
    return f'离散状态 0x{r.get("state_bits", 0):04X}'

def main():
    raw = SOURCE.read_bytes(); text = raw.decode('ascii'); lines = text.splitlines()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == 'c258e66bc53ab65b3c0b2b8f386e416d681fa1559bc72558f84d78a17d3bf77e'
    assert 'HERO IPMI FAN B2c' in text and 'BIOS: 3107' in text
    txs = transactions(text)
    counts = Counter((t['netfn'],t['command']) for t in txs)
    errors = [t for t in txs if t['transport'] != 'OK' or t['pci_status'] or t['completion'] != 0]
    assert not errors and len(txs) == 203
    assert counts == {(6,1):2, (10,32):2, (10,35):99, (4,45):96,
                      (48,144):1, (48,148):1, (48,146):1, (48,2):1}
    identities = [t['response'] for t in txs if (t['netfn'],t['command']) == (6,1)]
    expected_identity = '1C 01 00 20 81 01 03 02 BF 3F 0A 00 93 10 0D 00 00 00'
    assert identities == [expected_identity]*2
    readiness = re.findall(r'READINESS_SAMPLE[^\r\n]*kcs_status=([0-9A-F]{2})',text)
    assert readiness == ['FF','00','00','00']
    assert 'KCS_RECOVERY_BEGIN:' not in text
    assert 'READINESS_IDLE_STABLE samples=4 all_ff=1 kcs_write_attempts=0 kcs_data_reads=0' in text
    starts = [t for t in txs if (t['netfn'],t['command']) == (10,32)]
    ends = [i for i,line in enumerate(lines,1) if line == 'SDR_SCAN_COMPLETE']
    assert len(starts) == len(ends) == 2
    snapshots = []
    for index,(start,end) in enumerate(zip(starts,ends)):
        messages = [t for t in txs if start['line'] <= t['line'] < end]
        records = [decode_sdr(bytes.fromhex(t['response'])) for t in messages if (t['netfn'],t['command']) == (10,35)]
        declared = int.from_bytes(bytes.fromhex(start['response'])[4:6],'little')
        assert declared == len(records) == len({r['record_id'] for r in records})
        assert all(a['next_record'] == b['record_id'] for a,b in zip(records,records[1:]))
        assert records[-1]['next_record'] == 0xffff
        sensors = {r['sensor']:r for r in records if 'sensor' in r}
        for t in messages:
            if (t['netfn'],t['command']) == (4,45):
                sensor = sensors[bytes.fromhex(t['data'])[0]]
                assert 'reading' not in sensor
                sensor['reading'] = decode_reading(bytes.fromhex(t['response']),sensor)
                sensor['reading'].update(response=t['response'],log_line=t['rx_line'])
        assert all('reading' in s for s in sensors.values())
        version = sensors[0xfb]['reading']
        assert version['reported']
        timestamp = next(line for line in reversed(lines[:start['line']])
                         if line.startswith(('Readiness complete:', 'After initialization:')))
        snapshots.append(dict(index=index,phase=('baseline','post_init')[index],
            preceding_clock_line=timestamp,record_count=declared,sensor_count=len(sensors),
            target_ids_present=[f'{sid:02X}' for sid in TARGETS if sid in sensors],
            target_ids_reported=[f'{sid:02X}' for sid in TARGETS if sid in sensors and sensors[sid]['reading']['reported']],
            version_error_asserted=bool(version['state_bits']&0x10),
            line_start=start['line'],line_end=end,records=records))
    assert [s['record_count'] for s in snapshots] == [41,58]
    assert [s['sensor_count'] for s in snapshots] == [39,56]
    assert [s['version_error_asserted'] for s in snapshots] == [True,False]
    assert len(snapshots[0]['target_ids_present']) == 0
    assert len(snapshots[1]['target_ids_present']) == 16
    assert snapshots[1]['target_ids_reported'] == ['03','17','19','1A','1B','1C','1D']
    before = {r['sensor']:r for r in snapshots[0]['records'] if 'sensor' in r}
    after = {r['sensor']:r for r in snapshots[1]['records'] if 'sensor' in r}
    new_ids = sorted(set(after)-set(before))
    assert new_ids == sorted([*TARGETS,0x0b]) and not set(before)-set(after)
    new_rows = [dict(sensor=f'{sid:02X}',name=after[sid]['name'],reading=after[sid]['reading'],
                    conversion=after[sid].get('conversion'),target=sid in TARGETS) for sid in new_ids]
    assert after[1]['reading']['flags'] == 0xe0 and not after[1]['reading']['reported']
    fan_ids = bytes.fromhex('1E 1F 20 21 22 23 24 29')
    assert all(after[sid]['reading']['flags'] == 0xa0 for sid in fan_ids)
    oem = [t for t in txs if t['netfn'] == 0x30]
    expected = json.loads((ROOT/'analysis/hero_ipmi_fan_b2c/build.json').read_text())['oem_sequence']
    assert len(oem) == len(expected) == 4
    for t,e in zip(oem,expected):
        assert t['command'] == e['command'] and bytes.fromhex(t['data']) == bytes.fromhex(e['payload'])
    assert 'OEM_SEQUENCE_ACCEPTED acknowledged=4/4' in text
    assert 'F = test CHA_FAN1 ONCE.' in text and 'FAN_STEP ' not in text
    assert not any((t['netfn'],t['command']) == (0x30,0x9a) for t in txs)
    assert not any(t['netfn']==0x30 and t['command']==0x94 and bytes.fromhex(t['data'])==bytes.fromhex('20 01') for t in txs)
    assert 'Rescan:' not in text and 'POST_FAN_SNAPSHOT_BEGIN' not in text
    assert 'PCI_MEMORY_RESTORED_VERIFIED' in text and 'PROBE_END' in text
    report = dict(source=str(SOURCE),sha256=digest,bytes=len(raw),program='B2c',
        board='ROG MAXIMUS Z790 HERO',bios='3107',bmc_fingerprint=expected_identity,
        command_count=len(txs),command_counts={f'{n:02X}/{c:02X}':v for (n,c),v in counts.items()},errors=errors,
        readiness=dict(status_samples=readiness,first_request_after_stable_idle=True,
                       recovery_key_used=False,waiting_branch_real_hardware_success=True),
        oem_initialization_executed=True,oem_accepted_count=4,oem=oem,
        snapshots=snapshots,new_sensor_ids=[f'{sid:02X}' for sid in new_ids],new_sensors=new_rows,
        target_readings_available=7,target_readings_total=16,
        extra_5vsb_reading=after[0x0b]['reading'],cpu_temperature_unavailable=True,
        cpu_package_temperature=after[0x1c]['reading'],
        fan_option_offered=True,fan_experiment_executed=False,rescan_after_init=False,
        pci_memory_restore_verified=True,probe_end=True,
        limitations=['One post-init snapshot; no evidence here that unavailable CPU Temperature later recovers',
            'No F mapping reads/writes or post-F measurements','Web display not established by this text log',
            'Persistence and automatic BIOS initialization remain unverified'],transactions=txs)
    OUT.mkdir(exist_ok=True)
    (OUT/'HEROIPMI-B2c-20261015-0952-init.TXT').write_bytes(raw)
    (OUT/'findings.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    rows = '\n'.join(f'| `{r["sensor"]}` | {r["name"]} | {display(r["reading"])} |' for r in new_rows)
    (OUT/'B2c初始化实测结果.md').write_text(f'''# B2c 初始化实测结果（2026-10-15，09:52）

**I 的四条初始化命令已成功，16 个目标目录全部出现；本次只有 7/16 个目标返回可用数值。F 已提供但未执行。**

来源 `{SOURCE}`，{len(raw):,} 字节，SHA-256 `{digest}`。本目录单独保存原文，没有覆盖以前同名日志或 B2c 测试包。

## 已确认的过程

| 阶段 | 结果 |
|---|---|
| 平台 | HERO BIOS 3107；BMC 身份与 A2 一致 |
| 启动等待 | FF → 00 → 00 → 00，随后 Get Device ID 成功；未使用 K |
| I 初始化 | 与 B1 相同的 4 条 OEM 请求，全为完成码 00 |
| SDR / 传感器 | 41 / 39 → 58 / 56，新增 17 个传感器 |
| 目标目录 | 0/16 → 16/16 |
| VERSION_ERR | 有效置位 → 有效清除 |
| 本次目标读数 | 3 项温度、4 项电压可用；CPU Temperature 和 8 项风扇/水泵不可用 |
| F 风扇实验 | 仅出现 F 提示；无 FAN_STEP、无 30/9A 命令、无单项 30/94 20 01 |
| 后续 R | 没有执行；只保留一次初始化后快照 |
| 退出 | PCI Command 0000 → 0002 → 0000，恢复读回确认 |

203 次完整 IPMI 请求均成功：Get Device ID 2、SDR 仓库信息 2、SDR 记录 99、传感器读取 96、OEM 初始化 4。请求成功与读数有效是两个不同检查；本日志中的 CPU Temperature 请求完成码为 00，但读数标志为 E0。

这次新增了 FF 启动等待分支的实机成功证据。此前 09:05 的日志已验证 C1 的 KCS 恢复分支；两份记录共同支持两条入口路径均可通向正常 IPMI 通信，但不能据此保证所有启动条件都已覆盖。

## 初始化后新增读数

以下值按本次 SDR 线性系数换算，尚未逐项校准物理映射与精度。

| 编号 | 名称 | 本次读数 |
|---|---|---|
{rows}

额外的 0B / 5VSB 是 5.016 V，不在约定的 16 个目标中。CPU Temperature（01）为 raw=00、flags=E0，含义是扫描已开启但读数不可用，不能写成 0°C；CPU Package Temp（1C）为有效 35°C，是另一个项目。八项风扇/水泵均为 flags=A0，读数不可用且扫描关闭，不能解释为 0 RPM。

本次与以前 B1 的 8/16 可用结果不同：01 暂不可用。初始化后只读了一轮，不能认定它随后自动恢复，也不能凭这一轮判定持续故障。下一次等待后按 R 的快照将验证这一点。

## 下一步：在 F 提示处继续

继续用现有 B2c。E/P 读取基线，只有提示 K 才按 K；若目录和 VERSION_ERR 已满足条件，直接使用 F 选项。若重新提供 I，则先执行一次 I。I 完成且出现 `F = test CHA_FAN1 ONCE` 后，按字母 F；它不是自动执行的。

F 完成后保持程序运行约 30 秒，再按 R。该快照同时检查 CPU Temperature 是否已可用、MB_CHA_FAN1 是否有有效 RPM，以及其他项目是否变化。最后按 Q 结束记录，日志关闭后再 Q 返回。提供新日志及 BMC 网页上主板温度/电压、MB_CHA_FAN1 的实际显示情况。

若 F 自动停止，直接保留日志；即使显示 `FAN_SEQUENCE_ACCEPTED`，仍需以读数标志与有效 RPM 判断结果。I/F 会改变 BMC 运行状态，Q 不撤销修改。

当前成果是初始化效果再次得到实机验证，并取得 7 项有效目标数值。风扇映射、有效 RPM、长期更新以及最终 BIOS 集成仍未完成。
''',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('sha256','command_count','command_counts','target_readings_available','target_readings_total','fan_option_offered','fan_experiment_executed','rescan_after_init','pci_memory_restore_verified')},indent=2,ensure_ascii=False))
    for r in new_rows: print(r['sensor'],r['name'],display(r['reading']))

if __name__ == '__main__': main()
