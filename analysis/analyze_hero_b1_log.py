"""Decode and compare the user's B1 hardware snapshots; never execute log text."""
from pathlib import Path
from collections import Counter
import datetime as dt
import hashlib, json, re
from analyze_hero_a2_log import transactions, decode_sdr, decode_reading, TARGETS

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_b1_result'
SOURCE=ROOT/'HEROIPMI-001.TXT'


def display(r):
    if not r['reported']:
        return '不可用' + ('；扫描关闭' if not r['scanning_enabled'] else '')
    if 'value' in r:
        return f'{r["value"]:g} {r["unit"]}'
    if 'state_bits' in r:
        return f'离散状态 0x{r["state_bits"]:04X}'
    return f'原始值 0x{r["raw"]:02X}'


def main():
    raw=SOURCE.read_bytes();txt=raw.decode('ascii');lines=txt.splitlines()
    txs=transactions(txt)
    errors=[t for t in txs if t['transport']!='OK' or t['pci_status'] or t['completion']!=0]
    assert not errors,errors
    starts=[t for t in txs if (t['netfn'],t['command'])==(10,32)]
    stops=[i for i,line in enumerate(lines,1) if line=='SDR_SCAN_COMPLETE']
    assert len(starts)==len(stops)==4
    snapshots=[]
    for index,(start,stop) in enumerate(zip(starts,stops)):
        messages=[t for t in txs if start['line']<=t['line']<stop]
        declared=int.from_bytes(bytes.fromhex(start['response'])[4:6],'little')
        records=[decode_sdr(bytes.fromhex(t['response'])) for t in messages if (t['netfn'],t['command'])==(10,35)]
        assert len(records)==declared and len({r['record_id'] for r in records})==declared
        assert all(a['next_record']==b['record_id'] for a,b in zip(records,records[1:]))
        assert records[-1]['next_record']==0xffff
        sensors={r['sensor']:r for r in records if 'sensor' in r}
        assert len(sensors)==len([r for r in records if 'sensor' in r])
        for t in messages:
            if (t['netfn'],t['command'])==(4,45):
                sid=bytes.fromhex(t['data'])[0]
                s=sensors[sid];assert 'reading' not in s
                s['reading']=decode_reading(bytes.fromhex(t['response']),s)
                s['reading']['log_line']=t['rx_line']
                s['reading']['response']=t['response']
        assert all('reading' in s for s in sensors.values())
        timestamp=next(line for line in reversed(lines[:start['line']])
                       if line.startswith(('Started:','Rescan:','After initialization:')))
        snapshots.append(dict(index=index,phase=['baseline','baseline_rescan','post_init','post_init_rescan'][index],
            timestamp=timestamp,line_start=start['line'],line_end=stop,record_count=declared,
            sensor_count=len(sensors),reported_count=sum(s['reading']['reported'] for s in sensors.values()),
            target_ids_present=[f'{i:02X}' for i in TARGETS if i in sensors],
            target_ids_reported=[f'{i:02X}' for i in TARGETS if i in sensors and sensors[i]['reading']['reported']],
            version_error_asserted=bool(sensors[0xfb]['reading']['state_bits']&0x10),
            records=records,sensors=sensors))
    baseline=snapshots[1]['sensors'];first=snapshots[2]['sensors'];last=snapshots[3]['sensors']
    new_ids=sorted(set(last)-set(baseline));removed_ids=sorted(set(baseline)-set(last))
    new_rows=[]
    for sid in new_ids:
        assert first[sid]['raw']==last[sid]['raw'],'SDR definition changed between post-init samples'
        new_rows.append(dict(sensor=f'{sid:02X}',name=last[sid]['name'],target=sid in TARGETS,
            first=first[sid]['reading'],second=last[sid]['reading'],conversion=last[sid].get('conversion'),
            raw_changed=first[sid]['reading']['raw']!=last[sid]['reading']['raw']))
    oem=[t for t in txs if t['netfn']==0x30]
    expected=json.loads((ROOT/'analysis/hero_ipmi_init_b1/build.json').read_text())['oem_sequence']
    assert len(oem)==len(expected)==4
    for t,e in zip(oem,expected):
        assert t['command']==e['command'] and bytes.fromhex(t['data'])==bytes.fromhex(e['payload'])
    assert [s['record_count'] for s in snapshots]==[41,41,58,58]
    assert [s['sensor_count'] for s in snapshots]==[39,39,56,56]
    assert [s['version_error_asserted'] for s in snapshots]==[True,True,False,False]
    assert len(new_ids)==17 and not removed_ids
    assert len(snapshots[-1]['target_ids_present'])==16 and len(snapshots[-1]['target_ids_reported'])==8
    assert len(txs)==399
    assert 'PCI_MEMORY_RESTORED_VERIFIED' in txt and 'PROBE_END' in txt
    times=[]
    for s in snapshots[2:]:
        parts=re.search(r'(\d{4})-(\d+)-(\d+) (\d+):(\d+):(\d+)',s['timestamp'])
        times.append(dt.datetime(*map(int,parts.groups())))
    elapsed=(times[1]-times[0]).total_seconds()
    report=dict(source=SOURCE.name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        board='ROG MAXIMUS Z790 HERO',bios='3107',bmc_fingerprint=next(t['response'] for t in txs if (t['netfn'],t['command'])==(6,1)),
        command_count=len(txs),command_counts={f'{n:02X}/{c:02X}':v for (n,c),v in Counter((t['netfn'],t['command']) for t in txs).items()},
        errors=errors,oem=oem,snapshots=snapshots,new_sensor_ids=[f'{i:02X}' for i in new_ids],
        removed_sensor_ids=[f'{i:02X}' for i in removed_ids],new_sensors=new_rows,
        post_snapshot_start_interval_seconds=elapsed,
        pci_memory_enable_verified=True,pci_memory_restore_verified=True,probe_end=True,
        proven=['Four fixed B1 OEM packets completed with code 00 on actual HERO 3107 / BMC fingerprint 1.3.13',
                'VERSION_ERR offset 4 deasserted in both post-init snapshots',
                'All 16 candidate target SDRs appeared; 8 temperature/voltage readings available, 8 fan readings unavailable with scanning disabled',
                'Additional 5VSB Voltage SDR 0B appeared with a reported reading',
                'CPU/CPU Package temperature and CPU Core/DRAM VDDQ voltage raw readings changed across post-init snapshots',
                'Temporary PCI Command bit restored and read back'],
        not_proven=['Accuracy and physical identity of every new sensor','Fan RPM acquisition or fan control',
                    'Persistence after application exit, OS boot, warm/cold boot or BMC power loss',
                    'BMC Web UI rendering','Full donor DXE execution, modified CAP boot or authentication'],
        transactions=txs)
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/SOURCE.name).write_bytes(raw)
    (OUT/'findings.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    md=['# HERO B1 实机结果（2026-09-29）','',
        '**结论：候选初始化已在 HERO 3107 上产生实际效果。主板温度/电压监控已有可用且部分变化的读数；主板风扇/水泵转速仍不可用。不能把 16/16 目录出现等同于 16/16 功能完成。**','',
        f'原始日志 `{SOURCE.name}`，{len(raw):,} 字节，SHA-256 `{report["sha256"]}`。日志运行主板为 ROG MAXIMUS Z790 HERO，BIOS 3107；BMC 身份与前次 A2 完全匹配。','',
        '## 实测过程','',
        '| 阶段 | 固件时钟 | SDR 记录 | 传感器记录 | 目标出现 | 目标读数可用 | VERSION_ERR |',
        '|---|---|---:|---:|---:|---:|---|']
    phase_names=['首次基线','初始化前复扫','初始化后立即读取','初始化后复扫']
    for name,s in zip(phase_names,snapshots):
        time=re.search(r'\d{4}-\d+-\d+ (\d+:\d+:\d+)',s['timestamp'])[1]
        md.append(f'| {name} | {time} | {s["record_count"]} | {s["sensor_count"]} | {len(s["target_ids_present"])}/16 | {len(s["target_ids_reported"])}/16 | '+('置位' if s['version_error_asserted'] else '已清除')+' |')
    md+=['',f'两次初始化后快照开始时间相差 **{elapsed:g} 秒**，不是 30 秒。记录只覆盖 UEFI 应用内的这段时间，没有应用退出后或重启后的采样。','',
        '四条 OEM 指令均收到完成码 `00`，按顺序为 `30/90 80`、`30/94 固定16组编号/01`、`30/92 00 00`、`30/02 01`。完整载荷及返回原始字节保存在 findings.json。没有逐条指令之间的目录采样，因此不能单独认定是哪一条使 VERSION_ERR 消失或新增目录。','',
        '共 **399 次请求**：设备身份 2 次、SDR 仓库信息 4 次、SDR 记录 198 次、传感器读取 191 次、OEM 初始化 4 次。全部传输和完成码成功。PCI Command 经 `0000→0002→0000`，退出恢复读回成功。成功完成码不等于每个读数均可用。','',
        '## 新增项目及换算值','',
        '值按当前 BMC 返回的 SDR 线性系数换算，尚未与 BIOS Monitor 或独立仪表逐项校准。对 unavailable/scanning-disabled 项不换算为 0 RPM。','',
        '| 编号 | BMC 名称 | 初始化后 | 12 秒后 |', '|---|---|---|---|']
    for r in new_rows:
        md.append(f'| `{r["sensor"]}` | {r["name"]} | {display(r["first"])} | {display(r["second"])} |')
    md+=['','16 个候选目标中，4 项温度与 4 项电压均返回可用状态；8 项主板风扇/水泵均为 `flags=A0`（读数不可用，扫描关闭）。额外出现的 `0B / 5VSB Voltage` 不在 16 个候选列表中，单独计数。','',
        '`VERSION_ERR` 两次从 `00 C0 10 80` 变为 `00 C0 00 80`：扫描开启、读数状态有效，错误位确实清除；不是简单根据 raw=00 判断。','',
        'B1 没有读取主板 HWM 协议并持续推送数值；其初始化后只发送标准读取命令。多个新传感器原始值变化支持“BMC 已在更新数据”的判断，但尚不能证明所有项目的物理映射、精度、长期更新和操作系统阶段行为。','',
        '## 风扇尚缺的环节','',
        '供体发布函数在参数偏移 `52=1` 时，另行进入 OEM `30/9A` 映射/模式发送与主板 EC 写入路径。B1 没有执行该分支。随后用户提供的 BIOS Monitor 截图显示 CHA_FAN1 为 2884 RPM，其余列出的风扇/水泵/流量为 N/A；说明至少 CHA_FAN1 在主板侧已有可读转速。截图不是 BMC 网页，也不是与 B1 同时采样。','',
        '对 ASUS BMC 1.3.13 固件的静态分析及离线函数仿真确认：命令 `30/9A` 的 RPM 映射与模式/PWM/类型设置相互独立；主板 CHA_FAN1 驱动使用 RPM 映射数组第 2 项。尚未读到实机映射表，因此不能认定其当前必为零。后续 B2 先读取并核对这些表，仅在符合条件时修改 CHA_FAN1 一项并重新启用传感器 20。详见 `../hero_ipmi_fan_b2/风扇适配依据.md` 与 B2 使用说明。','',
        '供体 EC 协议 GUID 为 `4058B109-BA63-4F6A-846C-64A7DCC44FD9`；发布函数通过接口偏移 `10` 写入 `FF`、`92/93/90`（另一分支 `86/87/84`）。这些寄存器和供体数组不能未经 HERO 当前版本核对就整套照搬，尤其要区分转速遥测与改变风扇控制权。','',
        '## 当前进度和下一步','',
        '1. **完成实测**：PCI/KCS、候选四条初始化、VERSION_ERR 清除、目标目录创建、8 项温度/电压返回可用读数。','2. **正在适配**：已确定 CHA_FAN1 是可用的主板对照点；已分析官方 HERO 3107 的 HWM 描述符，并完成 B2 单项映射实验程序的离线检查。B2 尚无实机结果，其余风扇/水泵映射未验证。','3. **等待实机补证**：BMC 网页显示、与 BIOS Monitor 对照、应用退出及重启后的持续更新。B1 可再次进入读取模式检查，但不要为重复采样再次发送初始化；按 E/P 后读取或 R 即可，最后 Q 退出。','4. **尚未完成**：自动开机初始化及最终 BIOS 集成、DXE 派发、固件签名和可恢复的刷写验证。现有 R1 CAP 的依赖缺陷仍需修正，不能因为 B1 成功就视作已可刷成品。','']
    (OUT/'B1实测结果.md').write_text('\n'.join(md),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('sha256','command_count','command_counts','new_sensor_ids','post_snapshot_start_interval_seconds')},ensure_ascii=False,indent=2))
    for r in new_rows:
        print(r['sensor'],r['name'],display(r['first']),'->',display(r['second']))


if __name__=='__main__':main()
