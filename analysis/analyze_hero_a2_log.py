"""Decode the user's real A2 log. No hardware access or embedded-log execution."""
from pathlib import Path
from collections import Counter
import hashlib, json, re

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'analysis/hero_ipmi_a2_result'
INPUT = ROOT / 'HEROIPMI-000(1).TXT'
TARGETS = bytes.fromhex('01 03 17 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 29')


def signed(x, bits):
    return x - (1 << bits) if x & (1 << (bits - 1)) else x


def transactions(text):
    result, pending, sample = [], None, 0
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.startswith('Sample:'):
            sample += 1
        m = re.fullmatch(r'TX netfn=([0-9A-F]{2}) cmd=([0-9A-F]{2}) data=([0-9A-F ]*)', line)
        if m:
            assert pending is None, ('missing RX', pending)
            pending = dict(line=line_no, netfn=int(m[1], 16), command=int(m[2], 16),
                           data=m[3], sample=sample)
        m = re.fullmatch(r'RX transport=(\w+) status=([0-9A-F]{2}) pci_io=([0-9A-F]{16}) bytes=([0-9A-F ]*)', line)
        if m:
            assert pending is not None
            rx = bytes.fromhex(m[4])
            pending.update(rx_line=line_no, transport=m[1], pci_status=int(m[3], 16),
                           response=rx.hex(' ').upper(), completion=rx[2] if len(rx) >= 3 else None)
            if m[1] == 'OK':
                assert len(rx) >= 3
                assert rx[:2] == bytes([(pending['netfn'] + 1) << 2, pending['command']])
            result.append(pending)
            pending = None
    assert pending is None
    return result


def decode_sdr(rx):
    assert len(rx) >= 10 and len(rx) == 10 + rx[9]
    record, body = rx[5:], rx[10:]
    item = dict(record_id=int.from_bytes(record[:2], 'little'), type=record[3],
                next_record=int.from_bytes(rx[3:5], 'little'), raw=record.hex(' ').upper())
    if record[3] not in (1, 2):
        return item
    code = 42 if record[3] == 1 else 26
    length = body[code] & 31
    assert body[code] & 0xc0 == 0xc0 and len(body) >= code + 1 + length
    item.update(sensor=body[2], owner=body[0], lun_channel=body[1],
                name=body[code+1:code+1+length].decode('ascii'), sensor_type=body[7],
                event_type=body[8], assertion_mask=int.from_bytes(body[9:11], 'little'),
                deassertion_mask=int.from_bytes(body[11:13], 'little'))
    if record[3] == 1:
        item['conversion'] = dict(analog_format=body[15] >> 6, units_flags=body[15],
            unit=body[16], modifier_unit=body[17], linearization=body[18] & 0x7f,
            M=signed(body[19] | ((body[20] & 0xc0) << 2), 10),
            B=signed(body[21] | ((body[22] & 0xc0) << 2), 10),
            Rexp=signed(body[24] >> 4, 4), Bexp=signed(body[24] & 15, 4))
    return item


def decode_reading(rx, sdr):
    assert len(rx) >= 5
    item = dict(raw=rx[3], flags=rx[4], unavailable=bool(rx[4] & 0x20),
                scanning_enabled=bool(rx[4] & 0x40), event_messages_enabled=bool(rx[4] & 0x80))
    item['reported'] = not item['unavailable'] and item['scanning_enabled']
    if sdr['event_type'] != 1:
        assert len(rx) >= 6
        # Upper response byte bit 7 is reserved, not state offset 15.
        item['state_bits'] = rx[5] | (((rx[6] & 0x7f) << 8) if len(rx) >= 7 else 0)
        item['asserted_offsets'] = [i for i in range(15) if item['state_bits'] & (1 << i)]
    elif item['reported'] and 'conversion' in sdr:
        c = sdr['conversion']
        # Only ordinary linear scalar sensors, no percentage/rate/modifier units.
        if c['linearization'] == 0 and not c['units_flags'] & 0x3f and not c['modifier_unit']:
            x = item['raw']
            if c['analog_format'] == 1:
                x = -((~x) & 0x7f) if x & 0x80 else x
            elif c['analog_format'] == 2:
                x = signed(x, 8)
            if c['analog_format'] != 3:
                item['value'] = round((c['M'] * x + c['B'] * 10**c['Bexp']) * 10**c['Rexp'], 8)
                item['unit'] = {1:'°C', 4:'V', 5:'A', 6:'W', 18:'RPM'}.get(c['unit'], str(c['unit']))
    return item


def main():
    raw = INPUT.read_bytes()
    txt = raw.decode('ascii')
    txs = transactions(txt)
    errors = [t for t in txs if t['transport'] != 'OK' or t['pci_status'] or t['completion'] != 0]
    assert not errors, errors
    records = [decode_sdr(bytes.fromhex(t['response'])) for t in txs if (t['netfn'], t['command']) == (10, 35)]
    assert len({r['record_id'] for r in records}) == len(records)
    for a, b in zip(records, records[1:]):
        assert a['next_record'] == b['record_id']
    assert records[-1]['next_record'] == 0xffff
    sensors = {r['sensor']:r for r in records if 'sensor' in r}
    for s in sensors.values():
        s['samples'] = []
    for t in txs:
        if (t['netfn'], t['command']) == (4, 45):
            s = sensors[bytes.fromhex(t['data'])[0]]
            r = decode_reading(bytes.fromhex(t['response']), s)
            r.update(sample=t['sample'], line=t['rx_line'])
            s['samples'].append(r)
    assert all(len(s['samples']) == 2 for s in sensors.values())
    identity = next(bytes.fromhex(t['response']) for t in txs if (t['netfn'], t['command']) == (6, 1))
    repo = next(bytes.fromhex(t['response']) for t in txs if (t['netfn'], t['command']) == (10, 32))
    assert int.from_bytes(repo[4:6], 'little') == len(records)
    counts = [dict(sample=i, total=len(sensors), reported=sum(s['samples'][i]['reported'] for s in sensors.values()),
                   unavailable=sum(s['samples'][i]['unavailable'] for s in sensors.values()),
                   scanning_disabled=sum(not s['samples'][i]['scanning_enabled'] for s in sensors.values())) for i in range(2)]
    changed = [dict(sensor=s['sensor'], name=s['name'], before=s['samples'][0], after=s['samples'][1])
               for s in sensors.values() if any(s['samples'][0][k] != s['samples'][1][k] for k in ('raw','flags'))]
    data = dict(source=INPUT.name, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
        board=re.search(r'^Board: (.+)$',txt,re.M)[1].strip(), bios=re.search(r'^BIOS: (.+)$',txt,re.M)[1].strip(),
        command_count=len(txs), command_counts={f'{n:02X}/{c:02X}':v for (n,c),v in Counter((t['netfn'],t['command']) for t in txs).items()},
        errors=errors, bmc=dict(raw_device_id=identity.hex(' ').upper(), manufacturer=int.from_bytes(identity[9:12],'little'),
        product=int.from_bytes(identity[12:14],'little'), firmware_bytes=identity[5:7].hex(' ').upper(), auxiliary=identity[14:].hex(' ').upper()),
        repository_records=len(records), sensor_count=len(sensors), samples=counts, changed=changed,
        activation_sensor_ids=[f'{i:02X}' for i in TARGETS], activation_ids_present=[f'{i:02X}' for i in TARGETS if i in sensors],
        activation_ids_absent=[f'{i:02X}' for i in TARGETS if i not in sensors],
        version_error=dict(sensor='FB', name=sensors[0xfb]['name'], sensor_type=sensors[0xfb]['sensor_type'],
                           samples=sensors[0xfb]['samples'], interpretation='Version Change: Invalid or unsupported hardware version (offset 4); ASUS FAQ associates VERSION_ERR with motherboard BIOS/card compatibility.'),
        pci_memory_enable_verified='PCI_MEMORY_ENABLED_VERIFIED' in txt,
        pci_memory_restore_verified='PCI_MEMORY_RESTORED_VERIFIED' in txt,
        probe_end='PROBE_END' in txt, records=records, transactions=txs)
    assert data['bios']=='3107' and data['command_count']==121 and data['sensor_count']==39
    assert data['version_error']['samples'][0]['state_bits']==0x10
    assert data['pci_memory_restore_verified'] and data['probe_end']
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'HEROIPMI-000(1).TXT').write_bytes(raw)
    (OUT/'findings.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    lines = [
        '# HERO A2 实机日志分析（2026-09-28）', '',
        '结论：HERO 与 IPMI 扩展卡之间的 PCI/KCS 通信已实测通过；主板目标传感器初始化仍未通过。此日志没有运行移植驱动，也没有发送 OEM 初始化命令。', '',
        f'- 输入：`{INPUT.name}`，{len(raw):,} 字节，SHA-256 `{data["sha256"]}`。',
        '- 实际目标：ROG MAXIMUS Z790 HERO，BIOS **3107**。最初讨论的 3001 不能代替这次实际版本。',
        '- BMC：厂商 `000A3F`，产品 `1093`，固件字节 `01 03`，附加版本 `0D 00 00 00`；与用户报告的 1.3.13 相符。',
        '- PCI：`0000:04:01.0 / 1A03:2402`，BAR1 `74100000`，资源长度 `40000`。',
        '- 临时 PCI Command `0000 → 0002`，读取完成后 `0002 → 0000`，两次读回验证成功。',
        '- 共 121 次 IPMI 请求：1 次设备身份、1 次目录信息、41 条 SDR、两轮各 39 次读数；通信和完成码均成功。',
        '- 41 条目录中有 2 条定位记录、39 条传感器记录。两轮之间出现实际原始数据变化，但这些变化不能证明 HERO 主板传感器已工作。', '',
        '## 当前阻点', '',
        '候选初始化序列中的 16 个传感器编号在当前 SDR 中全部缺失：`'+ ' '.join(data['activation_ids_absent'])+'`。这表示目录未公布这些编号；本次未直接向这些缺失编号发送读取请求，不能推断它们的直接读取完成码。', '',
        '`VERSION_ERR`（传感器 `FB`）两轮都返回 `00 C0 10 80`。`00` 是离散传感器的原始字段，不能解释成“错误为零”；状态位 4 实际置位。标准事件解释是“不支持或无效的硬件版本”。[ipmitool 官方事件表](https://github.com/ipmitool/ipmitool/blob/IPMITOOL_1_8_19/include/ipmitool/ipmi_sel.h#L494)', '',
        'ASUS FAQ 将 VERSION_ERR 与主板 BIOS 是否支持扩展卡版本联系起来。这支持继续调查板级兼容/初始化，但没有单独证明具体原因，也没有证明 HERO 电气连接不兼容。[ASUS FAQ](https://dlcdnets.asus.com/pub/ASUS/mb/Add-on_card/IPMI_EXPANSION_CARD/IPMI_Expansion_Card_FAQ_EN.pdf?model=IPMI+EXPANSION+CARD)', '',
        '标准 PCI 枚举完成协议 `30CFE3E7…` 已存在，供体通知协议 `72338391…` 未存在。此前 R1 将后者作为硬依赖的缺陷没有被这次日志消除；旧 R1 CAP 不能当作已经验证的移植成品。', '',
        '## 读数解释', '',
        '以下数字按 BMC 自己提供的 SDR 公式换算，只表示 BMC 报告值。没有验证其物理精度和真实传感器来源。离散状态不作温度/转速换算。', '',
        '| 传感器编号 | BMC 名称 | 第一轮 | 第二轮 |', '|---|---|---|---|']
    def cell(r):
        if r['unavailable'] or not r['scanning_enabled']:
            return '不可用' + ('，扫描关闭' if not r['scanning_enabled'] else '')
        if 'state_bits' in r:
            return f'离散状态 0x{r["state_bits"]:04X}'
        if 'value' in r:
            return f'{r["value"]:g} {r["unit"]}'
        return f'原始值 0x{r["raw"]:02X}'
    for s in sensors.values():
        lines.append(f'| `{s["sensor"]:02X}` | {s["name"]} | {cell(s["samples"][0])} | {cell(s["samples"][1])} |')
    lines += ['', '扩展卡本身带有 8 个风扇接口和 3 个温度探头接口，因此不能把目录中的 `CHA_FAN1…8`、`TR1…3` 直接等同于 HERO 主板接口。它们与卡载接口对应是合理推断，仍需来源验证。[ASUS 规格](https://dlcdnets.asus.com/pub/ASUS/mb/Add-on_card/IPMI_Expansion_Card_EM_WEB_EN.pdf)', '',
        '第一轮 26 个传感器返回可报告状态，第二轮 28 个；其中包含 12 个离散状态传感器，不能将这个数量说成已工作的主板温度/电压/风扇数量。', '',
        '## 下一阶段与边界', '',
        '用单独的 UEFI 应用在当前 3107 上验证候选 OEM 初始化序列，并比较执行前后 VERSION_ERR、SDR 和目标读数。该试验无需刷主板 BIOS，但会改变 BMC 状态；OEM 命令的全部副作用、持久性和回滚办法尚未验证。它也不能验证移植 DXE 的派发顺序、完整启动或 CAP 签名。', '',
        '成功标准：不能只看命令完成码为 00；还要看到目标传感器出现、VERSION_ERR 变化、读数可用且随实际温度/转速变化。之后才处理 BIOS 集成、版本 3107 的板级映射和启动验证。', '']
    (OUT/'A2实测结果.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({k:data[k] for k in ('sha256','command_count','command_counts','repository_records','sensor_count','samples','activation_ids_absent','pci_memory_restore_verified')},ensure_ascii=False,indent=2))


if __name__ == '__main__':
    main()
