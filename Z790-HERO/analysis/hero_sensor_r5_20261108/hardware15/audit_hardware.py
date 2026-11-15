"""Audit complete R5 .15 captures offline; no device access or source mutation."""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LIVE = ROOT / "analysis/hero15_rc5_live_20261108"
CORE = HERE.parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def provenance(path):
    raw = path.read_bytes()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": len(raw), "sha256": sha(raw)}


def capture(name):
    spec = importlib.util.spec_from_file_location("r5_capture", CORE / "autoboot15/decode_captures.py")
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    folder = LIVE / "captures" / name
    pages = sorted(folder.glob("*.qr.bin"))
    data, meta = decoder.assemble([p.read_bytes() for p in pages])
    actual = LIVE / (name + ".TXT")
    assert actual.read_bytes() == data, f"TXT differs from all CRC-validated pages: {name}"
    return data.decode("ascii"), {**provenance(actual), **meta,
        "pages_evidence": [provenance(p) for p in pages]}


def blob(s):
    return bytes.fromhex(s.strip())


def pairs(text):
    commands = []
    pending = None
    for line_no, line in enumerate(text.splitlines(), 1):
        m = re.fullmatch(r"(TX|OEM_TX|DMI_SET) ([0-9A-F]{2})/([0-9A-F]{2})(?: (.*))?", line)
        request = None
        if m:
            request = (m[1], int(m[2], 16), int(m[3], 16), blob(m[4] or ""))
        m = re.fullmatch(r"FAN_SET 30/9A (.*)", line)
        if m:
            request = ("FAN_SET", 0x30, 0x9A, blob(m[1]))
        m = re.fullmatch(r"DMI_GET selector=([0-9A-F]{2}) offset=0 count=192", line)
        if m:
            request = ("DMI_GET", 0x30, 3, bytes([int(m[1], 16), 0, 0, 192]))
        if request:
            assert pending is None, (pending, line)
            kind, netfn, cmd, body = request
            pending = {"line": line_no, "kind": kind, "netfn": netfn, "command": cmd,
                       "request_hex": body.hex(), "request_bytes": body}
        m = re.fullmatch(r"(RX|OEM_RX|DMI_RX|DMI_SET_RX|FAN_SET_RX) ([A-Z_]+)(?: (.*))?", line)
        if m:
            assert pending is not None, line
            assert m[2] == "OK", line
            reply = blob(m[3] or "")
            assert len(reply) >= 3 and reply[:3] == bytes([(pending["netfn"] + 1) << 2, pending["command"], 0]), line
            pending.update({"response_line": line_no, "response_hex": reply.hex(), "response_bytes": reply})
            commands.append(pending)
            pending = None
    assert pending is None, pending
    return commands


def smbios_requests():
    raw = (LIVE / "host-DMI.bin").read_bytes()
    at = 0
    types = {}
    while at < len(raw):
        assert len(raw) - at >= 6
        ty, length = raw[at], raw[at + 1]
        assert length >= 4
        end = raw.index(b"\0\0", at + length)
        strings = raw[at + length:end].split(b"\0")
        record = raw[at:at + length]
        if ty in (0, 2):
            assert ty not in types
            types[ty] = (record, strings)
        at = end + 2
        if ty == 127:
            break
    assert raw[at - 6] == 127
    def string(ty, offset):
        record, strings = types[ty]
        index = record[offset]
        assert 1 <= index <= len(strings)
        value = strings[index - 1]
        assert value and all(32 <= c <= 126 for c in value)
        return value + b"\0"
    return {2: b"\x02" + b"".join(string(2, off) for off in (4, 5, 6, 7)),
            0: b"\0" + string(0, 5) + string(0, 8)}, raw[:at]


def sensor_records(section_commands):
    found = {}
    readings = {}
    for cmd in section_commands:
        netfn, number, rx = cmd["netfn"], cmd["command"], cmd["response_bytes"]
        if (netfn, number) == (10, 0x23):
            record = rx[5:]
            assert len(record) == 5 + record[4] and record[2] == 0x51
            if record[3] not in (1, 2):
                continue
            body = record[5:]
            id = body[2]
            assert id not in found
            code = 42 if record[3] == 1 else 26
            size = body[code] & 31
            assert size <= len(body) - code - 1
            name = body[code + 1:code + 1 + size].decode("ascii") if body[code] >> 6 == 3 else None
            found[id] = {"id": id, "name": name, "type": body[7], "event": body[8],
                         "record_id": int.from_bytes(record[:2], "little"), "raw_sdr_hex": record.hex()}
        if (netfn, number) == (4, 0x2D):
            id = cmd["request_bytes"][0]
            assert len(rx) >= 5
            readings[id] = {"raw": rx[3], "flags": rx[4], "raw_response": rx.hex(),
                            "available": (rx[4] & 0x60) == 0x40}
    return [{**found[id], **readings.get(id, {})} for id in sorted(found)]


def main():
    before, before_meta = capture("hero15-r5-preflight")
    loaded, loaded_meta = capture("hero15-r5-loaded")
    full, full_meta = capture("hero15-r5-after-ready")
    expected_core = "81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4"
    assert sha((CORE / "USB/EFI/HERO/HeroIpmiR5.efi").read_bytes()) == expected_core
    for text in (before, loaded, full):
        assert f"FROZEN_R5_SHA256={expected_core}" in text
        assert "MANUAL_RUN_CALLS=0 SYNTHETIC_EVENT_SIGNALS=0 APP_CALLBACKS=0" in text
        assert "TARGET_UUID=b222f546-dbb3-9ac8-bbfb-581122d8be9f" in text
    assert "API_CONNECTED=00" in before and "PREFLIGHT_SAFE:" in before
    assert "PCI_BDF=0000:0000000000000074:01.0" in before
    assert "HERO_IPMI_CFG_STATUS=800000000000000E" in before
    assert "HeroIpmiAttempt LOCK_STATUS=800000000000000E" in before
    assert "HeroIpmiDmiAttempt LOCK_STATUS=800000000000000E" in before
    assert "LOAD_IMAGE=0000000000000000 START_IMAGE=0000000000000000" in loaded
    assert "R3 ready_seen=00" in loaded and "FINAL requests=00000000" in loaded
    assert not pairs(loaded)
    assert full.count("READY_TO_BOOT_AUTO_ENABLED R5 sensor+Dashboard") == 1
    assert full.count("R5_SENSORS_INITIALIZE_BEGIN") == 1
    assert "R3 ready_seen=01 sensor_status=0000000000000000 dashboard_status=0000000000000000" in full
    assert "R5_SENSORS_END status=0000000000000000" in full
    assert "R4_DASHBOARD_END status=0000000000000000" in full
    commands = pairs(full)
    final = re.search(r"^FINAL (.+)$", full, re.M)[1]
    final = {k: int(v, 16) for k, v in re.findall(r"(\w+)=([0-9A-F]+)", final)}
    assert final["requests"] == len(commands) == 237
    assert final["ack"] == 4 and final["targets"] == 16
    assert final["version_asserted"] == final["locked"] == 0
    assert final["attempted"] == final["pci_restored"] == 1

    candidate = [c for c in commands if c["kind"] == "OEM_TX"]
    expected = [(0x90, "80"), (0x94, "01010301170119011a011b011c011d011e011f01200121012201230124012901"),
                (0x92, "0000"), (0x02, "01")]
    assert [(c["command"], c["request_hex"]) for c in candidate] == expected
    assert all(len(c["response_bytes"]) == 3 for c in candidate)
    fan_set = [c for c in commands if c["kind"] == "FAN_SET"]
    assert len(fan_set) == 1
    fan = fan_set[0]
    assert fan["request_bytes"][:2] == b"\x01\x01" and len(fan["request_bytes"]) == 17
    assert fan["response_bytes"][3:] == fan["request_bytes"][2:]
    rpm_gets = [c for c in commands if (c["netfn"], c["command"], c["request_bytes"]) == (0x30, 0x9A, b"\x01\0")]
    old_rpm = rpm_gets[0]["response_bytes"][3:]
    new_rpm = fan["request_bytes"][2:]
    assert len(old_rpm) == len(new_rpm) == 15 and old_rpm[2] == 0 and new_rpm[2] == 0x62
    assert [i for i, (a, b) in enumerate(zip(old_rpm, new_rpm)) if a != b] == [2]
    assert candidate[0]["line"] < fan["line"] < candidate[1]["line"]
    control_reads = {}
    for cmd in commands:
        if (cmd["netfn"], cmd["command"]) == (0x30, 0x9A) and cmd["kind"] == "TX":
            assert len(cmd["request_bytes"]) == 2 and cmd["request_bytes"][1] == 0
            selector = cmd["request_bytes"][0]
            control_reads.setdefault(selector, []).append(cmd["response_bytes"][3:])
    for selector in (0, 2, 3):
        assert len(set(control_reads[selector])) == 1
    assert control_reads[0][0] == b"\0"
    assert control_reads[2][0] == b"\0" * 15
    assert control_reads[3][0] == b"\1" * 15

    source_requests, source_raw = smbios_requests()
    # Linux DMI and this later UEFI boot have the same selected Type0/Type2
    # strings, but their whole-table CRCs differ. Do not equate those snapshots.
    source_match = re.search(r"SMBIOS_BYTES=([0-9A-F]+) CRC32=([0-9A-F]+)", before)
    assert source_match is not None
    assert f"DMI_SOURCE table_crc={source_match[2]} bytes={source_match[1]}" in full
    setters = [c for c in commands if c["kind"] == "DMI_SET"]
    assert [c["request_bytes"][0] for c in setters] == [2, 0]
    for cmd in setters:
        selector = cmd["request_bytes"][0]
        wanted = source_requests[selector]
        assert cmd["request_bytes"] == wanted
        assert cmd["response_bytes"] == bytes([0xC4, 4, 0, len(wanted) - 1])
        following = next(c for c in commands if c["line"] > cmd["line"] and c["kind"] == "DMI_GET")
        assert following["request_bytes"][0] == selector
        assert following["response_bytes"] == bytes([0xC4, 3, 0, len(wanted) - 1]) + wanted[1:]
    assert "dmi_matched=05 dmi_written=05 dmi_locked=00" in full
    allowed_standard = {(6, 1), (10, 0x20), (10, 0x23), (4, 0x2D), (0x30, 0x9A)}
    assert all((c["netfn"], c["command"]) in allowed_standard for c in commands if c["kind"] == "TX")
    restores = re.findall(r"^PCI_RESTORE write=([0-9A-F]+) read=([0-9A-F]+) after=([0-9A-F]+)\r?$", full, re.M)
    assert restores == [("0" * 16, "0" * 16, "0000")] * 2
    assert full.count("PCI_ENABLE 16-bit Command only; before=0000") == 2
    assert full.count("PCI_SELECTED_BDF=0000:74:01.0") == 2

    snapshots = []
    for m in re.finditer(r"SDR_SNAPSHOT_BEGIN\r?\n(.*?)SDR_SNAPSHOT_END targets=([0-9A-F]+) readable=([0-9A-F]+) version_asserted=([0-9A-F]+)", full, re.S):
        cs = pairs(m[1])
        infos = [c["response_bytes"] for c in cs if (c["netfn"], c["command"]) == (10, 0x20)]
        assert len(infos) == 2 and infos[0] == infos[1]
        snapshots.append({"targets": int(m[2], 16), "readable": int(m[3], 16), "version_asserted": int(m[4], 16),
                          "declared_records": int.from_bytes(infos[0][4:6], "little"), "sensors": sensor_records(cs)})
    assert len(snapshots) == 2 and snapshots[0]["version_asserted"] == 1
    assert snapshots[1]["targets"] == 16 and snapshots[1]["version_asserted"] == 0
    fans = []
    for sensor in snapshots[1]["sensors"]:
        if sensor["id"] not in (0x1E, 0x1F, 0x20):
            continue
        record = bytes.fromhex(sensor["raw_sdr_hex"])
        body = record[5:]
        # Exact unsigned RPM unit, linear conversion, M=120/B=0/exponents0.
        assert record[3] == 1 and body[15:25] == bytes.fromhex("00120000780000000000")
        fans.append({"id": sensor["id"], "name": sensor["name"],
                     "raw": sensor["raw"], "flags": sensor["flags"],
                     "available": sensor["available"],
                     "rpm": sensor["raw"] * 120 if sensor["available"] else None,
                     "conversion": "SDR: unsigned linear, RPM unit, M120/B0/R0/Bexp0"})
    for command in commands:
        command.pop("request_bytes")
        command.pop("response_bytes")
    result = {"passed": True, "scope": "Exact R5 runtime two-pass real-BDS protocol audit; no flash acceptance claim",
        "inputs": [before_meta, loaded_meta, full_meta, provenance(LIVE / "host-DMI.bin")],
        "core": provenance(CORE / "USB/EFI/HERO/HeroIpmiR5.efi"),
        "first_pass_entry_requests": 0, "real_ready_to_boot_observed": True,
        "pci": {"bdf": "0000:74:01.0", "bar1": "0x78100000", "bar1_bytes": 262144,
                "initial_command": 0, "both_restores_verified": True},
        "command_count": len(commands), "command_counts": dict(Counter(f'{c["netfn"]:02X}/{c["command"]:02X}' for c in commands)),
        "final": final, "oem_initialization_acks": 4,
        "fan_mapping": {"writes": 1, "changed_index": 2, "before_hex": old_rpm.hex(), "after_hex": new_rpm.hex(),
                        "mode_pwm_type_preserved": True, "samples": [x.rstrip("\r") for x in re.findall(r"^FAN_SAMPLE .+$", full, re.M)],
                        "immediate_sdr_fans": fans},
        "dashboard": {"selectors_written": [2, 0], "exact_local_source_and_readback": True,
                      "dmi_matched_mask": 5, "dmi_written_mask": 5, "attempt_latch_cleared": True,
                      "uefi_source_bytes": int(source_match[1], 16), "uefi_source_crc32": source_match[2],
                      "linux_source_crc32": f"{zlib.crc32(source_raw):08X}",
                      "cross_snapshot_check": "Selected Type0/Type2 identity strings match; whole-table CRC differs and is not asserted equal."},
        "sdr_snapshots": snapshots, "commands": commands,
        "limits": ["This is a RAM-loaded exact-driver real-BDS test, not final CAP flash or native FFS dispatch evidence.",
                   "Available flag and raw sensor bytes are reported separately; 16 target records do not imply 16 positive physical readings.",
                   "CPU/OPT actual fan baseline must be compared with fresh BMC readings; no new CPU/OPT mapping is inferred.",
                   "Warm/cold repeat and final package validation are separate evidence."]}
    (HERE / "hardware-verification.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    summary = """R5 在 .15 的实机启动验证：协议阶段通过

本报告核验 .15 的 4 页预检、7 页加载日志和 65 页真实 ReadyToBoot 日志。
65 页数据全部通过分段 CRC、整份 CRC 和长度校验，重组后与 TXT 逐字节一致。
最终日志 33065 字节，SHA256 671544f9fb2ced692b74d878ef8c2d1d09d5aa7ebe58edcb07f1f3c24ae588f5。

已证实
1. UEFI 实际管理接口为 0000:74:01.0，BAR1 78100000 / 256KiB。
   预检仅一张匹配卡，配置变量和两个尝试锁均不存在。
2. 第一遍仅加载驱动，0 次 BMC 请求；同次启动重新选择 ISO 后，真实
   ReadyToBoot 触发一次初始化。启动器没有手动 run 或伪造事件。
3. 237 个请求/应答逐个核对，均成功；4 个初始化 OEM 各发送一次、4/4 ACK。
   SDR 记录由 41 增为 58，16 个目标传感器全部出现，VERSION_ERR 清除。
4. 风扇 RPM 表只将索引 2 从 00 改为 62，恰好一次 SET；完整读回相同。
   Mode、PWM、type 始终不变。未新增 CPU/OPT 映射。
5. Dashboard 按 selector2、selector0 各写一次，本机身份内容和立即读回精确一致。
   所选 Type0/Type2 字符串也与本机 Linux DMI 相同；两次整份 SMBIOS 的 CRC
   不同，报告未将两份表宣称为相同。传感器和 Dashboard 尝试锁均正常清除。
6. 两阶段 PCI Command 均从 0000 临时启用内存访问，结束后精确恢复至 0000。

传感器读数的实际范围
初始化当时，16 个目标中 6 个读数可用：4 项主板电压和 CPU/CPU_OPT 风扇。
CPU_FAN 为 2520 RPM，CPU_OPT_FAN 为 3720 RPM，来自各自 SDR 的 M=120 换算。
此前 BIOS 页面为 2683 / 4364 RPM，两次采样并非同时，不要求数值完全一致。
MB_CHA_FAN1 的三次采样均 raw0 / flagsA0，不可用；该机 BIOS 上 CHA1 未接。
CPU/MB/Package/VRM 温度当时 raw0 / flagsE0，不可用，不能据此宣称温度已通过。
后续应以重新加载页面后的数据及标准 IPMI 新读数判断。

边界
这是精确 R5 驱动的 RAM 加载和真实 BDS 事件验证，不等于最终 CAP 刷写或
原生 FFS 调度验证。旧网页曾出现标签与数值错位，298-navigate 不作为通过证据。
本报告不宣称 P6/S23 菜单、配置保存、重启后重复执行和恢复刷写已经通过。
本分析没有连接设备或执行硬件命令。
"""
    (HERE / "硬件验证摘要.txt").write_text(summary, encoding="utf-8")
    print(json.dumps({"passed": True, "commands": len(commands), "snapshots": [{k: s[k] for k in ("targets", "readable", "version_asserted", "declared_records")} for s in snapshots],
                      "report": provenance(HERE / "hardware-verification.json")}))


if __name__ == "__main__":
    main()
