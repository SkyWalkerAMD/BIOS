"""Offline comparison of captured standard replies with RC3 R2 baseline gates.

This is a source-guided check of data fields, not execution of the R2 PE driver.
No network imports, sockets or BMC commands.
"""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "analysis/hero_ipmi_rc3_20261104/FIELD-PACKAGE/05-SOURCE/R2/source"
CAPTURE = HERE / "live_71_20261108.json"
TARGETS = (1, 3, 0x17, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
           0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x29)


def inspect():
    capture = json.loads(CAPTURE.read_text(encoding="utf-8"))
    reads = {e["label"]: e for e in capture["events"] if e["type"] == "read"}
    records = [e for e in capture["events"] if e["type"] == "sdr_record"]
    expected_identity = "2081010302bf3f0a0093100d000000"
    errors = []
    gates = {"device_id_exact_fingerprint": reads["device_id"]["completion_code"] == 0
             and reads["device_id"]["response_hex"] == expected_identity}
    before = bytes.fromhex(reads["sdr_info_before"]["response_hex"])
    after = bytes.fromhex(reads["sdr_info_after"]["response_hex"])
    declared = int.from_bytes(before[1:3], "little")
    gates["repository_info_length"] = len(before) >= 14
    gates["declared_count_1_to_128"] = 0 < declared <= 128
    gates["declared_count_equals_traversal"] = declared == len(records)
    gates["repository_bytes_unchanged"] = before == after
    seen, visited, next_id = set(), set(), 0
    targets, readable, skipped_sharing = [], [], []
    fb_sdr, version_valid, asserted = False, False, False
    for item in records:
        if next_id in visited:
            errors.append("record request loop")
        visited.add(next_id)
        response = reads.get(f"sdr_{next_id:04X}")
        if response is None or response["completion_code"] != 0:
            errors.append("missing/failed SDR reply")
            break
        raw = bytes.fromhex(response["response_hex"])
        record = raw[2:]
        if len(raw) < 7 or len(raw) != 7 + record[4] or record[2] != 0x51:
            errors.append("SDR length/version")
            break
        rid = int.from_bytes(record[:2], "little")
        if next_id and rid != next_id:
            errors.append("record ID mismatch")
        next_id = int.from_bytes(raw[:2], "little")
        if record[3] not in (1, 2):
            continue
        body = record[5:]
        name_at = 42 if record[3] == 1 else 26
        if len(body) <= name_at or (body[name_at] & 31) > len(body) - name_at - 1:
            errors.append("probe_sensor parse fails")
            continue
        owner, lun, sensor = body[0:3]
        sensor_type, event_type = body[7], body[8]
        share = body[18] & 15 if record[3] == 2 else 0
        if owner != 0x20 or lun != 0 or share > 1:
            skipped_sharing.append({"sensor": sensor, "owner": owner, "lun_byte": lun, "share": share})
            continue
        if sensor in seen:
            errors.append(f"duplicate sensor {sensor:02X}")
        seen.add(sensor)
        if sensor == 0xFB:
            fb_sdr = sensor_type == 0x2B and event_type == 0x6F and item.get("name") == "VERSION_ERR"
        if sensor in TARGETS:
            index = TARGETS.index(sensor)
            expected_type = 4 if index >= 8 else 1 if sensor in (1, 3, 0x1C, 0x1D) else 2
            if sensor_type != expected_type or event_type != 1:
                errors.append(f"target type/event {sensor:02X}")
            targets.append(sensor)
        reading = reads.get(f"sensor_{sensor:02X}")
        if reading is None or reading["completion_code"] != 0:
            errors.append(f"sensor completion {sensor:02X}")
            continue
        value = bytes.fromhex(reading["response_hex"])
        if len(value) < 2:
            errors.append(f"sensor reply length {sensor:02X}")
            continue
        if sensor == 0xFB:
            version_valid = len(value) >= 4 and sensor_type == 0x2B and event_type == 0x6F and value[1] & 0x60 == 0x40
            asserted = version_valid and bool(value[2] & 0x10)
        if sensor in TARGETS and event_type == 1 and value[1] & 0x60 == 0x40:
            readable.append(sensor)
    gates.update({"traversal_ends_FFFF": next_id == 0xFFFF,
                  "SDR_records_and_sensor_reads_accepted_by_field_checks": not errors,
                  "VERSION_ERR_SDR_exact": fb_sdr, "VERSION_ERR_read_valid": version_valid,
                  "VERSION_ERR_asserted_for_init_path": asserted})
    result = {
        "capture": str(CAPTURE), "capture_sha256": hashlib.sha256(CAPTURE.read_bytes()).hexdigest(),
        "method": "Offline source-guided field checks; not R2 PE execution and not proof of KCS/UEFI runtime behavior",
        "sources_sha256": {name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()
                           for name in ("engine.c", "probe_core.c", "driver.c", "common.c")},
        "gates": gates, "field_checks_all_pass": all(gates.values()), "errors": errors,
        "records": len(records), "readable_record_sensor_ids": len(seen), "skipped_sharing_or_owner": skipped_sharing,
        "R2_target_SDR_count": len(targets), "R2_readable_target_count": len(readable),
        "R2_target_ids_present": targets,
        "finding": "Captured DeviceID/SDR/sensor replies do not identify a failing R2 baseline field gate; zero target SDRs and asserted VERSION_ERR match uninitialized state. Disabled TR/fan/PSU2 flags alone do not cause snapshot() to fail when CC=0.",
        "not_testable_from_LAN": [
            "Actual SMBIOS board and BIOS strings seen by the DXE driver (requires HERO / 3107)",
            "ReadyToBoot event dispatch and core protocol installation",
            "HeroIpmiCfg enabled/valid attributes and HeroIpmiAttempt absence",
            "PCI enumeration, exact ASPEED BDF 0000:04:01.0, BAR1 and memory decode",
            "Exclusive KCS ownership, idle samples, response timings and transaction integrity during boot",
            "BMC readiness/SDR contents at boot, which can differ from this later LAN sample",
            "Outcome of OEM initialization commands; none sent by this probe"
        ],
        "lan_user_permission_correction": {"affected_capture": CAPTURE.name,
            "meaning": "All 12 LAN parameter GETs on channels 1 and 7 returned D4 (insufficient privilege). Initial summary read_supported=false was ambiguous and is superseded by completion-code evidence: support is undetermined at USER privilege.",
            "raw_evidence_unchanged": True}
    }
    output = HERE / "r2_baseline_from_lan.json"
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("field_checks_all_pass", "records", "readable_record_sensor_ids", "R2_target_SDR_count", "errors")}, indent=2))


if __name__ == "__main__":
    inspect()
