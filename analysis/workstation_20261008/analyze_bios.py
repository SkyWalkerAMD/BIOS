"""Read-only analysis of three supplied ASUS capsules; output stays in this folder."""
from pathlib import Path
from collections import Counter, defaultdict
import argparse
import csv
import hashlib
import json
import lzma
import re
import struct
import subprocess
import uuid
import zipfile

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent.parent
EXTRACTOR = ROOT / "tools/UEFIExtract_A75/UEFIExtract.exe"
INPUTS = {
    "W790_SAGE_2003": "Pro-WS-W790E-SAGE-SE-ASUS-2003.zip",
    "W890_SAGE_0603": "Pro-WS-W890E-SAGE-SE-ASUS-0603.zip",
    "W790_ACE_2003": "Pro-WS-W790-ACE-ASUS-2003.zip",
}
OFFICIAL_HASHES = {
    "W790_SAGE_2003": "d093fb2a045633eb7285a45606ea1548d9250982e266f7480193296ed8231845",
    "W790_ACE_2003": "4ca36875d8c37310fe4e6eaddfd59e2433d3c2dbaf1d9551d3ade59f4a1ee47d",
    "W890_SAGE_0603": "5bad35967954afb2f10123828e3698c1f36b413b21ce127f15778ed424997df8",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, data):
    (OUT / name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def extract():
    result = {}
    for tag, name in INPUTS.items():
        source = ROOT / name
        record = {"source": name, "zip_size": source.stat().st_size,
                  "zip_sha256": sha(source.read_bytes())}
        expected = OFFICIAL_HASHES.get(tag)
        record.update(official_zip_sha256=expected,
                      official_zip_hash_match=record["zip_sha256"] == expected if expected else None)
        with zipfile.ZipFile(source) as z:
            bad = z.testzip()
            if bad:
                raise ValueError(f"ZIP CRC failure: {name}: {bad}")
            record["zip_crc_ok"] = True
            record["members"] = [{"name": x.filename, "size": x.file_size,
                                   "compressed_size": x.compress_size, "crc32": f"{x.CRC:08X}",
                                   "timestamp": list(x.date_time), "sha256": sha(z.read(x))}
                                  for x in z.infolist() if not x.is_dir()]
            caps = [x for x in z.infolist() if x.filename.lower().endswith(".cap")]
            if len(caps) != 1:
                raise ValueError(f"Expected one CAP in {name}, got {len(caps)}")
            member = caps[0]
            payload = z.read(member)
        target_dir = OUT / tag
        target_dir.mkdir(exist_ok=True)
        # Preserve standalone update data for inspection; never execute the bundled renamer.
        with zipfile.ZipFile(source) as z:
            for x in z.infolist():
                if x.filename.lower().endswith(".bin"):
                    dest = target_dir / Path(x.filename.replace("\\", "/")).name
                    b = z.read(x)
                    if dest.exists() and dest.read_bytes() != b:
                        raise ValueError(f"Existing extracted BIN differs: {dest}")
                    dest.write_bytes(b)
        cap = target_dir / Path(member.filename.replace("\\", "/")).name
        if cap.exists():
            if cap.read_bytes() != payload:
                raise ValueError(f"Existing output differs: {cap}")
        else:
            cap.write_bytes(payload)
        record.update(cap=str(cap.relative_to(OUT)), cap_size=len(payload), cap_sha256=sha(payload),
                      capsule_guid=str(uuid.UUID(bytes_le=payload[:16])).upper(),
                      capsule_header_size=struct.unpack_from("<I", payload, 16)[0],
                      capsule_flags=f"0x{struct.unpack_from('<I', payload, 20)[0]:08X}",
                      capsule_declared_size=struct.unpack_from("<I", payload, 24)[0])
        record["capsule_size_matches_header"] = record["capsule_declared_size"] == len(payload)
        print(tag, "ZIP CRC OK", "official match", record["official_zip_hash_match"],
              "CAP", len(payload), "header", record["capsule_header_size"], flush=True)
        dump = cap.with_name(cap.name + ".dump")
        log = target_dir / "uefiextract.log"
        if not (target_dir / "extraction_complete.json").exists():
            if dump.exists():
                raise ValueError(f"Incomplete previous extraction; inspect before retry: {dump}")
            with log.open("w", encoding="utf-8") as stream:
                p = subprocess.run([str(EXTRACTOR), str(cap), "all"], stdout=stream,
                                   stderr=subprocess.STDOUT, check=False, timeout=240)
            record["extractor_exit_code"] = p.returncode
            if p.returncode != 0:
                raise RuntimeError(f"UEFIExtract returned {p.returncode}; see {log}")
            (target_dir / "extraction_complete.json").write_text(
                json.dumps({"cap_sha256": sha(payload), "exit_code": p.returncode}), encoding="utf-8")
        else:
            done = json.loads((target_dir / "extraction_complete.json").read_text())
            if done["cap_sha256"] != sha(payload):
                raise ValueError("Extraction marker does not match source")
            record["extractor_exit_code"] = done["exit_code"]
        result[tag] = record
        save("packages.json", result)
        print(tag, "extraction complete", flush=True)


INTEREST = re.compile(r"ipmi|bmc|aspeed|asmb|sensor|hwm|fan|nct67|super.?io|servermgmt|redfish|vroc|raid|secure.?boot|tpm|tcg|microcode|bios.?version|pro.?ws|build.?date", re.I)
CATEGORIES = {
    "ipmi_bmc": re.compile(r"ipmi|bmc|aspeed|asmb|servermgmt|redfish|^rf[A-Z]|^RemoteFWConfiguration|sel(?:log|event)|(?:pei|dxe|smm)sel", re.I),
    "monitor_fan_sio": re.compile(r"sensor|hwm|fan|nct|super.?io|^sio|asus.?ec|^ec(?:smm|dxe)", re.I),
    "storage": re.compile(r"vroc|raid|sata|nvme|ahci|vmd", re.I),
    "security": re.compile(r"secure.?boot|tcg|tpm|measured|trusted|boot.?guard|security|authenticate", re.I),
    "network": re.compile(r"network|undi|pxe|ip[46]|tcp|udp|http|dhcp|snp|mnp|dns|tls|iscs|vlan", re.I),
}


def strings(data):
    yield from (x.group().decode("ascii") for x in re.finditer(rb"[ -~]{6,}", data))
    yield from (x.group().decode("utf-16-le") for x in re.finditer(rb"(?:[ -~]\x00){6,}", data))


def intel_regions(data, header_size):
    spi = data[header_size:]
    if spi[16:20] != bytes.fromhex("5aa5f00f"):
        return {"signature_ok": False}
    flmap0 = struct.unpack_from("<I", spi, 0x14)[0]
    frba = ((flmap0 >> 16) & 0xFF) * 16
    names = {0: "Descriptor", 1: "BIOS", 2: "ME", 3: "GbE", 4: "Platform Data", 8: "EC", 9: "Device Expansion 2"}
    regions = []
    for n in range(16):
        v = struct.unpack_from("<I", spi, frba + n * 4)[0]
        base = (v & 0x7FFF) << 12
        end = (((v >> 16) & 0x7FFF) + 1) << 12
        # Unallocated entries are zero or have base > limit.
        if (n and v == 0) or base >= end or end > len(spi):
            continue
        regions.append({"index": n, "name": names.get(n, f"Region {n}"), "raw_flreg": f"0x{v:08X}",
                        "spi_start": f"0x{base:08X}", "spi_end_exclusive": f"0x{end:08X}",
                        "cap_start": f"0x{base+header_size:08X}", "size": end-base,
                        "sha256": sha(spi[base:end]), "all_ff": spi.count(b"\xff", base, end) == end-base})
    return {"signature_ok": True, "flmap0": f"0x{flmap0:08X}", "frba": f"0x{frba:X}", "regions": regions}


def inventory_one(tag, package, guid_db):
    cap = OUT / package["cap"]
    dump = cap.with_name(cap.name + ".dump")
    infos = {}
    for p in sorted(dump.rglob("info.txt")):
        txt = p.read_text(encoding="utf-8", errors="replace")
        parsed = {}
        for key, value in re.findall(r"^([^:\r\n]+): ?([^\r\n]*)", txt, re.M):
            # UEFIExtract repeats Type: first the tree node kind, then a numeric FFS/section code.
            if key in parsed:
                parsed[key + " (numeric)"] = value
            else:
                parsed[key] = value
        infos[p.parent] = parsed
    file_dirs = {d for d, info in infos.items() if info.get("Type") == "File" and "File GUID" in info}
    if len(file_dirs) < 100:
        raise ValueError(f"Implausibly low FFS count for {tag}: {len(file_dirs)}")
    section_owners = defaultdict(list)
    for d, inf in infos.items():
        if inf.get("Type") == "Section":
            owner = next((p for p in d.parents if p in file_dirs), None)
            if owner:
                section_owners[owner].append(d)
    modules = []
    for d in sorted(file_dirs):
        inf = infos[d]
        header = (d / "header.bin").read_bytes() if (d / "header.bin").exists() else b""
        body = (d / "body.bin").read_bytes() if (d / "body.bin").exists() else b""
        module = {"guid": inf["File GUID"], "type": inf.get("Subtype"), "size": len(header)+len(body),
                  "sha256": sha(header+body), "ui": [], "sections": [], "strings": [],
                  "path": str(d.relative_to(OUT)), "info": inf}
        evidence = set()
        for sd in section_owners[d]:
            si = infos[sd]
            kind = si.get("Subtype", "")
            bp = sd / "body.bin"
            if not bp.exists():
                continue
            if kind in ("Compressed", "Compression", "GUID defined"):
                continue
            b = bp.read_bytes()
            if kind == "User interface":
                module["ui"].append(b.decode("utf-16-le", errors="replace").rstrip("\0"))
            sec = {"type": kind, "size": len(b), "sha256": sha(b), "path": str(bp.relative_to(OUT))}
            if "dependency" in kind:
                sec["hex"] = b.hex()
            module["sections"].append(sec)
            if kind in ("PE32 image", "TE image", "Raw", "User interface", "Version"):
                evidence.update(s for s in strings(b) if INTEREST.search(s) or ".pdb" in s.lower())
        module["name"] = ";".join(module["ui"]) or guid_db.get(module["guid"].upper(), "")
        module["name_source"] = "embedded UI" if module["ui"] else "GUID database" if module["name"] else "unnamed"
        module["strings"] = sorted(evidence)
        module["categories"] = [name for name, pat in CATEGORIES.items() if pat.search(module["name"])]
        modules.append(module)
    nodes = []
    for d, inf in infos.items():
        if inf.get("Type") in ("Region", "Intel microcode", "Volume", "NVAR entry", "CPD partition"):
            node = {"path": str(d.relative_to(OUT)), "info": inf}
            bp = d / "body.bin"
            if bp.exists() and inf.get("Type") in ("Intel microcode", "NVAR entry"):
                b = bp.read_bytes()
                node.update(body_size=len(b), sha256=sha(b))
                if inf.get("Type") == "Intel microcode":
                    # UEFIExtract writes microcode header and payload separately.
                    hp = d / "header.bin"
                    raw = (hp.read_bytes() if hp.exists() else b"") + b
                    node["full_sha256"] = sha(raw)
                    node["dword_checksum_ok"] = len(raw) % 4 == 0 and (sum(struct.unpack(f"<{len(raw)//4}I", raw)) & 0xFFFFFFFF) == 0
                    node["full_bytes"] = len(raw)
            nodes.append(node)
    raw = cap.read_bytes()
    identities = sorted(set(s for s in strings(raw[-0x100000:]) if re.search(r"ASUS|Pro.?WS|20\d\d|\d\d/\d\d/\d{4}", s)))
    log = (OUT / tag / "uefiextract.log").read_text(errors="replace")
    warnings = dict(Counter(x for x in log.splitlines() if "::" in x))
    result = {"package": package, "descriptor": intel_regions(raw, package["capsule_header_size"]),
              "module_count": len(modules), "unique_guids": len({m["guid"] for m in modules}),
              "file_types": dict(Counter(m["type"] for m in modules)), "modules": modules,
              "category_counts": {cat: sum(cat in m["categories"] for m in modules) for cat in CATEGORIES},
              "nodes": nodes, "trailing_identity_strings": identities, "parser_messages": warnings}
    save(f"{tag}/inventory.json", result)
    print(tag, "files", len(modules), "unique GUIDs", result["unique_guids"], result["category_counts"], flush=True)
    print("ME", [(n["info"].get("Version"), n["info"].get("Full size")) for n in nodes
                 if n["info"].get("Type") == "Region" and n["info"].get("Subtype") == "ME"], flush=True)
    return result


def compare_pair(left, right):
    a, b = left["modules"], right["modules"]
    groups = defaultdict(list)
    for m in b:
        groups[m["guid"]].append(m)
    rows, pending = [], []
    for m in a:
        match = next((q for q in groups[m["guid"]] if q["sha256"] == m["sha256"]), None)
        if match:
            groups[m["guid"]].remove(match)
            rows.append({"status": "identical", "guid": m["guid"], "name": m["name"],
                         "left_path": m["path"], "right_path": match["path"]})
        else:
            pending.append(m)
    for m in pending:
        candidates = groups[m["guid"]]
        match = candidates.pop(0) if candidates else None
        row = {"status": "changed" if match else "left_only", "guid": m["guid"], "name": m["name"],
               "left_path": m["path"], "right_path": match["path"] if match else ""}
        if match:
            pe1 = [(s["type"], s["sha256"]) for s in m["sections"] if s["type"] in ("PE32 image", "TE image")]
            pe2 = [(s["type"], s["sha256"]) for s in match["sections"] if s["type"] in ("PE32 image", "TE image")]
            row["executable_sections_identical"] = bool(pe1) and pe1 == pe2
        rows.append(row)
    for rest in groups.values():
        for m in rest:
            rows.append({"status": "right_only", "guid": m["guid"], "name": m["name"],
                         "left_path": "", "right_path": m["path"]})
    return {"counts": dict(Counter(x["status"] for x in rows)), "rows": rows,
            "changed_with_identical_executables": sum(x.get("executable_sections_identical", False) for x in rows)}


def inventory():
    packages = json.loads((OUT / "packages.json").read_text())
    db = {r[0].upper(): r[1] for r in csv.reader((ROOT / "analysis/uefitool_guids.csv").open(encoding="utf-8")) if len(r) > 1}
    results = {tag: inventory_one(tag, package, db) for tag, package in packages.items()}
    comparisons = {}
    for a, b in (("W790_SAGE_2003", "W790_ACE_2003"), ("W790_SAGE_2003", "W890_SAGE_0603"), ("W790_ACE_2003", "W890_SAGE_0603")):
        comparisons[a + "__vs__" + b] = compare_pair(results[a], results[b])
    save("comparisons.json", comparisons)
    summary = {tag: {k: v for k, v in data.items() if k not in ("modules", "nodes")} for tag, data in results.items()}
    for tag, data in results.items():
        summary[tag]["microcodes"] = [n for n in data["nodes"] if n["info"]["Type"] == "Intel microcode"]
        summary[tag]["me_regions"] = [n for n in data["nodes"] if n["info"]["Type"] == "Region" and n["info"].get("Subtype") == "ME"]
        summary[tag]["ipmi_bmc_modules"] = [{k:m[k] for k in ("name", "guid", "size", "sha256", "path")} for m in data["modules"] if "ipmi_bmc" in m["categories"]]
    save("summary.json", summary)
    with (OUT / "modules.tsv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["image", "name", "guid", "type", "bytes", "sha256", "categories", "path"])
        for tag, data in results.items():
            for m in data["modules"]:
                w.writerow([tag, m["name"], m["guid"], m["type"], m["size"], m["sha256"], ";".join(m["categories"]), m["path"]])
    for key, data in comparisons.items():
        print(key, data["counts"], "changed but same PE", data["changed_with_identical_executables"], flush=True)


def details():
    all_details = {}
    for tag in INPUTS:
        inv = json.loads((OUT / tag / "inventory.json").read_text(encoding="utf-8"))
        structs = {}
        for guid, output_name in (("AB017B39-014F-4A69-A457-7E16B09DE825", "embedded_setup_structures.h"),
                                  ("E013E1CF-82DC-4CC6-8369-1C32C0047346", "embedded_server_structures.h")):
            m = next(x for x in inv["modules"] if x["guid"] == guid)
            raw = next(s for s in m["sections"] if s["type"] == "Raw")
            b = (OUT / raw["path"]).read_bytes()
            (OUT / tag / output_name).write_bytes(b)
            for body, name in re.findall(r"typedef\s+struct\s*\{([^{}]*)\}\s*(\w+)\s*;", b.decode("ascii")):
                if name not in ("SETUP_DATA", "SERVER_MGMT_CONFIGURATION_DATA", "ASUS_QFAN_SETUP_DATA", "ASUS_HWM_SETUP_ONEOF"):
                    continue
                offset, fields, unparsed = 0, [], []
                for line in body.splitlines():
                    line = line.split("//", 1)[0].strip()
                    if not line:
                        continue
                    v = re.fullmatch(r"(U?INT(?:8|16|32|64)|CHAR(?:8|16))\s+(\w+)((?:\[\d+\])*)\s*;", line)
                    if not v:
                        unparsed.append(line)
                        continue
                    size = int(re.search(r"\d+", v[1])[0]) // 8
                    for count in re.findall(r"\[(\d+)\]", v[3]):
                        size *= int(count)
                    fields.append({"name": v[2], "type": v[1] + v[3], "offset": offset, "size": size})
                    offset += size
                entry = {"packed_size": offset if not unparsed else None, "fields": fields,
                         "unparsed": unparsed, "source_file": output_name,
                         "packing_note": "Sequential packed offsets; checked against embedded NVAR/default size where available."}
                if name in structs and structs[name]["fields"] != entry["fields"]:
                    raise ValueError(f"Conflicting schema for {tag} {name}")
                structs[name] = entry
        variables = []
        for n in inv["nodes"]:
            inf = n["info"]
            if inf["Type"] == "NVAR entry" and inf.get("Text") in ("Setup", "ServerSetup", "AsusQFanSetupData", "AsusHwmSetupOneof"):
                schema = {"Setup": "SETUP_DATA", "ServerSetup": "SERVER_MGMT_CONFIGURATION_DATA",
                          "AsusQFanSetupData": "ASUS_QFAN_SETUP_DATA", "AsusHwmSetupOneof": "ASUS_HWM_SETUP_ONEOF"}[inf["Text"]]
                variables.append({"name": inf["Text"], "guid": inf.get("Variable GUID"), "bytes": n.get("body_size"),
                                  "path": n["path"], "schema": schema,
                                  "matches_packed_schema": n.get("body_size") == structs.get(schema, {}).get("packed_size")})
        # Find IFR VARSTORE opcodes by their known variable GUID; validate length, id, size and name.
        ifr_varstores = []
        known_guids = {v["guid"] for v in variables if v["guid"]}
        for m in inv["modules"]:
            if m["name"] not in ("Setup", "ServerMgmtSetup"):
                continue
            for s in m["sections"]:
                if s["type"] != "PE32 image":
                    continue
                b = (OUT / s["path"]).read_bytes()
                for guid in known_guids:
                    needle = uuid.UUID(guid).bytes_le
                    pos = -1
                    while (pos := b.find(needle, pos+1)) >= 0:
                        off = pos-2
                        if off < 0 or b[off] != 0x24:
                            continue
                        length = b[off+1] & 0x7F
                        if length < 23 or off+length > len(b):
                            continue
                        var_id, size = struct.unpack_from("<HH", b, off+18)
                        name = b[off+22:off+length].split(b"\0", 1)[0].decode("ascii", errors="replace")
                        if name not in ("Setup", "ServerSetup", "AsusQFanSetupData", "AsusHwmSetupOneof"):
                            continue
                        ifr_varstores.append({"module": m["name"], "section_path": s["path"], "section_offset": off,
                                              "var_id": var_id, "guid": guid, "size": size, "name": name})
        security = [{"name": m["name"], "guid": m["guid"], "size": m["size"]} for m in inv["modules"]
                    if "security" in m["categories"]]
        all_details[tag] = {"schemas": structs, "variables": variables, "ifr_varstores": ifr_varstores,
                            "security_modules": security,
                            "executable_ffs_count": sum(any(s["type"] in ("PE32 image", "TE image") for s in m["sections"]) for m in inv["modules"]),
                            "pad_ffs_count": sum(m["type"] == "Pad" for m in inv["modules"])}
        print(tag, "schemas", {k: v["packed_size"] for k,v in structs.items()},
              "IFR", [(v["name"], v["size"]) for v in ifr_varstores], flush=True)
    save("details.json", all_details)


def cpd_manifests(data):
    # CPD_REV1/2_HEADER, CPD_ENTRY and CPD_MANIFEST_HEADER layouts follow
    # https://github.com/LongSoft/UEFITool/blob/new_engine/common/ffs.h
    result = []
    for hit in re.finditer(re.escape(b"$CPD"), data):
        base = hit.start()
        if base + 20 > len(data):
            continue
        count = struct.unpack_from("<I", data, base+4)[0]
        hlen = data[base+10]
        if data[base+8] not in (1, 2) or hlen not in (16, 20) or not 0 < count < 256:
            continue
        if base + hlen + count*24 > len(data):
            continue
        for i in range(count):
            ent = base + hlen + i*24
            name = data[ent:ent+12].split(b"\0", 1)[0]
            if not name.endswith(b".man"):
                continue
            pos = base + (struct.unpack_from("<I", data, ent+12)[0] & 0x1FFFFFF)
            length = struct.unpack_from("<I", data, ent+16)[0]
            if pos+max(length, 48) > len(data) or data[pos+28:pos+32] != b"$MN2":
                continue
            vendor = struct.unpack_from("<I", data, pos+16)[0]
            version = ".".join(map(str, struct.unpack_from("<4H", data, pos+36)))
            result.append({"partition": data[base+12:base+16].rstrip(b"\0").decode("ascii", errors="replace"),
                           "name": name.decode("ascii"), "manifest_offset": pos, "length": length,
                           "vendor": f"0x{vendor:X}", "version": version,
                           "svn": struct.unpack_from("<I", data, pos+44)[0]})
    return result


def extended():
    result = {}
    for tag in INPUTS:
        inv = json.loads((OUT / tag / "inventory.json").read_text(encoding="utf-8"))
        cap = (OUT / inv["package"]["cap"]).read_bytes()
        ext = next(r for r in inv["descriptor"]["regions"] if r["index"] == 9)
        start = int(ext["cap_start"], 16)
        data = cap[start:start+ext["size"]]
        entry = {"region_all_ff": ext["all_ff"], "region_sha256": sha(data)}
        if not ext["all_ff"]:
            first = re.search(rb"[^\xff]", data).start()
            length = int.from_bytes(data[first+20:first+23], "little")
            ffs = data[first:first+length]
            if len(ffs) != length or ffs[18] != 2:
                raise ValueError("Unexpected extension FFS header")
            header_check = (sum(ffs[:24]) - ffs[17] - ffs[23]) & 255
            section = ffs[24:]
            section_length = int.from_bytes(section[:3], "little")
            compression_guid = str(uuid.UUID(bytes_le=section[4:20])).upper()
            if header_check or section_length != len(section) or section[3] != 2 or compression_guid != "EE4E5898-3914-4259-9D6E-DC7BD79403CF":
                raise ValueError("Unexpected extension section structure")
            payload = section[struct.unpack_from("<H", section, 20)[0]:]
            expected = int.from_bytes(payload[5:13], "little")
            if not 0 < expected < 32*1024*1024:
                raise ValueError("Unexpected LZMA expansion size")
            raw = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
            if len(raw) != expected or int.from_bytes(raw[:3], "little") != len(raw) or raw[3] != 0x19:
                raise ValueError("Invalid expanded raw section")
            output = "W790_common_ME_update.bin"
            if (OUT / output).exists() and (OUT / output).read_bytes() != raw[4:]:
                raise ValueError("W790 ME update payloads differ")
            (OUT / output).write_bytes(raw[4:])
            entry.update(cap_offset=f"0x{start+first:X}", spi_offset=f"0x{start+first-4096:X}",
                         ffs_guid=str(uuid.UUID(bytes_le=ffs[:16])).upper(), ffs_size=length,
                         ffs_header_checksum_valid=True, ffs_sha256=sha(ffs), compression_guid=compression_guid,
                         raw_section_size=len(raw), update_payload_size=len(raw)-4,
                         update_payload_sha256=sha(raw[4:]), output=output,
                         manifests=cpd_manifests(raw[4:]))
        if tag == "W890_SAGE_0603":
            standalone = OUT / tag / "MeFwUpdate_19.10.6.1494_Coporate.bin"
            b = standalone.read_bytes()
            entry["standalone_me_update"] = {"path": str(standalone.relative_to(OUT)), "size": len(b),
                                             "sha256": sha(b), "manifests": cpd_manifests(b)}
        me = next(r for r in inv["descriptor"]["regions"] if r["index"] == 2)
        mstart = int(me["cap_start"], 16)
        entry["spi_me_manifests"] = cpd_manifests(cap[mstart:mstart+me["size"]])
        result[tag] = entry
        print(tag, "extension empty", entry["region_all_ff"], "SPI ME versions",
              sorted({m["version"] for m in entry["spi_me_manifests"] if m["partition"] in ("FTPR", "NFTP", "RBEP")}), flush=True)
    save("extended_regions.json", result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["extract", "inventory", "details", "extended"])
    args = parser.parse_args()
    {"extract": extract, "inventory": inventory, "details": details, "extended": extended}[args.stage]()
