"""Static ACE1904 update-range review; no hardware, network, signing or image edits."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import struct
import sys
import uuid

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
REF = OUT.parent
BASE = REF.parent
ROOT = BASE.parents[3]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ident(p):
    data = p.read_bytes()
    return {"path": p.relative_to(ROOT).as_posix(), "bytes": len(data), "sha256": sha(data)}


def save(name, obj):
    p = OUT / name
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return ident(p)


def source_ref(p, token, elf_va=None):
    text = p.read_text(encoding="utf-8")
    assert token in text, (p, token)
    return {**ident(p), "line": text[:text.index(token)].count("\n") + 1,
            "token": token, **({"elf_va": elf_va} if elf_va else {})}


spec = importlib.util.spec_from_file_location("ann_readonly", REF / "annotate_bmc1313.py")
ann = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ann)
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

pdk = REF / "bmc1313_inputs/usr/local/lib/libpdkapp.so.13.2.0"
elf = ann.Elf32(pdk)
inv = json.loads((REF / "preservation_pdk_decompile/function_inventory.json").read_text(encoding="utf-8"))
assert inv["executable_sha256"] == sha(elf.data) == "afb0816890841a0bf6c4edaea734242a8cb04bc7c6fff11177d83decb8b1c98d"
symbols = {s["name"]: s for s in elf.symbols if s["section_index"] and s["info"] & 15 == 2}
native = {"binary": ident(pdk), "method": "Targeted actual ARM ELF Ghidra decompilation plus independent ELF relocation/literal and Capstone instruction binding. Not REA: the installed REA provider rejects ARM ELF.", "functions": {}}
for f in inv["functions"]:
    if not f.get("pseudocode_file") or f["name"] not in symbols:
        continue
    s = symbols[f["name"]]
    assert int(f["address"], 16) - s["va"] == 0x10000
    cp = REF / "preservation_pdk_decompile" / f["pseudocode_file"]
    code = cp.read_text(encoding="utf-8")
    literals = {a: elf.literal(int(a, 16) - 0x10000) for a in sorted(set(re.findall(r"(?:DAT_|PTR_)([0-9a-fA-F]{8})", code)))}
    data = elf.data[elf.offset(s["va"], s["size"]):][:s["size"]]
    rows = []
    for i in Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(data, s["va"]):
        row = {"elf_va": hex(i.address), "bytes": i.bytes.hex(), "instruction": i.mnemonic + " " + i.op_str}
        if i.mnemonic in ("bl", "blx") and i.op_str.startswith("#"):
            row["target_name"] = elf.names.get(int(i.op_str[1:], 0))
        rows.append(row)
    ap = OUT / cp.name
    ap.write_text("/* Actual ELF literal annotations; Ghidra address bias 0x10000.\n" + json.dumps(literals, indent=2) + "\n*/\n" + code, encoding="utf-8")
    native["functions"][f["name"]] = {"elf_va": hex(s["va"]), "bytes": len(data), "bytes_sha256": sha(data), "decompile": ident(cp), "annotated": ident(ap), "instructions": rows, "literals": literals}
native_id = save("native_pdk_evidence.json", native)

caps = [
    ("official", ROOT / "analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP", "03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29"),
    ("candidate05", BASE / "lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin", "9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455"),
    ("engineering", BASE / "engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP", "e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08"),
]
caps_report = {}
tables, headers = [], []
for name, p, digest in caps:
    data = p.read_bytes()
    assert sha(data) == digest and len(data) == 0x4001000
    payload = data[0x1000:]
    positions = [m.start() for m in re.finditer(re.escape(b"$BOOTEFI$"), payload)]
    assert positions == [0x3ECC75C]
    hp = positions[0]
    header = payload[hp:hp + 0xCB]
    word = lambda off: struct.unpack_from("<I", header, off)[0]
    assert word(0x75) == 0x4000000 and word(0xBB) == 4
    tp = (word(0x75) + word(0xBF)) & 0xFFFFFFFF
    table = payload[tp:tp + word(0xBB) * 9]
    records = []
    for n in range(word(0xBB)):
        block_id, offset, size = struct.unpack_from("<BII", table, n * 9)
        assert offset + size <= len(payload)
        records.append({"id": block_id, "offset": hex(offset), "bytes": size, "end_exclusive": hex(offset + size), "raw_record": table[n * 9:n * 9 + 9].hex()})
    caps_report[name] = {"artifact": ident(p), "payload_sha256": sha(payload), "header_raw_offset": hex(hp), "header_sha256": sha(header), "header_bytes_hex": header.hex(), "table_raw_offset": hex(tp), "table_sha256": sha(table), "records": records,
        "board": header[0xE:0x2C].split(b"\0")[0].decode("ascii"), "version_bytes": list(header[0xC:0xE]),
        "NvramBase_physical": hex(word(0x89)), "Nvram_raw_offset": hex((word(0x89) + word(0x75)) & 0xFFFFFFFF), "Nvram_bytes": word(0x8D),
        "AsusBackup_raw_offset": hex((word(0x9F) + word(0x75)) & 0xFFFFFFFF), "AsusBackup_bytes": word(0xA3)}
    tables.append(table)
    headers.append(header)
assert tables[0] == tables[1] == tables[2] and headers[0] == headers[1] == headers[2]
assert caps_report["candidate05"]["payload_sha256"] == caps_report["engineering"]["payload_sha256"]
cap_id = save("ace1904_nonprogram_table.json", caps_report)

rp = BASE / "lock_1904_candidate05/lab/asus_review/verification/9b038c4eae111a98/20261108_115832/W790-ACE-1904.review.bin.report.txt"
report_text = rp.read_text(encoding="utf-8")
logo_line = next(x for x in report_text.splitlines() if "7BB28B99-61BB-11D5-9A5D-0090273FC14D" in x)
compressed_line = next(x for x in report_text.splitlines() if "AB017B39-014F-4A69-A457-7E16B09DE825" in x)
def report_file(line):
    fields = [f.strip() for f in line.split("|")]
    start, size = int(fields[2], 16) - 0x1000, int(fields[3], 16)
    return {"CAP_report_line": line, "raw_offset": hex(start), "bytes": size, "raw_end_exclusive": hex(start + size)}
logo, compressed = report_file(logo_line), report_file(compressed_line)
assert int(logo["raw_offset"], 16) == 0x313A2F0
assert int(compressed["raw_offset"], 16) < 0x3131000 < 0x3132000 < int(compressed["raw_end_exclusive"], 16)
candidate = caps[1][1].read_bytes()[0x1000:]
for item, guid in [(logo, "7bb28b99-61bb-11d5-9a5d-0090273fc14d"), (compressed, "ab017b39-014f-4a69-a457-7e16b09de825")]:
    off = int(item["raw_offset"], 16)
    assert candidate[off:off + 16] == uuid.UUID(guid).bytes_le
    assert int.from_bytes(candidate[off + 20:off + 23], "little") == item["bytes"]
    item["bytes_sha256"] = sha(candidate[off:off + item["bytes"]])
assert candidate[0x3110000:0x3110008] == b"ASUSSCP$" and candidate[0x3114000:0x3114008] == b"ASUSBKP$"
assert candidate[0x3120000:0x3130000] == b"\xFF" * 0x10000

front = BASE / "bmc_static_readonly/selected_modules/views_maintenance_BIOSUpdateView.js"
ft = front.read_text(encoding="utf-8")
assert "r.SECTION_FLASH=0" in ft and "r.FlashOffset=" in ft and "preserve" not in ft.lower()
sources = {
    "frontend_FlashBIOS": source_ref(front, "FlashBIOS:function()"),
    "frontend_UploadBIOS": source_ref(front, "UploadBIOS:function()"),
    "start": source_ref(REF / "bmc1313_bios_decompile/00013ce4-bios_start_update.c", "bios_start_update(", "0x3ce4"),
    "configuration_wrapper": source_ref(REF / "bmc1313_bios_decompile/00013c30-BiosConfiguration.c", "BiosConfiguration(", "0x3c30"),
    "configuration": source_ref(OUT / "00013e54-PDK_ASUSBIOSConfiguration.c", "PDK_ASUSBIOSConfiguration(", "0x3e54"),
    "header_parse": source_ref(OUT / "0001380c-PDK_GetASUSBIOSInfo.c", "PDK_GetASUSBIOSInfo(", "0x380c"),
    "flash_worker": source_ref(REF / "bmc1313_bios_decompile/000137fc-bios_flash.c", "void bios_flash(", "0x37fc"),
    "contiguous_loop": source_ref(REF / "bmc1313_host_decompile/000115d0-flash_bios_image.c", "flash_bios_image(", "0x15d0"),
    "block_compare_erase_write": source_ref(REF / "bmc1313_host_decompile/00011360-spi_write_erase_block.c", "spi_write_erase_block(", "0x1360"),
    "rest_body_fields": source_ref(REF / "bmc1313_annotated/rest/0012d73c-putBIOSStartFlashMode_func.c", "putBIOSStartFlashMode_func(", "0x12d73c"),
    "extracted_candidate_layout": ident(rp),
}

review = {
    "status": "STATIC_CURRENT_BMC1313_NORMAL_UPDATE_EXTENT_AND_PRESERVATION_REVIEW",
    "scope": "Existing official BMC1.3.13 ELF evidence and live-matching frontend; three additional PDK functions decompiled and bound to actual bytes. No BMC access, programming, image edit or live preservation test.",
    "script": ident(Path(__file__).resolve()), "native_pdk_evidence": native_id, "capsule_header_table_evidence": cap_id, "sources": sources,
    "normal_frontend": {"route": "PUT /api/maintenance/bios/flash", "body_for_this_CAP": {"FWUPDATEID": "the normal active update ID", "COMPONENT_ID": 2, "COMPONENT_DATA_LEN": 67108864, "SECTION_FLASH": 0, "FlashOffset": 0}, "payload_upload": "The ordinary frontend removes the 0x1000 CAP header, then stages all 0x4000000 payload bytes as bios.bin. The signature ROM map is not passed as a write-range list.", "named_preservation_options": [], "BMC_configuration_preserve_flags": "The separate BMC preserve_configuration/Redfish AMI preserve settings are not BIOS SMBIOS/NVRAM selectors in this route."},
    "write_extent": {"raw_interval": "[0x00000000,0x04000000)", "behavior": "bios_start_update uses actual staged file length, subject to a separate optional resident-signature trailer rule; bios_flash invokes flash_bios_image, which reads sequential configured erase blocks and calls spi_write_erase_block for the entire payload. No CAP ROM-map, BIOS-only range or individual FFS filter is present in this loop.", "identical_blocks": "spi_write_erase_block reads and compares every byte. Identical blocks skip erase/write; a differing block is erased with MEMERASE and rewritten. Thus 64MiB is the comparison/eligible extent, not a claim every block is always physically erased.", "erase_geometry": "Uses g_coremacros+0x1c; current live MTD geometry has not been measured by this review."},
    "automatic_preservation": {"mechanism": "BiosConfiguration opens current host MTD and staged bios.bin. PDK_ASUSBIOSConfiguration uses the uploaded candidate header's NonProgramBlock table, copying current MTD bytes to the same offsets in bios.bin before the worker compares and writes.", "table_source": "Candidate $BOOTEFI$ header, not the signed Aptio ROM-map attributes and not a semantic SMBIOS/NVRAM option mask.", "ranges": caps_report["candidate05"]["records"], "conditional_effect": "If the current header is recognized and all reads/copies are correct, the first48MiB and three small listed ranges become equal to current MTD; the low-level comparator then avoids changes to those bytes.", "failure_boundaries": ["Current MTD major/minor both zero returns success without preserving.", "Missing/empty uploaded nonprogram table returns success without preserving.", "The normal source reads and staged writes have unchecked return values. A subsequent readback is compared to the allocated source buffer, not to a separately validated source acquisition. Function success alone is insufficient evidence of correct source-byte preservation.", "The current header and full current firmware were not acquired here. An identical AMITSE/Setup identity does not prove all current ranges or custom firmware modules equal official1904." ]},
    "data_effects": [
        {"item": "Descriptor/ME and other bytes in the raw first48MiB", "result": "Conditionally retained by block ID1, covering all[0,0x03000000). This is a copy-and-compare preservation mechanism, not a hard writer range restriction."},
        {"item": "ASUS SCP/backup data", "result": "Raw[0x03110000,0x03120000) is copied. Official bytes contain ASUSSCP$ at0x03110000 and ASUSBKP$ at0x03114000; header AsusBackup region[0x03114000,0x03118000) lies inside. Existing custom content in that interval is conditionally retained."},
        {"item": "Raw[0x03120000,0x03130000)", "result": "Copied as block ID3. It is allFF in the official candidate; the current machine's contents and semantic data type are unknown."},
        {"item": "SMBIOS identities/serial/UUID or other machine data", "result": "No named SMBIOS preserve option or semantic SMBIOS field migration occurs in this reviewed route. Only bytes lying in the listed intervals are conditionally retained; no blanket claim that every SMBIOS identity or machine-specific datum survives is supported."},
        {"item": "NVRAM/Setup/Boot/password variables", "result": "The candidate header declares physical0xFF010000,size0x80000 => raw[0x03010000,0x03090000). None intersects the NPB ranges, and the extracted image contains factory NVAR records there. This update path does not preserve that NVRAM interval; current variable contents may be replaced/reset. No NVRAM preserve checkbox or request flag is exposed by the normal frontend."},
        {"item": "Custom SHUANG splash/logo module", "result": "No logo-preserve option. The candidate's Logo.bmp FFS is outside all NPB intervals; its different erase blocks remain eligible for replacement with the official candidate bytes. The live SHUANG module's exact location/content was not dumped, so retention cannot be promised.", "candidate_logo": logo},
        {"item": "Other custom BIOS modules or policy changes", "result": "No module merge or per-FFS patching occurs. Nonpreserved differences are replaced by candidate content, even when AMITSE/Setup code and displayed1904 version match."},
    ],
    "partial_ffs_preservation_caveat": {"range": "raw[0x03131000,0x03132000)", "candidate_container": compressed, "finding": "The fourth nonprogram range lies inside an existing compressed Freeform file. Copying differing current bytes here would produce a mixed candidate/current compressed object. No live difference or corruption is asserted; this is why version/module matching cannot establish full image compatibility."},
    "delivery_boundary": "The deliverable is an official1904-based engineered full image with a tested standalone CAP signature. It is not a delta patch of188's SHUANG customized firmware, not a guarantee of retaining all machine-specific data, and not yet a proven complete remote flash/recovery path.",
    "reviewable_before_any_real_update": ["State explicitly that normal update may restore official splash/modules and reset NVRAM; do not silently promise preservation of current custom firmware.", "Bind any later plan to these exact CAP hashes, payload, NPB table and ordinary non-force frontend semantics; the current independent signature acceptance does not exercise this path.", "Record any normally obtained current header/range/backup evidence and its limits. Unknown bytes or cabling stay unknown; neither success status nor a header-only read proves preservation or recovery.", "Do not treat Entry/Prepare/biosversion or full update as a read-only dry-run; their separate documented state/GPIO/driver effects still apply."],
}
result = save("update_preservation_review.json", review)
text = """正常 BIOS 更新覆盖范围与保留边界（ACE1904 / BMC1.3.13，离线静态审查）

正常前端发 COMPONENT_ID=2、COMPONENT_DATA_LEN=67108864、SECTION_FLASH=0、FlashOffset=0，加正常更新 ID。CAP 去掉0x1000头后上传完整64MiB payload。没有 SMBIOS/NVRAM/Logo 保留复选项或对应请求字段；BMC自身的 preserve_configuration 配置不是这些 BIOS 数据的保留开关。

写入端遍历整个 raw[0,0x04000000)，逐擦除块读取并比较。相同块跳过；不同块擦除后写入。CAP签名 ROM map不是写入白名单。不能说只更新适配驱动，也不能说一定擦写全部64MiB。

正常写前按候选 $BOOTEFI$ 的 NonProgramBlock表，把现机同偏移字节复制到暂存 bios.bin：
1. [0x00000000,0x03000000)：48MiB，包含非BIOS前部；
2. [0x03110000,0x03120000)：64KiB，含 ASUSSCP$/ASUSBKP$ 和头声明的 ASUS backup区；
3. [0x03120000,0x03130000)：64KiB，官方镜像为全FF，现机内容语义未取得；
4. [0x03131000,0x03132000)：4KiB，落在现有压缩Freeform文件内部，不能把它称作通用SMBIOS保留。
三份已验签输入的头和此表完全相同。保留依赖正确识别现机头和成功读写；后端有版本为0/缺表时成功跳过，以及源读/暂存写返回值未检查的限制。返回成功不等于已证明保留字节正确。

NVRAM raw[0x03010000,0x03090000)不在保留范围，正常更新可能替换/重置当前Setup、Boot、密码等变量。SMBIOS序号/UUID只能对确实位于上述表范围内的数据谈有条件保留，不能承诺全部机器数据。

候选 Logo.bmp FFS位于raw0x0313A2F0，大小0x1834，不在任何保留范围。未提取现机SHUANG模块，不能承诺保留；普通更新会让不受表保护的定制模块差异被候选官方内容替换。第4个保留区若与现机压缩对象有差异还会混入旧片段，不能用1904版本相同或AMITSE/Setup相同来替代整片比较。

准确交付表述：官方1904基础的完整工程镜像，已通过当前独立CAP验签；不是对188现有SHUANG整片固件的局部补丁，不保证保留全部定制/机器数据，也尚未完成正常远程刷写及恢复验收。未连接BMC、未写flash、未改任何镜像。

精确函数/源码行/ELF字节证据和三个CAP身份见 update_preservation_review.json、native_pdk_evidence.json、ace1904_nonprogram_table.json。
"""
(OUT / "README-preservation.txt").write_text(text, encoding="utf-8")
print(json.dumps({"review": result, "readme": ident(OUT / "README-preservation.txt"), "table": cap_id, "native": native_id}))
