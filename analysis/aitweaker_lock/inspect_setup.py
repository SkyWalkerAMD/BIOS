"""Inspect original setup resources and code without altering any firmware."""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent.parent
PREVIOUS = ROOT / "analysis/workstation_20261008"
TAGS = ["W790_SAGE_2003", "W790_ACE_2003", "W890_SAGE_0603"]
sys.path.insert(0, str(ROOT / "tools/pydeps"))


def get_module(tag, name):
    inv = json.loads((PREVIOUS / tag / "inventory.json").read_text(encoding="utf-8"))
    m = next(m for m in inv["modules"] if m["name"] == name)
    s = next(s for s in m["sections"] if s["type"] == "PE32 image")
    data = (PREVIOUS / s["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == s["sha256"]
    return m, s, data


def read_ucs2(data, pos, end):
    start = pos
    while pos + 2 <= end:
        if data[pos:pos+2] == b"\0\0":
            return data[start:pos].decode("utf-16-le"), pos+2
        pos += 2
    raise ValueError("Unterminated UCS2 string")


def string_packages(data):
    packages = []
    for hit in re.finditer(b"en-US\0", data):
        base = hit.start() - 46
        if base < 0:
            continue
        value, hlen, soff = struct.unpack_from("<III", data, base)
        length = value & 0xFFFFFF
        if value >> 24 != 4 or hlen != soff or not 46 < soff < length or base+length > len(data):
            continue
        pos, end, token, strings, offsets = base+soff, base+length, 1, {}, {}
        while pos < end:
            begin = pos
            block = data[pos]
            pos += 1
            if block == 0:
                break
            if block in (0x14, 0x15, 0x16, 0x17):
                if block in (0x15, 0x17):
                    pos += 1
                count = 1
                if block in (0x16, 0x17):
                    count = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                for _ in range(count):
                    offsets[token] = pos
                    strings[token], pos = read_ucs2(data, pos, end)
                    token += 1
            elif block == 0x20:
                original = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                strings[token], offsets[token] = strings[original], offsets[original]
                token += 1
            elif block in (0x21, 0x22):
                width = 2 if block == 0x21 else 1
                token += int.from_bytes(data[pos:pos+width], "little")
                pos += width
            elif block in (0x30, 0x31, 0x32, 0x40):
                width = {0x30:1, 0x31:2, 0x32:4, 0x40:2}[block]
                block_length = int.from_bytes(data[begin+2:begin+2+width], "little")
                if block_length < 2+width:
                    raise ValueError("Invalid extended string block")
                pos = begin + block_length
            else:
                raise ValueError(f"Unsupported string block {block:#x} at {begin:#x}")
        if pos != end:
            raise ValueError(f"String package end mismatch {pos:#x} != {end:#x}")
        packages.append({"offset": base, "length": length, "strings": strings, "offsets": offsets})
    return packages


def strings_stage():
    findings = {}
    for tag in TAGS:
        folder = OUT / tag
        folder.mkdir(exist_ok=True)
        findings[tag] = {}
        for name in ("Setup", "AMITSE", "PasswordSupport"):
            m, s, b = get_module(tag, name)
            packages = string_packages(b)
            (folder / (name + "_en_us.json")).write_text(json.dumps(packages, ensure_ascii=False, indent=2), encoding="utf-8")
            relevant = []
            for pack in packages:
                for token, value in pack["strings"].items():
                    if re.search(r"Ai.?Tweaker|^(Enter|Create|Confirm).{0,30}Password|^Invalid Password$", value, re.I):
                        relevant.append({"token": token, "offset": pack["offsets"][token], "text": value})
            findings[tag][name] = {"guid":m["guid"], "section_path": s["path"], "sha256":s["sha256"], "strings":relevant}
            print(tag, name, [(hex(x["token"]), x["text"]) for x in relevant], flush=True)
    (OUT / "string_findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")


def disassemble_stage():
    import capstone
    import pefile
    findings = json.loads((OUT / "string_findings.json").read_text(encoding="utf-8"))
    result = {}
    for tag in TAGS:
        _, _, data = get_module(tag, "AMITSE")
        pe = pefile.PE(data=data)
        base = pe.OPTIONAL_HEADER.ImageBase
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail, md.skipdata = True, True
        token = next(x["token"] for x in findings[tag]["AMITSE"]["strings"] if x["text"] == "Enter AiTweaker Password")
        matches, lines = [], []
        for section in pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            code = section.get_data()
            for ins in md.disasm(code, base+section.VirtualAddress):
                lines.append(f"{ins.address-base:08x}: {ins.bytes.hex():30} {ins.mnemonic:8} {ins.op_str}")
                if ins.id and any(o.type == capstone.x86.X86_OP_IMM and o.imm == token for o in ins.operands):
                    matches.append({"rva": ins.address-base, "file_offset":pe.get_offset_from_rva(ins.address-base),
                                    "instruction":ins.mnemonic+" "+ins.op_str})
        (OUT / tag / "AMITSE_disassembly.txt").write_text("\n".join(lines), encoding="utf-8")
        result[tag] = {"image_base":base, "password_string_token":token, "token_immediate_matches":matches,
                       "sections":[{"name":s.Name.rstrip(b'\0').decode(), "rva":s.VirtualAddress, "file_offset":s.PointerToRawData, "raw_size":s.SizeOfRawData, "virtual_size":s.Misc_VirtualSize} for s in pe.sections]}
        print(tag, "AiTweaker token",hex(token),"candidate code references",matches, flush=True)
    (OUT / "code_findings.json").write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    {"strings":strings_stage, "disassemble":disassemble_stage}[sys.argv[1]]()
