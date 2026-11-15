"""Static ELF section/symbol/relocation binding for the archived 1.3.13 SPI driver.

This never loads the kernel module or accesses any device. Function offsets are
section-relative ELF coordinates, not a measured BMC runtime address.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
sys.path.insert(0, str(ROOT / "tools/pydeps"))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

def main():
    path = HERE / "host_spi_flash_hw.ko"
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == "b25d0c08d9f5d10d308a7ef8f289f77db014f70a4a9c9eff0dbde2257c171944"
    assert data[:7] == b"\x7fELF\x01\x01\x01"
    shoff = struct.unpack_from("<I", data, 32)[0]
    shsize, shnum, shstr = struct.unpack_from("<HHH", data, 46)
    assert shsize == 40
    raw = [struct.unpack_from("<10I", data, shoff+i*shsize) for i in range(shnum)]
    ns = raw[shstr]
    nb = data[ns[4]:ns[4]+ns[5]]
    sections = []
    for v in raw:
        name = nb[v[0]:].split(b"\0", 1)[0].decode()
        sections.append(dict(zip(("name_index", "type", "flags", "va", "offset", "size", "link", "info", "alignment", "entry_size"), v), name=name))
    syms = []
    st = next(s for s in sections if s["type"] == 2)
    names = sections[st["link"]]
    strings = data[names["offset"]:names["offset"]+names["size"]]
    for p in range(st["offset"], st["offset"]+st["size"], 16):
        n, value, size, info, other, section = struct.unpack_from("<IIIBBH", data, p)
        syms.append(dict(name=strings[n:].split(b"\0", 1)[0].decode(), value=value, size=size, info=info, section=section))
    rels = []
    for s in sections:
        if s["type"] != 9:
            continue
        for p in range(s["offset"], s["offset"]+s["size"], 8):
            offset, info = struct.unpack_from("<II", data, p)
            rels.append(dict(section=s["info"], offset=offset, type=info&255, symbol=syms[info>>8]))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    evidence = []
    # Three local helper boundaries are also independently observed in the
    # Ghidra instruction/function inventory. They have no named ELF symbol.
    functions = [s for s in syms if s["info"]&15 == 2 and s["section"] and s["size"]]
    functions += [dict(name="local_FUN_00010488", section=3, value=0x208, size=0xc0),
                  dict(name="local_FUN_00010548", section=3, value=0x2c8, size=0x11c),
                  dict(name="local_FUN_00010664", section=3, value=0x3e4, size=0x104)]
    for f in functions:
        sec = sections[f["section"]]
        start = sec["offset"]+f["value"]
        rawfn = data[start:start+f["size"]]
        assert len(rawfn) == f["size"]
        selected = [x for x in rels if x["section"] == f["section"] and f["value"] <= x["offset"] < f["value"]+f["size"]]
        ins = [dict(section_offset=hex(x.address), bytes=x.bytes.hex(), instruction=x.mnemonic+" "+x.op_str) for x in md.disasm(rawfn, f["value"])]
        evidence.append(dict(name=f["name"], section=sec["name"], section_offset=hex(f["value"]), file_offset=hex(start), size=f["size"], sha256=hashlib.sha256(rawfn).hexdigest(), relocations=selected, instructions=ins))
    out = dict(status="STATIC_NATIVE_BINDINGS_ONLY_NO_DEVICE_OR_MODULE_EXECUTION", source=dict(path=path.relative_to(ROOT).as_posix(), sha256=hashlib.sha256(data).hexdigest()), sections=sections, functions=evidence,
               limits=["ET_REL instructions require their recorded relocations at load time; raw branch immediates alone are not runtime targets.", "Ghidra default section bases are analysis coordinates, not live BMC addresses."])
    target = HERE / "kernel_native_evidence.json"
    target.write_text(json.dumps(out, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(dict(functions=len(evidence), path=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest())))

if __name__ == "__main__":
    main()
