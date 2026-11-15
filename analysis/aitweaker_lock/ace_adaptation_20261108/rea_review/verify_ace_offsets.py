"""Independent original-byte corroboration; ordinary PE/Capstone, not REA."""
from pathlib import Path
import hashlib
import json
import struct
import sys

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

ACE = ROOT / "analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi"
SAGE = ROOT / "analysis/aitweaker_lock/lock_sage_1904/analysis/modules/AMITSE.efi"
assert hashlib.sha256(ACE.read_bytes()).hexdigest() == "99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5"
assert hashlib.sha256(SAGE.read_bytes()).hexdigest() == "531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1"
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
images = {name: pefile.PE(str(path)).get_memory_mapped_image() for name, path in (("ace", ACE), ("sage", SAGE))}


def instructions(name, start, end):
    return list(md.disasm(images[name][start:end], start))


def normalize(ins):
    operands = []
    for op in ins.operands:
        if op.type == X86_OP_REG:
            operands.append(("reg", ins.reg_name(op.reg), op.size))
        elif op.type == X86_OP_IMM:
            value = "relative-code-target" if ins.mnemonic == "call" or ins.mnemonic.startswith("j") else op.imm
            operands.append(("imm", value, op.size))
        elif op.type == X86_OP_MEM:
            m = op.mem
            disp = "rip-target" if m.base == X86_REG_RIP else m.disp
            operands.append(("mem", ins.reg_name(m.base), ins.reg_name(m.index), m.scale, disp, op.size))
    return ins.mnemonic, operands


pairs = [("history_parent", 0x1017c, 0x10270, 0x1012c),
         ("history_append", 0x10270, 0x104b0, 0x10220),
         ("key_decoder_stub", 0x5cb0, 0x5d3c, 0x5c60),
         ("page_leave_stub", 0x322b4, 0x32484, 0x32264),
         ("form_notification_stub", 0x329cc, 0x32adc, 0x3297c),
         ("page_input", 0x16c70, 0x17224, 0x16c20),
         ("navigation_dispatch", 0x62bc, 0x6348, 0x626c)]
records = []
for label, start, end, reference in pairs:
    ace = instructions("ace", start, end)
    sage = instructions("sage", reference, reference + end - start)
    body = []
    calls = []
    refs = []
    for ins in ace:
        body.append(f"{ins.address:08x} {ins.bytes.hex():<30} {ins.mnemonic:8} {ins.op_str}")
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                refs.append({"instruction": hex(ins.address), "target": hex(ins.address + ins.size + op.mem.disp)})
            if ins.mnemonic == "call" and op.type == X86_OP_IMM:
                calls.append({"instruction": hex(ins.address), "target": hex(op.imm)})
    (OUT / f"original-ace-{label}.asm.txt").write_text("\n".join(body) + "\n", encoding="utf-8")
    records.append({"label": label, "ace_start": hex(start), "ace_end_exclusive": hex(end),
                    "sage_start": hex(reference), "ace_bytes_sha256": hashlib.sha256(images["ace"][start:end]).hexdigest(),
                    "ace_instruction_count": len(ace), "sage_instruction_count": len(sage),
                    "same_normalized_instruction_sequence": [normalize(x) for x in ace] == [normalize(x) for x in sage],
                    "direct_calls": calls, "rip_references": refs})

text = next(s for s in pefile.PE(str(ACE)).sections if s.Name.rstrip(b"\0") == b".text")
formset_xrefs = []
for ins in instructions("ace", text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize):
    for op in ins.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and ins.address + ins.size + op.mem.disp == 0x92268:
            formset_xrefs.append({"instruction": hex(ins.address), "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic, "operands": ins.op_str})
pointer = struct.unpack_from("<Q", images["ace"], 0x6af80)[0]
assert pointer == 0x16c70
assert formset_xrefs
assert all(record["same_normalized_instruction_sequence"] for record in records)
page_input = next(record for record in records if record["label"] == "page_input")
page_calls = {(int(ref["instruction"], 16), int(ref["target"], 16)) for ref in page_input["direct_calls"]}
assert {(0x16e56, 0x5cb0), (0x16ef8, 0x322b4), (0x17201, 0x329cc),
        (0x1701c, 0x62bc), (0x17054, 0x10270), (0x16eb8, 0x1017c)} <= page_calls
assert any(ref["instruction"] == "0x16fe8" for ref in formset_xrefs)
report = {
    "status": "PASS",
    "classification": "STATIC_ORIGINAL_BYTE_CORROBORATION_NOT_REA_NOT_HARDWARE_EXECUTION",
    "ace_sha256": hashlib.sha256(ACE.read_bytes()).hexdigest(),
    "sage_sha256": hashlib.sha256(SAGE.read_bytes()).hexdigest(),
    "capstone_version": __import__("capstone").__version__, "pefile_version": pefile.__version__,
    "pairs": records,
    "page_input_slot": {"rva": "0x6af80", "value": hex(pointer), "expected_function": "0x16c70"},
    "formset_table_slot": {"rva": "0x92268", "rip_relative_references": formset_xrefs},
    "limitations": ["Normalized comparison ignores RIP-relative displacements and relative call/jump target immediates; every used target needs independent identity verification.",
                    "Ranges are analyst-selected original-byte spans; equality is correspondence evidence, not a complete control-flow or runtime equivalence proof.",
                    "The key decoder, page-leave, and notification functions remain explicit stubs in the proposed history regression."]
}
(OUT / "original_byte_offset_review.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"pairs": [{k: x[k] for k in ("label", "ace_start", "sage_start", "same_normalized_instruction_sequence")} for x in records],
                  "page_input_slot": report["page_input_slot"], "formset_table_references": len(formset_xrefs)}, indent=2))
