"""Independent bounded review of ACE HISTORY02, with additional edge cases.

Reads the main adapter's fixture definitions only; writes no production or main
test artifacts. OEM history declarations are corroborated from original PE bytes.
The compiled driver runs under Unicorn; no EFI code runs on the host CPU.
"""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
DRIVER = HERE.parent / "lock_1904_history02/driver"
ORIGINAL = ROOT / "analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules"
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import capstone
import pefile


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


expected = {
    DRIVER / "build/AiTweakerLock1904.efi": "598daaa53564f9b4610e300946fd588c2108a9842cb5f15cf67ee8e8d0a2fd84",
    ORIGINAL / "AMITSE.efi": "99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5",
    ORIGINAL / "Setup.efi": "cccec44562198457d7f72e76df3a73bc8ec61244c94428219ee990963d6922dc",
}
for path, digest in expected.items():
    assert sha(path) == digest, path
build = json.loads((DRIVER / "build/build.json").read_text(encoding="utf8"))
assert build["efi_sha256"] == expected[DRIVER / "build/AiTweakerLock1904.efi"]
for rel, digest in build["sources"].items():
    assert sha(DRIVER.parent / rel) == digest, rel
for rel, digest in build["external_sources"].items():
    assert sha(ROOT / rel) == digest, rel

checks = []


def check(name, result):
    assert result, name
    checks.append(name)


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
original_pe = pefile.PE(str(ORIGINAL / "AMITSE.efi"))
references = []
listing = []
for start, end in [(0x1017C, 0x1026F), (0x10270, 0x104AE)]:
    for ins in md.disasm(original_pe.get_data(start, end - start), start):
        listing.append(f"{ins.address:08x}: {ins.mnemonic} {ins.op_str}")
        for operand in ins.operands:
            if operand.type == capstone.CS_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
                references.append({"instruction_rva": hex(ins.address), "target_rva": hex(ins.address + ins.size + operand.mem.disp), "width": operand.size, "text": ins.mnemonic + " " + ins.op_str})
reference_map = {int(item["instruction_rva"], 16): item for item in references}
for instruction, target, width in [
    (0x10191, 0x82778, 4), (0x101B4, 0x82748, 8),
    (0x101BB, 0x82760, 8), (0x10210, 0x82754, 4),
    (0x102C9, 0x82758, 4), (0x102D4, 0x82760, 8),
    (0x102F5, 0x82754, 4), (0x10493, 0x82778, 4),
]:
    item = reference_map[instruction]
    check(f"original instruction {instruction:#x} identifies {target:#x} width={width}", int(item["target_rva"], 16) == target and item["width"] == width)

adapter = DRIVER / "verify_adapter.py"
prefix = adapter.read_text(encoding="utf8").split("\nchecks=[]", 1)[0]
scope = {"__file__": str(adapter)}
exec(compile(prefix, str(adapter), "exec"), scope)
VM, TSE, SETUP, HEAP, symbols, d, w = (scope[n] for n in ["VM", "TSE", "SETUP", "HEAP", "symbols", "d", "w"])
HISTORY = HEAP + 0x180000


def new_vm():
    v = VM()
    assert v.call(symbols["attach_platform"], TSE, 0xA2000, SETUP, 0x1A4000) == 1
    v.start()
    v.current(1)
    return v


def poll(v):
    v.call(TSE + 0x34B7C)


def snapshot(v):
    return bytes(v.u.mem_read(HISTORY, 28 * 32)), v.getd(TSE + 0x82754), v.getd(TSE + 0x82778)


for capacity in [1, 8212]:
    v = new_vm()
    v.u.mem_write(TSE + 0x82758, d(capacity))
    v.u.mem_write(HISTORY - 16, b"A" * 16)
    v.u.mem_write(HISTORY + capacity * 32, b"Z" * 16)
    poll(v)
    check(f"capacity {capacity} redirects to Main with one native root", v.getd(v.app + 0x28) == 0 and v.getd(TSE + 0x82754) == 0 and v.getd(TSE + 0x82778) == 1 and v.getd(HISTORY + 8) == 0x2713)
    check(f"capacity {capacity} does not overwrite neighboring bytes", bytes(v.u.mem_read(HISTORY - 16, 16)) == b"A" * 16 and bytes(v.u.mem_read(HISTORY + capacity * 32, 16)) == b"Z" * 16)
    check(f"capacity {capacity} root has no native parent", v.getq(HISTORY + 16) == 0 and v.getd(HISTORY + 24) == 0)

for name, mutation in [
    ("zero page count", lambda v: v.u.mem_write(v.app + 0x2C, d(0))),
    ("all pages are child pages", lambda v: [v.u.mem_write(p + 0x32, w(1)) for p in v.pages]),
    ("all pages hidden", lambda v: [v.u.mem_write(p + 0x34, b"\x01") for p in v.pages]),
    ("every safe page index mismatches array position", lambda v: [v.u.mem_write(v.pages[i] + 0x30, w(1)) for i in [0, 5, 7]]),
]:
    v = new_vm()
    mutation(v)
    before = snapshot(v)
    poll(v)
    check(name + ": browser exit requested", bytes(v.u.mem_read(v.app + 0x5A, 1)) == b"\x01")
    check(name + ": no false safe-root/history commit", snapshot(v) == before and v.getd(v.app + 0x28) == 1)

for name, mutation in [
    ("Main hidden", lambda v: v.u.mem_write(v.pages[0] + 0x34, b"\x01")),
    ("Main child", lambda v: v.u.mem_write(v.pages[0] + 0x32, w(1))),
    ("Main index inconsistent", lambda v: v.u.mem_write(v.pages[0] + 0x30, w(1))),
]:
    v = new_vm()
    mutation(v)
    poll(v)
    check(name + ": consistent foreign-HII unprotected top-level fallback", v.getd(v.app + 0x28) == 5 and v.getd(TSE + 0x82754) == 5 and v.getd(HISTORY + 8) == 0x6001 and v.getd(TSE + 0x82778) == 1 and bytes(v.u.mem_read(v.app + 0x5A, 1)) == b"\0")

check("EBS implementation intentionally unchanged", (DRIVER / "services.c").read_bytes() == (ROOT / "analysis/aitweaker_lock/lock_1904/driver/services.c").read_bytes())
(HERE / "ace_original_history_disassembly.txt").write_text("\n".join(listing) + "\n", encoding="utf8")
result = {
    "status": "PASS_INDEPENDENT_BOUNDED_HISTORY02_REVIEW",
    "checks": len(checks), "check_names": checks,
    "identities": {str(p.relative_to(ROOT)): sha(p) for p in [*expected, DRIVER / "platform.c", DRIVER / "services.c", DRIVER / "build/build.json", DRIVER / "build/driver.map", adapter, Path(__file__)]},
    "original_rip_references": references,
    "remaining_risks_not_modified": ["ExitBootServices restoration error handling", "Ownerless/late attach protection", "First active-browser discovery/no retry", "Ordinary boot and Save timing", "Persistent or direct Del/F2 hardware validation"],
    "limits": ["Original PE instructions corroborate history layout; they do not observe hardware.", "Additional semantic cases execute compiled ACE driver and original poll dispatch in Unicorn using constructed native page objects and stubbed firmware/password services.", "No production source or primary test result was modified; no BMC connection or firmware execution occurred."]
}
(HERE / "history02-independent-review.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf8")
print(json.dumps({"status": result["status"], "checks": len(checks), "driver_sha256": expected[DRIVER / "build/AiTweakerLock1904.efi"]}))
