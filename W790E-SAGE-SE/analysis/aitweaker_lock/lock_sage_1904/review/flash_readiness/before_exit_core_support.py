"""Read-only static and bounded native-emulation review of original 1904 DXE Core.

The event creation, GUID broadcast, notification queue/TPL dispatch, and
ExitBootServices control flow execute from the original extracted machine code.
Allocation, CPU/timer protocols, status reporting and success-path CRC are local
test doubles. No physical device, VM firmware, or candidate driver is executed.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[1]
ROOT = CASE.parents[2]
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import capstone
import pefile
import unicorn
from unicorn import x86_const as x86

PIN_CORE = "d8684ae913fe44bfcb950c0635299465d7813b1f60407a733f7cce34e50f584d"
PIN_CAP = "aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3"
CORE = HERE / "runtime_navigation/OriginalDxeCore.efi"
PRIOR = HERE / "runtime_navigation/original_dxe_event_evidence.json"
ORIGINAL = CASE.parent / "official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP"
BEFORE = "8be0e274-3970-4b44-80c5-1ab9502f3bfc"
EXIT = "27abf055-b1b8-4c26-8048-748f37baa2df"
FAILED = "4f6c5507-232f-4787-b95e-72f862490cb1"
OTHER = "c9d31f15-10ae-40aa-aacb-18311489aba7"
BASE = 0x10000000
ARENA = 0x20000000
STACK = 0x30000000
STUB = 0x40000000
STOP = STUB + 0xFF00
INVALID = 0x8000000000000002


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class CoreHarness:
    def __init__(self, source: bytes):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        pe = pefile.PE(data=source)
        pe.relocate_image(BASE)
        mapped = pe.get_memory_mapped_image()
        self.uc.mem_map(BASE, (max(len(mapped), pe.OPTIONAL_HEADER.SizeOfImage) + 0xFFF) & ~0xFFF)
        self.uc.mem_write(BASE, mapped)
        self.uc.mem_map(ARENA, 0x20000)
        self.uc.mem_map(STACK, 0x20000)
        self.uc.mem_map(STUB, 0x10000)
        self.uc.mem_write(STUB, b"\xc3" * 0x10000)
        self.heap = ARENA + 0x8000
        self.events = {}
        self.trace = []
        self.stub_callbacks = {}
        self.current_case = "initialization"
        self.executed_native = set()
        self.q(BASE + 0x16B30, 4)  # CurrentTpl = TPL_APPLICATION.
        self.q(BASE + 0x16B38, 31)  # EventQueueLock.Tpl = TPL_HIGH_LEVEL.
        self.q(BASE + 0x16B40, 4)
        self.d(BASE + 0x16B48, 1)
        self.list_head(BASE + 0x16B50)  # NotifySignal list.
        for tpl in range(32):
            self.list_head(BASE + 0x1F340 + 16 * tpl)
        self.q(BASE + 0x17B10, 0)  # Pending TPL bitmap.
        self.list_head(BASE + 0x16E28)  # Memory map list (empty test fixture).
        self.q(BASE + 0x16E38, 31)
        self.q(BASE + 0x16E40, 4)
        self.d(BASE + 0x16E48, 1)
        self.q(BASE + 0x17AE0, 0x1234)  # Current map key.
        self.q(BASE + 0x17AE8, 0x1234)  # Lower accepted key bound.
        self.q(BASE + 0x17AB8, ARENA + 0x100)  # Timer protocol.
        self.q(ARENA + 0x108, STUB + 0x100)
        self.q(BASE + 0x17AC0, ARENA + 0x200)  # CPU protocol.
        self.q(ARENA + 0x208, STUB + 0x200)
        self.q(ARENA + 0x210, STUB + 0x210)
        self.q(BASE + 0x17A90, 0)  # No SMM protocol in this fixture.
        self.q(BASE + 0x17A68, ARENA + 0x300)  # System table.
        self.q(BASE + 0x17BB0, ARENA + 0x500)  # Boot Services storage for terminal zeroing.
        self.q(BASE + 0x15D48, ARENA + 0x700)  # Runtime architecture structure.
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def q(self, address: int, value: int) -> None:
        self.uc.mem_write(address, struct.pack("<Q", value))

    def d(self, address: int, value: int) -> None:
        self.uc.mem_write(address, struct.pack("<I", value))

    def readq(self, address: int) -> int:
        return struct.unpack("<Q", self.uc.mem_read(address, 8))[0]

    def list_head(self, address: int) -> None:
        self.q(address, address)
        self.q(address + 8, address)

    def return_stub(self, value: int = 0) -> None:
        rsp = self.uc.reg_read(x86.UC_X86_REG_RSP)
        self.uc.reg_write(x86.UC_X86_REG_RAX, value)
        self.uc.reg_write(x86.UC_X86_REG_RIP, self.readq(rsp))
        self.uc.reg_write(x86.UC_X86_REG_RSP, rsp + 8)

    def hook(self, uc, address, size, _):
        if address == STOP:
            uc.emu_stop()
            return
        if BASE <= address < BASE + 0x22000:
            self.executed_native.add(address - BASE)
        if address == BASE + 0x1083C:  # CoreAllocateZeroPool helper.
            length = uc.reg_read(x86.UC_X86_REG_RDX)
            require(length == 0xB8, "unexpected event allocation size")
            pointer = self.heap
            self.heap += (length + 15) & ~15
            self.return_stub(pointer)
        elif address in (BASE + 0x111A8, BASE + 0x256C):
            # Reporting and terminal System Table CRC are not the target.
            self.return_stub(0)
        elif address == STUB + 0x100:
            self.trace.append({"kind": "timer_set_period", "period": uc.reg_read(x86.UC_X86_REG_RDX)})
            self.return_stub(0)
        elif address in (STUB + 0x200, STUB + 0x210):
            self.return_stub(0)  # CPU interrupt enable/disable protocol.
        elif address in self.stub_callbacks:
            event_name = self.stub_callbacks[address]
            event = uc.reg_read(x86.UC_X86_REG_RCX)
            require(event == self.events[event_name], "callback event handle mismatch")
            self.trace.append({"kind": "notify", "event": event_name, "tpl": self.readq(BASE + 0x16B30), "event_handle": event})
            self.return_stub(0)

    def call(self, rva: int, args: list[int]) -> int:
        rsp = STACK + 0x1F000 - 8
        self.uc.mem_write(rsp, bytes(0x100))
        self.q(rsp, STOP)
        for reg, value in zip((x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9), args):
            self.uc.reg_write(reg, value)
        for i, value in enumerate(args[4:]):
            self.q(rsp + 0x28 + i * 8, value)
        self.uc.reg_write(x86.UC_X86_REG_RSP, rsp)
        self.uc.reg_write(x86.UC_X86_REG_RFLAGS, 0x202)
        self.uc.emu_start(BASE + rva, STOP + 1, timeout=2_000_000, count=200000)
        require(self.uc.reg_read(x86.UC_X86_REG_RIP) == STOP, "emulation did not return within budget")
        return self.uc.reg_read(x86.UC_X86_REG_RAX)

    def register(self, name: str, event_guid: str, tpl: int) -> dict:
        index = len(self.events)
        guid_pointer = ARENA + 0x1000 + index * 32
        out_pointer = ARENA + 0x2000 + index * 8
        callback = STUB + 0x1000 + index * 16
        self.uc.mem_write(guid_pointer, uuid.UUID(event_guid).bytes_le)
        self.stub_callbacks[callback] = name
        status = self.call(0x9328, [0x200, tpl, callback, 0, guid_pointer, out_pointer])
        require(status == 0, "CoreCreateEventEx failed")
        event = self.readq(out_pointer)
        self.events[name] = event
        require(bytes(self.uc.mem_read(event + 0x38, 16)) == uuid.UUID(event_guid).bytes_le, "event GUID copy")
        return {"name": name, "guid": event_guid, "tpl": tpl, "status": status, "handle": event}

    def ebs(self, key: int, name: str) -> dict:
        self.trace = []
        before_guard = self.uc.mem_read(BASE + 0x15CC0, 1)[0]
        status = self.call(0x25A0, [ARENA + 0x900, key])
        return {
            "name": name,
            "map_key": key,
            "status": f"0x{status:016x}",
            "one_time_flag_before": before_guard,
            "one_time_flag_after": self.uc.mem_read(BASE + 0x15CC0, 1)[0],
            "callbacks": self.trace.copy(),
        }


def assert_trace(case: dict, notify_names: list[str], timer_count: int, status: int) -> None:
    require(case["status"] == f"0x{status:016x}", case["name"] + " status")
    require([e["event"] for e in case["callbacks"] if e["kind"] == "notify"] == notify_names, case["name"] + " callback sequence")
    require(len([e for e in case["callbacks"] if e["kind"] == "timer_set_period"]) == timer_count, case["name"] + " timer count")
    require(case["one_time_flag_after"] == 0, case["name"] + " one-time flag not cleared")


def main() -> None:
    source = CORE.read_bytes()
    prior = json.loads(PRIOR.read_text(encoding="utf-8"))
    require(sha(source) == PIN_CORE == prior["sha256"], "core SHA binding")
    require(sha(ORIGINAL.read_bytes()) == PIN_CAP, "original CAP SHA binding")
    original_extracted = ROOT / prior["source"]
    require(original_extracted.read_bytes() == source, "core copy differs from extraction")
    pe = pefile.PE(data=source)
    mapped = pe.get_memory_mapped_image()
    require(struct.unpack_from("<Q", mapped, 0x15E90 + 0xE8)[0] == 0x25A0, "Boot Services EBS slot")
    require(struct.unpack_from("<Q", mapped, 0x15E90 + 0x170)[0] == 0x9328, "Boot Services CreateEventEx slot")
    for offset in (0x15AF0, 0x15C20):
        require(mapped[offset:offset + 16] == uuid.UUID(BEFORE).bytes_le, "Before GUID")
    require(mapped[0x15BE0:0x15BF0] == uuid.UUID(EXIT).bytes_le, "Exit GUID")
    require(mapped[0x159C0:0x159D0] == uuid.UUID(FAILED).bytes_le, "failure GUID")
    require(mapped[0x15CC0] == 1, "one-time flag initial value")
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ranges = {}
    for name, start, end in (
        ("ExitBootServices", 0x25A0, 0x277F),
        ("NotifySignalList", 0x9280, 0x92E4),
        ("QueueEventNotification", 0x921C, 0x927D),
        ("CreateEventEx", 0x9328, 0x955F),
        ("RestoreTplAndDispatch", 0xCC98, 0xCDC4),
    ):
        ranges[name] = [{"rva": hex(i.address), "bytes": i.bytes.hex(), "instruction": i.mnemonic + " " + i.op_str} for i in disassembler.disasm(mapped[start:end], start)]
    cases, registrations, visited = [], [], set()
    for scenario in ("first_valid", "first_invalid_then_valid", "two_invalid"):
        harness = CoreHarness(source)
        regs = [
            harness.register("before16", BEFORE, 16),
            harness.register("before8", BEFORE, 8),
            harness.register("exit16", EXIT, 16),
            harness.register("failed16", FAILED, 16),
            harness.register("other16", OTHER, 16),
        ]
        registrations.append({"scenario": scenario, "events": regs})
        if scenario == "first_valid":
            case = harness.ebs(0x1234, "first_valid")
            assert_trace(case, ["before16", "before8", "before16", "before8", "exit16"], 1, 0)
            cases.append(case)
        else:
            case = harness.ebs(0x1233, scenario + ":first_invalid")
            assert_trace(case, ["before16", "before8", "before16", "before8", "exit16", "failed16"], 1, INVALID)
            cases.append(case)
            second_valid = scenario == "first_invalid_then_valid"
            case = harness.ebs(0x1234 if second_valid else 0x1233, scenario + ":retry")
            assert_trace(case, [] if second_valid else ["failed16"], 0, 0 if second_valid else INVALID)
            cases.append(case)
        visited.update(harness.executed_native)
    require({0x25D7, 0x25E3, 0x25FE, 0x92BC, 0xCD4C, 0x26A6}.issubset(visited), "required native paths were not executed")
    report = {
        "status": "PASS_ORIGINAL_DXE_CORE_SUPPORTS_AND_DISPATCHES_BEFORE_EXIT_GROUP",
        "script_sha256": sha(Path(__file__).read_bytes()),
        "inputs": {
            "official_cap": {"path": str(ORIGINAL), "sha256": PIN_CAP},
            "original_core": {"path": str(CORE), "sha256": PIN_CORE, "bytes": len(source), "original_extracted_path": str(original_extracted)},
            "prior_guid_evidence": {"path": str(PRIOR), "sha256": sha(PRIOR.read_bytes())},
        },
        "no_device_access_or_production_changes": True,
        "native_locations": {
            "boot_services_table_rva": "0x15e90",
            "exit_boot_services_rva": "0x25a0",
            "create_event_ex_rva": "0x9328",
            "before_guid_rvas": ["0x15af0", "0x15c20"],
            "exit_guid_rva": "0x15be0",
            "before_group_broadcast_calls": ["0x25d7", "0x25e3"],
            "timer_stop_indirect_call": "0x25f4",
            "exit_group_broadcast_call": "0x25fe",
            "broadcast_function": "0x9280",
            "queued_callback_invocation": "0xcd4c",
            "one_time_flag_rva": "0x15cc0",
            "one_time_flag_initial": 1,
            "one_time_flag_cleared_at": "0x2603",
            "invalid_key_error_path": ["0x2625", "0x267a", "0x269f", "0x26a6", "0x2767"],
            "failed_exit_group_guid": FAILED,
        },
        "confirmed_semantics": [
            "CreateEventEx accepts the official BeforeExitBootServices GUID and copies all 16 bytes into the event record; it is added to the notify-signal list.",
            "On the first ExitBootServices call, flag 0x15cc0 starts at 1. The code compares MapKey early but does not return on mismatch before broadcasting.",
            "Two separate calls signal the SAME BeforeExitBootServices GUID. Original notification code queues and dispatches matching callbacks at their TPL before continuing.",
            "The timer protocol receives period zero after both Before broadcasts. The Exit group is then broadcast and the one-time flag cleared.",
            "Wrong MapKey can then produce EFI_INVALID_PARAMETER and a separate vendor failure-group notification; this does not undo the earlier Before/Exit callbacks or restore the one-time flag.",
            "On a subsequent call after an invalid-key return, Before/Exit/timer-stop are skipped. A corrected key can succeed without re-notifying these groups.",
        ],
        "driver_implications": [
            "BeforeExitBootServices is supported in this exact original ASUS Core; it is not merely a latest-OVMF capability.",
            "Cleanup must be idempotent: each matching Before callback is dispatched twice on the first attempt in this Core.",
            "An unsuccessful first ExitBootServices call still retires a driver using these callbacks. If Boot Services continue, do not reinstall pointers into reclaimed/retired driver state and do not rely on a retry to signal Before again.",
            "This evidence does not by itself validate the candidate driver cleanup, every later live hook installed by other components, or the behavior of a different DxeCore version.",
        ],
        "emulation_scope": {
            "engine": "Unicorn x86-64",
            "native_functions": ["CoreCreateEventEx", "event allocation/registration logic after allocation", "ExitBootServices", "GUID group matching", "notification queue", "RestoreTpl dispatch", "success/failure branching"],
            "test_doubles": ["zero-pool allocator", "CPU interrupt protocol", "timer protocol", "status reporter", "terminal system-table CRC routine", "callback observers"],
            "map_fixture": "empty descriptor list with current key and minimum key 0x1234",
            "is_hardware_test": False,
            "does_not_use_candidate_driver": True,
        },
        "registrations": registrations,
        "native_emulation_cases": cases,
        "executed_native_rvas": [hex(v) for v in sorted(visited)],
        "disassembly": ranges,
        "sources": [
            {"url": "https://raw.githubusercontent.com/tianocore/edk2/master/MdePkg/Include/Guid/EventGroup.h", "scope": "Official Before/Exit event GUID values"},
            {"url": "https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html", "scope": "CreateEventEx event groups, ExitBootServices and partial-shutdown/retry semantics; actual duplicate notifications are observed original binary behavior"},
        ],
    }
    out = HERE / "before_exit_core_support.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "output": str(out), "sha256": sha(out.read_bytes()), "cases": len(cases), "create_event_ex_calls": sum(len(x["events"]) for x in registrations)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
