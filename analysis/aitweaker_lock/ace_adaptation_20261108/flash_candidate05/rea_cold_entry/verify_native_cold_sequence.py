"""Bounded original ACE startup ordering with actual candidate discovery/HII.

The native AMITSE protocol initializer, BDS dispatch table, EndOfDxe handler,
BootManager bridge/setup-request block and first BrowserLoop prefix execute in
Unicorn. Hardware/OEM helper functions and service providers are explicit
fixtures. The test stops at the first native page-cache builder, not a desktop.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
BASE = ROOT / "analysis/aitweaker_lock/ace_adaptation_20261108"
CASE04 = BASE / "lock_1904_integrated04"
CASE03 = BASE / "lock_1904_integrated03"
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile

TSE_FILE = ROOT / "analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi"
BDS_FILE = BASE / "integration03_rea_review/modules/OriginalBds.efi"
PINS = {TSE_FILE: "99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5",
        BDS_FILE: "c1d6d582c8349b87ed54961570924b90b2b6fb9e711c2160469fdb0bd41c8c2f"}
GUID = lambda s: uuid.UUID(s).bytes_le
BROWSER_GUID = GUID("b9d4c360-bcfb-4f9b-9298-53c136982258")
BOOT_MANAGER_GUID = GUID("8a91b1e1-56c7-4adc-abeb-1c2ca1729eff")
END_DXE_GUID = GUID("02ce967a-dd7e-4ffc-9ee7-810cf0470880")
BDS = 0x30000000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=BASE / "flash_candidate05/lock_1904_candidate05/driver/build")
    parser.add_argument("--output", type=Path, default=HERE / "native_cold_sequence.json")
    args = parser.parse_args()
    build = args.build.resolve()
    digest = hashlib.sha256((build / "AiTweakerLock1904.efi").read_bytes()).hexdigest()
    for path, expected in PINS.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
    template = CASE04 / "owner_review/integrated_publication_retirement_regression.fixture.py"
    ns = {"__file__": str(CASE03 / "owner_review/verify_publication_retirement.py"),
          "BINDING_BUILD": build, "BINDING_SHA": digest, "BASE_FIXTURE": CASE03 / "driver/build"}
    exec(compile(template.read_text(encoding="utf8"), str(template), "exec"), ns)
    globals().update({k: ns[k] for k in ("HiiVM", "U", "R", "TSE", "SETUP", "HEAP", "STOP", "symbols", "q", "d", "ERR", "DBGUID", "STRGUID", "HANDLE")})
    svc_names = ["CreateEvent", "CreateEventEx", "RegisterNotify", "SignalEvent", "CloseEvent", "InstallProtocol", "InstallMultiple", "SetTimer", "NativeReset", "OpenProtocol"]
    svc = {name: STOP + 0x5000 + i * 0x10 for i, name in enumerate(svc_names)}
    resume = STOP + 0x7e00

    class ColdVM(HiiVM):
        def __init__(self, policy="formbrowser", hii=True):
            self.policy = policy
            self.hii_available = hii
            self.trace = []
            self.events = []
            self.protocols = {}
            self.registrations = []
            self.callback_frames = []
            self.native_callbacks_skipped = []
            self.cache_reached = False
            self.native_return = None
            self.run_prefix = False
            self.deferred_callback_fired = False
            self.dispatch_started = False
            super().__init__()
            self.browser_ready = False
            self.u.mem_write(symbols["services_initialized"], d(0))
            self.u.mem_write(TSE + 0x82628, q(0))
            self.u.mem_write(TSE + 0x824c0, q(self.st))
            self.u.mem_write(TSE + 0x824c8, q(self.bs))
            self.u.mem_write(TSE + 0x824d8, q(self.rt))
            self.u.mem_write(self.st + 0x30, q(HEAP + 0x1b8000))
            self.u.mem_write(HEAP + 0x1b8000, q(svc["NativeReset"]))
            for offset, name in [(0x50, "CreateEvent"), (0x170, "CreateEventEx"), (0xa8, "RegisterNotify"),
                                 (0x68, "SignalEvent"), (0x70, "CloseEvent"), (0x80, "InstallProtocol"),
                                 (0x148, "InstallMultiple"), (0x58, "SetTimer"), (0x118, "OpenProtocol")]:
                self.u.mem_write(self.bs + offset, q(svc[name]))
            pe = pefile.PE(str(BDS_FILE)); pe.relocate_image(BDS)
            raw = pe.get_memory_mapped_image()
            self.map(BDS, (len(raw) + 4095) & ~4095); self.u.mem_write(BDS, raw)
            self.u.mem_write(BDS + 0x1ff30, q(self.bs)); self.u.mem_write(BDS + 0x1ff40, q(self.rt))
            self.table = [self.getq(BDS + 0x1b8c0 + i * 8) for i in range(67)]
            self.main_helpers = self.callees("amitse/responses/002-main-initializer.json") - {0x2624, 0x77f0}
            self.installer_helpers = {0x20e20, 0x20ee4, 0x447c}
            self.prefix_helpers = {0x36190, 0x6f00, 0x40bc}
            targets = [*svc.values(), resume, TSE + 0xe21a, TSE + 0xdf40, TSE + 0xcdb8,
                       TSE + 0x2780, TSE + 0x2b6a, BDS + 0x283f]
            targets += [TSE + a for a in self.main_helpers | self.installer_helpers | self.prefix_helpers]
            targets += self.table + [BDS + 0x9c48, BDS + 0x18e0]
            for address in set(targets):
                self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)

        def callees(self, path):
            dct = json.loads((HERE / path).read_text(encoding="utf8"))["result"]["structuredContent"]
            return {int(x["address"], 16) for x in dct["normalized_result"]["callees"]}

        def record(self, event, **values):
            self.trace.append({"event": event, "stage": self.getq(TSE + 0x82628),
                               "ready": self.getd(symbols["platform_ready"]),
                               "manager": self.getd(symbols["manager_installed"]),
                               "active": self.u.mem_read(symbols["password_core"] + 200, 1)[0],
                               "depth": self.getd(symbols["loop_depth"]), **values})

        def deliver(self, callbacks, label):
            callbacks = [x for x in callbacks if x["callback"] in (symbols["discover"], symbols["before_exiting"], symbols["exiting"])]
            if not callbacks:
                self.ret(0); return
            self.callback_frames.append({"outer": self.u.context_save(), "queue": callbacks, "label": label})
            self.next_callback()

        def next_callback(self):
            frame = self.callback_frames[-1]
            event = frame["queue"].pop(0)
            self.record("dispatch_registered_driver_callback", reason=frame["label"], callback=hex(event["callback"]))
            sp = 0x70000000 + 0x200000 - len(self.callback_frames) * 0x10000 + 0xfe08
            self.u.mem_write(sp, q(resume) + bytes(0x100))
            self.u.reg_write(R.UC_X86_REG_RSP, sp)
            self.u.reg_write(R.UC_X86_REG_RCX, event["handle"])
            self.u.reg_write(R.UC_X86_REG_RDX, event["context"])
            self.u.reg_write(R.UC_X86_REG_RIP, event["callback"])

        def hook(self, u, address, size, data):
            if address == resume and self.callback_frames:
                if self.callback_frames[-1]["queue"]:
                    self.next_callback()
                else:
                    frame = self.callback_frames.pop()
                    u.context_restore(frame["outer"])
                    self.record("registered_driver_callback_returned", reason=frame["label"])
                    self.ret(0)
                return
            if address == STOP + 0x110:
                guid = bytes(u.mem_read(self.arg(0), 16))
                if guid in (DBGUID, STRGUID) and not self.hii_available:
                    self.ret(ERR(14)); return
                if guid in self.protocols:
                    u.mem_write(self.arg(2), q(self.protocols[guid])); self.ret(0); return
            if address in (svc["CreateEvent"], svc["CreateEventEx"]):
                group = bytes(u.mem_read(self.argn(4), 16)) if address == svc["CreateEventEx"] else None
                handle = HEAP + 0x1f9000 + len(self.events) * 0x20
                event = {"handle": handle, "callback": self.arg(2), "context": self.arg(3), "group": group, "type": self.arg(0)}
                self.events.append(event)
                u.mem_write(self.argn(5 if group is not None else 4), q(handle))
                self.ret(0); return
            if address == svc["RegisterNotify"]:
                guid = bytes(u.mem_read(self.arg(0), 16)); event = next(x for x in self.events if x["handle"] == self.arg(1))
                self.registrations.append((guid, event)); u.mem_write(self.arg(2), q(0x12340000 + len(self.registrations)))
                self.ret(0); return
            if address in (svc["InstallProtocol"], svc["InstallMultiple"]):
                guid = bytes(u.mem_read(self.arg(1), 16))
                interface = self.arg(3) if address == svc["InstallProtocol"] else self.arg(2)
                self.protocols[guid] = interface
                if not self.getq(self.arg(0)):
                    u.mem_write(self.arg(0), q(0x8800 + len(self.protocols)))
                self.record("install_protocol", guid=str(uuid.UUID(bytes_le=guid)), interface=hex(interface))
                if guid == BROWSER_GUID:
                    self.browser_ready = True
                    if self.policy == "formbrowser":
                        self.deliver([e for g, e in self.registrations if g == guid], "FormBrowser2 publication"); return
                if self.policy == "stage4" and self.getq(TSE + 0x82628) == 4 and not self.deferred_callback_fired:
                    self.deferred_callback_fired = True
                    self.deliver([e for e in self.events if e["type"] & 0x80000000], "timer at stage4 provider return"); return
                self.ret(0); return
            if address == svc["SignalEvent"]:
                event = next(x for x in self.events if x["handle"] == self.arg(0))
                if event["group"] == END_DXE_GUID:
                    self.record("native_BDS_EndOfDxe")
                    if self.policy in ("formbrowser", "enddxe"):
                        self.deliver([x for x in self.events if x["group"] == END_DXE_GUID], "original BDS EndOfDxe"); return
                if event["callback"] not in (symbols["discover"], symbols["before_exiting"], symbols["exiting"]):
                    self.native_callbacks_skipped.append(hex(event["callback"] - TSE))
                self.ret(0); return
            if address in (svc["CloseEvent"], svc["SetTimer"], svc["NativeReset"]):
                self.ret(0); return
            if address == svc["OpenProtocol"]:
                self.ret(ERR(14)); return
            if address in self.table:
                self.record("BDS_table_handler", index=self.table.index(address), rva=hex(address - BDS))
                if address not in (BDS + 0x194c, BDS + 0x25ec):
                    self.ret(0); return
            if address in (BDS + 0x9c48, BDS + 0x18e0):
                self.ret(0); return
            if address == TSE + 0x2780 and self.dispatch_started:
                self.record("native_BootManager_interface_called")
                # The native setup-request block is replayed with documented
                # branch-live registers; hardware key acquisition is not modeled.
                u.reg_write(R.UC_X86_REG_RAX, 1); u.reg_write(R.UC_X86_REG_RSI, 4)
                u.reg_write(R.UC_X86_REG_R12, 1); u.reg_write(R.UC_X86_REG_R15, 0)
                u.reg_write(R.UC_X86_REG_RSP, u.reg_read(R.UC_X86_REG_RSP) - 8)
                u.reg_write(R.UC_X86_REG_RIP, TSE + 0x2b21); return
            if address in [TSE + a for a in self.main_helpers | self.installer_helpers | self.prefix_helpers]:
                self.ret(0); return
            if address == TSE + 0xe21a and self.run_prefix:
                self.body_context = u.context_save()
                self.record("original_browser_prefix_entered")
                return
            if address in (TSE + 0xdf40, TSE + 0xcdb8) and self.run_prefix:
                self.cache_reached = True
                self.record("first_native_cache_boundary", function=hex(address - TSE), package_updates=self.update_calls)
                u.emu_stop(); return
            if address == TSE + 0x2b6a and self.dispatch_started:
                self.native_return = u.reg_read(R.UC_X86_REG_RAX)
                self.record("native_browser_returned_before_cache", result=hex(self.native_return))
                u.emu_stop(); return
            if address == BDS + 0x283f and self.dispatch_started:
                u.emu_stop(); return
            super().hook(u, address, size, data)

        def driver_entry(self):
            self.record("driver_entry_begin")
            result = self.call(symbols["efi_main"], 0xcafe, self.st)
            self.record("driver_entry_return", result=hex(result))
            assert result == 0

        def initialize_native(self):
            self.record("AMITSE_initializer_begin")
            self.call(TSE + 0x1034, 0xabc1, self.st)
            self.record("AMITSE_initializer_return")
            assert self.protocols[BROWSER_GUID] == TSE + 0x6b528
            assert self.protocols[BOOT_MANAGER_GUID] == TSE + 0x6ab40

        def bds_until_cache(self):
            self.u.mem_write(TSE + 0x82748, q(0)); self.u.mem_write(TSE + 0x921e8, q(0))
            self.u.mem_write(TSE + 0x82768, b"\1")
            self.dispatch_started = self.run_prefix = True
            sp = 0x70000000 + 0x3ffe00
            self.u.mem_write(sp, bytes(0x100))
            self.u.reg_write(R.UC_X86_REG_RSP, sp)
            for reg in (R.UC_X86_REG_RSI, R.UC_X86_REG_RDI, R.UC_X86_REG_RCX):
                self.u.reg_write(reg, 0)
            self.u.emu_start(BDS + 0x2817, 0, count=200000000)
            assert self.u.reg_read(R.UC_X86_REG_RIP) in (TSE + 0xdf40, TSE + 0xcdb8, TSE + 0x2b6a, BDS + 0x283f)

    rows = []
    scenarios = [("FormBrowser2 notification before first BDS setup", "formbrowser", True, True, True),
                 ("EndOfDxe catches deferred discovery", "enddxe", True, True, True),
                 ("HII unavailable at attach then available before first owner", "formbrowser", False, True, True),
                 ("HII remains unavailable at first owner", "formbrowser", False, False, True),
                 ("first notification inside original stage4 prefix", "stage4", True, True, True),
                 ("driver absent while original native setup proceeds", "never", True, True, False)]
    for name, policy, initial_hii, entry_hii, driver_present in scenarios:
        vm = ColdVM(policy, initial_hii)
        if driver_present:
            vm.driver_entry()
        vm.initialize_native()
        vm.hii_available = entry_hii
        vm.bds_until_cache()
        row = {"case": name, "cache_reached": vm.cache_reached, "native_return": None if vm.native_return is None else hex(vm.native_return),
               "trace": vm.trace, "native_notification_callbacks_not_executed": sorted(set(vm.native_callbacks_skipped)),
               "ready": vm.getd(symbols["platform_ready"]), "manager_installed": vm.getd(symbols["manager_installed"]),
               "active": vm.u.mem_read(symbols["password_core"] + 200, 1)[0], "owner_depth": vm.getd(symbols["loop_depth"]),
               "hii_package_updates": vm.update_calls}
        if driver_present and policy != "stage4" and entry_hii:
            assert row["cache_reached"] and row["ready"] == row["manager_installed"] == row["active"] == row["owner_depth"] == 1
            assert row["hii_package_updates"] == 1
        elif not entry_hii:
            assert not row["cache_reached"] and vm.native_return == ERR(15) and row["owner_depth"] == 0
        elif policy == "stage4":
            assert row["cache_reached"] and row["ready"] == 1 and row["owner_depth"] == row["active"] == 0
        else:
            assert row["cache_reached"] and row["ready"] == row["owner_depth"] == 0
        rows.append(row)
    report = {"status": "PASS_BOUNDED_NATIVE_SEQUENCE_WITH_CONFIRMED_COLD_ENTRY_GAPS", "driver_sha256": digest,
              "cases": len(rows), "rows": rows, "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "native_inputs": {str(p.relative_to(ROOT)): h for p, h in PINS.items()},
              "fixture_sha256": hashlib.sha256(template.read_bytes()).hexdigest(),
              "production_changes": False, "device_access": False,
              "limits": ["Not physical Del/F2 acceptance. Hardware key acquisition, early BootManager initialization, native notification callbacks and unrelated BDS handlers are explicit fixtures.",
                         "The original BDS dispatch table/EndOfDxe/bridge and AMITSE protocol publication/setup-call block/browser prefix execute unchanged.",
                         "Actual candidate efi_main, initialize_services, discover, attachment, owner wrapper, HII insertion and live verification execute; UEFI services/page attributes are fixtures.",
                         "Execution stops before the first native page-cache builder. Actual page-cache construction and complete rendering remain unproved.",
                         "Successful prior driver loading and a sufficiently early notification are assumptions, not properties enforced by an optional DXE image."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    print(json.dumps({"status": report["status"], "cases": len(rows), "output": str(args.output)}))


if __name__ == "__main__":
    main()
