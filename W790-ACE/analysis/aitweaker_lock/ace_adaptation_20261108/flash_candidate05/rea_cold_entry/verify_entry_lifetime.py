"""Execute the frozen EFI entry and real retirement callbacks in Unicorn.

Only UEFI services are fixtures. A service return can synchronously dispatch
the actual callbacks already registered by initialize_services. This verifies
observable use-after-retirement behavior, not a duplicate entry state machine.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import importlib.util
import json
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
CASE = ROOT / "analysis/aitweaker_lock/ace_adaptation_20261108/lock_1904_integrated04"
PIN = "463b94139cb64207e1b756965ebb9ca3513250c8712bbbcd20798fd317dec904"


def load(build):
    spec = importlib.util.spec_from_file_location("cold_entry_owner", CASE / "owner_review/verify_owner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ns = module.load_runtime(build)
    globals().update({k: ns[k] for k in ("RuntimeVM", "U", "R", "TSE", "SETUP", "HEAP", "STOP", "symbols", "q", "d", "HANDLE")})
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=CASE / "driver/build")
    parser.add_argument("--output", type=Path, default=HERE / "entry_lifetime_463b.json")
    parser.add_argument("--expect-clean", action="store_true")
    args = parser.parse_args()
    build = args.build.resolve()
    digest = hashlib.sha256((build / "AiTweakerLock1904.efi").read_bytes()).hexdigest()
    if build == (CASE / "driver/build").resolve():
        assert digest == PIN
    load(build)
    providers = {name: STOP + 0x4000 + index * 0x10 for index, name in enumerate(
        ("CreateEvent", "CreateEventEx", "InstallProtocol", "RegisterNotify", "SetTimer", "CloseEvent"))}
    sentinel = STOP + 0x7f00
    before_guid = uuid.UUID("8be0e274-3970-4b44-80c5-1ab9502f3bfc").bytes_le

    class EntryVM(RuntimeVM):
        def __init__(self, trigger):
            self.trigger = trigger
            self.events = []
            self.provider_trace = []
            self.callbacks_run = []
            self.pending = None
            self.triggered = False
            self.self_li = HEAP + 0x1f8000
            super().__init__()
            self.browser_ready = False
            self.u.mem_write(symbols["services_initialized"], d(0))
            self.u.mem_write(symbols["discovery_timer"], q(0))
            for offset, name in [(0x50, "CreateEvent"), (0x170, "CreateEventEx"),
                                 (0x80, "InstallProtocol"), (0xa8, "RegisterNotify"),
                                 (0x58, "SetTimer"), (0x70, "CloseEvent")]:
                self.u.mem_write(self.bs + offset, q(providers[name]))
            for address in [*providers.values(), sentinel]:
                self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)

        def retired(self):
            return bool(self.getd(symbols["boot_services_ended"]))

        def finish_provider(self, label, status=0):
            self.provider_trace.append({"provider": label, "after_retirement": self.retired()})
            if label == self.trigger and not self.triggered:
                self.triggered = True
                callbacks = [e for e in self.events if e["callback"] == symbols["before_exiting"]]
                callbacks += [e for e in self.events if e["callback"] == symbols["exiting"]]
                assert callbacks, "No installed EBS callback at injection point"
                self.pending = {"outer": self.u.context_save(), "status": status, "queue": callbacks}
                self.run_next_callback()
            else:
                self.ret(status)

        def run_next_callback(self):
            event = self.pending["queue"].pop(0)
            self.callbacks_run.append(event["label"])
            sp = 0x70000000 + 0x1ffe08
            self.u.mem_write(sp, q(sentinel) + bytes(0x100))
            self.u.reg_write(R.UC_X86_REG_RSP, sp)
            self.u.reg_write(R.UC_X86_REG_RCX, event["handle"])
            self.u.reg_write(R.UC_X86_REG_RDX, 0)
            self.u.reg_write(R.UC_X86_REG_RIP, event["callback"])

        def hook(self, u, address, size, data):
            if address == sentinel and self.pending:
                if self.pending["queue"]:
                    self.run_next_callback()
                else:
                    pending = self.pending
                    self.pending = None
                    u.context_restore(pending["outer"])
                    self.ret(pending["status"])
                return
            if address in (providers["CreateEvent"], providers["CreateEventEx"]):
                callback = self.arg(2)
                if callback == symbols["exiting"]:
                    label = "CreateExitEvent"
                elif callback == symbols["before_exiting"]:
                    label = "CreateBeforeExitEvent"
                elif address == providers["CreateEventEx"]:
                    label = "CreateEndOfDxeEvent"
                elif self.arg(0) & 0x80000000:
                    label = "CreateDiscoveryTimer"
                else:
                    label = "CreateLoadedNotifyEvent" if not any(e["label"] == "CreateLoadedNotifyEvent" for e in self.events) else "CreateBrowserNotifyEvent"
                handle = HEAP + 0x1f9000 + len(self.events) * 0x20
                self.u.mem_write(self.argn(5 if address == providers["CreateEventEx"] else 4), q(handle))
                self.events.append({"label": label, "callback": callback, "handle": handle})
                self.finish_provider(label)
                return
            if address == providers["RegisterNotify"]:
                guid = bytes(u.mem_read(self.arg(0), 16))
                label = "RegisterBrowserNotify" if guid == uuid.UUID("b9d4c360-bcfb-4f9b-9298-53c136982258").bytes_le else "RegisterLoadedNotify"
                u.mem_write(self.arg(2), q(0x12340000 + len(self.provider_trace)))
                self.finish_provider(label)
                return
            if address == providers["InstallProtocol"]:
                u.mem_write(self.arg(0), q(0x7788))
                self.finish_provider("InstallStatusProtocol")
                return
            if address == HANDLE and self.arg(0) == 0xcafe:
                u.mem_write(self.arg(2), q(self.self_li))
                self.finish_provider("HandleSelfLoadedImage")
                return
            if address == providers["SetTimer"]:
                self.finish_provider("SetDiscoveryTimer")
                return
            if address == providers["CloseEvent"]:
                self.finish_provider("CloseEvent")
                return
            super().hook(u, address, size, data)

    cases = [None, "CreateExitEvent", "CreateBeforeExitEvent", "InstallStatusProtocol", "HandleSelfLoadedImage",
             "CreateLoadedNotifyEvent", "RegisterLoadedNotify", "CreateBrowserNotifyEvent", "RegisterBrowserNotify",
             "CreateEndOfDxeEvent", "CreateDiscoveryTimer", "SetDiscoveryTimer"]
    rows = []
    for trigger in cases:
        vm = EntryVM(trigger)
        result = vm.call(symbols["efi_main"], 0xcafe, vm.st)
        later = [x["provider"] for x in vm.provider_trace if x["after_retirement"]]
        row = {"trigger": trigger or "none", "entry_return": hex(result), "callback_injected": vm.triggered,
               "actual_callbacks_run": vm.callbacks_run, "retired": vm.retired(),
               "subsequent_boot_service_calls": later, "provider_trace": vm.provider_trace,
               "loaded_image_unload_written": vm.getq(vm.self_li + 0x58) != 0,
               "services_initialized": vm.getd(symbols["services_initialized"])}
        if trigger:
            assert vm.triggered and vm.retired()
            if args.expect_clean:
                assert not later, (trigger, later)
                if trigger == "HandleSelfLoadedImage":
                    assert not row["loaded_image_unload_written"]
        else:
            assert result == 0 and not vm.retired()
        rows.append(row)
    report = {"status": "PASS_NO_POST_RETIREMENT_PROVIDER_CALLS" if args.expect_clean else "BASELINE_REAL_EFI_POST_RETIREMENT_CALLS_OBSERVED",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "driver_sha256": digest, "build_manifest_sha256": hashlib.sha256((build / "build.json").read_bytes()).hexdigest(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": len(rows), "rows": rows,
              "production_changes": False, "device_access": False,
              "limits": ["Synchronous callback delivery is an explicit UEFI provider reentry fixture, not evidence of its physical frequency.",
                         "Real compiled efi_main, initialize_services, password-core initialization and registered BeforeExit/Exit callbacks execute.",
                         "Boot Services remain mapped after retirement deliberately, so all subsequent uses can be observed instead of ending at the first unmapped read.",
                         "No native ASUS BDS boot or password persistence is claimed by these cases."]}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    print(json.dumps({"status": report["status"], "cases": len(rows),
                      "cases_with_post_retirement_calls": sum(bool(r["subsequent_boot_service_calls"]) for r in rows),
                      "output": str(args.output)}))


if __name__ == "__main__":
    main()
