"""Fault-inject frozen ACE EFI publication and wrapper retirement paths.

Actual compiled attach/HII/policy/wrapper/service retirement code executes in
Unicorn against relocated original ACE modules. Firmware APIs, patch outcomes,
HII storage and complete browser body are explicit fixtures, never hardware.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import uuid

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BUILD = PROJECT / "driver/build"
EXPECTED = "efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(BUILD / "AiTweakerLock1904.efi") == EXPECTED
spec = importlib.util.spec_from_file_location("owner_definitions", HERE / "verify_owner.py")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
ns = owner.load_runtime(BUILD)
for name in ["RuntimeVM", "U", "R", "TSE", "SETUP", "HEAP", "STOP", "symbols", "q", "d", "w", "ERR", "HANDLE", "OC", "OCGUID"]:
    globals()[name] = ns[name]

checks = []
evidence = {"attach": [], "hii": [], "wrapper": []}


def check(name, value):
    assert value, name
    checks.append(name)


class FaultVM(RuntimeVM):
    def __init__(self):
        self.patch_plan = {}
        self.patch_counts = {}
        self.patch_log = []
        self.hii_action = "success"
        self.retirement_return = None
        self.retirement_return_value = None
        self.retirement_done = False
        self.hii_entries = 0
        super().__init__()

    def inject_native_retirement(self, symbol, result):
        target = self.getq(self.u.reg_read(R.UC_X86_REG_RSP))
        self.retirement_return = target
        self.retirement_return_value = result
        self.u.hook_add(U.UC_HOOK_CODE, self.finish_retirement, begin=target, end=target)
        self.u.reg_write(R.UC_X86_REG_RIP, symbols[symbol])

    def finish_retirement(self, u, address, size, data):
        if address == self.retirement_return:
            u.reg_write(R.UC_X86_REG_RAX, self.retirement_return_value)
            self.retirement_return = None
            self.retirement_done = True

    def hook(self, u, address, size, data):
        if address == symbols["patch_memory"]:
            target, source, length = self.arg(0), self.arg(1), self.arg(2)
            ordinal = self.patch_counts.get(target, 0) + 1
            self.patch_counts[target] = ordinal
            action = self.patch_plan.get((target, ordinal), "success")
            before = bytes(u.mem_read(target, length))
            proposed = bytes(u.mem_read(source, length))
            if action in ("success", "copy_then_error"):
                u.mem_write(target, proposed)
            self.patch_log.append({"target": hex(target), "length": length, "ordinal": ordinal,
                                   "action": action, "before": before.hex(),
                                   "proposed": proposed.hex(), "after": bytes(u.mem_read(target, length)).hex()})
            self.patches.append([target, length])
            self.ret(int(action == "success"))
            return
        if address == symbols["install_hii_management"]:
            self.hii_entries += 1
            if self.hii_action == "real":
                return
            if self.hii_action in ("before_exit", "end_only"):
                self.inject_native_retirement("before_exiting" if self.hii_action == "before_exit" else "end_platform", 1)
                return
            self.ret(int(self.hii_action == "success"))
            return
        super().hook(u, address, size, data)

    def attach(self):
        return self.call(symbols["attach_platform"], TSE, 0xa2000, SETUP, 0x1a4000)

    def state_report(self):
        return {"platform_ready": self.getd(symbols["platform_ready"]),
                "publication_attempted": self.getd(symbols["publication_attempted"]),
                "loop_depth": self.getd(symbols["loop_depth"]),
                "mode": self.getd(symbols["password_core"] + 196),
                "active": self.u.mem_read(symbols["password_core"] + 200, 1)[0],
                "unlocked": self.u.mem_read(symbols["password_core"] + 201, 1)[0],
                "token": self.getq(symbols["password_core"] + 168),
                "boot_services_ended": self.getd(symbols["boot_services_ended"]),
                "runtime_guard_present": self.getq(self.rt + 0x58) == symbols["guarded_set"],
                "owned": self.call(symbols["platform_session_owned"]),
                "can_enter": self.call(symbols["platform_can_enter"])}


# Every individual OEM publication can fail before or after its write; when
# rollback succeeds there is no residual OEM hook and the retry latch closes.
targets = [("render", 0x6af78, 8), ("page_input", 0x6af80, 8),
           ("app_input", 0x6ae90, 8), ("navigation", 0x7cb30, 8),
           ("poll", 0x82998, 8), ("frame_prologue", 0x15370, 15),
           ("loop_prologue", 0xe208, 18)]
for name, rva, length in targets:
    for action in ("no_copy_error", "copy_then_error"):
        v = FaultVM()
        original = {label: bytes(v.u.mem_read(TSE + off, n)) for label, off, n in targets}
        v.patch_plan[(TSE + rva, 1)] = action
        result = v.attach()
        residual = [label for label, off, n in targets if bytes(v.u.mem_read(TSE + off, n)) != original[label]]
        count = len(v.patch_log)
        retry = v.attach()
        check(name + "/" + action + ": error with complete OEM rollback and no retry",
              result == 0 and not residual and retry == 0 and len(v.patch_log) == count and v.call(symbols["platform_attach_retry_safe"]) == 0)
        evidence["attach"].append({"case": name + "/" + action, "result": result,
                                   "residual_oem_hooks": residual, "second_attach_result": retry,
                                   "state": v.state_report(), "patch_log": v.patch_log})

# A rollback failure may retain only the loop wrapper while all UI gates have
# reverted. The terminal latch prevents retry but does not prove atomicity.
v = FaultVM()
v.patch_plan[(TSE + 0xe208, 1)] = "copy_then_error"
v.patch_plan[(TSE + 0xe208, 2)] = "no_copy_error"
check("failed loop publication reports failure", v.attach() == 0)
v.start()
state = v.state_report()
before = v.calls["render"]
v.current(1)
v.call(v.getq(TSE + 0x6af78), v.pages[1])
changed = bytearray(26681)
changed[4] = 1
write_status = v.write(OC, OCGUID, changed)
check("residual loop is entered although platform_ready is zero", state["platform_ready"] == 0 and state["loop_depth"] == 1)
check("rollback failure leaves original protected renderer reachable", v.calls["render"] == before + 1)
check("residual wrapper fault state still denies protected write", write_status == ERR(15) and state["can_enter"] == 0)
evidence["attach"].append({"case": "loop_copy_error_and_rollback_error", "state_in_native_body": state,
                           "original_protected_renderer_called": True, "protected_write_status": hex(write_status),
                           "patch_log": v.patch_log})

# HII database and strings providers with the unmodified original ACE forms.
AREA = 0x61000000
DB, STRINGS, CONFIG = AREA, AREA + 0x1000, AREA + 0x2000
HLIST, EXPORT, UPDATE, DRIVER, LANG, NEWSTRING, SETSTRING = [STOP + 0x3000 + 16 * i for i in range(7)]
DBGUID = uuid.UUID("ef9fc172-0a1b2-4693-b327-6d32fc416042".replace("0a1b2", "a1b2")).bytes_le
STRGUID = uuid.UUID("0fd96974-23aa-4cdc-b9cb-98d17750322a").bytes_le
ORIGINAL_PACKAGE = (BUILD / "setup_hii_policy_fixture.bin").read_bytes()


class HiiVM(FaultVM):
    def __init__(self):
        self.package = ORIGINAL_PACKAGE
        self.alloc_cursor = AREA + 0x10000
        self.strings_created = 0
        self.update_calls = 0
        self.update_action = "success"
        super().__init__()
        self.map(AREA, 0x1000000)
        self.u.mem_write(DB + 0x10, q(UPDATE) + q(HLIST) + q(EXPORT))
        self.u.mem_write(DB + 0x50, q(DRIVER))
        self.u.mem_write(STRINGS, q(NEWSTRING) + q(0) + q(SETSTRING) + q(LANG))
        self.u.mem_write(CONFIG, q(SETUP + 0x1500) + q(SETUP + 0x152c) + q(SETUP + 0x1534))
        self.u.mem_write(symbols["setup_hii"], q(0))
        self.hii_action = "real"
        for address in [HLIST, EXPORT, UPDATE, DRIVER, LANG, NEWSTRING, SETSTRING, symbols["alloc"], symbols["release"]]:
            self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)

    def hook(self, u, address, size, data):
        if address == STOP + 0x110:
            guid = bytes(u.mem_read(self.arg(0), 16))
            if guid in (DBGUID, STRGUID):
                u.mem_write(self.arg(2), q(DB if guid == DBGUID else STRINGS))
                self.ret(0)
                return
        if address == HANDLE and self.arg(0) == 0x9911:
            u.mem_write(self.arg(2), q(CONFIG))
            self.ret(0)
            return
        if address == symbols["alloc"]:
            pointer = self.alloc_cursor
            self.alloc_cursor += (self.arg(0) + 15) & ~15
            assert self.alloc_cursor < AREA + 0x1000000
            self.ret(pointer)
            return
        if address == symbols["release"]:
            self.ret(0)
            return
        if address == HLIST:
            u.mem_write(self.arg(3), q(8))
            out = self.argn(4)
            if out:
                u.mem_write(out, q(self.handle))
            self.ret(0 if out else ERR(5))
            return
        if address == EXPORT:
            out = self.arg(3)
            u.mem_write(self.arg(2), q(len(self.package)))
            if out:
                u.mem_write(out, self.package)
            self.ret(0 if out else ERR(5))
            return
        if address == DRIVER:
            u.mem_write(self.arg(2), q(0x9911))
            self.ret(0)
            return
        if address == LANG:
            out = self.arg(2)
            u.mem_write(self.arg(3), q(6))
            if out:
                u.mem_write(out, b"en-US\0")
            self.ret(0 if out else ERR(5))
            return
        if address == NEWSTRING:
            self.strings_created += 1
            u.mem_write(self.arg(2), w(0x100 + self.strings_created))
            self.ret(0)
            return
        if address == SETSTRING:
            self.ret(0)
            return
        if address == UPDATE:
            self.update_calls += 1
            if self.update_action in ("success", "commit_then_error", "commit_then_retire"):
                data_pointer = self.arg(2)
                self.package = bytes(u.mem_read(data_pointer, self.getd(data_pointer + 16)))
            if self.update_action == "commit_then_retire":
                self.inject_native_retirement("before_exiting", 0)
                return
            self.ret(ERR(7) if self.update_action in ("no_commit_error", "commit_then_error") else 0)
            return
        super().hook(u, address, size, data)

    def install(self):
        return self.call(symbols["install_hii_management"], SETUP, 0x1a4000)

    def hii_report(self):
        return {"manager_installed": self.getd(symbols["manager_installed"]),
                "setup_hii": hex(self.getq(symbols["setup_hii"])),
                "route": hex(self.getq(CONFIG + 8)), "callback": hex(self.getq(CONFIG + 16)),
                "native_config": self.getq(CONFIG + 8) == SETUP + 0x152c and self.getq(CONFIG + 16) == SETUP + 0x1534,
                "strings_created": self.strings_created, "update_calls": self.update_calls,
                "package_bytes": len(self.package), "package_sha256": hashlib.sha256(self.package).hexdigest(),
                "retirement_ran": self.retirement_done, **self.state_report()}


for label, patch_action, rollback_action, update_action in [
    ("config_no_copy_error_rollback_success", "no_copy_error", "success", "success"),
    ("config_copy_error_rollback_success", "copy_then_error", "success", "success"),
    ("config_copy_error_rollback_error", "copy_then_error", "no_copy_error", "success"),
    ("update_no_commit_error_rollback_success", "success", "success", "no_commit_error"),
    ("update_no_commit_error_rollback_error", "success", "no_copy_error", "no_commit_error"),
    ("update_commit_error_rollback_success", "success", "success", "commit_then_error"),
]:
    v = HiiVM()
    v.patch_plan[(CONFIG, 1)] = patch_action
    v.patch_plan[(CONFIG, 2)] = rollback_action
    v.update_action = update_action
    first = v.install()
    initial = v.hii_report()
    check(label + ": never claims HII success on failure", first == 0 and initial["manager_installed"] == 0)
    v.patch_plan.clear()
    v.update_action = "success"
    retry = v.install()
    after = v.hii_report()
    expect_retry_success = initial["native_config"] and initial["package_bytes"] == len(ORIGINAL_PACKAGE)
    check(label + ": retry is successful only with intact original callback and forms", bool(retry) == expect_retry_success)
    evidence["hii"].append({"case": label, "first_result": first, "first_state": initial,
                            "second_result": retry, "second_state": after, "patch_log": v.patch_log,
                            "provider_partial_commit_is_synthetic": update_action == "commit_then_error"})

v = HiiVM()
v.update_action = "no_commit_error"
result = v.attach()
state = v.hii_report()
check("attach succeeds while HII publication failed", result == 1 and state["platform_ready"] == 1 and state["manager_installed"] == 0)
evidence["hii"].append({"case": "platform_ready_does_not_mean_HII_ready", "attach_result": result, "state": state})

v = HiiVM()
check("normal actual HII installation succeeds", v.install() == 1)
v.u.mem_write(CONFIG + 8, q(SETUP + 0x152c) + q(SETUP + 0x1534))
v.package = ORIGINAL_PACKAGE
retry = v.install()
check("manager latch returns stale success after provider replacement", retry == 1 and v.hii_report()["native_config"] and len(v.package) == len(ORIGINAL_PACKAGE))
evidence["hii"].append({"case": "stale_success_after_provider_replacement", "second_result": retry, "state": v.hii_report(),
                        "provider_replacement_is_synthetic": True})

# The native wrapper still calls the browser if HII installation fails. It is
# fail-closed for grants; a later successful HII retry cannot recover ap_fault.
v = FaultVM()
check("wrapper fixture attaches", v.attach() == 1)
v.hii_action = "failure"
v.start()
failed = v.state_report()
check("HII failure native body is entered but no session is authorized", failed["loop_depth"] == 1 and failed["mode"] == 3 and failed["active"] == 0 and failed["can_enter"] == 0)
v.end()
v.hii_action = "success"
v.start()
retried = v.state_report()
check("successful later HII retry retains fault mode", retried["mode"] == 3 and retried["active"] == 1 and retried["can_enter"] == 0)
evidence["wrapper"].append({"case": "HII_failure_then_success", "failure_body_state": failed, "next_body_state": retried})

for method in ("end_platform", "before_exiting"):
    v = FaultVM()
    check(method + ": fixture attaches", v.attach() == 1)
    v.start()
    v.call(symbols[method], 0, 0)
    retired = v.state_report()
    v.end()
    returned = v.state_report()
    check(method + ": outstanding wrapper underflows after depth reset", returned["loop_depth"] == 0xffffffff)
    v.body_context = None
    reentry = v.call(TSE + 0xe208)
    check(method + ": subsequent wrapper rejects without grant", reentry == ERR(15) and v.call(symbols["platform_session_owned"]) == 0)
    evidence["wrapper"].append({"case": method + "_during_native_body", "after_retirement": retired,
                                "after_old_wrapper_return": returned, "next_entry_status": hex(reentry),
                                "end_only_is_injected_API_use": method == "end_platform"})

for action in ("before_exit", "end_only"):
    v = FaultVM()
    check(action + ": fixture attaches", v.attach() == 1)
    v.hii_action = action
    v.start()
    state = v.state_report()
    check(action + ": native browser body reached despite retirement during HII", v.retirement_done and state["loop_depth"] == 1)
    if action == "before_exit":
        check("real BeforeExit during HII prevents authorization but not native continuation", state["boot_services_ended"] == 1 and state["owned"] == 0)
    else:
        check("end_platform alone during HII is undone by pending increment", state["owned"] == 1)
    evidence["wrapper"].append({"case": action + "_during_HII_install", "state_in_native_body": state,
                                "HII_body_is_fixture_with_real_retirement_code": True})

check("production EFI remains unchanged", sha(BUILD / "AiTweakerLock1904.efi") == EXPECTED)
report = {"status": "FAILURE_BOUNDARIES_AND_WRAPPER_DEFECTS_REPRODUCED", "driver_sha256": EXPECTED,
          "test_sha256": sha(Path(__file__)), "checks": len(checks), "check_names": checks,
          "original_amitse_sha256": sha(ns["CASE"] / "modules/AMITSE.efi") if "CASE" in ns else "99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5",
          "original_forms_fixture_sha256": hashlib.sha256(ORIGINAL_PACKAGE).hexdigest(),
          "evidence": evidence,
          "scope_limits": [
              "No production source or binary mutation, BMC operation, firmware flashing, or hardware validation.",
              "Actual frozen attach, HII installation, policy insertion, wrapper and BeforeExit code execute in Unicorn; firmware HII APIs and patch outcomes are controlled fixtures.",
              "copy_then_error models patch_memory's documented post-copy page-attribute-restoration failure return; no occurrence of that platform failure is claimed.",
              "Provider partial commit/replacement and end_platform-only calls are adversarial robustness fixtures, not observed vendor behavior.",
              "The native browser body is paused at the original relocated prologue continuation; this does not run the full graphical browser.",
          ]}
(HERE / "publication_retirement_review.json").write_text(json.dumps(report, indent=2), encoding="utf8")
print(json.dumps({"status": report["status"], "checks": len(checks), "driver_sha256": EXPECTED,
                  "attach_cases": len(evidence["attach"]), "hii_cases": len(evidence["hii"]),
                  "wrapper_cases": len(evidence["wrapper"])}, indent=2))
