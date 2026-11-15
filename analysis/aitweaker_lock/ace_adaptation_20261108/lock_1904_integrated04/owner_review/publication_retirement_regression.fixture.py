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
BUILD = BINDING_BUILD
EXPECTED = BINDING_SHA
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



AREA = 0x61000000
DB, STRINGS, CONFIG = AREA, AREA + 0x1000, AREA + 0x2000
HLIST, EXPORT, UPDATE, DRIVER, LANG, NEWSTRING, SETSTRING = [STOP + 0x3000 + 16 * i for i in range(7)]
DBGUID = uuid.UUID("ef9fc172-0a1b2-4693-b327-6d32fc416042".replace("0a1b2", "a1b2")).bytes_le
STRGUID = uuid.UUID("0fd96974-23aa-4cdc-b9cb-98d17750322a").bytes_le
ORIGINAL_PACKAGE = (BASE_FIXTURE / "setup_hii_policy_fixture.bin").read_bytes()


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

