"""Execute the bounded publication/retirement regression on a supplied EFI.

Reuses the frozen integrated03 fault providers and original ACE image fixtures;
does not execute or rebuild the production driver on the Windows host.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import time

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BASE = PROJECT.parent / "lock_1904_integrated03"
TEMPLATE = BASE / "owner_review/verify_publication_retirement.py"
BASE_SHA = "efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-folder", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build = args.build_folder.resolve()
    manifest = json.loads((build / "build.json").read_text(encoding="utf8"))
    digest = sha(build / "AiTweakerLock1904.efi")
    assert digest == manifest["efi_sha256"]
    assert sha(BASE / "driver/build/AiTweakerLock1904.efi") == BASE_SHA
    for rel, expected in manifest["sources"].items():
        assert sha(build.parent.parent / rel) == expected, rel
    source = TEMPLATE.read_text(encoding="utf8")
    prefix = source[:source.index("# Every individual OEM publication")]
    prefix = prefix.replace('BUILD = PROJECT / "driver/build"', "BUILD = BINDING_BUILD")
    prefix = prefix.replace('EXPECTED = "' + BASE_SHA + '"', "EXPECTED = BINDING_SHA")
    hii = source[source.index("AREA = 0x61000000"):source.index("\nfor label, patch_action,")]
    hii = hii.replace('(BUILD / "setup_hii_policy_fixture.bin")', '(BASE_FIXTURE / "setup_hii_policy_fixture.bin")')
    effective = prefix + "\n" + hii
    args.output.parent.mkdir(parents=True, exist_ok=True)
    effective_path = args.output.with_suffix(".fixture.py")
    effective_path.write_text(effective, encoding="utf8")
    ns = {"__file__": str(TEMPLATE), "BINDING_BUILD": build, "BINDING_SHA": digest, "BASE_FIXTURE": BASE / "driver/build"}
    exec(compile(effective, str(effective_path), "exec"), ns)
    for name in ["FaultVM", "HiiVM", "U", "R", "TSE", "SETUP", "HEAP", "STOP", "symbols", "q", "d", "w", "ERR", "DB", "CONFIG", "HLIST", "EXPORT", "UPDATE", "DRIVER", "LANG", "NEWSTRING", "SETSTRING", "HANDLE", "ORIGINAL_PACKAGE"]:
        globals()[name] = ns[name]
    checks, evidence = [], {"attach": [], "hii": [], "wrapper": [], "live_ifr": []}

    def check(name, value):
        assert value, name
        checks.append(name)

    def enter(v):
        v.body_context = None
        status = v.call(TSE + 0xe208)
        return status, v.body_context is not None

    targets = [("render", 0x6af78, 8), ("page_input", 0x6af80, 8), ("app_input", 0x6ae90, 8),
               ("navigation", 0x7cb30, 8), ("poll", 0x82998, 8), ("frame", 0x15370, 15),
               ("save_iterator", 0x142ac, 18), ("save_stay", 0x440fc, 16), ("loop", 0xe208, 18)]
    for label, rva, length in targets:
        for action in ("no_copy_error", "copy_then_error"):
            v = FaultVM()
            original = {name: bytes(v.u.mem_read(TSE + off, n)) for name, off, n in targets}
            v.patch_plan[(TSE + rva, 1)] = action
            first = v.attach()
            residual = [name for name, off, n in targets if bytes(v.u.mem_read(TSE + off, n)) != original[name]]
            count = len(v.patch_log)
            second = v.attach()
            check(label + "/" + action + ": rollback remains complete and retry remains terminal",
                  first == second == 0 and not residual and len(v.patch_log) == count and v.call(symbols["platform_attach_retry_safe"]) == 0)
            evidence["attach"].append({"case": label + "/" + action, "first": first, "second": second, "residual": residual})
    v = FaultVM()
    v.patch_plan[(TSE + 0xe208, 1)] = "copy_then_error"
    v.patch_plan[(TSE + 0xe208, 2)] = "no_copy_error"
    check("residual loop fixture reports failed publication", v.attach() == 0)
    status, body = enter(v)
    check("residual loop refuses entry without platform_ready", status == ERR(15) and not body and v.getd(symbols["loop_depth"]) == 0)
    evidence["attach"].append({"case": "failed loop publication and failed rollback", "status": hex(status), "body_entered": body, "state": v.state_report()})

    for label, rva in (("save_iterator", 0x142ac), ("save_stay", 0x440fc)):
        v = FaultVM()
        v.patch_plan[(TSE + rva, 1)] = "copy_then_error"
        v.patch_plan[(TSE + rva, 2)] = "no_copy_error"
        check(label + ": failed publication remains not ready", v.attach() == 0 and v.getd(symbols["platform_ready"]) == 0)
        result = v.call(TSE + rva)
        check(label + ": retained residual entry is permanently retired", result == 0 and v.call(symbols["platform_attach_retry_safe"]) == 0)
        evidence["attach"].append({"case": label + " failed rollback", "residual_call_result": result, "state": v.state_report()})

    for method in ("end_platform", "before_exiting"):
        v = FaultVM()
        check(method + ": attaches", v.attach() == 1)
        v.start()
        v.call(symbols[method], 0, 0)
        v.end()
        state = v.state_report()
        check(method + ": old wrapper preserves zero retired depth", state["loop_depth"] == 0 and state["active"] == 0 and state["owned"] == 0)
        status, body = enter(v)
        check(method + ": retired wrapper cannot create a new session", status == ERR(15) and not body)
        v.state(2, 1, 1)
        check(method + ": explicit disabled mode cannot undo retirement", v.call(symbols["platform_can_enter"]) == 0)
        evidence["wrapper"].append({"case": method + " during native body", "state_after_return": state, "reentry": hex(status)})

    for action in ("before_exit", "end_only"):
        v = FaultVM()
        check(action + ": attaches", v.attach() == 1)
        v.hii_action = action
        status, body = enter(v)
        state = v.state_report()
        check(action + ": HII-time retirement prevents native body", v.retirement_done and status == ERR(15) and not body and state["loop_depth"] == 0 and state["owned"] == 0)
        evidence["wrapper"].append({"case": action + " during HII", "status": hex(status), "body_entered": body, "state": state})

    v = FaultVM()
    check("HII failure fixture attaches", v.attach() == 1)
    v.hii_action = "failure"
    status, body = enter(v)
    check("HII install failure refuses browser body and clears readiness", status == ERR(15) and not body and v.getd(symbols["platform_ready"]) == 0 and v.getd(symbols["password_core"] + 196) == 3)
    v.hii_action = "success"
    previous = v.hii_entries
    second, body = enter(v)
    check("failed browser management is not silently retried into a new session", second == ERR(15) and not body and v.hii_entries == previous)
    evidence["wrapper"].append({"case": "HII install failure", "state": v.state_report(), "first": hex(status), "second": hex(second)})

    class ReentrantVM(FaultVM):
        def __init__(self):
            self.reentrant = False
            self.inner_status = None
            super().__init__()

        def hook(self, u, address, size, data):
            if address == symbols["install_hii_management"] and self.reentrant:
                self.inject_native_retirement("browser_loop", 1)
                return
            super().hook(u, address, size, data)

        def finish_retirement(self, u, address, size, data):
            if address == self.retirement_return:
                self.inner_status = u.reg_read(R.UC_X86_REG_RAX)
            super().finish_retirement(u, address, size, data)

    v = ReentrantVM()
    check("reentrant fixture attaches", v.attach() == 1)
    v.reentrant = True
    status, body = enter(v)
    check("HII notification cannot recursively begin another owner", body and v.inner_status == ERR(15) and v.getq(symbols["password_core"] + 168) == 1 and v.getd(symbols["loop_depth"]) == 1)
    v.reentrant = False
    outer = v.body_context
    v.u.mem_write(symbols["password_core"] + 201, b"\x01")
    v.call(TSE + 0xe208)
    check("ordinary nested wrapper remains authorized", v.getd(symbols["loop_depth"]) == 2 and v.call(symbols["platform_can_enter"]) == 1)
    v.end(0x11223344)
    v.body_context = outer
    check("ordinary nested return preserves outer grant", v.getd(symbols["loop_depth"]) == 1 and v.call(symbols["platform_can_enter"]) == 1)
    v.end()
    check("ordinary outer return closes owner", v.getd(symbols["loop_depth"]) == 0 and v.call(symbols["platform_session_owned"]) == 0)
    evidence["wrapper"].append({"case": "HII reentry versus ordinary native nesting", "inner_status": hex(v.inner_status), "normal_nesting_passed": True})

    for label, patch, rollback, update in [
        ("config no-copy error", "no_copy_error", "success", "success"),
        ("config post-copy error", "copy_then_error", "success", "success"),
        ("config post-copy error and failed rollback", "copy_then_error", "no_copy_error", "success"),
        ("database error without commit", "success", "success", "no_commit_error"),
        ("database error and failed callback rollback", "success", "no_copy_error", "no_commit_error"),
        ("database error after partial commit", "success", "success", "commit_then_error"),
        ("database false success without commit", "success", "success", "success_without_commit"),
    ]:
        v = HiiVM()
        v.patch_plan[(CONFIG, 1)] = patch
        v.patch_plan[(CONFIG, 2)] = rollback
        v.update_action = update
        first = v.install()
        state = v.hii_report()
        check(label + ": publication failure is latched and reported", first == 0 and state["manager_installed"] == 0 and v.getd(symbols["manager_failed"]) == 1 and state["mode"] == 3)
        count, strings, updates = len(v.patch_log), v.strings_created, v.update_calls
        v.patch_plan.clear()
        v.update_action = "success"
        retry = v.install()
        check(label + ": no blind retry after failed publication", retry == 0 and len(v.patch_log) == count and v.strings_created == strings and v.update_calls == updates)
        evidence["hii"].append({"case": label, "first": first, "second": retry, "state": state, "patch_log": v.patch_log})

    v = HiiVM()
    started = time.monotonic()
    check("normal real HII installation and readback succeed", v.install() == 1)
    valid_package = v.package
    count, strings = v.update_calls, v.strings_created
    check("installed manager verifies live state without republishing", v.install() == 1 and v.update_calls == count and v.strings_created == strings)
    normal_seconds = time.monotonic() - started

    def records(package):
        found = []
        p = 20
        while p < len(package):
            header = int.from_bytes(package[p:p+4], "little")
            length, kind = header & 0xffffff, header >> 24
            if kind == 2:
                offset = p + 4
                while offset < p + length:
                    op, size = package[offset], package[offset+1] & 127
                    found.append((offset, op, size, p))
                    offset += size
            p += length
        return found

    parsed = records(valid_package)
    actions = {int.from_bytes(valid_package[off+6:off+8], "little"): (off, package_start)
               for off, op, size, package_start in parsed if op == 12 and size >= 13 and int.from_bytes(valid_package[off+6:off+8], "little") in (0xffe0, 0xffe1)}
    set_at, form_package = actions[0xffe0]
    clear_at = actions[0xffe1][0]
    security_at = next(off for off, op, size, _ in parsed if op == 1 and int.from_bytes(valid_package[off+2:off+4], "little") == 0x271e)
    formset_at = next(off for off, op, _, _ in parsed if op == 0x0e)

    def changed(offset, raw):
        package = bytearray(valid_package)
        package[offset:offset+len(raw)] = raw
        return bytes(package)

    def splice(offset, remove, raw):
        package = bytearray(valid_package[:offset] + raw + valid_package[offset+remove:])
        delta = len(raw) - remove
        struct.pack_into("<I", package, 16, len(package))
        old_header = int.from_bytes(package[form_package:form_package+4], "little")
        struct.pack_into("<I", package, form_package, old_header + delta)
        return bytes(package)

    mutants = [
        ("all management actions removed", ns["ORIGINAL_PACKAGE"]),
        ("clear action missing", splice(clear_at, 15, b"")),
        ("duplicate set action", splice(set_at, 0, valid_package[set_at:set_at+15])),
        ("clear reuses set ID", changed(clear_at + 6, w(0xffe0))),
        ("wrong form", changed(security_at + 2, w(0x271d))),
        ("wrong formset", changed(formset_at + 2, b"\xff")),
        ("callback flag absent", changed(set_at + 12, b"\0")),
        ("callback extra question flags", changed(set_at + 12, b"\x05")),
        ("wrong question opcode", changed(set_at, b"\x07")),
        ("action acquires nested scope", changed(set_at + 1, b"\x8f")),
        ("question varstore assigned", changed(set_at + 8, w(29))),
        ("question offset changed", changed(set_at + 10, w(0))),
        ("config string assigned", changed(set_at + 13, w(1))),
        ("zero prompt", changed(set_at + 2, w(0))),
        ("zero help", changed(set_at + 4, w(0))),
        ("hidden inside conditional scope", splice(set_at, 15, b"\x0a\x82" + valid_package[set_at:set_at+15] + b"\x29\x02")),
        ("package list size mismatch", changed(16, d(len(valid_package)+1))),
        ("malformed form package length", changed(form_package, d(0x02000003))),
        ("truncated package end", valid_package[:-1]),
    ]
    for label, package in mutants:
        v.package = package
        result = v.call(symbols["manager_live"], DB, v.handle, CONFIG)
        check(label + ": live IFR rejected", result == 0)
        evidence["live_ifr"].append({"case": label, "result": result, "package_sha256": hashlib.sha256(package).hexdigest()})
    v.package = valid_package
    check("bounded validator still accepts intact live package", v.call(symbols["manager_live"], DB, v.handle, CONFIG) == 1)

    for label in ("ConfigAccess callback replaced", "ConfigAccess route replaced", "IFR actions removed"):
        v = HiiVM()
        check(label + ": initial manager installs", v.install() == 1)
        if label.startswith("ConfigAccess callback"):
            v.u.mem_write(CONFIG + 16, q(SETUP + 0x1534))
        elif label.startswith("ConfigAccess route"):
            v.u.mem_write(CONFIG + 8, q(SETUP + 0x152c))
        else:
            v.package = ns["ORIGINAL_PACKAGE"]
        first = v.install()
        check(label + ": installed latch cannot report stale success", first == 0 and v.getd(symbols["manager_installed"]) == 0 and v.getd(symbols["manager_failed"]) == 1)
        check(label + ": stale manager fails credential mode", v.getd(symbols["password_core"] + 196) == 3)
        evidence["hii"].append({"case": label, "result": first, "state": v.hii_report()})

    class RetirementHiiVM(HiiVM):
        def __init__(self):
            self.post_retirement_calls = []
            super().__init__()

        def hook(self, u, address, size, data):
            watched = [STOP + 0x110, HANDLE, HLIST, EXPORT, UPDATE, DRIVER, LANG, NEWSTRING, SETSTRING, symbols["alloc"], symbols["release"]]
            if address in watched and self.getd(symbols["boot_services_ended"]):
                self.post_retirement_calls.append(hex(address))
            super().hook(u, address, size, data)

    v = RetirementHiiVM()
    v.update_action = "commit_then_retire"
    result = v.install()
    check("real BeforeExit inside database update prevents manager success", result == 0 and v.getd(symbols["boot_services_ended"]) == 1 and v.getd(symbols["manager_failed"]) == 1)
    check("HII retirement continuation performs no provider or pool calls", not v.post_retirement_calls)
    evidence["hii"].append({"case": "BeforeExit during UpdatePackageList", "result": result, "state": v.hii_report(), "post_retirement_calls": v.post_retirement_calls})

    check("frozen integrated03 driver unchanged", sha(BASE / "driver/build/AiTweakerLock1904.efi") == BASE_SHA)
    check("tested driver identity unchanged", sha(build / "AiTweakerLock1904.efi") == digest)
    report = {"status": "PASS_PUBLICATION_RETIREMENT_AND_LIVE_HII_GUARDS", "driver_sha256": digest,
              "build_manifest_sha256": sha(build / "build.json"), "baseline_driver_sha256": BASE_SHA,
              "baseline_counterexample_report": str(BASE / "owner_review/publication_retirement_review.json"),
              "checks": len(checks), "check_names": checks, "evidence": evidence,
              "normal_HII_install_plus_revalidation_emulation_seconds": round(normal_seconds, 3),
              "sources": {str(p): sha(p) for p in [Path(__file__), TEMPLATE, effective_path]},
              "hardware_validation_performed": False,
              "limits": [
                  "Actual compiled attach, HII policy/publication, wrapper and BeforeExit paths execute against relocated original ACE modules in Unicorn.",
                  "Firmware HII APIs, patch success/partial-write outcomes, allocation and complete OEM browser body are explicit fixtures.",
                  "copy_then_error fixtures model bytes and return status; real memory-attribute restoration failures also fault the core and cannot improve authorization.",
                  "Live HII is validated on installation and each outer wrapper entry; this does not prove OEM page-cache refresh or detection of changes after that boundary.",
                  "Provider exports are capped at 4 MiB with scope depth 64. Validation performs no scan per key event or render.",
                  "Irrecoverable partial publication remains terminal; no claim of transactional rollback or safe reinstallation is made.",
                  "No BMC, real flash, physical machine or real graphical BIOS performance was tested by this agent.",
              ]}
    args.output.write_text(json.dumps(report, indent=2), encoding="utf8")
    print(json.dumps({"status": report["status"], "checks": len(checks), "driver_sha256": digest,
                      "live_ifr_cases": len(evidence["live_ifr"]), "report": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
