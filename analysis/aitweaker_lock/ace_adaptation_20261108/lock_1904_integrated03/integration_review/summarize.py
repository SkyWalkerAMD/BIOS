"""Summarize the completed integrated-03 regressions without running tests."""
from pathlib import Path
import datetime
import hashlib
import json

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
DRIVER = PROJECT / "driver"
BUILD = DRIVER / "build"
ROOT = next(p for p in PROJECT.parents if (p / "tools/pydeps").is_dir())
EXPECTED = "efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf8"))


def main():
    driver_sha = sha(BUILD / "AiTweakerLock1904.efi")
    assert driver_sha == EXPECTED
    manifest = read(BUILD / "build.json")
    assert manifest["efi_sha256"] == driver_sha
    identities = []
    for base, key in ((PROJECT, "sources"), (ROOT, "external_sources")):
        for rel, expected in manifest[key].items():
            actual = sha(base / rel)
            identities.append({"file": rel, "sha256": actual, "matches_manifest": actual == expected})
    assert all(row["matches_manifest"] for row in identities)
    definitions = [
        ("adapter", "adapter_emulation.json", "cases", "bounded x64 machine-code emulation, OEM functions and services explicitly stubbed"),
        ("history", "history_regression.json", "checks", "original ACE native history/parent functions plus compiled redirect, constructed native page and service fixtures"),
        ("policy", "policy_test.json", "assertions", "pure compiled policy objects linked into a test DLL; exact original 1904 IFR and malformed/fuzz input assertions"),
        ("entropy", "entropy_test.json", "checks", "actual production CPU entropy machine code with controlled CPUID/RDSEED outcomes"),
        ("hii_abi", "hii_abi_test.json", "cases", "actual production callback ABI with explicit owned-session preconditions and adjacent memory canaries"),
    ]
    tests = []
    for name, filename, count_key, scope in definitions:
        data = read(BUILD / filename)
        assert data.get("status") == "PASS" or data.get("passed") is True, name
        assert data.get("driver_sha256", data.get("driver_efi_sha256")) == driver_sha, name
        count = data[count_key]
        if isinstance(count, list):
            count = len(count)
        tests.append({"name": name, "status": "PASS", "checks": count, "scope": scope,
                      "report": "driver/build/" + filename, "report_sha256": sha(BUILD / filename)})
    vm = read(BUILD / "vm_integration.json")
    assert vm["all_passed"] and vm["driver_sha256"] == driver_sha
    assert vm["fixture_sha256"] == sha(BUILD / "VM-INTEGRATION-ONLY.EFI")
    boots = [boot for group in vm["groups"] for boot in group["boots"]]
    assert len(boots) == 6 and all(boot["passed"] for boot in boots)
    assert all(group["medium_sha256_before"] == group["medium_sha256_after"] for group in vm["groups"] if group["readonly_iso"])
    attempts = [read(p) for p in sorted(HERE.glob("*/run_summary.json"))]
    assert len(attempts) >= 7 and all(a["production_efi_unchanged"] for a in attempts)
    summary = {
        "status": "PASS_COMPILED_REGRESSIONS_AND_SIX_OVMF_COLD_BOOTS",
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "production_efi_sha256": driver_sha,
        "production_rebuilt": False,
        "production_sources_modified_by_this_validation": False,
        "test_fixture_modified_by_this_validation": False,
        "production_build_manifest_sha256": sha(BUILD / "build.json"),
        "production_source_identities": identities,
        "regressions": tests,
        "regression_assertions_total": sum(t["checks"] for t in tests),
        "vm": {"driver_sha256": vm["driver_sha256"], "fixture_sha256": vm["fixture_sha256"],
               "firmware_sha256": vm["firmware_sha256"], "report": "driver/build/vm_integration.json",
               "report_sha256": sha(BUILD / "vm_integration.json"),
               "fixture_source_sha256": sha(DRIVER / "vm_fixture.c"),
               "cold_boots": len(boots), "checks_total": sum(b["checks"] for b in boots),
               "boot_seconds": [b["seconds"] for b in boots], "groups": vm["groups"]},
        "attempts": attempts,
        "failed_attempts_preserved": [a for a in attempts if a["exit_code"] != 0],
        "hardware_validation_performed_by_this_agent": False,
        "bmc_actions_performed_by_this_agent": False,
        "scope_limits": [
            "OVMF cold boots exercise production DXE dispatch and unsupported-board refusal, plus an integration application linked from actual services/UI/HII/policy/crypto objects.",
            "The VM integration application deliberately uses a synthetic session owner and scripted console keys; platform.c and the complete ASUS graphical browser are not linked into that application.",
            "Original ACE graphical navigation/session ownership is bounded machine-code emulation, covered separately in owner_review/integrated_owner_regression.json and the adapter/history reports.",
            "VM timings include QEMU TCG and firmware startup, and are not real ASUS latency or boot-performance measurements.",
            "No result here establishes real-board visual behavior, hardware entropy, firmware flash acceptance, or recovery capability.",
        ],
    }
    path = HERE / "integration_validation_summary.json"
    path.write_text(json.dumps(summary, indent=2), encoding="utf8")
    print(json.dumps({"status": summary["status"], "driver_sha256": driver_sha,
                      "regression_assertions": summary["regression_assertions_total"],
                      "vm_cold_boots": len(boots), "vm_checks": summary["vm"]["checks_total"],
                      "vm_boot_seconds": summary["vm"]["boot_seconds"], "summary": str(path)}, indent=2))


if __name__ == "__main__":
    main()
