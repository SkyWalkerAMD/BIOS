"""Run an integration check while preserving immutable per-attempt evidence.

This helper never calls the production build.  Production EFI identity is
asserted before and after every permitted check.
"""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
DRIVER = HERE.parent / "driver"
EXPECTED = "efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395"
CHECKS = {
    "verify_adapter": "adapter_emulation.json",
    "verify_history": "history_regression.json",
    "verify_policy": "policy_test.json",
    "verify_entropy": "entropy_test.json",
    "verify_hii_abi": "hii_abi_test.json",
    "build_vm": None,
    "run_vm": "vm_integration.json",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    name = sys.argv[1]
    if name not in CHECKS:
        raise SystemExit("Only the listed integration checks are permitted")
    efi = DRIVER / "build/AiTweakerLock1904.efi"
    before = sha(efi)
    assert before == EXPECTED, ("Unexpected production EFI", before)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    attempt = HERE / (stamp + "_" + name)
    attempt.mkdir()
    script = DRIVER / (name + ".py")
    shutil.copy2(script, attempt / script.name)
    result_path = DRIVER / "build" / CHECKS[name] if CHECKS[name] else None
    if result_path and result_path.exists():
        shutil.copy2(result_path, attempt / ("previous_" + result_path.name))
    started = time.monotonic()
    with (attempt / "stdout.log").open("wb") as out, (attempt / "stderr.log").open("wb") as err:
        process = subprocess.run([sys.executable, str(script)], cwd=DRIVER,
                                 stdin=subprocess.DEVNULL, stdout=out, stderr=err)
    after = sha(efi)
    if result_path and result_path.exists():
        shutil.copy2(result_path, attempt / result_path.name)
    summary = {
        "check": name, "exit_code": process.returncode,
        "seconds": round(time.monotonic() - started, 3),
        "production_efi_sha256_before": before,
        "production_efi_sha256_after": after,
        "production_efi_unchanged": before == after == EXPECTED,
        "test_script_sha256": sha(script),
        "attempt_directory": str(attempt),
    }
    (attempt / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
    print(json.dumps(summary, indent=2), flush=True)
    if process.returncode:
        for log in ("stdout.log", "stderr.log"):
            print(log + " tail:\n" + (attempt / log).read_text(encoding="utf8", errors="replace")[-7000:], flush=True)
    assert after == EXPECTED, "Production EFI changed during integration check"
    raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
