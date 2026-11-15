"""Narrow error branch: BeforeExit registration fails, CloseEvent retires.

Uses the real compiled entry/initialize_services and previously registered Exit
callback. Derivation is explicit and leaves the earlier 12-case fixture intact.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1]
original = HERE / "verify_entry_lifetime.py"
source = original.read_text(encoding="utf8")
insertion = '                handle = HEAP + 0x1f9000 + len(self.events) * 0x20\n'
assert source.count(insertion) == 1
source = source.replace(insertion,
    '                if label == "CreateBeforeExitEvent":\n'
    '                    self.finish_provider(label, (1 << 63) | 7)\n'
    '                    return\n' + insertion)
start = source.index('    cases = [None, "CreateExitEvent"')
end = source.index('    rows = []', start)
source = source[:start] + '    cases = ["CloseEvent"]\n' + source[end:]
derived = HERE / "close_retirement_edge.fixture.py"
derived.write_text(source, encoding="utf8")
rows = []
for label, build, expected in [
    ("463b", BASE / "lock_1904_integrated04/driver/build", "0x8000000000000007"),
    ("71b05e", BASE / "flash_candidate05/lock_1904_candidate05/driver/build", "0x0"),
]:
    out = HERE / ("close_retirement_edge_" + label + ".json")
    command = [sys.executable, str(derived), "--build", str(build), "--output", str(out)]
    if label == "71b05e":
        command += ["--expect-clean"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    report = json.loads(out.read_text(encoding="utf8"))
    row = report["rows"][0]
    assert row["entry_return"] == expected and row["retired"]
    assert row["actual_callbacks_run"] == ["CreateExitEvent"]
    assert not row["subsequent_boot_service_calls"] and not row["services_initialized"]
    rows.append({"build": label, "driver_sha256": report["driver_sha256"], "entry_return": row["entry_return"],
                 "commands": command, "report": out.name, "report_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
                 "stdout": result.stdout, "stderr": result.stderr})
summary = {"status": "PASS_05_RETURNS_RESIDENT_SUCCESS_AFTER_CLOSEEVENT_RETIREMENT",
           "baseline_04_returns_loader_error_after_registered_callback_retirement": True,
           "cases_per_build": 1, "rows": rows,
           "base_source_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
           "derived_source_sha256": hashlib.sha256(derived.read_bytes()).hexdigest(),
           "limitations": ["Deliberate provider-reentry fault injection, not evidence that physical normal initialization triggers ExitBootServices.",
                           "Failure of BeforeExit creation is explicit; its callback is never registered in this scenario.",
                           "Only the real previously registered Exit callback runs while CloseEvent is returning.",
                           "No production source or image was modified."]}
(HERE / "close_retirement_edge_summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf8")
print(summary["status"])
