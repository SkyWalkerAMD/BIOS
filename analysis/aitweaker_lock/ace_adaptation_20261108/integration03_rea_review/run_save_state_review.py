"""Owned static REA session for ACE 1904 original save-state evidence.

This runs the installed analysis engine only. It never executes firmware code
or connects to the BMC. Complete requests and responses remain beside this file.
"""
from pathlib import Path
import datetime
import hashlib
import json
import os
import queue
import subprocess
import threading
import time

BASE = Path(__file__).resolve().parent
OUT = BASE / "save_state_rea"
OUT.mkdir(exist_ok=True)
ROOT = BASE.parents[3]
NODE = ROOT / "tools/rea-runtime/node-v26.13.0-win-x64/node.exe"
REA = ROOT / "tools/rea-runtime/node_modules/rea-agents/scripts/rea.mjs"
TARGET = ROOT / "analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi"
COMMANDS = OUT / "commands"
RESPONSES = OUT / "responses"
TEMP = OUT / "runtime-temp"
for directory in (COMMANDS, RESPONSES, TEMP):
    directory.mkdir(exist_ok=True)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


env = os.environ.copy()
env.update(
    GHIDRA_INSTALL_DIR=str(ROOT / "tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC"),
    JAVA_HOME="D:/JAVA/jdk-27",
    REA_ANALYSIS_PROVIDER="ghidra",
    REA_GHIDRA_SEED_FILE=str(OUT / "seeds.tsv"),
    TEMP=str(TEMP),
    TMP=str(TEMP),
    NO_COLOR="1",
)
plan = [
    ("001-open", "open_binary", {"path": str(TARGET), "provider_id": "ghidra"}),
    ("002-refresh-cache-record", "analyze_function", {"procedure": "0x11d48", "detail": "complete"}),
    ("003-refresh-cache-index", "analyze_function", {"procedure": "0x11d8c", "detail": "complete"}),
    ("004-post-save-reconnect", "analyze_function", {"procedure": "0x29d14", "detail": "complete"}),
    ("005-confirm-save", "analyze_function", {"procedure": "0x19ef4", "detail": "complete"}),
    ("006-save-validation", "analyze_function", {"procedure": "0x32484", "detail": "complete"}),
    ("007-oem-callback-lookup", "analyze_function", {"procedure": "0x5a54", "detail": "complete"}),
    ("008-cache-refresh-bytes", "read_bytes", {"address": "0x11d48", "length": 130}),
    ("009-evidence-bundle", "get_evidence_bundle", {"detail": "complete"}),
]
save(OUT / "plan.json", [{"label": label, "name": name, "arguments": args} for label, name, args in plan])
log = (OUT / "rea-stderr.log").open("w", encoding="utf-8")
proc = subprocess.Popen(
    [str(NODE), str(REA), "mcp"], cwd=ROOT, env=env,
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
    text=True, encoding="utf-8", bufsize=1, creationflags=subprocess.CREATE_NO_WINDOW,
)
save(OUT / "provenance.json", {
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "controller_pid": os.getpid(), "rea_pid": proc.pid,
    "command": [str(NODE), str(REA), "mcp"],
    "target": str(TARGET), "target_sha256": hashlib.sha256(TARGET.read_bytes()).hexdigest(),
    "ghidra": env["GHIDRA_INSTALL_DIR"], "java_home": env["JAVA_HOME"],
    "seed_path": env["REA_GHIDRA_SEED_FILE"],
    "seed_sha256": hashlib.sha256((OUT / "seeds.tsv").read_bytes()).hexdigest(),
    "classification": "STATIC_REA_ANALYSIS_NOT_HARDWARE_EXECUTION",
})
messages = queue.Queue()


def reader():
    for line in proc.stdout:
        try:
            messages.put(json.loads(line))
        except ValueError:
            messages.put({"transport_text": line})
    messages.put({"transport_eof": True})


threading.Thread(target=reader, daemon=True).start()
serial = 0


def rpc(method, params, timeout=900):
    global serial
    serial += 1
    request = {"jsonrpc": "2.0", "id": serial, "method": method, "params": params}
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            value = messages.get(timeout=min(2, end - time.monotonic()))
        except queue.Empty:
            continue
        if value.get("id") == serial:
            return value
        with (OUT / "notifications.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(value) + "\n")
        if value.get("transport_eof"):
            raise RuntimeError("REA connection closed")
    raise TimeoutError(method)


try:
    save(OUT / "initialize.json", rpc("initialize", {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "ace-1904-save-state-review", "version": "1"},
    }, 30))
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()
    catalog = rpc("tools/list", {}, 30)
    save(OUT / "tool-catalog.json", catalog)
    advertised = {tool["name"] for tool in catalog["result"]["tools"]}
    for label, name, arguments in plan:
        assert name in advertised, name
        request = {"name": name, "arguments": arguments}
        save(COMMANDS / (label + ".json"), request)
        print("Running", label, name, flush=True)
        started = time.monotonic()
        response = rpc("tools/call", request)
        save(RESPONSES / (label + ".json"), response)
        print("Saved", label, round(time.monotonic() - started, 2), "seconds", flush=True)
        if response.get("error") or response.get("result", {}).get("isError"):
            raise RuntimeError("REA call failed; inspect " + label)
finally:
    if proc.poll() is None:
        try:
            request = {"name": "close_binary", "arguments": {}}
            save(COMMANDS / "010-close.json", request)
            response = rpc("tools/call", request, 60)
            save(RESPONSES / "010-close.json", response)
        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=45)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=10)
    log.close()
    print("REA session closed; process exit", proc.returncode, flush=True)
