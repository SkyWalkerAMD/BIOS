"""Owned, static REA cold-entry review. No target execution or BMC access."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import os
import queue
import subprocess
import threading
import time

BASE = Path(__file__).resolve().parent
ROOT = next(p for p in BASE.parents if (p / "tools/pydeps").is_dir())
PREVIOUS = ROOT / "analysis/aitweaker_lock/ace_adaptation_20261108/integration03_rea_review"
TARGETS = {
    "core_policy": (PREVIOUS / "modules/OriginalDxeCore.efi", [
        ("core-initialization-body", "0x1c34"),
        ("firmware-volume-discovery", "0x9dc0"),
        ("dependency-section-reader", "0x988c"),
    ], []),
    "core": (PREVIOUS / "modules/OriginalDxeCore.efi", [
        ("core-main", "0x1c04"),
        ("dispatcher", "0x9a74"),
        ("schedule-with-ordering", "0x9ccc"),
        ("evaluate-depex", "0xf004"),
    ], [("dispatcher-to-bds", "0x24d4", 91), ("dispatcher-region", "0x9a74", 604)]),
    "bds": (PREVIOUS / "modules/OriginalBds.efi", [
        ("bds-dispatch", "0x26cc"),
        ("end-of-dxe", "0x194c"),
        ("boot-manager-bridge", "0x25ec"),
    ], [("dispatch-table", "0x1b8c0", 544)]),
    "amitse": (ROOT / "analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi", [
        ("main-initializer", "0x1034"),
        ("protocol-installer", "0x2624"),
        ("post-publication-initializer", "0x77f0"),
        ("boot-manager", "0x2780"),
        ("browser-loop", "0xe208"),
        ("external-send-form", "0x20f34"),
    ], [("loop-prefix", "0xe208", 192), ("protocol-methods", "0x6b528", 16)]),
    "notify": (ROOT / "analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi", [
        ("protocol-notify-dispatch", "0x790c"),
        ("late-notify-callback", "0x7798"),
        ("initial-cache-builder", "0xdf40"),
        ("existing-cache-refresh", "0xcdb8"),
        ("poll-original", "0x34b7c"),
    ], [("native-notify-record-table", "0x6adb0", 144)]),
}


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=TARGETS)
    args = parser.parse_args()
    target, functions, byte_ranges = TARGETS[args.target]
    out = BASE / args.target
    out.mkdir(exist_ok=True)
    commands, responses, temp = [out / x for x in ("commands", "responses", "runtime-temp")]
    for directory in (commands, responses, temp):
        directory.mkdir(exist_ok=True)
    seed = out / "seeds.tsv"
    seed.write_text("# Selected ACE1904 original functions for static cold-entry evidence.\n" +
                    "".join(f"{address}\tfunction\tCandidate_ACE1904_{name.replace('-', '_')}\n" for name, address in functions), encoding="utf8")
    node = ROOT / "tools/rea-runtime/node-v26.13.0-win-x64/node.exe"
    rea = ROOT / "tools/rea-runtime/node_modules/rea-agents/scripts/rea.mjs"
    env = os.environ.copy()
    env.update(GHIDRA_INSTALL_DIR=str(ROOT / "tools/rea-hero-12.1.4/ghidra_12.1.4_PUBLIC"),
               JAVA_HOME="D:/JAVA/jdk-27", REA_ANALYSIS_PROVIDER="ghidra",
               REA_GHIDRA_SEED_FILE=str(seed), TEMP=str(temp), TMP=str(temp), NO_COLOR="1")
    plan = [("open", "open_binary", {"path": str(target), "provider_id": "ghidra"})]
    plan += [(name, "analyze_function", {"procedure": address, "detail": "complete"}) for name, address in functions]
    plan += [(name, "read_bytes", {"address": address, "length": length}) for name, address, length in byte_ranges]
    # Individual function responses already retain complete inline Evidence.
    # A large whole-session bundle duplicates those dossiers and exceeds MCP's
    # 10 MiB response budget; summarize the inventory without rerunning analysis.
    plan += [("evidence-bundle", "get_evidence_bundle", {"detail": "summary"})]
    save(out / "plan.json", [{"label": n, "name": t, "arguments": a} for n, t, a in plan])
    log = (out / "rea-stderr.log").open("w", encoding="utf8")
    process = subprocess.Popen([str(node), str(rea), "mcp"], cwd=ROOT, env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                               text=True, encoding="utf8", bufsize=1,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    canonical_seed = "".join(line + "\n" for line in seed.read_text(encoding="utf8").splitlines()
                             if line.strip() and not line.lstrip().startswith("#"))
    save(out / "provenance.json", {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "command": [str(node), str(rea), "mcp"], "controller_pid": os.getpid(), "rea_pid": process.pid,
        "target": str(target), "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "runtime": {k: env[k] for k in ("GHIDRA_INSTALL_DIR", "JAVA_HOME", "REA_ANALYSIS_PROVIDER", "REA_GHIDRA_SEED_FILE")},
        "raw_seed_sha256": hashlib.sha256(seed.read_bytes()).hexdigest(),
        "canonical_seed_sha256": hashlib.sha256(canonical_seed.encode()).hexdigest(),
        "classification": "STATIC_SHIPPED_ARTIFACT_EVIDENCE_NOT_PHYSICAL_COLD_BOOT",
    })
    messages = queue.Queue()

    def reader():
        for line in process.stdout:
            try:
                messages.put(json.loads(line))
            except ValueError:
                messages.put({"transport_text": line})
        messages.put({"transport_eof": True})

    threading.Thread(target=reader, daemon=True).start()
    serial = 0

    def rpc(method, params, timeout=900):
        nonlocal serial
        serial += 1
        request = {"jsonrpc": "2.0", "id": serial, "method": method, "params": params}
        process.stdin.write(json.dumps(request) + "\n")
        process.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                value = messages.get(timeout=min(2, deadline - time.monotonic()))
            except queue.Empty:
                continue
            if value.get("id") == serial:
                return value
            with (out / "notifications.jsonl").open("a", encoding="utf8") as stream:
                stream.write(json.dumps(value) + "\n")
            if value.get("transport_eof"):
                raise RuntimeError("REA connection closed")
        raise TimeoutError(method)

    closed = None
    try:
        save(out / "initialize.json", rpc("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "ace1904-cold-entry-review", "version": "1"}}, 30))
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        process.stdin.flush()
        catalog = rpc("tools/list", {}, 30)
        save(out / "tool-catalog.json", catalog)
        names = {x["name"] for x in catalog["result"]["tools"]}
        for i, (label, name, arguments) in enumerate(plan, 1):
            assert name in names
            request = {"name": name, "arguments": arguments}
            file_name = f"{i:03d}-{label}.json"
            save(commands / file_name, request)
            print("Running", args.target, file_name, flush=True)
            start = time.monotonic()
            response = rpc("tools/call", request)
            save(responses / file_name, response)
            print("Saved", file_name, round(time.monotonic()-start, 2), "seconds", flush=True)
            if response.get("error") or response.get("result", {}).get("isError"):
                raise RuntimeError("REA call failed; inspect " + file_name)
    finally:
        if process.poll() is None:
            try:
                request = {"name": "close_binary", "arguments": {}}
                save(commands / "999-close.json", request)
                closed = rpc("tools/call", request, 60)
                save(responses / "999-close.json", closed)
            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
        log.close()
        save(out / "close-status.json", {"process_exit_code": process.returncode,
                                         "close_response_present": closed is not None,
                                         "closed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})
        print("REA session closed; process exit", process.returncode, flush=True)


if __name__ == "__main__":
    main()
