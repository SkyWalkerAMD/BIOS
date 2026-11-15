from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent
F05 = REFERENCE.parent
ROOT = F05.parents[3]

def ref(path):
    data = path.read_bytes()
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

native = REFERENCE / "bmc1313_inputs/usr/local/bin/spx_restservice"
assert ref(native)["sha256"] == "75eef2d473eec66a1751ee4bd1b541c65c33883f5efdcbe85993161033c34596"
operation = F05 / "bmc_postprepare05/operations/spi_log_excerpt.mjs"
fixture = json.loads((HERE / "log_excerpt_fixture.json").read_text())
assert fixture["status"] == "PASS_DUMMY_ONLY_NO_BMC"
assert fixture["source_sha256"] == ref(operation)["sha256"]

report = {
    "schema": "ace1904_prepare_spi_diagnostic_routes_v1",
    "status": "NORMAL_READ_ONLY_LOG_ROUTES_CONFIRMED_OFFLINE",
    "scope": {
        "bmc_version": "ASUS KODO 1.3.13",
        "method": "Previously extracted official binary, installed Ghidra decompilation with resolved ELF literals, matching captured frontend, and official default logging configuration.",
        "new_rea_session": False,
        "bmc_network_requests_by_this_review": 0,
        "hardware_diagnosis_performed": False,
        "actual_failure_context": "Parent reported Prepare HTTP 500/code 1373 after owned Entry, before any CAP/payload upload, flash, or verifyimage command. This generic IPC/initial-upgrade error does not identify the physical failure."
    },
    "identity": {
        "official_image_sha256": "d55f90cba2cf6348d1f8031e44fe8643f77afca50f3384d3521742da2c57fef9",
        "matching_official_and_observed_frontend_sha256": "347723cb88313830ab749787c3ff609aabd2f2ebf9233ad287b286aedf4a7b83",
        "restservice": ref(native)
    },
    "normal_authentication": "Use the already authenticated ordinary web session/cookie jar and X-CSRFTOKEN. These routes do not use update UID and require no update mode, flash action, logging-setting change, or diagnostic generation.",
    "routes": [
        {
            "method": "GET", "path": "/api/settings/log", "parameters": {},
            "native_function": "getSettingsLog_func", "elf_va": "0x35fd8",
            "behavior": "Getter calls AMIGetRemoteLogConfWithPortType and, where applicable, AMIGetLocalLogConf. No setter in this inspected handler.",
            "response": "HTTP 200 object: id, audit_log, system_log, port_type, file_size, rotate_count, port, server_addr, remote, local.",
            "retained_fields": ["system_log", "local", "remote", "file_size", "rotate_count"],
            "system_log_codes": {"0": "disabled", "1": "local", "2": "remote", "3": "local and remote"},
            "privacy": "Do not retain server_addr, port, credentials, headers, or complete response. Returned local/remote values explain whether the current local files may be absent.",
            "errors": "Normal auth failures 401; getter failures 500 with code 0x487/0x488. Do not echo bodies in the collection operation."
        },
        {
            "method": "GET", "path": "/api/logs/system", "parameters": {"level": [3, 5, 6, 8]},
            "native_function": "getSystemLog_func", "elf_va": "0xf80dc",
            "fixed_backend_files": {"3": "/var/log/err.log", "5": "/var/log/warning.log", "6": "/var/log/debug.log", "8": "/var/log/info.log"},
            "behavior": "Integer level selects a fixed file through switch. fileread plus line parsing emits an array. No caller-specified path/file parameter, shell command, file clear, GPIO change, flash, or update preparation in the inspected handler.",
            "response": "HTTP 200 array of {id:integer,timestamp:integer,hostname:string,message:string}; message contains full parsed text before the UI's own shortening.",
            "limitations": [
                "No backend date or pagination option was found in the normal UI/handler; each GET reads the current severity file. Date filtering in the official UI is client side.",
                "Keep original numeric timestamps. The handler parses the timestamp and calls mktime; BMC clock and timezone cannot be assumed to match collector UTC.",
                "Missing/unreadable file returns an empty array; malformed timestamp lines are skipped; rotated files are not returned.",
                "Whole responses exist temporarily in memory, but only the final filtered, redacted excerpt is saved."
            ]
        }
    ],
    "kernel_logging_relevance": {
        "factory_configuration": "Official default rsyslog loads imklog, includes syslog.conf, and routes kernel/system severity messages into the fixed files above. This is evidence of supported logging capability, not proof of the target's current runtime configuration or retention.",
        "known_spi_probe_messages": [
            "[SPI] SPI chip write enable timeout",
            "[SPI]CE%d JEDEC ID = 0x%08X",
            "[SPI]%s read_id buf=0x%s id=%d",
            "[SPI]%s filp_open failed",
            "[SPI]%s kernel_write failed",
            "[%s] not support id 0x%06X",
            "[SPI] Can't match SPI chip"
        ],
        "meaning": "A retained exact driver/probe/JEDEC message could distinguish a narrower failure stage. A missing message, generic 1373, or successful KVM session cannot establish cable connection, SPI capacity, or recoverability.",
        "rom_id": "Kernel probe writes /var/rom_id.tmp, but no supported normal read-only API exposing that runtime file was found. No arbitrary-file request is proposed."
    },
    "excluded_routes": [
        {"path": "/api/system_diagnostics/generate_system_diagnostics_logs", "reason": "Frontend GET initiates generation; it is a mutation, not a passive log read. Native backend/collection contents were not established in the inspected binary set."},
        {"path": "/api/system_diagnostics/download_system_diagnostics_log", "reason": "Only frontend reference found; backend and privacy scope not established. Do not supply arbitrary file names."},
        {"path": "/api/logs/help-data", "reason": "Inspected native handler serves help resources under a fixed web-resource root; it is not a supported general runtime SPI-log reader."},
        {"path": "/api/logs/audit", "reason": "Broader administrative history is unnecessary for this narrow SPI failure diagnosis and may expose user/network metadata."}
    ],
    "operation": {
        "source": ref(operation), "fixture": ref(HERE / "log_excerpt_fixture.json"),
        "fixture_script": ref(HERE / "verify_log_excerpt.mjs"),
        "checks": fixture["case_count"], "dummy_only": True,
        "request_allowlist": ["GET /api/settings/log", "GET /api/logs/system?level=3", "GET /api/logs/system?level=5", "GET /api/logs/system?level=6", "GET /api/logs/system?level=8"],
        "behavior": "No arguments. Requires existing bmcRF.auth.Authorization solely to build in-memory exact-secret replacement. Discards auth-bearing lines, replaces exact known secret variants and long opaque values before truncating. Up to last 40 matching rows per severity, with original timestamps, level, redacted message, and counts. Drops hostname and remote server. All responses must pass HTTP/schema validation before a single exclusive-create output write.",
        "error_output": "SPI_LOG_EXCERPT_FAILED only; no source exception or response body is emitted.",
        "output_relative": "analysis/aitweaker_lock/ace_adaptation_20261108/flash_candidate05/bmc_postprepare05/spi-log-excerpt.json",
        "not_executed_on_bmc_by_reviewer": True,
        "memory_limit": "Temporary decoded Buffer is zeroed and redaction references discarded. JavaScript immutable strings are not claimed to support guaranteed heap erasure."
    },
    "evidence": [ref(HERE / name) for name in [
        "00035fd8-getSettingsLog_func.c", "000f80dc-getSystemLog_func.c",
        "collection_system-log.js", "views_SystemLogView.js", "template-systemlog.js",
        "views_maintenance_SystemDiagnosticsView.js", "logging_config_manifest.json",
        "official_etc_defconfig_rsyslog.conf", "official_etc_defconfig_syslog.conf", "official_etc_init.d_rsyslog"
    ]] + [ref(REFERENCE / "recovery_kernel_decompile/00011154-spi_flash_probe.c")]
}
output = HERE / "diagnostic_routes_review.json"
output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps({"status": report["status"], "report": ref(output)}, ensure_ascii=False))
