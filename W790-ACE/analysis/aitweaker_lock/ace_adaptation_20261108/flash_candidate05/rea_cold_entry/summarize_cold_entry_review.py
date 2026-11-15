"""Bind local REA dossiers, original bytes and bounded native execution results."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
BASE = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf8"))


def bound(path):
    path = Path(path).resolve()
    return {"path": str(path.relative_to(ROOT)), "sha256": sha(path), "bytes": path.stat().st_size}


def main():
    sessions = []
    evidence_by_label = {}
    for name in ("amitse", "bds", "notify", "core", "core_policy"):
        folder = HERE / name
        provenance = read(folder / "provenance.json")
        target = Path(provenance["target"])
        assert sha(target) == provenance["target_sha256"]
        pe = pefile.PE(str(target))
        assert pe.OPTIONAL_HEADER.ImageBase == 0
        original_image = pe.get_memory_mapped_image()
        raw_seed = (folder / "seeds.tsv").read_bytes()
        canonical = "".join(row + "\n" for row in raw_seed.decode("utf8").splitlines()
                            if row.strip() and not row.lstrip().startswith("#")).encode()
        assert hashlib.sha256(raw_seed).hexdigest() == provenance["raw_seed_sha256"]
        assert hashlib.sha256(canonical).hexdigest() == provenance["canonical_seed_sha256"]
        rows, errors = [], []
        for response_path in sorted((folder / "responses").glob("*.json")):
            response = read(response_path)
            result = response.get("result", {})
            if response.get("error") or result.get("isError"):
                assert name == "amitse" and response_path.name == "010-evidence-bundle.json"
                errors.append({"response": bound(response_path), "classification": "resource_constraint_whole_bundle_exceeds_10MiB",
                               "complete_individual_function_evidence_retained": True})
                continue
            evidence = result.get("structuredContent", {})
            operation = evidence.get("operation")
            if operation not in ("analyze_function", "read_bytes"):
                continue
            normalized = evidence["normalized_result"]
            row = {"label": response_path.stem, "evidence_id": evidence["evidence_id"],
                   "operation": operation, "provider": evidence["provider"],
                   "request": bound(folder / "commands" / response_path.name), "response": bound(response_path)}
            evidence_by_label[name + "/" + response_path.stem] = evidence["evidence_id"]
            seed_limits = [x for x in evidence["limitations"] if "Ghidra analysis was seeded" in x]
            assert len(seed_limits) == 1 and provenance["canonical_seed_sha256"] in seed_limits[0]
            if operation == "analyze_function":
                procedure = normalized["procedure"]
                row["address"] = procedure["address"]
                row["caller_asserted_name"] = procedure["name"]
                row["original_body_ranges"] = []
                for item in procedure["body"]["ranges"]:
                    start, end = int(item["start"], 16), int(item["end"], 16)
                    code = original_image[start:end+1]
                    assert len(code) == end-start+1
                    row["original_body_ranges"].append({"start": item["start"], "end_inclusive": item["end"],
                        "bytes": len(code), "sha256": hashlib.sha256(code).hexdigest()})
                row["raw_body_hash_meaning"] = "Original mapped-file bytes in Ghidra-reported body ranges; not a decompiler correctness certificate."
                row["pseudocode_present"] = bool(normalized.get("pseudocode"))
                row["assembly_instruction_count"] = len(normalized.get("assembly", []))
            else:
                address = int(normalized["address"], 16)
                code = bytes.fromhex(normalized["bytes_hex"])
                assert normalized["complete"] and len(code) == normalized["requested_bytes"]
                assert code == original_image[address:address+len(code)]
                row.update(address=normalized["address"], bytes=len(code), complete=True,
                           original_file_bytes_equal=True, bytes_sha256=hashlib.sha256(code).hexdigest())
            rows.append(row)
        close = read(folder / "close-status.json")
        close_response = read(folder / "responses/999-close.json")
        assert close["process_exit_code"] == 0 and close["close_response_present"]
        assert close_response["result"]["structuredContent"] == {"result": None}
        sessions.append({"session": name, "target": bound(target), "provenance": bound(folder / "provenance.json"),
            "raw_seed_sha256": provenance["raw_seed_sha256"], "canonical_effective_rows_sha256": provenance["canonical_seed_sha256"],
            "seed_identity_rule": "Remove blank/comment lines, preserve effective TSV rows, join with LF and final LF; Evidence uses this canonical digest.",
            "seeded_names_are_caller_assertions": True, "evidence": rows, "bundle_errors": errors,
            "close_result": close, "close_response": bound(folder / "responses/999-close.json"), "closed_successfully": True})

    build = BASE / "flash_candidate05/lock_1904_candidate05/driver/build"
    candidate = build / "AiTweakerLock1904.efi"
    pin = "71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98"
    assert sha(candidate) == pin
    core = read(HERE / "core_dispatch_sequence.json")
    native = read(HERE / "native_cold_sequence.json")
    lifetime = read(HERE / "entry_lifetime_71b05e.json")
    baseline = read(HERE / "entry_lifetime_463b.json")
    edge = read(HERE / "close_retirement_edge_summary.json")
    assert core["driver_sha256"] == native["driver_sha256"] == lifetime["driver_sha256"] == pin
    assert core["cases"] == 3 and native["cases"] == 6 and lifetime["cases"] == 12
    assert not any(r["subsequent_boot_service_calls"] for r in lifetime["rows"])
    assert all(r["entry_return"] == "0x0" for r in lifetime["rows"])
    assert sum(bool(r["subsequent_boot_service_calls"]) for r in baseline["rows"]) == 10
    alternatives = [
        {"option": "Keep current VariableArch AND VariableWriteArch driver DEPEX", "recommendation": "RECOMMENDED_MINIMUM_FOR_CURRENT_05",
         "guarantee": "On the original ordinary Core path, discovered and eligible images are synchronously started before Core calls BDS; actual driver-before and driver-after orderings both attach before first native loop.",
         "readiness": "Attachment and HII publication remain separately checked; first real owner wrapper revalidates/inserts HII before original cache construction.",
         "does_not_guarantee": "Authentication/load success, arbitrary early/OEM entry, unavailable SMBIOS or target images, resource failure, or universal fail-closed behavior when the driver never runs.",
         "native_modification": "None", "cycle": "No new dependency cycle."},
        {"option": "Driver BEFORE AMITSE DEPEX", "recommendation": "NOT_NEEDED_FOR_PROVED_ORDINARY_ORDER",
         "guarantee": "Core 0x988c recognizes BEFORE and 0x9ccc recursively schedules the referenced predecessor before its target.",
         "readiness": "Ordering does not assert successful initialization, installed hooks or HII readiness.",
         "risk": "BEFORE is treated specially instead of evaluating a normal boolean expression; replacing the current dependency expression can schedule the driver before its variable prerequisites. A safe design needs its own prerequisite checks.",
         "native_modification": "Driver DEPEX only, but changes timing without solving load failure.", "cycle": "Mutual BEFORE/AFTER dependencies could recurse or stall; not proposed."},
        {"option": "Add driver to original APRIORI list", "recommendation": "NOT_NEEDED_AND_NOT_VALIDATED_HERE",
         "guarantee": "Intended to force earlier dispatch only; it does not establish readiness or loading success.",
         "readiness": "Must separately establish services and protocols at the new position.",
         "risk": "Changes the original 20-entry startup schedule; no exact ACE APRIORI scheduling branch replay was performed. Do not claim prerequisite preservation from these results.",
         "native_modification": "Original firmware-volume APRIORI list.", "cycle": "No dependency handshake is added, so it cannot resolve readiness by itself."},
        {"option": "AMITSE DEPEX depends on existing driver status protocol", "recommendation": "AVOID_AS_READINESS_FIX",
         "guarantee": "Protocol existence can enforce a driver-publication ordering, but the present status protocol is installed before notification setup and initial discovery; existence does not mean platform_ready.",
         "readiness": "The current protocol query reports readiness but DEPEX only tests presence.",
         "risk": "If the driver/status installation fails, all AMITSE initialization and its BootManager/FormBrowser2 interfaces can be unavailable. This is broader than denying Ai Tweaker; overall BDS fallback behavior is not established here.",
         "native_modification": "Original AMITSE dependency section.",
         "cycle": "Using a newly published fully-ready protocol instead would deadlock: attach waits for AMITSE FormBrowser2 while AMITSE would wait for attach-ready."},
        {"option": "Native pre-loop EnsureReady handshake", "recommendation": "OPTIONAL_FUTURE_POLICY_CHANGE_NOT_REQUIRED_BY_NORMAL_ORDER",
         "guarantee": "An independently resident original-module call could synchronously test/init the driver before a particular loop; it needs precise ABI and failure behavior proof.",
         "readiness": "A handshake after AMITSE protocol publication avoids the dependency cycle, but whole-loop denial removes the entire common Setup browser for that invocation.",
         "risk": "A selective Ai-only policy requires covering initial page selection and navigation/direct callback paths; one common-loop check is not a complete selective guard. Preserve native boot and unrelated pages; do not patch BDS to manufacture readiness.",
         "native_modification": "New original-module code and hooks, with relocation, byte fingerprints and rollback validation.",
         "cycle": "No cycle if AMITSE initialization remains runnable and the handshake is after protocol publication."},
    ]
    decision = {"status": "RETAIN_CURRENT_05_NO_ADDITIONAL_NATIVE_READINESS_PATCH", "driver_sha256": pin,
                "alternatives": alternatives, "ordinary_path_assumptions": core["conditions"],
                "fault_model_note": "The late-stage4 and absent-driver scenarios demonstrate scope limits; they are not observations that normal physical cold startup failed.",
                "physical_cold_boot_acceptance": "NOT_VERIFIED", "flash_authentication_acceptance": "NOT_VERIFIED"}
    decision_path = HERE / "readiness_options.json"
    decision_path.write_text(json.dumps(decision, indent=2)+"\n", encoding="utf8")
    report = {
        "status": "PASS_CONDITIONAL_COLD_ENTRY_ORDER_REVIEW_WITH_PHYSICAL_ACCEPTANCE_OPEN",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "board": "ASUS Pro WS W790-ACE", "original_bios": "1904", "candidate": bound(candidate),
        "candidate_build_manifest": bound(build / "build.json"),
        "production_sources_modified_by_this_review": False, "bmc_access": False, "firmware_writes": False,
        "recommendation": decision["status"], "readiness_options": bound(decision_path),
        "rea_sessions": sessions,
        "rea_counts": {"sessions": len(sessions), "complete_function_responses": sum(r["operation"] == "analyze_function" for s in sessions for r in s["evidence"]),
                       "read_byte_responses_compared_equal_to_original": sum(r["operation"] == "read_bytes" for s in sessions for r in s["evidence"]),
                       "sessions_closed_successfully": len(sessions)},
        "runtime": {"provider": "Ghidra 12.1.4 via installed REA 6.8 stdio", "java_home": "D:/JAVA/jdk-27",
                    "local_loopback": "Authenticated analysis bridge only; scoped sandbox escalation was used because sandbox loopback is denied.",
                    "seed_names": "Caller assertions; findings require original bytes and observed static control flow, not names alone.",
                    "runner_current_source": bound(HERE / "run_rea.py"), "runner_version_note": "Runner grew new target plans after prior sessions; per-session saved plan/commands/responses are the exact execution record."},
        "static_observations": [
            {"claim": "Core initialization calls dispatcher 0x9a74 at 0x24d4 before BDS architecture Entry at 0x252d.", "evidence": [evidence_by_label["core_policy/002-core-initialization-body"], evidence_by_label["core/006-dispatcher-to-bds"]]},
            {"claim": "Dispatcher drains its queue, rescans eligible discovered images, schedules them and synchronously calls StartImage before returning to BDS.", "evidence": [evidence_by_label["core/003-dispatcher"], evidence_by_label["core/004-schedule-with-ordering"]]},
            {"claim": "Missing DEPEX means all architecture protocol readiness is checked; the original AMITSE FFS has no DEPEX and is absent from APRIORI. Setup DEPEX includes both variable architecture prerequisites used by the candidate.", "evidence": [evidence_by_label["core/005-evaluate-depex"], evidence_by_label["core_policy/004-dependency-section-reader"]], "original_section_inventory": bound(HERE / "core_dispatch_sequence.json")},
            {"claim": "AMITSE main initializer 0x1034 publishes BootManager and FormBrowser2 through 0x2624, then runs 0x77f0 notification registration. This occurs independently of the later native browser loop.", "evidence": [evidence_by_label["amitse/002-main-initializer"], evidence_by_label["amitse/003-protocol-installer"], evidence_by_label["amitse/004-post-publication-initializer"]]},
            {"claim": "Normal BDS table calls EndOfDxe handler at index9 before BootManager bridge at index65; bridge invokes original AMITSE BootManager0x2780 and native Setup calls BrowserLoop0xe208. External SendForm0x20f34 is a separate caller.", "evidence": [evidence_by_label["bds/002-bds-dispatch"], evidence_by_label["bds/003-end-of-dxe"], evidence_by_label["bds/004-boot-manager-bridge"], evidence_by_label["amitse/005-boot-manager"], evidence_by_label["amitse/007-external-send-form"]]},
            {"claim": "BrowserLoop stage4 may be observed after the entry prologue has already run. A later entry patch cannot retroactively create ownership of that invocation.", "evidence": [evidence_by_label["amitse/006-browser-loop"], evidence_by_label["amitse/008-loop-prefix"]]},
            {"claim": "First native cache builder0xdf40 must see the inserted manager package; it also reaches original variable initialization/commit, which must not be blanket blocked as an authenticated user save.", "evidence": [evidence_by_label["notify/004-initial-cache-builder"], evidence_by_label["notify/005-existing-cache-refresh"]]},
            {"claim": "Original poll0x34b7c looks up its provider only when global0x82998 is null. Native notification registration table has no direct assignment to this installed poll proxy slot.", "evidence": [evidence_by_label["notify/006-poll-original"], evidence_by_label["notify/007-native-notify-record-table"], evidence_by_label["notify/002-protocol-notify-dispatch"]]},
        ],
        "bounded_execution_results": [
            {"report": bound(HERE / "core_dispatch_sequence.json"), "cases": 3, "result": core["status"],
             "meaning": "Both ordinary enumeration orders and delayed dependency satisfaction reach BDS with ready=manager=1, stage0, depth0; first native cache sees a real owner."},
            {"report": bound(HERE / "native_cold_sequence.json"), "cases": 6, "result": native["status"],
             "meaning": "Early FormBrowser2 and EndOfDxe paths attach; owner can defer HII until entry; persistent HII absence rejects before cache; late stage4 and absent driver expose explicit scope limits.",
             "callback_address_format_note": "Its native_notification_callbacks_not_executed values are relative to the AMITSE mapping. 0x20001928 denotes BDS RVA0x1928, not an AMITSE RVA."},
            {"report": bound(HERE / "entry_lifetime_463b.json"), "cases": 12, "result": "04_BASELINE_COUNTEREXAMPLE", "post_retirement_provider_call_cases": 10,
             "meaning": "Provider reentry fixture exposes real compiled entry continuation after retirement; this does not claim such reentry occurred in physical firmware."},
            {"report": bound(HERE / "entry_lifetime_71b05e.json"), "cases": 12, "result": lifetime["status"],
             "meaning": "05 returns resident SUCCESS and makes no subsequent provider call at every injected retirement return point."},
            {"report": bound(HERE / "close_retirement_edge_summary.json"), "cases_per_build": 1, "result": edge["status"],
             "meaning": "After BeforeExit event creation fails, retirement during CloseEvent now returns SUCCESS; 04 returned loader error. This is an extra branch beyond the 12-case entry suite."},
        ],
        "ebs_relation": {"existing_original_ACE_core_evidence": bound(BASE / "integration03_rea_review/ace_before_exit_core_support.json"),
                         "existing_production05_validation": "Parent owns EBS81, discovery53 (includes24), source binding and complete save/UI suites; none rerun here.",
                         "contract": "BeforeExit permanently retires local owners and restores the guarded runtime pointer before final Exit; initialization/notification callers must stop after retirement and keep any published callback code resident."},
        "inferences": [
            "No additional AMITSE/BDS/APRIORI change is needed to establish the ordinary successful DXE-to-first-native-loop order under the listed conditions.",
            "Changing AMITSE to depend on a fully-attached ready protocol would create a FormBrowser2 readiness cycle.",
            "Optional driver absence/load failure is a distinct policy question; it is not evidence that current normal scheduling is broken."],
        "unknowns": [
            "Physical permanent-DXE cold boot and actual Del/F2 acquisition have not been accepted by these offline tests.",
            "Original firmware authentication, Boot Guard coverage and supported flash acceptance remain separate open work owned by the parent.",
            "PE authentication/loading, all architecture providers, dynamic page attributes, original notification helper bodies, full native page cache construction/rendering and actual save persistence are not fully emulated.",
            "Any early/OEM entry before ordinary BDS, or native provider callback that reenters Setup during DXE initialization, is outside the demonstrated normal chain.",
            "If the candidate never loads or setup prerequisites never become available, universal selective Ai denial is not established; no blanket BDS/native initialization block is proposed."],
        "counting_note": "Offline scenarios and static function dossiers are different evidence categories; no aggregate is represented as a hardware test count. RAM H02/H03/H04 hardware counts do not establish permanent cold-start acceptance.",
    }
    report_path = HERE / "cold_entry_review_summary.json"
    report_path.write_text(json.dumps(report, indent=2)+"\n", encoding="utf8")
    print(json.dumps({"status": report["status"], "counts": report["rea_counts"], "summary": bound(report_path), "decision": bound(decision_path)}))


if __name__ == "__main__":
    main()
