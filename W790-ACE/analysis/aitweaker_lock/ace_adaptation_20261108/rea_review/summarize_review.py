"""Produce a compact ledger from retained, real REA responses."""
from pathlib import Path
import hashlib
import json
import sys
import zlib

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile


def read(label):
    path = OUT / "responses" / (label + ".json")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert "error" not in document, label
    result = document["result"]
    assert not result.get("isError"), label
    payload = result.get("structuredContent")
    if payload is None:
        payload = json.loads(next(c["text"] for c in result["content"] if c["type"] == "text"))
    return payload, path


provenance = json.loads((OUT / "provenance.json").read_text(encoding="utf-8"))
target = Path(provenance["target"])
pe = pefile.PE(str(target))
original = pe.get_memory_mapped_image()
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
function_records = []
for label in ("002-history-parent", "003-history-append"):
    evidence, path = read(label)
    result = evidence["normalized_result"]
    (OUT / (label + ".c")).write_text(result["pseudocode"], encoding="utf-8")
    function_records.append({
        "response": str(path.relative_to(ROOT)), "response_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "evidence_id": evidence["evidence_id"], "operation": evidence["operation"],
        "procedure_address": result["procedure"]["address"],
        "analyst_seed_name": result["procedure"]["name"],
        "provider": evidence["provider"], "analysis_profile_digest": evidence["analysis_profile"]["digest"],
        "subject_sha256": evidence["subject"]["digest"]["sha256"],
        "relationship_coverage": evidence["relationship_coverage"],
        "limitations": evidence["limitations"],
    })
reads = []
for label in ("004-parent-bytes", "005-append-bytes", "006-globals"):
    evidence, path = read(label)
    result = evidence["normalized_result"]
    start = int(result["address"], 16)
    data = bytes.fromhex(result["bytes_hex"])
    match = data == original[start:start + len(data)]
    assert result["complete"] and match, label
    reads.append({"response": str(path.relative_to(ROOT)), "evidence_id": evidence["evidence_id"],
                  "address": result["address"], "requested_bytes": result["requested_bytes"],
                  "returned_bytes": result["returned_bytes"], "complete": result["complete"],
                  "sha256": hashlib.sha256(data).hexdigest(), "equals_original_mapped_file_bytes": match})
close, close_path = read("008-close")
offsets = json.loads((OUT / "original_byte_offset_review.json").read_text(encoding="utf-8"))
parent_id = function_records[0]["evidence_id"]
append_id = function_records[1]["evidence_id"]
report = {
    "status": "PASS_STATIC_REVIEW",
    "classification": "STATIC_REA_AND_ORIGINAL_BYTE_REVIEW_NOT_HARDWARE_EXECUTION",
    "target": {"board": "ASUS Pro WS W790-ACE", "bios_version": "1904", "module": "AMITSE",
               "path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
               "text_crc32": f"{zlib.crc32(original[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]) & 0xffffffff:08X}"},
    "runtime": {"rea": "6.8.0", "provider": function_records[0]["provider"],
                "ghidra_path": provenance["ghidra"], "seed_sha256": provenance["seed_sha256"],
                "seed_sha256_scope": "Raw seeds.tsv file bytes including comments; captured at execution start",
                "rea_canonical_seed_sha256": read("002-history-parent")[0]["analysis_profile"]["parameters"]["analysis_seeds"]["sha256"],
                "rea_canonical_seed_sha256_scope": "Parsed effective entries serialized as lowercase-address TSV with LF; excludes comments and blank lines",
                "seed_identity_note": "seed_identity_note.json"},
    "execution_recovery": {
        "first_attempt": "attempt1-loopback-blocked",
        "initial_error": "provider_timeout at authenticated-loopback bridge readiness; Ghidra auto-analysis itself completed in 23 seconds",
        "confirmed_blocker": "Separate localhost TCP connect returned PermissionError WinError 10013 in the sandbox",
        "recovery": "The same local-only static REA script was allowed through a scoped sandbox escalation; no client/global configuration was changed",
        "second_attempt": "All seven planned calls succeeded; final close_binary returned result null and the owned REA process exited 0",
    },
    "functions": function_records,
    "analysis_bytes_checked_against_original": reads,
    "observations": [
        {"claim": "History parent lookup is at RVA 0x1017c; it uses 32-byte records, key fields +0/+8 and parent fields +0x10/+0x18.", "evidence_ids": [parent_id]},
        {"claim": "History append at RVA 0x10270 copies the previous last record's key into the new record's parent fields; changing app.current alone does not rewrite the existing history root.", "evidence_ids": [append_id]},
        {"claim": "Referenced globals: application pointer 0x82748, root-search lower bound 0x82754, record capacity 0x82758, record-buffer pointer 0x82760, used count 0x82778.", "evidence_ids": [parent_id, append_id]},
        {"claim": "Original PageInput calls parent/append/dispatcher at verified sites; the original 0x6af80 slot stores 0x16c70 and the formset-table pointer at 0x92268 is referenced by PageInput 0x16fe8.", "source": "original_byte_offset_review.json", "evidence_type": "ordinary PE and Capstone original bytes"},
    ],
    "inferences": [
        {"claim": "The SAGE history-root correction is applicable to ACE 1904 after using the independently resolved ACE addresses and retaining pointer, range, ownership, and writeability checks.", "basis": [parent_id, append_id, "original_byte_offset_review.json"], "validation_required": "Execute ACE original history/PageInput bytes with the newly compiled ACE implementation; hardware UI remains a separate step."},
    ],
    "unknowns": [
        "Static analysis does not observe the current BMC host, its loaded modules, BIOS UI, passwords, or runtime history allocation.",
        "Analyst seed names and starts are supplied annotations; REA provider limitations and unresolved indirect call coverage remain as recorded.",
        "Zero initial values in static global storage do not establish any runtime global value.",
        "This review does not establish ASUS graphical, EZ, search, direct Del/F2, firmware deployment, flash acceptance, or reboot persistence behavior.",
    ],
    "original_byte_comparison": {"path": "original_byte_offset_review.json", "status": offsets["status"],
                                 "sha256": hashlib.sha256((OUT / "original_byte_offset_review.json").read_bytes()).hexdigest(),
                                 "normalized_function_pairs": len(offsets["pairs"]),
                                 "all_pairs_match": all(p["same_normalized_instruction_sequence"] for p in offsets["pairs"]),
                                 "limitations": offsets["limitations"]},
    "close": {"response": str(close_path.relative_to(ROOT)), "result": close,
              "response_sha256": hashlib.sha256(close_path.read_bytes()).hexdigest()},
}
(OUT / "rea_review_summary.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps({"status": report["status"], "target": report["target"],
                  "evidence_ids": [f["evidence_id"] for f in function_records], "close": close}, indent=2))
