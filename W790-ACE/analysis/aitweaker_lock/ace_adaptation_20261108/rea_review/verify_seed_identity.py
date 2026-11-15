"""Explain raw-file versus REA canonical seed identity without rerunning REA."""
from pathlib import Path
import hashlib
import json

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
raw = (OUT / "seeds.tsv").read_bytes()
rows = []
for raw_line in raw.decode("utf-8").split("\n"):
    line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
    if not line.strip() or line.startswith("#"):
        continue
    fields = line.split("\t")
    fields[0] = hex(int(fields[0], 16))
    rows.append("\t".join(fields) + "\n")
canonical = "".join(rows).encode("utf-8")
raw_sha = hashlib.sha256(raw).hexdigest()
canonical_sha = hashlib.sha256(canonical).hexdigest()
provenance = json.loads((OUT / "provenance.json").read_text(encoding="utf-8"))
assert raw_sha == provenance["seed_sha256"]
evidence = []
for label in ("002-history-parent", "003-history-append"):
    path = OUT / "responses" / (label + ".json")
    record = json.loads(path.read_text(encoding="utf-8"))["result"]["structuredContent"]
    commitment = record["analysis_profile"]["parameters"]["analysis_seeds"]
    assert canonical_sha == commitment["sha256"]
    evidence.append({"response": str(path.relative_to(ROOT)), "evidence_id": record["evidence_id"],
                     "analysis_seed_commitment": commitment})
provider = ROOT / "tools/rea-runtime/node_modules/rea-agents/dist/ghidra/GhidraAnalysisSeeds.js"
bridge = ROOT / "tools/rea-runtime/node_modules/rea-agents/bridge/ghidra/ReaGhidraApplySeeds.java"
note = {
    "status": "PASS_RAW_AND_CANONICAL_IDENTITIES_RECONCILED",
    "scope": "Read existing seed bytes, retained Evidence and installed provider implementation; no REA analysis rerun",
    "raw_file": {"path": str((OUT / "seeds.tsv").relative_to(ROOT)), "bytes": len(raw), "sha256": raw_sha,
                 "matches_execution_provenance": True, "includes": "Comments and all literal file bytes"},
    "rea_canonical_seed_snapshot": {"bytes": len(canonical), "sha256": canonical_sha,
                                    "text": canonical.decode("utf-8"), "function_entries": 2,
                                    "normalization": "Ignore blank lines and lines starting with #; strip terminal CR; parse address as integer; emit lowercase 0x hex, fixed TSV field order, preserve entry order, append LF to each row"},
    "installed_provider_sources": [
        {"path": str(provider.relative_to(ROOT)), "sha256": hashlib.sha256(provider.read_bytes()).hexdigest(),
         "line_56": "Parser ignores blank and # comment lines",
         "line_91": "normalizedSeeds serializes parsed entries with lowercase hexadecimal addresses and LF",
         "line_135": "Analysis profile sha256 is SHA-256 of normalized serialization",
         "line_150": "Before import, re-read canonical SHA must match committed profile",
         "line_155": "Writes the canonical snapshot passed to Ghidra",
         "line_175": "Rejects bridge report when snapshot SHA or entry count disagrees"},
        {"path": str(bridge.relative_to(ROOT)), "sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
         "line_20": "Java script receives the canonical snapshot",
         "line_40": "Java hashes exact canonical snapshot bytes and reports that SHA"},
    ],
    "retained_evidence": evidence,
    "conclusion": "The two hashes intentionally identify different serializations of the same two seed entries. The raw file still matches the execution-time provenance, and both function Evidence records match the independently reproduced canonical digest. This is not evidence of changed analysis seeds.",
}
(OUT / "seed_identity_note.json").write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"status": note["status"], "raw_sha256": raw_sha, "rea_canonical_sha256": canonical_sha}, indent=2))
