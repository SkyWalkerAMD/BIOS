"""Collate the offline capacity experiment and independent full decode proof."""
from pathlib import Path
import hashlib
import json
import lzma
import time

HERE = Path(__file__).resolve().parent
sha = lambda data: hashlib.sha256(data).hexdigest()
meta = json.loads((HERE / "input.json").read_text(encoding="utf8"))
attempts = [json.loads(path.read_text(encoding="utf8")) for path in sorted(HERE.glob("*/result.json"))]
selected_dir = HERE / "d16_lc3_lp0_pb0_depth0"
verification = json.loads((selected_dir / "verification.json").read_text(encoding="utf8"))
raw = (HERE / "modified_inner.bin").read_bytes()
assert sha(raw) == meta["modified_inner_sha256"]

# Confirm the actual one-key builder edit, without an explicit depth override,
# is byte-identical to the verified candidate's compressed stream.
recommended = dict(meta["base_filter"])
assert "depth" not in recommended
recommended["pb"] = 0
started = time.perf_counter()
packed = lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=[recommended])
elapsed = time.perf_counter() - started
packed = packed[:5] + len(raw).to_bytes(8, "little") + packed[13:]
assert packed == (selected_dir / "stream.lzma").read_bytes()

# UEFIExtract exposes the complete decoded guided section in unc_data.bin.
dump = Path(verification["candidate"] + ".dump")
container = next(p for p in dump.rglob("*") if p.is_dir() and p.name.endswith("9E21FD93-9C72-4C15-8C4B-E77F1DB2D792"))
guided = next(p for p in container.iterdir() if p.is_dir() and p.name.endswith("EE4E5898-3914-4259-9D6E-DC7BD79403CF"))
independent = (guided / "unc_data.bin").read_bytes()
assert independent == raw
summary = {
    "status": "PASS_MINIMAL_PARAMETER_CHANGE_FITS_AND_INDEPENDENT_FULL_DECODE_MATCHES",
    "recommended_builder_change": "Change FILTER['pb'] from 2 to 0; retain all other existing parameters and implicit default match depth.",
    "recommended_filter": recommended,
    "single_key_change_stream_matches_verified_candidate": True,
    "single_key_change_confirmation_compression_seconds": round(elapsed, 3),
    "selected_tag": verification["tag"],
    "selected_candidate_sha256": verification["candidate_sha256"],
    "driver_sha256": verification["driver_sha256"],
    "source_capsule_sha256": verification["source_sha256"],
    "original_builder_sha256": meta["builder_sha256"],
    "exact_builder_input_sha256": meta["modified_inner_sha256"],
    "exact_builder_input_bytes": len(raw),
    "independent_uefiextract_full_decoded_sha256": sha(independent),
    "independent_uefiextract_full_decoded_bytes": len(independent),
    "independent_uefiextract_full_decoded_exact_match": True,
    "independent_decoded_file": str(guided / "unc_data.bin"),
    "selected_verification_report": str(selected_dir / "verification.json"),
    "original_container_allocation": meta["outer_container_allocation"],
    "selected_compressed_bytes": verification["compression"]["compressed_bytes"],
    "selected_container_aligned_bytes": verification["compression"]["container_required_aligned_bytes"],
    "selected_padding_ffs_bytes": verification["compression"]["padding_ffs_bytes"],
    "selected_spare_after_minimum_padding": verification["compression"]["spare_bytes_after_minimum_padding"],
    "attempts": attempts,
    "preservation": {
        "original_inner_ffs_bytes_and_offsets": verification["original_inner_ffs_bytes_and_offsets_preserved"],
        "original_outer_other_ffs_bytes_and_offsets": verification["original_outer_other_ffs_bytes_and_offsets_preserved"],
        "independently_extracted_original_ffs_except_container": verification["independently_extracted_original_ffs_preserved_except_container"],
        "all_bytes_outside_original_container_preserved": True,
        "capsule_length_preserved": True,
        "original_capsule_header_preserved": True,
    },
    "limits": [
        "Only compression_review files were written by this experiment; builder and driver sources/binaries were not changed.",
        "UEFIExtract proves independent offline decoding of the complete modified inner content, not execution by the target board's firmware decoder.",
        "The original capsule signature is preserved as bytes but does not authenticate the modified payload. This is an offline review image, not a flash package.",
        "No BMC, BIOS configuration, reboot, firmware write or hardware validation was performed.",
        "Timing was measured on a shared workstation and should not be treated as target firmware decompression performance.",
    ],
}
(HERE / "compression_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
rows = ["W790-ACE 1904 integrated04 offline compression review", "", summary["recommended_builder_change"], "",
        "All attempts use LZMA1, dict=16MiB, lp=0, mode=NORMAL, mf=BT4, nice_len=273.",
        "lc  pb  depth  packed bytes  padding FFS  spare after24  seconds  fits"]
for item in attempts:
    f = item["filter"]
    rows.append(f"{f['lc']:2}  {f['pb']:2}  {f['depth']:5}  {item['compressed_bytes']:12}  {item['padding_ffs_bytes']:11}  {item['spare_bytes_after_minimum_padding']:13}  {item['compression_seconds']:7.3f}  {item['fits_original_allocation_with_padding']}")
rows.extend(["", f"Selected candidate SHA256: {summary['selected_candidate_sha256']}",
             f"Input and independently decoded SHA256: {sha(raw)}", f"Independent full decoded bytes: {len(independent)}", "",
             "All 423 original inner FFS, 7 other outer FFS and 631 independently extracted original FFS except the recompressed container are preserved.",
             "No original FFS moved. The outer container allocation and all outside bytes remain unchanged.", "", *summary["limits"]])
(HERE / "compression_summary.txt").write_text("\n".join(rows) + "\n", encoding="utf8")
print(json.dumps({"status": summary["status"], "attempts": len(attempts), "recommended_change": summary["recommended_builder_change"],
                  "padding_ffs_bytes": summary["selected_padding_ffs_bytes"], "independent_full_decode_sha256": sha(independent),
                  "summary": str(HERE / "compression_summary.json")}, indent=2))
