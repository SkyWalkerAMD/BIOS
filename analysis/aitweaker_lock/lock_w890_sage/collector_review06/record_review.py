"""Read-only inventory of frozen collector evidence; writes this review directory only.

This does not build a collector, start a VM, connect a device, or invoke firmware.
"""
from pathlib import Path
import hashlib
import json
import math
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = ROOT / "analysis/aitweaker_lock"
SAGE = BASE / "lock_w890_sage"
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binding(path):
    return {"path": path.relative_to(ROOT).as_posix(),
            "bytes": path.stat().st_size, "sha256": digest(path)}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(name, value):
    (HERE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    catalog_path = SAGE / "foreign_hii05/catalog.json"
    hardware_path = SAGE / "remote_172_20_2_245/hardware-inventory01-1794101290712-4fbdfdee/hardware-log.txt"
    assert digest(catalog_path) == "9a69367a97bcd082dc07d46d1a47a17638f23b752042bcd54d193694123a48e0"
    assert digest(hardware_path) == "c8525877817f0b0792cf913826d05aade3dd5683a2096e31ebc8d5571ef6c0b0"
    catalog = read_json(catalog_path)
    inputs = [catalog_path, hardware_path]
    rows = []
    for package in catalog["packages"]:
        row = {"package_list_guid": package["package_list_guid"],
               "runtime_instances": package["hardware_instances"],
               "runtime_forms_bytes_available": False,
               "runtime_producer_text_sha256_available": False,
               "static_forms": [], "static_producers": []}
        for form in package["forms_packages"]:
            path = ROOT / form["blob_path"]
            assert digest(path) == form["sha256"] and path.stat().st_size == form["bytes"]
            inputs.append(path)
            row["static_forms"].append({**binding(path), "form_count": form["form_count"],
                                        "raw_qr_pages_lower_bound_at_768": math.ceil(form["bytes"] / 768)})
        for module in package["producer_modules"]:
            path = ROOT / module["path"]
            assert digest(path) == module["sha256"]
            inputs.append(path)
            pe = pefile.PE(str(path))
            sections = [s for s in pe.sections if s.Name.rstrip(b"\0") == b".text"]
            assert len(sections) == 1
            text = sections[0]
            mapped = pe.get_memory_mapped_image()
            content = mapped[text.VirtualAddress:text.VirtualAddress + text.Misc_VirtualSize]
            assert len(content) == text.Misc_VirtualSize
            expected = [s for s in module["sections"] if s["name"] == ".text"]
            assert hashlib.sha256(content).hexdigest() == expected[0]["sha256"]
            relocations = []
            for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
                for entry in block.entries:
                    if entry.type and text.VirtualAddress <= entry.rva < text.VirtualAddress + text.Misc_VirtualSize:
                        relocations.append({"rva": entry.rva, "type": entry.type,
                                            "original_u64": int.from_bytes(mapped[entry.rva:entry.rva + 8], "little")})
            rel = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
            row["static_producers"].append({
                "name": module["module_name"], "ffs_guid": module["ffs_guid"], **binding(path),
                "preferred_image_base": pe.OPTIONAL_HEADER.ImageBase,
                "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
                "text_rva": text.VirtualAddress, "text_bytes": text.Misc_VirtualSize,
                "original_text_sha256": hashlib.sha256(content).hexdigest(),
                "reloc_directory_rva": rel.VirtualAddress, "reloc_directory_bytes": rel.Size,
                "reloc_directory_sha256": hashlib.sha256(mapped[rel.VirtualAddress:rel.VirtualAddress + rel.Size]).hexdigest(),
                "text_relocations": relocations,
                "runtime_observation": "NOT_COLLECTED"})
        rows.append(row)

    relative_inputs = [
        "probe_p2/source/probe.c", "probe_p2/source/probe_core.c", "probe_p2/build.py",
        "probe_p2/build.json", "probe_p2/verification.json", "probe_p2/extended_verification.json",
        "probe_p2/guarded_verification.json", "probe_p2/USB/EFI/BOOT/BOOTX64.EFI",
        "uefi_vm_20261015/summary.json", "uefi_vm_20261015/results.json",
        "probe_p3_kvm/source/probe.c", "probe_p3_kvm/source/probe_core.c", "probe_p3_kvm/source/kvm.c",
        "probe_p3_kvm/source/efi_min.h", "probe_p3_kvm/source/vendor/qrcodegen.c",
        "probe_p3_kvm/build.py", "probe_p3_kvm/build.json", "probe_p3_kvm/package_dual.py",
        "probe_p3_kvm/decode_captures.py", "probe_p3_kvm/verify_capture.py",
        "probe_p3_kvm/verify_inventory.py", "probe_p3_kvm/verify_vm.py",
        "probe_p3_kvm/capture_verification.json", "probe_p3_kvm/inventory_verification.json",
        "probe_p3_kvm/release_verification.json",
        "probe_p3_kvm/vm/sata_1280x800/result.json",
        "probe_p3_kvm/vm/usb_1024x768/result.json",
        "probe_p3_kvm/vm/usb_640x480_idle330/result.json",
        "lock_w890_sage/diagnostic_native01/native_bridge.c",
        "lock_w890_sage/diagnostic_native01/native_sample.c",
        "lock_w890_sage/diagnostic_native01/native_sample.h",
        "lock_w890_sage/diagnostic_native01/source/probe.c",
        "lock_w890_sage/diagnostic_native01/build.py",
        "lock_w890_sage/diagnostic_native01/verify_sample.py",
        "lock_w890_sage/diagnostic_native01/verify_efi.py",
        "lock_w890_sage/diagnostic_native01/qualification.json",
        "lock_w890_sage/diagnostic_native01/build/build.json",
        "lock_w890_sage/diagnostic_native01/build/sample_tests.json",
        "lock_w890_sage/diagnostic_native01/build/efi_tests.json",
        "lock_w890_sage/diagnostic_native01/build/BOOTX64.EFI",
        "lock_w890_sage/diagnostic_native01/build/W890-NATIVE-SAMPLE01-NOFLASH.iso",
        "lock_w890_sage/diagnostic_native01/build/vm/sata_800x600/result.json",
        "lock_w890_sage/release_review/native_sampler_review.json",
        "lock_w890_sage/remote_172_20_2_245/hardware-inventory01-1794101290712-4fbdfdee/decoded.json",
        "lock_w890_sage/remote_172_20_2_245/hardware-inventory01-1794101290712-4fbdfdee/native-sample-review.json",
        "lock_w890_sage/remote_172_20_2_245/decode_inventory.py",
        "lock_w890_sage/foreign_hii05/registration_provenance.json",
        "lock_w890_sage/foreign_hii05/rea05/GetCpuInfo_0x10f4.summary.json",
        "lock_w890_sage/foreign_hii05/rea05/GetCpuInfo_0x1380.summary.json",
        "lock_w890_sage/foreign_hii05/rea05/GetCpuInfo_0x131c.summary.json",
        "lock_w890_sage/foreign_hii05/rea05/GetCpuInfo_0x2854.summary.json",
    ]
    inputs.extend(BASE / p for p in relative_inputs)
    inputs = sorted(set(inputs))
    source_bindings = [binding(p) for p in inputs]

    counts = [f["bytes"] for r in rows for f in r["static_forms"]]
    foreign = sum(f["bytes"] for r in rows if r["package_list_guid"] != "899407d7-99fe-43d8-9a21-79ec328cac21" for f in r["static_forms"])
    sizing = {
        "status": "LOCAL_STATIC_MEASUREMENT_AND_DESIGN_BUDGET_ONLY",
        "qr_raw_payload_bytes_per_page": 768,
        "known_unique_forms_bytes": sum(counts),
        "known_foreign_forms_bytes": foreign,
        "known_unique_forms_qr_pages_lower_bound": math.ceil(sum(counts) / 768),
        "known_foreign_forms_qr_pages_lower_bound": math.ceil(foreign / 768),
        "unknown_25fd_forms_bytes": None,
        "runtime_getcpuinfo_forms_bytes": None,
        "proposed_binary_fingerprint_budget_bytes": 8192,
        "proposed_binary_fingerprint_budget_pages": math.ceil(8192 / 768),
        "illustrative_fixed_record_budget": {
            "header_and_status_bytes": 512, "hii_instance_records": 13,
            "reserved_bytes_per_hii_record": 256, "module_records_budget": 16,
            "reserved_bytes_per_module_record": 256,
            "total_bytes": 512 + 13 * 256 + 16 * 256,
            "pages": math.ceil((512 + 13 * 256 + 16 * 256) / 768),
            "not_serialized_or_implemented": True},
        "proposed_delta_artifact_cap_bytes": 12288,
        "proposed_delta_artifact_cap_pages": 16,
        "proposed_first_round_total_qr_pages_cap": 27,
        "over_budget_behavior": "Report exact required byte count and PARTIAL / NEEDS_NARROWER_SELECTION_OR_FILE; do not silently truncate or auto-page thousands of QR frames.",
        "compression_assumption": "None; costs include reserved artifact metadata but not any unimplemented compression gains.",
        "rows": rows}
    write_json("sizing.json", sizing)

    p2vm = read_json(BASE / "uefi_vm_20261015/summary.json")
    p3capture = read_json(BASE / "probe_p3_kvm/capture_verification.json")
    p3inventory = read_json(BASE / "probe_p3_kvm/inventory_verification.json")
    ns = SAGE / "diagnostic_native01"
    qual = read_json(ns / "qualification.json")
    assert digest(ns / "build/BOOTX64.EFI") == qual["efi_sha256"]
    assert digest(ns / "build/W890-NATIVE-SAMPLE01-NOFLASH.iso") == qual["iso_sha256"]
    assert read_json(ns / "build/sample_tests.json")["cases"] == 58
    assert len(read_json(ns / "build/efi_tests.json")["cases"]) == 9
    assert digest(BASE / "probe_p2/USB/EFI/BOOT/BOOTX64.EFI") == p2vm["p2_efi_sha256"]
    review = {
        "schema_version": 1,
        "status": "DESIGN_ONLY_NO_NEW_COLLECTOR_NO_DEVICE_ACCESS",
        "scope": "Existing sources, saved hardware logs and prior local validation results only.",
        "known_hardware_inventory": {"handles": sum(len(p["hardware_instances"]) for p in catalog["packages"]),
                                     "forms_count_sum": sum(h["forms"] for p in catalog["packages"] for h in p["hardware_instances"]),
                                     "unique_package_list_guids": len(catalog["packages"]),
                                     "unknown_25fd_handles": 2, "unknown_25fd_forms_sum": 8},
        "current_dual_mode": {"separate_frontends": True,
                              "file": "probe_p2/source/probe.c::save_log, marker-checked own boot volume only",
                              "qr": "probe_p3_kvm/source/kvm.c, frozen native01 inherits display-only path",
                              "native01_foreign_hashes_or_delta_export": False},
        "prior_evidence_not_rerun": {
            "p2_file_vm_scenarios": p2vm["scenarios_passed"],
            "p3_qr_native_checks": p3capture["count"],
            "p3_inventory_actual_efi_cases": p3inventory["count"],
            "p3_ovmf_runs": 3,
            "native01_reader_cases": 58, "native01_actual_efi_cases": 9,
            "native01_ovmf": read_json(ns / "build/vm/sata_800x600/result.json")},
        "not_performed": ["Network / BMC / KVM interaction", "New EFI build", "New VM run",
                          "Device or firmware writes", "Mutation of frozen directories"],
        "gaps": [
            "No captured foreign forms package SHA-256 or bytes.",
            "No captured foreign producer text SHA-256; NON_FV identity is incomplete.",
            "NULL-driver GetCpuInfo runtime handle currently not bound to producer saved handle RVA 0x3538.",
            "GetCpuInfo runtime TEXT delta and unknown 25FD forms are not available in screenshots/logs.",
            "Native01 only bounds memory with UEFI descriptors; it is not a full page-table permission proof.",
            "BootOverride snapshot and stable double reads are not native lifetime / ownership proof.",
            "Existing decoder enforces P3 inventory envelope; a new payload schema requires a new strict decoder.",
            "No combined new fingerprint/delta collector or corresponding file+QR equivalence tests exist."],
        "sources": source_bindings}
    write_json("review.json", review)
    assert all(digest(ROOT / item["path"]) == item["sha256"] for item in source_bindings)
    local = [HERE / "README.txt", HERE / "record_review.py", HERE / "sizing.json", HERE / "review.json"]
    write_json("manifest.json", {"status": review["status"], "files": [binding(p) for p in local],
                                 "source_binding_count": len(source_bindings), "source_rechecked_unchanged": True})
    print(json.dumps({"status": review["status"], "bindings": len(source_bindings),
                      "forms_bytes": sum(counts), "foreign_bytes": foreign,
                      "manifest_sha256": digest(HERE / "manifest.json")}, indent=2))


if __name__ == "__main__":
    main()
