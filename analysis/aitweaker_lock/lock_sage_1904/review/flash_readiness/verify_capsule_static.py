"""Read-only, pinned-input analysis of the ASUS SAGE SE 1904 release capsule.

This performs RSA verification, never signing, flashing, changing protection,
or accessing a device. All changes for negative controls exist only in RAM.
The AMI signed-region rule below is a reverse-engineered rule for these exact
inputs, established by the original signature passing (and tampering failing).
It is not asserted to be a universal definition of every AMI capsule format.
"""

from __future__ import annotations

import hashlib
import json
import struct
import uuid
from pathlib import Path


HERE = Path(__file__).resolve().parent
CASE = HERE.parents[1]
ORIGINAL = (
    CASE.parent
    / "official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP"
)
CANDIDATE = CASE / "lab/asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin"
DRIVER = CASE / "driver/build/AiTweakerLock1904.efi"
PIN_ORIGINAL = "aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3"
PIN_CANDIDATE = "95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e"
PIN_DRIVER = "da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2"
CAPSULE_GUID = "4a3ca68b-7723-48fb-803d-578cc1fec44d"
RSA_CERT_GUID = "a7717414-c616-4977-9420-844712a735bf"
SHA256_GUID = "51aa59de-fdf2-4ea3-bc63-875fb7842ee9"
PUBLIC_KEY_FFS_GUID = "3feec852-f14c-4e7f-97fd-4c3a8c5bbecc"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(ok: bool, detail: str) -> None:
    if not ok:
        raise ValueError(detail)


def guid(data: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(data)))


def mgf1(seed: bytes, count: int) -> bytes:
    return b"".join(
        hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        for i in range((count + 31) // 32)
    )[:count]


def rsa_pss_sha256(block: bytes, message_digest: bytes) -> dict:
    """RFC 8017 RSAVP1 + EMSA-PSS-VERIFY, fixed observed salt length 8."""
    require(len(block) == 528, "RSA block length")
    require(guid(block[:16]) == SHA256_GUID, "RSA block hash identifier")
    require(len(message_digest) == 32, "SHA-256 digest length")
    modulus = block[16:272]
    signature = block[272:528]
    n = int.from_bytes(modulus, "big")
    s = int.from_bytes(signature, "big")
    require(n.bit_length() == 2048 and n & 1 == 1, "RSA modulus")
    result = {
        "scheme": "RSASSA-PSS",
        "rsa_modulus_bits": 2048,
        "public_exponent": 65537,
        "hash": "SHA-256",
        "mgf": "MGF1-SHA-256",
        "salt_bytes": 8,
        "em_bits": 2047,
        "modulus_sha256": sha(modulus),
        "signature_sha256": sha(signature),
        "message_digest": message_digest.hex(),
    }
    if s >= n:
        return result | {"valid": False, "failure": "signature representative >= modulus"}
    em = pow(s, 65537, n).to_bytes(256, "big")
    h = em[223:255]
    masked_db = em[:223]
    db = bytearray(a ^ b for a, b in zip(masked_db, mgf1(h, 223)))
    db[0] &= 0x7F
    salt = bytes(db[-8:])
    expected_h = hashlib.sha256(bytes(8) + message_digest + salt).digest()
    conditions = {
        "representative_in_range": s < n,
        "trailer_0xbc": em[-1] == 0xBC,
        "unused_top_bit_zero": masked_db[0] & 0x80 == 0,
        "padding_214_zero_bytes": bytes(db[:214]) == bytes(214),
        "delimiter_0x01": db[214] == 1,
        "digest_matches": h == expected_h,
    }
    return result | {
        "valid": all(conditions.values()),
        "checks": conditions,
        "salt": salt.hex(),
        "encoded_h": h.hex(),
        "computed_h": expected_h.hex(),
        "encoded_message_sha256": sha(em),
    }


def parse_capsule(data: bytes) -> dict:
    require(len(data) >= 4096, "short capsule")
    cap_guid = guid(data[:16])
    header_size, flags, cap_size, rom_offset, layout_offset = struct.unpack_from("<IIIHH", data, 16)
    require(cap_guid == CAPSULE_GUID, "unexpected capsule GUID")
    require(header_size == rom_offset == 4096 and cap_size == len(data), "capsule size/offset")
    require(flags == 0x10001 and layout_offset == 0x458, "unexpected AMI header")
    cert_size, cert_rev, cert_type = struct.unpack_from("<IHH", data, 0x20)
    require((cert_size, cert_rev, cert_type) == (0x438, 0x200, 0xEF1), "certificate header")
    require(0x20 + cert_size == layout_offset, "certificate boundary")
    require(guid(data[0x28:0x38]) == RSA_CERT_GUID, "certificate GUID")
    body_size = len(data) - rom_offset
    memory_base = 0x100000000 - body_size
    regions = []
    offset = layout_offset
    while True:
        require(offset + 24 <= header_size, "ROM layout overrun")
        entry = data[offset:offset + 24]
        offset += 24
        if entry == bytes(24):
            break
        physical, raw, size, kind, attrs = struct.unpack("<QIIII", entry)
        require(size > 0 and raw + size <= body_size, "ROM area bounds")
        require(physical == memory_base + raw, "ROM area address mapping")
        regions.append({
            "index": len(regions),
            "table_offset": offset - 24,
            "physical_address": physical,
            "body_offset": raw,
            "cap_offset": rom_offset + raw,
            "size": size,
            "kind": kind,
            "attributes": attrs,
            "included_by_observed_signature_rule": bool(attrs & 0x200),
        })
    require(len(regions) == 22 and offset == 0x680, "unexpected ROM layout termination")
    ordered = sorted(regions, key=lambda r: r["body_offset"])
    cursor = 0
    for item in ordered:
        require(item["body_offset"] == cursor, "ROM map not a disjoint whole-image partition")
        cursor += item["size"]
    require(cursor == body_size, "ROM map does not cover the image")
    return {
        "guid": cap_guid,
        "header_size": header_size,
        "flags": flags,
        "image_size": cap_size,
        "body_size": body_size,
        "body_offset": rom_offset,
        "physical_base": memory_base,
        "rom_layout_offset": layout_offset,
        "rom_layout_end_including_zero_terminator": offset,
        "rom_area_count": len(regions),
        "rom_map_disjoint_covers_entire_body": True,
        "certificate_length": cert_size,
        "certificate_revision": cert_rev,
        "certificate_type": cert_type,
        "certificate_guid": guid(data[0x28:0x38]),
        "rsa_block_offsets": [0x38, 0x248],
        "regions": regions,
    }


def firmware_digest(data: bytes, header: dict) -> bytes:
    context = hashlib.sha256()
    for area in header["regions"]:
        if area["included_by_observed_signature_rule"]:
            start = area["cap_offset"]
            context.update(data[start:start + area["size"]])
    context.update(data[header["rom_layout_offset"]:header["rom_layout_end_including_zero_terminator"]])
    return context.digest()


def signatures(data: bytes, header: dict) -> dict:
    return {
        "firmware_signature": rsa_pss_sha256(data[0x38:0x248], firmware_digest(data, header)),
        "certificate_signature": rsa_pss_sha256(data[0x248:0x458], hashlib.sha256(data[0x20:0x248]).digest()),
    }


def find_all(data: bytes, needle: bytes) -> list[int]:
    result, start = [], 0
    while (start := data.find(needle, start)) >= 0:
        result.append(start)
        start += 1
    return result


def parse_fit(data: bytes, header: dict) -> dict:
    pointer_offset = len(data) - 0x40
    pointer = struct.unpack_from("<Q", data, pointer_offset)[0]
    offset = pointer - header["physical_base"] + header["body_offset"]
    require(0 <= offset <= len(data) - 16, "FIT pointer bounds")
    require(data[offset:offset + 8] == b"_FIT_   ", "FIT signature")
    count = int.from_bytes(data[offset + 8:offset + 11], "little")
    require(1 <= count <= 4096 and offset + count * 16 <= len(data), "FIT size")
    entries = []
    for i in range(count):
        item = data[offset + 16 * i:offset + 16 * (i + 1)]
        entries.append({
            "index": i,
            "address": int.from_bytes(item[:8], "little"),
            "size_field": int.from_bytes(item[8:11], "little"),
            "reserved": item[11],
            "version": int.from_bytes(item[12:14], "little"),
            "type": item[14] & 0x7F,
            "checksum_valid_flag": bool(item[14] & 0x80),
            "checksum_field": item[15],
        })
    cv = entries[0]["checksum_valid_flag"]
    checksum_sum = sum(data[offset:offset + count * 16]) & 255
    require(not cv or checksum_sum == 0, "FIT checksum")
    return {
        "pointer_cap_offset": pointer_offset,
        "physical_address": pointer,
        "cap_offset": offset,
        "entry_count": count,
        "table_sha256": sha(data[offset:offset + count * 16]),
        "checksum_required": cv,
        "checksum_sum_mod256": checksum_sum,
        "checksum_interpretation": "not required because header C_V=0" if not cv else "verified",
        "entries": entries,
        "startup_acm_type_2_entries": [e for e in entries if e["type"] == 2],
        "key_manifest_type_0b_entries": [e for e in entries if e["type"] == 0xB],
        "boot_policy_manifest_type_0c_entries": [e for e in entries if e["type"] == 0xC],
        "hardware_boot_guard_enabled": None,
        "ibb_coverage_of_changed_region": None,
    }


def main() -> None:
    original, candidate = ORIGINAL.read_bytes(), CANDIDATE.read_bytes()
    require(sha(original) == PIN_ORIGINAL, "original CAP SHA-256 differs")
    require(sha(candidate) == PIN_CANDIDATE, "EXP02 SHA-256 differs")
    require(sha(DRIVER.read_bytes()) == PIN_DRIVER, "production driver SHA-256 differs")
    integration_path = CASE / "lab/asus_review_exp02/verification.json"
    integration = json.loads(integration_path.read_text(encoding="utf-8"))
    require(integration["status"] == "PASS", "integration verification status")
    require(integration["candidate_sha256"] == PIN_CANDIDATE and integration["driver_sha256"] == PIN_DRIVER, "integration evidence hash binding")
    require(integration["inserted_driver_pe32_exact_match"] is True, "integration driver match")
    require(len(original) == len(candidate), "image lengths differ")
    oh, ch = parse_capsule(original), parse_capsule(candidate)
    require(oh == ch and original[:4096] == candidate[:4096], "headers unexpectedly changed")
    osig, csig = signatures(original, oh), signatures(candidate, ch)
    require(all(s["valid"] for s in osig.values()), "original signatures do not verify")
    require(not csig["firmware_signature"]["valid"], "EXP02 unexpectedly verifies")
    require(csig["certificate_signature"]["valid"], "EXP02 certificate unexpectedly changed")
    changed = [i for i, (a, b) in enumerate(zip(original, candidate)) if a != b]
    require(bool(changed), "candidate has no change")
    count = len(changed)
    first, last = changed[0], changed[-1]
    del changed
    regions = []
    for area in oh["regions"]:
        a, b = area["cap_offset"], area["cap_offset"] + area["size"]
        regions.append(area | {
            "original_sha256": sha(original[a:b]),
            "exp02_sha256": sha(candidate[a:b]),
            "changed": original[a:b] != candidate[a:b],
        })
    require([r["index"] for r in regions if r["changed"]] == [13], "unexpected changed ROM regions")
    require(regions[13]["included_by_observed_signature_rule"], "DXE is not covered by signature")
    root_modulus = original[0x258:0x358]
    key_ffs_offset = 0x3E811B8
    key_raw_offset = key_ffs_offset + 24 + 4
    require(guid(original[key_ffs_offset:key_ffs_offset + 16]) == PUBLIC_KEY_FFS_GUID, "public-key FFS GUID")
    require(int.from_bytes(original[key_ffs_offset + 20:key_ffs_offset + 23], "little") == 284, "public-key FFS size")
    require(original[key_ffs_offset + 24:key_ffs_offset + 28] == b"\x04\x01\x00\x19", "public-key raw section")
    require(original[key_raw_offset:key_raw_offset + 256] == root_modulus, "root key differs from firmware raw FFS")
    require(original[key_ffs_offset:key_ffs_offset + 284] == candidate[key_ffs_offset:key_ffs_offset + 284], "root-key FFS changed")
    fit_original, fit_candidate = parse_fit(original, oh), parse_fit(candidate, ch)
    require(fit_original == fit_candidate, "FIT changed")

    controls = []
    for name, flip, expected_firmware, expected_certificate in (
        ("flip_one_byte_in_signed_dxe", first, False, True),
        ("flip_one_byte_in_unsigned_microcode_region", 0x3851000 + 0x90, True, True),
        ("flip_one_byte_in_certificate_signature", 0x358, True, False),
    ):
        altered = bytearray(original)
        altered[flip] ^= 1
        values = signatures(altered, oh)
        actual = (values["firmware_signature"]["valid"], values["certificate_signature"]["valid"])
        require(actual == (expected_firmware, expected_certificate), "negative control: " + name)
        controls.append({
            "name": name,
            "in_memory_only": True,
            "cap_offset": flip,
            "firmware_signature_valid": actual[0],
            "certificate_signature_valid": actual[1],
            "matches_expected": True,
        })
    signature_markers = [b"__KEYM__", b"__ACBP__", b"__IBBS__", b"__PMSG__", b"_AMIPFAT", b"$HASHTBL"]
    known_hash_guids = ["cbc91f44-a4bc-4a5b-8696-703451d0b053", "389cc6f2-1ea8-467b-ab8a-78e769ae2a15"]
    scan = {
        "scope": "exact original and EXP02 whole CAP byte streams; raw-byte absence is not proof of hardware policy",
        "markers": {m.decode(): {"original": find_all(original, m), "exp02": find_all(candidate, m)} for m in signature_markers},
        "known_vendor_protected_range_ffs_guids": {g: {"original": find_all(original, uuid.UUID(g).bytes_le), "exp02": find_all(candidate, uuid.UUID(g).bytes_le)} for g in known_hash_guids},
    }
    dump = Path(str(ORIGINAL) + ".dump")
    leaf_hits = []
    scanned = 0
    if dump.is_dir():
        for path in dump.rglob("body.bin"):
            if any(p.is_dir() for p in path.parent.iterdir()):
                continue
            data = path.read_bytes()
            scanned += 1
            for marker in signature_markers:
                hits = find_all(data, marker)
                if hits:
                    leaf_hits.append({"path": str(path.relative_to(dump)), "sha256": sha(data), "marker": marker.decode(), "offsets": hits})
    scan["original_uefiextract_leaf_bodies_scanned"] = scanned
    scan["original_uefiextract_leaf_marker_hits"] = leaf_hits
    scan["uefiextract_dump_limit"] = "Original dump was previously produced from the pinned CAP; auxiliary leaf scan is not a hardware read or comprehensive BIOS Guard format parser."
    report = {
        "status": "STATIC_REVIEW_COMPLETE_EXP02_FAILS_ORIGINAL_CAPSULE_SIGNATURE",
        "script_sha256": sha(Path(__file__).read_bytes()),
        "inputs": {
            "original": {"path": str(ORIGINAL), "sha256": sha(original), "bytes": len(original)},
            "exp02": {"path": str(CANDIDATE), "sha256": sha(candidate), "bytes": len(candidate)},
            "production_driver": {"path": str(DRIVER), "sha256": sha(DRIVER.read_bytes())},
            "prior_independent_integration_verification": {"path": str(integration_path), "sha256": sha(integration_path.read_bytes()), "embedded_driver_exact_match_reported": True},
        },
        "no_device_access_or_input_mutation": True,
        "capsule_header": oh,
        "capsule_header_unchanged": True,
        "signature_rule_evidence": {
            "status": "reverse-engineered for exact pinned capsule; original cryptographic validation and negative controls pass",
            "signed_region_filter": "attributes & 0x200 != 0",
            "signed_region_indices_in_order": [r["index"] for r in regions if r["included_by_observed_signature_rule"]],
            "signed_message": "concatenate selected ROM areas in table order, then CAP[0x458:0x680] including zero terminator",
            "certificate_message": "CAP[0x20:0x248] (WIN_CERTIFICATE metadata and first RSA block)",
            "uefi_guid_caveat": "The GUID labels an RSA2048/SHA256 certificate. This AMI extended two-block encoding verifies as PSS, not the single-block PKCS1-v1_5 example defined by UEFI. No universal AMI ABI is inferred.",
        },
        "original_signatures": osig,
        "exp02_signatures": csig,
        "original_firmware_contains_same_root_public_modulus": {
            "ffs_guid": PUBLIC_KEY_FFS_GUID,
            "ffs_cap_offset": key_ffs_offset,
            "raw_modulus_cap_offset": key_raw_offset,
            "modulus_sha256": sha(root_modulus),
            "ffs_sha256": sha(original[key_ffs_offset:key_ffs_offset + 284]),
            "candidate_unchanged": True,
            "trust_limit": "Matches a raw public-key FFS in the official image. This does not read the live board's trusted key or prove which updater authentication path is active.",
        },
        "byte_changes": {"count": count, "first_cap_offset": first, "last_cap_offset_inclusive": last, "changed_rom_region_indices": [13]},
        "rom_regions": regions,
        "negative_controls": controls,
        "fit": fit_original,
        "additional_guard_indicator_scan": scan,
        "boot_guard": {
            "km_bpm_in_this_fit": "absent",
            "boot_guard_enabled_on_live_hardware": None,
            "live_ibb_or_post_ibb_coverage_of_changed_dxe": None,
            "reason": "Release CAP FIT has only header plus two microcode entries. No KM/BPM is available to extract signed IBB ranges. Live SPI/manufacturing policy and read-only security status are unavailable to this analysis.",
        },
        "bios_guard": {
            "hardware_enabled": None,
            "authenticated_update_package_coverage": None,
            "reason": "No parsed BIOS Guard policy or verified BIOS Guard update package is established by this capsule review. Marker scans are supplemental only; neither absence nor support code establishes hardware enablement.",
        },
        "confirmed_blocker": "EXP02 retains the original capsule signatures but changes covered ROM region 13. Its firmware signature is mathematically invalid under the public key embedded in the unchanged original certificate.",
        "required_next_evidence": [
            "Manufacturer-authorized signing path for the exact custom image, or vendor confirmation of an officially supported customization/update mechanism; no private signing key is present in this analysis.",
            "A read-only live SPI/BIOS-region capture with provenance, and platform-specific read-only Boot Guard/BIOS Guard/flash protection status, before asserting actual boot-policy coverage or update acceptance.",
            "Exact authorized updater/recovery policy for W790E-SAGE SE (EZ Flash/FlashBack/BMC) and a supported validation-only result if available; this review sends no candidate to an updater.",
            "Safe recovery conditions plus firmware-integrated real-hardware qualification: cold boot, direct Del entry, persistent password storage, normal authorized saves, and the existing integration-audit limitations.",
        ],
        "sources": [
            {"url": "https://github.com/LongSoft/UEFITool/blob/new_engine/common/ffs.h", "scope": "AMI Aptio header/GUID, ROM layout offset, known vendor hash-file GUIDs; public parser implementation"},
            {"url": "https://uefi.org/specs/UEFI/2.11/32_Secure_Boot_and_Driver_Signing.html", "scope": "WIN_CERTIFICATE_UEFI_GUID and RSA2048/SHA256 block identifiers; must not confuse with observed AMI PSS extension"},
            {"url": "https://www.rfc-editor.org/rfc/rfc8017.html", "scope": "RSAVP1 and EMSA-PSS verification / MGF1 definitions"},
            {"url": "https://cdrdv2-public.intel.com/599500/599500_FW_Interface_Table_BIOS_Spec_Rev1p6.pdf", "scope": "FIT pointer, entries, KM/BPM types, and checksum-valid flag"},
            {"url": "https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html", "scope": "Boot Guard key/manifest/IBB relationship and hardware policy dependency; platform-generation limits apply"},
            {"url": "https://www.intel.com/content/www/us/en/developer/articles/technical/xeon-processor-scalable-family-technical-overview.html", "scope": "Boot Guard and BIOS Guard are distinct; BIOS Guard adds flash-update protection. General Xeon background, not evidence of target enablement."},
        ],
    }
    output = HERE / "capsule_static_review.json"
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["status"],
        "output": str(output),
        "report_sha256": sha(output.read_bytes()),
        "original_firmware_signature_valid": osig["firmware_signature"]["valid"],
        "exp02_firmware_signature_valid": csig["firmware_signature"]["valid"],
        "original_certificate_signature_valid": osig["certificate_signature"]["valid"],
        "exp02_certificate_signature_valid": csig["certificate_signature"]["valid"],
        "exp02_signed_message_sha256": csig["firmware_signature"]["message_digest"],
        "fit_entry_types": [e["type"] for e in fit_original["entries"]],
        "leaf_bodies_scanned": scanned,
        "leaf_marker_hits": len(leaf_hits),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
