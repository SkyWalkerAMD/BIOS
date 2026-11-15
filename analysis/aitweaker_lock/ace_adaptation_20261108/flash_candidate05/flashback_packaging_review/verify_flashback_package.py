"""Read-only ACE1904 FlashBack artifact checks. No updater or network operations.

Python standard library only. Neither source mode nor package mode creates a CAP
or ZIP. A PASS proves the pinned file preparation, not FlashBack acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import sys
import uuid
import zipfile

sys.dont_write_bytecode = True
CAP_BYTES = 0x4001000
HEADER_BYTES = 0x1000
FLASHBACK_NAME = "PWW790A.CAP"
CAP_GUID = "4a3ca68b-7723-48fb-803d-578cc1fec44d"
ORIGINAL_HEADER_SHA = "9c2df61b4c4e2c7337710a16d36df7ff91885a18e26a7efab68bcf9d6390f966"
PINS = {
    "official": "03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29",
    "candidate": "9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455",
    "engineering": "e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08",
}
PAYLOAD_PINS = {
    "official": "4b49cc330f8b8e22adb8716bd6570369464580fdd16092bc6d30d3ea1af183d0",
    "candidate": "2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809",
    "engineering": "2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809",
}
BASE = "analysis/aitweaker_lock/ace_adaptation_20261108/flash_candidate05"
OFFICIAL = "analysis/aitweaker_lock/official_W790_ACE_1904"
PATHS = {
    "official": OFFICIAL + "/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP",
    "candidate": BASE + "/lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin",
    "engineering": BASE + "/engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP",
}
ZIP_REL = OFFICIAL + "/Pro-WS-W790-ACE-ASUS-1904.zip"
ZIP_SHA = "dcae6e446cfb475755b0a5118317e28e88fc9af7c917bf5cf29c6da1a5fd3e37"
RENAMER_SHA = "412449d304c606dc57aa902fdf9bd040b756732b34307d2c274ebe9e06bf8732"
OLD_ZIP = BASE + "/delivery_review/archives/W790-ACE-1904-AI-TWEAKER-CANDIDATE05-ENGINEERING.zip"
OLD_ZIP_SHA = "d285cbd90fce3d66d683932a1e7c31fba47cf803eeb212fa2ab5acf746d87304"
FFS_OFFSET = 0x3FF0FE8
FFS_SHA = "46eb521d4bc2f39c9174f7afb7c9255898faf7e48068c5d9f5cd636d3462b985"
METADATA_OFFSET = 0x3FF1014
METADATA_SHA = "70999cc60337c37a5c9ddbd292b2393ced363104d7c2086b25ccb76ed3dd4590"
ASUS_TAG_OFFSET = 0x3ECD75C
NAME_OFFSET = ASUS_TAG_OFFSET + 0x91


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_record(path, root=None):
    path = Path(path).resolve()
    return {
        "path": path.relative_to(root).as_posix() if root and path.is_relative_to(root) else str(path),
        "bytes": path.stat().st_size,
        "sha256": sha(path.read_bytes()),
    }


def cap_info(data, role, label):
    require(len(data) == CAP_BYTES, role + ": full 64 MiB + 4096-byte CAP required")
    require(sha(data) == PINS[role], role + ": whole-file SHA256 mismatch")
    guid = str(uuid.UUID(bytes_le=data[:16]))
    header, flags, total = struct.unpack_from("<III", data, 16)
    require((guid, header, flags, total) == (CAP_GUID, HEADER_BYTES, 0x10001, CAP_BYTES), role + ": capsule header mismatch")
    require(sha(data[HEADER_BYTES:]) == PAYLOAD_PINS[role], role + ": payload mismatch")
    if role != "engineering":
        require(sha(data[:HEADER_BYTES]) == ORIGINAL_HEADER_SHA, role + ": original 4096-byte header differs")
    require(data[ASUS_TAG_OFFSET:ASUS_TAG_OFFSET + 9] == b"$BOOTEFI$", role + ": ASUS tag mismatch")
    official_name = b"PWW790A.CAP\0"
    require(data[NAME_OFFSET:NAME_OFFSET + len(official_name)] == official_name, role + ": official FlashBack name mismatch")
    ffs = data[FFS_OFFSET:FFS_OFFSET + 106]
    require(str(uuid.UUID(bytes_le=ffs[:16])) == "bb3bf734-d640-4cf5-afea-ca8cfa6020d1", role + ": FFS GUID mismatch")
    require(int.from_bytes(ffs[20:23], "little") == 106 and sha(ffs) == FFS_SHA, role + ": FFS identity mismatch")
    section = ffs[24:]
    require(int.from_bytes(section[:3], "little") == 82 and section[3] == 0x18, role + ": freeform section mismatch")
    require(str(uuid.UUID(bytes_le=section[4:20])) == "21ea00f3-d986-4281-89a3-94b24d2c6bd9", role + ": metadata subtype mismatch")
    metadata = data[METADATA_OFFSET:METADATA_OFFSET + 62]
    require(sha(metadata) == METADATA_SHA and metadata == section[20:], role + ": USBFLASH metadata differs")
    return {
        "role": role, "path_or_member": label, "bytes": len(data), "sha256": sha(data),
        "capsule_guid": guid, "header_bytes": header, "flags": hex(flags), "declared_total_bytes": total,
        "header_sha256": sha(data[:header]), "payload_bytes": len(data) - header, "payload_sha256": sha(data[header:]),
        "flashback_name": FLASHBACK_NAME, "name_CAP_offset": hex(NAME_OFFSET),
        "usbflashback_ffs_CAP_offset": hex(FFS_OFFSET), "usbflashback_ffs_SPI_offset": hex(FFS_OFFSET - HEADER_BYTES),
        "usbflashback_ffs_bytes": len(ffs), "usbflashback_ffs_sha256": sha(ffs),
        "metadata_CAP_offset": hex(METADATA_OFFSET), "metadata_SPI_offset": hex(METADATA_OFFSET - HEADER_BYTES),
        "metadata_bytes": len(metadata), "metadata_sha256": sha(metadata), "metadata_hex": metadata.hex(),
    }


def pe_offset(data, rva):
    require(data[:2] == b"MZ", "Renamer DOS header")
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    require(data[nt:nt + 4] == b"PE\0\0", "Renamer PE header")
    machine, count = struct.unpack_from("<HH", data, nt + 4)
    optional_size = struct.unpack_from("<H", data, nt + 20)[0]
    require(machine == 0x14C, "Renamer must be original x86 PE")
    optional = nt + 24
    require(struct.unpack_from("<H", data, optional)[0] == 0x10B, "Renamer PE32 header")
    require(struct.unpack_from("<I", data, optional + 28)[0] == 0x400000, "Renamer ImageBase")
    for index in range(count):
        section = optional + optional_size + index * 40
        _, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, section + 8)
        if virtual_address <= rva < virtual_address + raw_size:
            return raw_offset + rva - virtual_address
    raise ValueError("Renamer RVA lacks on-disk bytes")


def renamer_proof(data):
    require(len(data) == 128088 and sha(data) == RENAMER_SHA, "official Renamer identity mismatch")
    cases = [
        (0x107C, "c745d824424f4fc745dc54454649c645e024", "construct stack bytes '$BOOTEFI$'"),
        (0x1192, "33d28d04320fb60c180fbe4415d83bc875584283fa0872ea", "compare eight-byte '$BOOTEFI' prefix in loaded CAP"),
        (0x11B1, "8d839100000083c40403c6c6400c00", "return pointer to matching tag + 0x91; terminate at +0x0c"),
    ]
    rows = []
    for rva, expected, meaning in cases:
        offset = pe_offset(data, rva)
        raw = bytes.fromhex(expected)
        require(data[offset:offset + len(raw)] == raw, "Renamer instruction bytes differ")
        rows.append({"VA": hex(0x400000 + rva), "file_offset": hex(offset), "bytes_hex": raw.hex(), "meaning": meaning})
    message = b"This file has been renamed to %s. To use USB BIOS Flashback, copy %s to the root of your USB flash drive."
    require(data[0x1A428:0x1A428 + len(message)] == message, "Renamer usage string differs")
    return {"member": "BIOSRenamer.exe", "bytes": len(data), "sha256": sha(data), "executed": False,
            "method": "Pinned original PE bytes; x86 instructions statically decoded. No executable invocation.",
            "instructions": rows, "usage_string_file_offset": "0x1a428", "extracted_name": FLASHBACK_NAME}


def verify_sources(root):
    root = root.resolve()
    zip_path = root / ZIP_REL
    require(sha(zip_path.read_bytes()) == ZIP_SHA, "official ZIP identity mismatch")
    with zipfile.ZipFile(zip_path) as archive:
        require(archive.namelist() == ["Pro-WS-W790-ACE-ASUS-1904.CAP", "BIOSRenamer.exe"], "official ZIP contents differ")
        official = archive.read("Pro-WS-W790-ACE-ASUS-1904.CAP")
        renamer = renamer_proof(archive.read("BIOSRenamer.exe"))
    blobs = {role: (root / path).read_bytes() for role, path in PATHS.items()}
    require(blobs["official"] == official, "extracted official CAP differs from pinned ZIP member")
    rows = [cap_info(blobs[role], role, path) for role, path in PATHS.items()]
    require(blobs["official"][:HEADER_BYTES] == blobs["candidate"][:HEADER_BYTES], "candidate must retain complete original CAP header")
    require(blobs["candidate"][HEADER_BYTES:] == blobs["engineering"][HEADER_BYTES:], "candidate/engineering payload must be byte-identical")
    ranges = [(0x48, 0x148), (0x148, 0x248), (0x258, 0x358), (0x358, 0x458)]
    changed = [i for i in range(HEADER_BYTES) if blobs["candidate"][i] != blobs["engineering"][i]]
    require(changed and all(any(a <= i < b for a, b in ranges) for i in changed), "engineering header change outside four signature/key fields")
    previous = file_record(root / OLD_ZIP, root)
    require(previous["sha256"] == OLD_ZIP_SHA, "previous engineering delivery ZIP changed")
    return {
        "schema": "ace1904_flashback_sources_v1", "status": "PASS_FILE_PREPARATION_ONLY",
        "official_zip": file_record(zip_path, root), "renamer_static_proof": renamer, "capsules": rows,
        "candidate_complete_original_header_identical": True, "candidate_engineering_payload_byte_identical": True,
        "engineering_changed_header_bytes": len(changed),
        "engineering_allowed_change_ranges": [[hex(a), hex(b)] for a, b in ranges],
        "all_three_USBFLASHBACK_metadata_identical": True, "previous_engineering_zip_unchanged": previous,
        "selection_policy": "Root selects final package; proposed original-header candidate plus separate official recovery file.",
        "candidate_firmware_signature": "Retained original firmware signature does not authenticate the changed payload; existing mathematical and BMC tests rejected it.",
        "hardware_flashback_attempted": False, "hardware_flashback_acceptance_proven": False,
        "metadata_is_flashback_controller_implementation": False, "FLASH_READY": False,
    }


def safe_member(name):
    path = PurePosixPath(name)
    require(name and "\\" not in name and not path.is_absolute() and all(p not in (".", "..", "") for p in name.split("/")), "unsafe package member")
    require(":" not in name and str(path) == name, "ambiguous package member")
    return path


def package_names(candidate, recovery):
    for name in (candidate, recovery):
        path = safe_member(name)
        require(path.name == FLASHBACK_NAME and len(path.parts) >= 2, "two separate directories with exact PWW790A.CAP are required")
    require(candidate.casefold() != recovery.casefold(), "candidate and recovery paths must differ")


def verify_package(package, candidate, recovery):
    package_names(candidate, recovery)
    package = package.resolve()
    if package.is_dir():
        files = [p for p in package.rglob("*") if p.is_file()]
        require(all(p.resolve().is_relative_to(package) and not p.is_symlink() for p in files), "package contains outside or symbolic file")
        names = [p.relative_to(package).as_posix() for p in files]
        reader = lambda name: (package / name).read_bytes()
        size = lambda name: (package / name).stat().st_size
        container = {"path": str(package), "kind": "directory"}
        archive = None
    else:
        archive = zipfile.ZipFile(package)
        entries = [i for i in archive.infolist() if not i.is_dir()]
        names = [i.filename for i in entries]
        for entry in entries:
            safe_member(entry.filename)
            require(not (entry.flag_bits & 1), "encrypted package member")
            require(((entry.external_attr >> 16) & 0o170000) != 0o120000, "symbolic ZIP member")
        reader = archive.read
        size = lambda name: archive.getinfo(name).file_size
        container = {**file_record(package), "kind": "zip"}
    try:
        require(len(set(n.casefold() for n in names)) == len(names), "duplicate or case-colliding package members")
        caps = [n for n in names if PurePosixPath(n).suffix.lower() == ".cap"]
        require(set(caps) == {candidate, recovery}, "package must contain exactly the selected candidate and official recovery CAPs")
        require(all(size(name) == CAP_BYTES for name in (candidate, recovery)), "packaged CAP length differs")
        rows = [cap_info(reader(name), role, name) for role, name in (("candidate", candidate), ("official", recovery))]
        return {"schema": "ace1904_flashback_package_v1", "status": "PASS_FILE_IDENTITY_ONLY", "container": container,
                "file_count": len(names), "capsules": rows, "no_engineering_CAP_in_package": True,
                "hardware_flashback_acceptance_proven": False, "FLASH_READY": False}
    finally:
        if archive:
            archive.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("sources")
    source.add_argument("--workspace", type=Path, required=True)
    source.add_argument("--report", type=Path, required=True)
    package = commands.add_parser("package")
    package.add_argument("--input", type=Path, required=True)
    package.add_argument("--candidate", default="candidate05/PWW790A.CAP")
    package.add_argument("--recovery", default="official1904-recovery/PWW790A.CAP")
    package.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = verify_sources(args.workspace) if args.command == "sources" else verify_package(args.input, args.candidate, args.recovery)
    report["verifier"] = file_record(Path(__file__))
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    print(json.dumps({"status": report["status"], "report": str(args.report.resolve()), "report_sha256": sha(args.report.read_bytes())}))


if __name__ == "__main__":
    main()
