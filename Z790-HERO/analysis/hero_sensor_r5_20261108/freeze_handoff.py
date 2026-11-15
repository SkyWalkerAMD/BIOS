"""Freeze local R5 artifacts and test evidence; no build or device access."""
from pathlib import Path
import argparse, hashlib, json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def record(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    destination = HERE / "FROZEN-R5.json"
    if args.verify:
        manifest = json.loads(destination.read_text(encoding="utf-8"))
        for item in manifest["files"]:
            assert record(ROOT / item["path"]) == item, item["path"]
        for item in manifest["preserved_r4_sources"]:
            assert record(ROOT / item["path"]) == item, item["path"]
        print(json.dumps({"passed": True, "files": len(manifest["files"]),
                          "unchanged_r4": len(manifest["preserved_r4_sources"])}))
        return

    pins = {
        "USB/EFI/HERO/HeroIpmiR5.efi": "81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4",
        "HeroIpmiCoreR5.ffs": "be0d4f23272f8c98266629a9e10b1f36f47c35477eb997b3ce44525d230fc792",
        "autoboot15/USB/EFI/BOOT/BOOTX64.EFI": "b1b280e5d75e81ffae313c5f8ae4aa8fe422a08d6a44f83fa5888a5dce719d73",
        "autoboot15/HERO15-R5-AUTO-BDS-TEST.iso": "29b384da3ee6f87794898a0f78f363e1dbaaa731d72b3d1c87c9151fc4976594",
    }
    for path, expected in pins.items():
        assert record(HERE / path)["sha256"] == expected, path
    tests = ["verification.json", "entry-verification.json", "r3-verification.json",
             "r4-verification.json", "pci-selection-verification.json", "ffs-verification.json",
             "autoboot15/guarded-launcher-verification.json", "autoboot15/capture-verification.json",
             "autoboot15/vm-preflight/result.json"]
    for name in tests:
        result = json.loads((HERE / name).read_text(encoding="utf-8"))
        assert result.get("passed", result.get("all_passed")) is True, name
    original = HERE.parent / "hero_sensor_r4_20261108"
    origin = json.loads((HERE / "origin.json").read_text(encoding="utf-8"))
    preserved = []
    for relative, expected in origin["source_files"].items():
        item = record(original / relative)
        assert item["sha256"] == expected["sha256"] and item["bytes"] == expected["bytes"]
        preserved.append(item)
    assert record(original / "USB/EFI/HERO/HeroIpmiR4.efi")["sha256"] == origin["pe_sha256"]
    preserved.append(record(original / "USB/EFI/HERO/HeroIpmiR4.efi"))

    paths = {HERE / p for p in pins}
    paths.update(HERE / p for p in tests)
    paths.update(p for d in (HERE / "source", HERE / "autoboot15/source") for p in d.rglob("*") if p.is_file())
    paths.update(p for d in (HERE, HERE / "autoboot15") for p in d.glob("*.py"))
    paths.update(HERE / p for p in ["origin.json", "build.json", "driver.map",
        "autoboot15/build.json", "autoboot15/launcher.map", "autoboot15/USB/HERO_R5A.TAG",
        "autoboot15/实机操作说明.txt", "autoboot15/vm-preflight/OVMF-PREFLIGHT.TXT",
        "autoboot15/vm-preflight/booted.png", "autoboot15/vm-preflight/diagnostic.png",
        "autoboot15/vm-preflight/returned-firmware.png"])
    review = ROOT / "analysis/hero15_rc5_live_20261108/independent-review/portable-core-actual-pe-review.json"
    if review.exists():
        paths.add(review)
    launcher_review = ROOT / "analysis/hero15_rc5_live_20261108/independent-review/host15-r5-loader-review.json"
    if launcher_review.exists():
        paths.add(launcher_review)
    manifest = {
        "name": "R5 portable management PCI selector and guarded HERO15 real-BDS RAM test",
        "date": "2026-11-08", "hardware_result": "NOT_RUN_BY_THIS_AGENT",
        "core_ffs_guid": "89924765-f984-4ad3-839b-51fdce378d88",
        "core_scope": "HERO BIOS3107; variable PCI bus only; all R4 sensor/fan/Dashboard/config/attempt semantics retained",
        "launcher_identity": {"uuid": "b222f546-dbb3-9ac8-bbfb-581122d8be9f", "board": "ROG MAXIMUS Z790 HERO", "bios": "3107"},
        "workflow": "D read-only preflight and export; L explicit load only after fresh identical preflight; Q/Q then real same-boot BDS override; second pass observer",
        "no_implicit_operations": ["No flash", "No BMC reset", "No manual initialize API", "No synthetic event", "No application-held driver callback", "No inventory publisher"],
        "author_tests": {"core_protocol": 53, "core_lifecycle": 42, "dashboard": 29, "rpm": 38, "pci_selection": 60, "guarded_launcher": 48, "qr_export": 19},
        "ovmf_scope": "Final ISO boot; synthetic identity; absent-ASPEED rejection; complete 2-page QR; Q/Q exit. Does not simulate real BMC initialization.",
        "preserved_r4_sources": preserved,
        "files": [record(p) for p in sorted(paths)],
    }
    destination.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record(destination), ensure_ascii=False))


if __name__ == "__main__":
    main()
