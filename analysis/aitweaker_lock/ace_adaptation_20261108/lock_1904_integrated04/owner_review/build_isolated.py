"""Build owner/HII changes with frozen integrated03 dependencies for review."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BASE = PROJECT.parent / "lock_1904_integrated03"
ROOT = next(p for p in HERE.parents if (p / "tools/zig-x86_64-windows-0.14.1/zig.exe").is_file())
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import pefile

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    assert args.tag.replace("_", "").isalnum()
    snapshot = HERE / args.tag
    assert not snapshot.exists(), "Use a new tag to preserve prior evidence"
    output = snapshot / "driver/build"
    output.mkdir(parents=True)
    identities = []
    for folder, names in [
        ("driver", ["entry.c", "services.c", "cpu_entropy.c", "ui.c", "policy.c", "hii.c", "platform.c", "efi.h", "lock.h", "status.h", "policy_data.h", "policy.json"]),
        ("core", ["password_core.c", "password_crypto.c", "password_core.h"]),
    ]:
        for name in names:
            source = (PROJECT if name in ("hii.c", "platform.c") else BASE) / folder / name
            target = snapshot / folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = sha(source)
            shutil.copy2(source, target)
            assert sha(source) == sha(target) == digest
            identities.append({"origin": str(source.relative_to(ROOT)), "snapshot": str(target.relative_to(snapshot)), "sha256": digest})
    (snapshot / "source_snapshot.json").write_text(json.dumps(identities, indent=2), encoding="utf8")
    zig = ROOT / "tools/zig-x86_64-windows-0.14.1/zig.exe"
    env = os.environ.copy()
    env.update(ZIG_GLOBAL_CACHE_DIR=str(HERE / "zig-global"), ZIG_LOCAL_CACHE_DIR=str(HERE / "zig-local"))
    sources = [snapshot / "driver" / (n + ".c") for n in ["entry", "services", "cpu_entropy", "ui", "policy", "hii", "platform"]]
    sources += [snapshot / "core" / (n + ".c") for n in ["password_core", "password_crypto"]]
    sources += [ROOT / "analysis/aitweaker_lock/probe_p3_kvm/source/probe_core.c"]
    commands, objects = [], []
    for source in sources:
        obj = output / (source.stem + ".obj")
        command = [str(zig), "clang", "-target", "x86_64-unknown-windows-msvc", "-nostdinc", "-isystem", str(zig.parent / "lib/include"),
                   "-I", str(snapshot / "driver"), "-I", str(ROOT / "analysis/aitweaker_lock/probe_p3_kvm/source"), "-std=c11",
                   "-O2" if source.name == "password_crypto.c" else "-Oz", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
                   "-fno-stack-protector", "-mno-red-zone", "-fshort-wchar", "-c", str(source), "-o", str(obj)]
        subprocess.run(command, check=True, env=env, cwd=ROOT)
        commands.append(command)
        objects.append(str(obj))
    efi = output / "AiTweakerLock1904.efi"
    command = [str(zig), "lld-link", "/subsystem:efi_boot_service_driver", "/entry:efi_main", "/nodefaultlib", "/machine:x64", "/dynamicbase",
               "/fixed:no", "/nxcompat", "/timestamp:0", "/map:" + str(output / "driver.map"), "/out:" + str(efi), *objects]
    subprocess.run(command, check=True, env=env)
    commands.append(command)
    pe = pefile.PE(str(efi))
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    efi.write_bytes(pe.write())
    pe = pefile.PE(str(efi))
    assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem == 11 and not hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
    report = {"status": "BUILT_ISOLATED_INTEGRATED04_OWNER_REVIEW", "scope": "integrated04 platform.c/hii.c with all other sources frozen from integrated03; not the final integrated04 build",
              "efi_sha256": sha(efi), "efi_bytes": efi.stat().st_size,
              "sources": {row["snapshot"]: row["sha256"] for row in identities},
              "external_sources": {str(p.relative_to(ROOT)): sha(p) for p in (ROOT / "analysis/aitweaker_lock/probe_p3_kvm/source").glob("probe_core.*") if p.suffix in (".c", ".h")},
              "commands": commands}
    (output / "build.json").write_text(json.dumps(report, indent=2), encoding="utf8")
    print(json.dumps({"status": report["status"], "efi_sha256": report["efi_sha256"], "efi_bytes": report["efi_bytes"], "build": str(output)}, indent=2))


if __name__ == "__main__":
    main()
