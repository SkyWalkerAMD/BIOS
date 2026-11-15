"""Build the actual freestanding C core as COFF objects and an import-free test DLL."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ZIG = ROOT / "tools/zig-x86_64-windows-0.14.1/zig.exe"
OUT = HERE / "build"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build() -> dict:
    OUT.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(HERE / ".zig-global")
    env["ZIG_LOCAL_CACHE_DIR"] = str(HERE / ".zig-local")
    commands = []

    def run(argv: list[str]) -> None:
        commands.append(argv)
        subprocess.run(argv, env=env, cwd=HERE, check=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    flags = ["-target", "x86_64-unknown-windows-msvc", "-nostdinc",
             "-isystem", str(ZIG.parent / "lib/include"), "-std=c11", "-O2",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
             "-mno-red-zone", "-Wall", "-Wextra", "-Werror"]
    for name in ["password_core", "password_crypto"]:
        for test in [False, True]:
            target = OUT / (("test_" if test else "") + name + ".obj")
            run([str(ZIG), "clang", *flags,
                 *(["-DAITWK_TEST_EXPORT"] if test else []), "-c",
                 str(HERE / (name + ".c")), "-o", str(target)])
    dll = OUT / "password_core_test.dll"
    run([str(ZIG), "lld-link", "/dll", "/noentry", "/nodefaultlib",
         "/machine:x64", "/timestamp:0", "/out:" + str(dll),
         str(OUT / "test_password_core.obj"),
         str(OUT / "test_password_crypto.obj")])

    raw = dll.read_bytes()
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    assert raw[pe:pe + 4] == b"PE\0\0"
    optional = pe + 24
    assert struct.unpack_from("<H", raw, optional)[0] == 0x20B
    imports = struct.unpack_from("<II", raw, optional + 112 + 8)
    assert imports == (0, 0), "Core test DLL must have no imported runtime functions"
    report = {
        "compiler": subprocess.check_output([str(ZIG), "version"], env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).decode().strip(),
        "commands": commands,
        "import_directory": {"rva": imports[0], "size": imports[1]},
        "sources": {p.name: sha(p) for p in [HERE / "password_core.h",
            HERE / "password_core.c", HERE / "password_crypto.c"]},
        "artifacts": {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)}
            for p in [*sorted(OUT.glob("*.obj")), dll]},
    }
    (HERE / "build_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    result = build()
    print(json.dumps({"result": "PASS", "compiler": result["compiler"],
                      "dll_imports": result["import_directory"],
                      "artifacts": list(result["artifacts"])}))
