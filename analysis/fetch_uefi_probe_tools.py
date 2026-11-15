"""Fetch the pinned, portable compiler and primary reference headers locally."""
from pathlib import Path
import hashlib, json, urllib.request, zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / 'tools'
URL = 'https://ziglang.org/download/0.14.1/zig-x86_64-windows-0.14.1.zip'
SHA = '554f5378228923ffd558eac35e21af020c73789d87afeabf4bfd16f2e6feed2c'
ARCHIVE = TOOLS / 'zig-x86_64-windows-0.14.1.zip'
DEST = TOOLS / 'zig-x86_64-windows-0.14.1'

def fetch(url):
    with urllib.request.urlopen(url, timeout=45) as response:
        return response.read()

if __name__ == '__main__':
    TOOLS.mkdir(exist_ok=True)
    if not ARCHIVE.exists():
        data = fetch(URL)
        assert hashlib.sha256(data).hexdigest() == SHA
        ARCHIVE.write_bytes(data)
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest() == SHA
    if not (DEST / 'zig.exe').is_file():
        with zipfile.ZipFile(ARCHIVE) as z:
            for member in z.infolist():
                target = (TOOLS / member.filename).resolve()
                assert target.is_relative_to(DEST.resolve())
            z.extractall(TOOLS)
    print('Pinned Zig compiler verified:', DEST, flush=True)
    refs = ROOT / 'analysis/hero_ipmi_probe/source/reference'
    refs.mkdir(parents=True, exist_ok=True)
    urls = {
        'PciIo.h': 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/PciIo.h',
        'UefiSpec.h': 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Uefi/UefiSpec.h',
        'SimpleFileSystem.h': 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/SimpleFileSystem.h',
        'LoadedImage.h': 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/Protocol/LoadedImage.h',
        'Acpi10.h': 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/IndustryStandard/Acpi10.h',
        'SmBios.h': 'https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/MdePkg/Include/IndustryStandard/SmBios.h',
        'ipmi_kcs_sm.c': 'https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/char/ipmi/ipmi_kcs_sm.c',
        'ipmi_sdr.h': 'https://raw.githubusercontent.com/ipmitool/ipmitool/IPMITOOL_1_8_19/include/ipmitool/ipmi_sdr.h',
    }
    manifest = {'compiler': {'url': URL, 'sha256': SHA}, 'references': {}}
    for name, url in urls.items():
        p = refs / name
        if not p.exists():
            p.write_bytes(fetch(url))
        manifest['references'][name] = {'url': url, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
        print('Reference:', name, flush=True)
    (refs / 'sources.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
