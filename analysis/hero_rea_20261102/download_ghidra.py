"""Acquire the official REA-compatible Ghidra version into this workspace."""
from pathlib import Path
import urllib.request, hashlib, zipfile, json, time
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
RUNTIME = ROOT / 'tools/rea-hero-12.1.4'
URL = 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip'
SHA = 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'
RUNTIME.mkdir(exist_ok=True)
archive = RUNTIME / 'ghidra_12.1.4_PUBLIC_20260921.zip'
start = time.monotonic(); digest = hashlib.sha256(); total = 0
with urllib.request.urlopen(URL, timeout=60) as src, archive.open('xb') as dst:
    while block := src.read(1024 * 1024):
        dst.write(block); digest.update(block); total += len(block)
assert total == 569649598 and digest.hexdigest() == SHA
print('Verified Ghidra archive:', total, 'bytes', round(time.monotonic()-start, 1), 'seconds', flush=True)
with zipfile.ZipFile(archive) as z:
    for item in z.infolist():
        assert (RUNTIME / item.filename).resolve().is_relative_to(RUNTIME.resolve())
    z.extractall(RUNTIME)
report = {'source': URL, 'bytes': total, 'sha256': SHA, 'target': str(RUNTIME / 'ghidra_12.1.4_PUBLIC')}
(OUT / 'ghidra-tool-provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print('Extraction complete', flush=True)
