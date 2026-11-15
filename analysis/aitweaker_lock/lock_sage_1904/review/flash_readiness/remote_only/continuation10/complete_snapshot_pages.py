"""Accept a manually observed QR page into the same incomplete snapshot, without overwrites."""
from pathlib import Path
import hashlib, importlib.util, json, sys

ROOT = Path(__file__).resolve().parents[7]
HW = ROOT / 'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
DECODER = HW / 'read_native13_browser_baseline06_qr.py'
assert hashlib.sha256(DECODER.read_bytes()).hexdigest() == 'abdcad40b3fc79443ab6b0933a488c850cfeefb31645ef6081a3b39169d7c240'
spec = importlib.util.spec_from_file_location('browser06_manual', DECODER)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def main():
    folder, png, page = HW / sys.argv[1], HW / sys.argv[2], int(sys.argv[3])
    assert folder.parent == HW and png.parent == HW and png.suffix == '.png'
    assert folder.name == 'hardware-native13-browser-baseline06-1793713512938-ce806332'
    raw = mod.decoder.read_image(png)
    info = mod.decoder.parse_frame(raw)
    first = mod.decoder.parse_frame((folder / 'page-01.frame').read_bytes())
    assert mod.header(first['data']) == '0000000000000002'
    assert (info['page'], info['total'], info['crc'], info['pages']) == (page, 4911, 3438848396, 7)
    assert all(info[k] == first[k] for k in ('total', 'crc', 'pages'))
    assert page in range(4, 8)
    out = folder / f'page-{page:02d}'
    for suffix, data in (('.frame', raw), ('.png', png.read_bytes())):
        with out.with_suffix(suffix).open('xb') as handle:
            handle.write(data)
    note = {'page': page, 'source': png.name, 'sha256': hashlib.sha256(png.read_bytes()).hexdigest(),
            'reason': 'Continue same immutable snapshot after stale page caused bounded automatic capture to stop; no new Q or browser invocation.'}
    with (folder / f'manual-page-{page:02d}.json').open('x') as handle:
        json.dump(note, handle, indent=2)
    print(json.dumps(note))

if __name__ == '__main__':
    main()
