"""Decode captured inventory frames as data; validate all lengths and CRCs."""
from pathlib import Path
import hashlib, importlib.util, json, sys

HERE = Path(__file__).resolve().parent
decoder_path = HERE.parents[1] / 'probe_p3_kvm' / 'decode_captures.py'
spec = importlib.util.spec_from_file_location('inventory_decoder', decoder_path)
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)

if sys.argv[1] == 'frame':
    screenshot = Path(sys.argv[2])
    raw = decoder.read_image(screenshot)
    frame = decoder.parse_frame(raw)
    screenshot.with_suffix('.frame').write_bytes(raw)
    print(json.dumps({k:v for k,v in frame.items() if k != 'data'}))
elif sys.argv[1] == 'assemble':
    folder = Path(sys.argv[2])
    frames = sorted(folder.glob('*.frame'))
    raw, meta = decoder.assemble([p.read_bytes() for p in frames])
    target = folder / 'hardware-log.txt'
    if target.exists() and target.read_bytes() != raw:
        raise FileExistsError(target)
    target.write_bytes(raw)
    meta['files'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(folder.glob('*')) if p.is_file()}
    (folder / 'manifest.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    print(json.dumps(meta))
else:
    raise ValueError('Unsupported action')
