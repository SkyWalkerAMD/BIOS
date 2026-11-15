"""Decode register-only inventory frames; retain the original P3 decoder unchanged."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

HERE=Path(__file__).resolve().parent
path=HERE.parents[1]/'probe_p3_kvm/decode_captures.py'
spec=importlib.util.spec_from_file_location('p3_decoder',path)
decoder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)

if sys.argv[1]=='frame':
    screenshot=Path(sys.argv[2])
    raw=decoder.read_image(screenshot)
    frame=decoder.parse_frame(raw)
    screenshot.with_suffix('.frame').write_bytes(raw)
    print(json.dumps({k:v for k,v in frame.items() if k!='data'}))
elif sys.argv[1]=='assemble':
    folder=Path(sys.argv[2])
    raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.frame'))],require_inventory=False)
    if not raw.startswith(b'SPI-INVENTORY-04 LOCAL-CANDIDATE\r\n') or not raw.endswith(b'PROBE_COMPLETE\r\n'):
        raise ValueError('Unexpected diagnostic log identity')
    target=folder/'hardware-log.txt'
    if target.exists() and target.read_bytes()!=raw:
        raise FileExistsError(target)
    target.write_bytes(raw)
    meta['scope']='Physical register inventory only; not a firmware backup'
    meta['files']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob('*')) if p.is_file() and p.name!='manifest.json'}
    (folder/'manifest.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
    print(json.dumps(meta))
else:
    raise ValueError('Unsupported action')
