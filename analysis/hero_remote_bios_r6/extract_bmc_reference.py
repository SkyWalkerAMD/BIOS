"""Extract only Redfish implementation text from the official, archived image.
No image code is executed. No credentials/certificates are extracted.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage

source = ROOT / 'analysis/bmc_1_3_13_official/KODO1313.ima'
raw = source.read_bytes()
positions = []
start = 0
while (pos := raw.find(b'hsqs', start)) >= 0:
    positions.append(pos)
    start = pos + 4
out = Path(__file__).resolve().parent / 'bmc-reference'
manifest = []
for pos in positions:
    try:
        fs = SquashFsImage.from_file(str(source), offset=pos)
    except Exception:
        continue
    with fs:
        for item in fs:
            path = item.path
            selected = (
                path.startswith('/usr/local/redfish/') and path.endswith(('.lua', '.rcmd'))
                or path.startswith('/etc/defconfig/redfish/bios/static/') and path.endswith(('.js', '.html'))
                or path in ('/etc/defconfig/redfish_lighttpd.conf', '/etc/init.d/redfish-server')
            )
            if not selected or not item.is_file:
                continue
            relative = Path(path.lstrip('/'))
            target = (out / relative).resolve()
            if not target.is_relative_to(out.resolve()):
                raise ValueError('unsafe image path')
            data = item.read_bytes()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            manifest.append({'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'image_offset': pos})
(out / 'manifest.json').write_text(json.dumps({'source_sha256': hashlib.sha256(raw).hexdigest(), 'files': manifest}, indent=2), encoding='utf-8')
print(json.dumps({'extracted_text_files': len(manifest), 'filesystem_offsets': sorted(set(x['image_offset'] for x in manifest))}))
