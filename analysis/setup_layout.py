"""Decode the packed SETUP_DATA schema embedded in these ASUS images."""
from pathlib import Path
import json
import re
BASE = Path(__file__).resolve().parent
result = {}
for name in ['donor', 'hero']:
    src = (BASE / f'structures/{name}_setup.h').read_text(encoding='ascii')
    body = src.split('typedef struct {', 1)[1].split('} SETUP_DATA;', 1)[0]
    offset = 0
    fields = []
    for line in body.splitlines():
        if not line.strip():
            continue
        m = re.fullmatch(r'\s*(UINT8|UINT16|UINT32|UINT64)\s+(\w+)(?:\[(\d+)\])?;\s*', line)
        if not m:
            raise ValueError(line)
        n = int(m[1][4:]) // 8 * int(m[3] or 1)
        fields.append({'name': m[2], 'offset': offset, 'size': n})
        offset += n
    result[name] = {'size': offset, 'fields': fields}
    print(name, 'packed SETUP_DATA size', hex(offset))
    for f in fields:
        if f['offset'] <= 0xd0f < f['offset']+f['size'] or re.search(r'Bmc|Ipmi|FanControl|Redfish', f['name'], re.I):
            print(hex(f['offset']), f['size'], f['name'])
(BASE / 'setup_layout.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
