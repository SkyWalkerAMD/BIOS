"""Freeze the already-reviewed .71 bodies; this is deliberately not a generic uploader."""
from pathlib import Path
import hashlib
import json

BASE = Path(__file__).resolve().parent
SOURCE = BASE.parent / 'hero71-legacy'
manifest = json.loads((SOURCE / 'legacy-request-manifest.json').read_text('utf8'))
lines = ['/* Generated from frozen actual .71 payloads; exact SMBIOS source gate is mandatory. */',
         'typedef struct {unsigned get_id,write_id,method;const char *id,*body,*sha;UN bytes;} INV71_ITEM;']
rows = []
for i, request in enumerate(manifest['requests']):
    data = (SOURCE / request['file']).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == request['sha256'] and len(data) == request['bytes']
    text = data.decode('ascii')
    lines.append(f'static const char inv71_body_{i}[]=' + json.dumps(text) + ';')
    ident = request.get('expected_id', '')
    rows.append('{' + ','.join([str(1 if i == 0 else i + 6), str(1 if i == 0 else 2 if i == 1 else 3),
                               str(2 if i == 0 else 1), json.dumps(ident), f'inv71_body_{i}',
                               json.dumps(digest), f'sizeof(inv71_body_{i})-1']) + '}')
lines.append('static const INV71_ITEM inv71_items[6]={' + ',\n'.join(rows) + '};')
lines.append('static const char inv71_uuid[]="9b296595-55eb-e689-5fd2-08bfb8eeda44";')
(BASE / 'catalog71.h').write_text('\n'.join(lines) + '\n', encoding='ascii')
print(json.dumps({'items': len(rows), 'source_payload_sha256': manifest['source_payload_sha256']}))
