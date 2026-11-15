from pathlib import Path
import hashlib
import json
BASE = Path(__file__).resolve().parent
ACTUAL = BASE.parent / 'hero71-actual'
expected = {'inventory.pending.json': '06ec92d5c5ecf93fd109eff3c5f4e4cf5061db6f5001e8c60e9df787ce263172',
            'inventory.multipart.bin': 'ca584a4254dc0bdcc8eaf504a5f153d2e81098f20c24a37b43c4df7cfa88d6f3'}
lines = ['/* Frozen real .71 inventory; no changes to the original published bytes. */']
for filename, name in [('inventory.pending.json', 'bulk71_json_body'), ('inventory.multipart.bin', 'bulk71_multipart'),
                       ('boot-complete.json', 'bulk71_complete')]:
    data = (ACTUAL / filename).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if filename in expected: assert digest == expected[filename]
    if filename == 'boot-complete.json': assert data == b'{"BootComplete":true}'
    lines += [f'static const char {name}[]=' + json.dumps(data.decode('ascii')) + ';',
              f'static const char {name}_sha[]="{digest}";']
(BASE / 'bulk71_catalog.h').write_text('\n'.join(lines) + '\n', encoding='ascii')
# The capability/thermal documents are larger than legacy's four small objects.
path = BASE / 'bulk71_json.h'
text = path.read_text('utf8').replace('512', '2048')
path.write_text(text, encoding='utf8')
