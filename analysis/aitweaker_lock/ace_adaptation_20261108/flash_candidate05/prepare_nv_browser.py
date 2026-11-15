"""Copy the existing reviewed BMC runner into a separate persistence-test folder."""
from pathlib import Path
import hashlib
import json

here = Path(__file__).resolve().parent
source = here / 'bmc_spi06'
out = here / 'bmc_nv05'
assert not out.exists(), 'Preserve prior evidence'
(out / 'operations').mkdir(parents=True)
records = json.loads((source / 'runner-source-binding.json').read_text(encoding='utf8'))
bound = []
for item in records:
    data = (source / item['path']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == item['sha256']
    (out / item['path']).write_bytes(data)
    bound.append({'path': item['path'], 'source': str(source / item['path']), 'sha256': item['sha256']})
(out / 'runner-source-binding.json').write_text(json.dumps(bound, indent=2) + '\n', encoding='utf8')
print(json.dumps({'folder': str(out), 'files': len(bound), 'bmc_actions': False}))
