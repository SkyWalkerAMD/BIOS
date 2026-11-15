"""Prepare a new capture folder for the separately reviewed SPI06 medium."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'bmc_inventory01'
OUT = HERE / 'bmc_spi06'
assert not OUT.exists(), 'Preserve prior session evidence'
(OUT / 'operations').mkdir(parents=True)
records = json.loads((SOURCE / 'runner-source-binding.json').read_text(encoding='utf8'))
bound = []
for item in records:
    source = SOURCE / item['path']
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == item['sha256']
    (OUT / item['path']).write_bytes(data)
    bound.append({'path': item['path'], 'source': str(source), 'sha256': item['sha256']})
(OUT / 'runner-source-binding.json').write_text(json.dumps(bound, indent=2) + '\n', encoding='utf8')
print(json.dumps({'folder': str(OUT), 'files': len(bound)}))
