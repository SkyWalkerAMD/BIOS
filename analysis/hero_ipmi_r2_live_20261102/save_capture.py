"""Save the exact PNG bytes returned by the BMC viewer canvas."""
from pathlib import Path
import base64,json,sys
OUT=Path(__file__).resolve().parent
for name in sys.argv[1:]:
    p=OUT/'responses'/name
    d=json.loads(p.read_text(encoding='utf-8'));assert d['ok']
    r=d['result']
    if isinstance(r,list):r=next(c for c in r if c['id']=='kvm')
    assert r['image'].startswith('data:image/png;base64,')
    b=base64.b64decode(r['image'].split(',',1)[1],validate=True)
    dest=OUT/'screens'/(p.stem+'.png');assert not dest.exists() or dest.read_bytes()==b
    dest.write_bytes(b);print(dest.name,len(b))
