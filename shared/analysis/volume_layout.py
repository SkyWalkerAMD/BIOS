from pathlib import Path
import json
from inventory import ROOT
db=json.loads((ROOT/'analysis/inventory.json').read_text())
for cap,ms in db.items():
    if cap != 'ROG-MAXIMUS-Z790-HERO-ASUS-3001.CAP': continue
    p=ROOT/next(m['path'] for m in ms if m['guid']=='062A6204-8C80-4A27-9D09-96654C965894')
    for a in list(p.parents)[:6]:
        print(str(a.relative_to(ROOT)))
        print((a/'info.txt').read_text())
        print('children', [x.name for x in a.iterdir() if x.is_dir()][-6:])
