from pathlib import Path
import csv
import json
import re
import uuid
from inventory import ROOT

db = {r[0].upper(): r[1] for r in csv.reader((ROOT / 'analysis/uefitool_guids.csv').open(encoding='utf-8')) if len(r) > 1}
data = json.loads((ROOT / 'analysis/inventory.json').read_text(encoding='utf-8'))
targets = {'05602C82-5F85-4735-AF53-053502178D02', '2538B846-C828-40CC-8E7D-9E493C3EA09E',
           '68A0D4CA-9022-474C-BA22-483480DC9A0A', 'DF3D6877-CDA0-4195-B2B2-83747FF302B2',
           'AB83FEF1-15B7-4DF4-9A4A-34BCB554A0F3', '6372357A-06D7-43EF-B55C-1964F3DD6916'}
for cap, mods in data.items():
    print('\n', cap)
    for m in mods:
        if m['guid'] in {'FC510EE7-FFDC-11D4-BD41-0080C73C8881', '1B45CC0A-156A-428A-AF62-49864DA0E6E6'}:
            p = next((ROOT / m['path']).rglob('*Raw section/body.bin'))
            b = p.read_bytes()
            print('APRIORI', m['guid'], [f'{str(uuid.UUID(bytes_le=b[i:i+16])).upper()} {db.get(str(uuid.UUID(bytes_le=b[i:i+16])).upper(), "")}' for i in range(0, len(b), 16)])
        if m['guid'] not in targets:
            continue
        print('MODULE', m['guid'], db.get(m['guid'], ''))
        for p in (ROOT / m['path']).rglob('body.bin'):
            if 'PE32 image' not in p.parent.name:
                continue
            b = p.read_bytes()
            print('  GUID REFS', [(g, name) for g, name in db.items() if uuid.UUID(g).bytes_le in b])
            print('  STRINGS', [s.decode('utf-16-le') for s in re.findall(rb'(?:[ -~]\x00){5,}', b)])
