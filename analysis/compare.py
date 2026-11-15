from pathlib import Path
import csv
import json
import re
from collections import defaultdict
from inventory import ROOT

db = {r[0].upper(): r[1] for r in csv.reader((ROOT / 'analysis/uefitool_guids.csv').open(encoding='utf-8')) if len(r) > 1}
data = json.loads((ROOT / 'analysis/inventory.json').read_text(encoding='utf-8'))
donor = data['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']
hero = data['ROG-MAXIMUS-Z790-HERO-ASUS-3001.CAP']
normal = next(v for k, v in data.items() if 'proart_standard' in k and '3002' in k)
def compare_occurrences(reference):
    groups = defaultdict(list)
    for ref in reference:
        groups[ref['guid']].append(ref)
    status = {}
    # Match identical occurrences first so repeated GUIDs do not overwrite each other.
    for i, m in enumerate(donor):
        matches = groups[m['guid']]
        match = next((j for j, ref in enumerate(matches) if ref['sha256'] == m['sha256']), None)
        if match is not None:
            matches.pop(match)
            status[i] = 'identical'
    original_guids = {m['guid'] for m in reference}
    for i, m in enumerate(donor):
        if i in status:
            continue
        if groups[m['guid']]:
            groups[m['guid']].pop()
            status[i] = 'changed'
        else:
            status[i] = 'added' if m['guid'] not in original_guids else 'added_occurrence'
    return status

hs = compare_occurrences(hero)
ns = compare_occurrences(normal)
rows = []
for i, m in enumerate(donor):
    g = m['guid']
    rows.append(dict(guid=g, name=';'.join(m['ui']) or db.get(g, ''), type=m['type'],
                     bytes=m['size'], vs_hero=hs[i], vs_proart_standard=ns[i], source_path=m['path']))
with (ROOT / 'analysis/module_comparison.tsv').open('w', encoding='utf-8', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]), delimiter='\t')
    w.writeheader()
    w.writerows(rows)
for row in rows:
    if row['vs_proart_standard'] != 'identical':
        print(row)
print('Totals', {s: sum(r['vs_proart_standard'] == s for r in rows) for s in ['added', 'changed', 'identical']})
for name in ['manual', 'proart']:
    text = (ROOT / f'analysis/asus_{name}.html').read_text(encoding='utf-8')
    print(name, sorted(set(re.findall(r'/pub/ASUS/[^"<>]+?\.(?:pdf|zip)', text))))
