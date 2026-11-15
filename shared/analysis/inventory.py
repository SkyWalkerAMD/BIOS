"""Inventory the local UEFIExtract all-mode output, without changing firmware."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent.parent
INTEREST = re.compile(r'ipmi|bmc|aspeed|asmb|sensor|hwm|nct67|smbus|super.?io|servermgmt|servermanagement', re.I)

def inventory(cap):
    dump = ROOT / (cap + '.dump')
    infos = {}
    for p in dump.rglob('info.txt'):
        s = p.read_text(errors='replace')
        infos[p.parent] = (s, dict(re.findall(r'^([^:\r\n]+): ([^\r\n]*)', s, re.M)))
    modules = []
    for d, (txt, info) in infos.items():
        if not txt.startswith('Type: File\n') or 'File GUID' not in info:
            continue
        h = (d / 'header.bin').read_bytes()
        b = (d / 'body.bin').read_bytes() if (d / 'body.bin').exists() else b''
        strings, sections, ui = [], [], []
        for p in d.rglob('body.bin'):
            if p == d / 'body.bin':
                continue
            # Exclude nested FFS files inside a firmware-volume-image file.
            if any(parent in infos and infos[parent][0].startswith('Type: File\n')
                   for parent in p.parent.parents if parent != d and d in parent.parents):
                continue
            itxt, inf = infos.get(p.parent, ('', {}))
            if not itxt.startswith('Type: Section\n'):
                continue
            subtype = inf.get('Subtype', '')
            data = p.read_bytes()
            if subtype == 'User interface':
                ui.append(data.decode('utf-16-le', errors='replace').rstrip('\0'))
            if subtype in ('PE32 image', 'TE image', 'Raw', 'User interface'):
                ss = [x.decode('ascii') for x in re.findall(rb'[ -~]{5,}', data)]
                ss += [x.decode('utf-16-le') for x in re.findall(rb'(?:[ -~]\x00){5,}', data)]
                strings += [x for x in ss if INTEREST.search(x) or '.pdb' in x.lower()]
            if 'dependency' in subtype:
                sections.append({'type': subtype, 'hex': data.hex()})
        modules.append({'guid': info['File GUID'], 'type': info.get('Subtype'),
                        'base': info.get('Base'), 'offset': info.get('Offset'),
                        'size': len(h)+len(b), 'sha256': hashlib.sha256(h+b).hexdigest(),
                        'ui': ui, 'strings': sorted(set(strings)), 'depex': sections,
                        'path': str(d.relative_to(ROOT))})
    return modules

if __name__ == '__main__':
    inv = {}
    caps = sorted(ROOT.glob('*.CAP')) + sorted((ROOT / 'analysis/proart_standard').glob('*.CAP'))
    for cap in caps:
        if (ROOT / (cap.name + '.dump')).is_dir():
            inv[cap.name] = inventory(cap.name)
        elif cap.with_name(cap.name + '.dump').is_dir():
            inv[str(cap.relative_to(ROOT))] = inventory(str(cap.relative_to(ROOT)))
    (ROOT / 'analysis/inventory.json').write_text(json.dumps(inv, indent=2), encoding='utf-8')
    for name, mods in inv.items():
        print(name, len(mods), 'FFS files')
        for m in mods:
            if m['strings'] or any(INTEREST.search(x) for x in m['ui']):
                print(m['guid'], m['type'], m['size'], m['ui'], m['strings'][:18])
