"""Export reviewable donor modules and evidence; deliberately does not build or flash a BIOS."""
from pathlib import Path
import csv
import hashlib
import json
import re
import uuid
from inventory import ROOT

OUT = ROOT / 'analysis/porting_bundle'
OUT.mkdir(exist_ok=True)
data = json.loads((ROOT / 'analysis/inventory.json').read_text(encoding='utf-8'))
donor = data['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']
hero = data['ROG-MAXIMUS-Z790-HERO-ASUS-3001.CAP']
standard = next(v for k, v in data.items() if 'proart_standard' in k and '3002' in k)
db = {r[0].upper(): r[1] for r in csv.reader((ROOT / 'analysis/uefitool_guids.csv').open(encoding='utf-8')) if len(r) > 1}
hero_guids = {m['guid'] for m in hero}
standard_guids = {m['guid'] for m in standard}
selected = [m for m in donor if m['guid'] not in standard_guids]
manifest = []
OPCODES = {0:'BEFORE', 1:'AFTER', 2:'PUSH', 3:'AND', 4:'OR', 5:'NOT', 6:'TRUE', 7:'FALSE', 8:'END', 9:'SOR'}

def decode_depex(hexdata):
    b = bytes.fromhex(hexdata)
    pos, expr = 0, []
    while pos < len(b):
        op = b[pos]
        pos += 1
        item = {'op': OPCODES.get(op, f'UNKNOWN_{op:02X}')}
        if op in [0, 1, 2]:
            assert pos+16 <= len(b)
            guid = str(uuid.UUID(bytes_le=b[pos:pos+16])).upper()
            pos += 16
            item.update(guid=guid, name=db.get(guid, ''))
        expr.append(item)
        if op == 8:
            assert pos == len(b), 'Trailing DEPEX data needs investigation'
    return expr

for m in selected:
    md = ROOT / m['path']
    h = (md / 'header.bin').read_bytes()
    b = (md / 'body.bin').read_bytes()
    assert len(h) == 24
    raw = h+b
    assert int.from_bytes(h[20:23], 'little') == len(raw)
    assert (sum(h)-h[17]-h[23]) % 256 == 0
    assert (sum(b)+h[17]) % 256 == 0 if h[19]&0x40 else h[17] == 0xAA
    assert hashlib.sha256(raw).hexdigest() == m['sha256']
    name = db.get(m['guid'], m['guid'])
    moddir = OUT / 'donor_added_modules' / (m['guid'] + ('_' + name if name != m['guid'] else ''))
    moddir.mkdir(parents=True, exist_ok=True)
    ffs = moddir / 'original.ffs'
    ffs.write_bytes(raw)
    pe_count = 0
    for p in md.rglob('body.bin'):
        if 'PE32 image' in p.parent.name or 'TE image' in p.parent.name:
            pe_count += 1
            (moddir / f'image_{pe_count}.bin').write_bytes(p.read_bytes())
    manifest.append(dict(guid=m['guid'], name=name, type=m['type'], size=len(raw),
                         sha256=m['sha256'], absent_in_hero=m['guid'] not in hero_guids,
                         depex=[dict(type=d['type'], instructions=decode_depex(d['hex'])) for d in m['depex']],
                         strings=m['strings'], source_path=m['path'],
                         file=ffs.relative_to(OUT).as_posix(), classification='Unreviewed candidate, not a transplant allowlist'))

defaults = []
for p in (ROOT / 'ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP.dump').rglob('body.bin'):
    if p.parent.name.endswith(' ServerSetup'):
        body = p.read_bytes()
        defaults.append(dict(path=str(p.relative_to(ROOT)), size=len(body), sha256=hashlib.sha256(body).hexdigest()))
        (OUT / 'ServerSetup.donor_default.bin').write_bytes(body)
assert len({x['sha256'] for x in defaults}) == 1
summary = dict(status='STATIC_ANALYSIS_ONLY_NOT_FLASHABLE',
               original_files={p.name:dict(size=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in ROOT.glob('*.CAP')},
               donor_added_vs_standard_3002=len(selected), donor_added_vs_hero=len([m for m in donor if m['guid'] not in hero_guids]),
               server_setup_defaults=defaults, modules=manifest)
(OUT / 'manifest.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')

# Produce two exact proof excerpts for the Setup offset collision.
layout = json.loads((ROOT / 'analysis/setup_layout.json').read_text(encoding='utf-8'))
assert layout['donor']['size'] == 0xDDB and layout['hero']['size'] == 0xD45
donor_field = next(f for f in layout['donor']['fields'] if f['offset'] == 0xD0F)
hero_field = next(f for f in layout['hero']['fields'] if f['offset'] <= 0xD0F < f['offset']+f['size'])
assert donor_field['name'] == 'OnboardFanSrc'
assert hero_field['name'] == 'AsusHidePchPcieSpeedItem'
proof = dict(donor_size='0xDDB', hero_size='0xD45', accessed_offset='0xD0F',
             donor_field=donor_field, hero_field=hero_field, hero_array_index=0xD0F-hero_field['offset'],
             module='05602C82-5F85-4735-AF53-053502178D02',
             read_rva='0x886/0x88D/0x890', conditional_write_rva='0xAAA/0xAB1/0xAB9/0xAEB/0xAF2')
(OUT / 'setup_collision.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
asm = (ROOT / 'analysis/disassembly/donor_05602C82-5F85-4735-AF53-053502178D02.txt').read_text(encoding='utf-8').splitlines()
snippet = []
for line in asm:
    m = re.match(r'([0-9a-f]{8}):', line)
    if m and (0x85F <= int(m[1],16) <= 0x8AC or 0x9D4 <= int(m[1],16) <= 0xAF2):
        snippet.append(line)
(OUT / 'setup_collision_disassembly.txt').write_text('\n'.join(snippet), encoding='utf-8')
print(json.dumps({k:v for k,v in summary.items() if k not in ['modules','server_setup_defaults']}, indent=2))
print('ServerSetup defaults:', defaults)
print('All exported FFS checksums, sizes and source hashes verified.')
