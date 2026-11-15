"""Small read-only queries on extracted firmware images."""
from pathlib import Path
import json, re, sys, uuid, struct, hashlib
from inventory import ROOT

inventory = json.loads((ROOT / 'analysis/inventory.json').read_text(encoding='utf-8'))

def modules(label):
    for cap, ms in inventory.items():
        this = 'standard' if 'proart_standard' in cap else 'donor' if 'IPMI' in cap else 'hero'
        if label not in ('all', this):
            continue
        for m in ms:
            if m['type'] == 'Volume image':
                continue
            yield this, m

def images(m):
    for p in (ROOT / m['path']).rglob('body.bin'):
        if any(t in p.parent.name for t in ('PE32 image', 'TE image', 'Raw section', 'Subtype GUID')):
            yield p, p.read_bytes()

if __name__ == '__main__':
    mode, label, arg, *rest = sys.argv[1:]
    if mode == 'search':
        if arg.startswith('guid:'):
            needles = [uuid.UUID(arg[5:]).bytes_le]
        elif arg.startswith('hex:'):
            needles = [bytes.fromhex(arg[4:])]
        else:
            needles = [arg.encode(), arg.encode('utf-16-le')]
        for this, m in modules(label):
            for p, b in images(m):
                for needle in needles:
                    hits = [hex(x.start()) for x in re.finditer(re.escape(needle), b)]
                    if hits:
                        print(this, m['guid'], m['type'], p.parent.name, hits[:30], 'more=' + str(max(0, len(hits)-30)))
    else:
        for this, m in modules(label):
            if m['guid'] != arg:
                continue
            print(this, json.dumps(m, ensure_ascii=True))
            for p, b in images(m):
                print(p.parent.name, len(b), hashlib.sha256(b).hexdigest())
                if mode == 'strings':
                    print([(hex(x.start()), x[0].decode()) for x in re.finditer(rb'[ -~]{5,}', b)])
                    print([(hex(x.start()), x[0].decode('utf-16-le')) for x in re.finditer(rb'(?:[ -~]\x00){5,}', b)])
                elif mode == 'hex':
                    lo, hi = [int(x, 0) for x in rest]
                    for off in range(lo, min(hi,len(b)), 16):
                        v = b[off:off+16]
                        print(f'{off:04x}: {v.hex(" "):47} ' + ''.join(chr(x) if 32 <= x < 127 else '.' for x in v))
