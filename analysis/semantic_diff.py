"""Compare PEI instruction streams after normalizing image base addresses."""
from pathlib import Path
import sys, re, difflib
base = Path(__file__).resolve().parent / 'disassembly'
guid = sys.argv[1]
def stream(label):
    ls = (base / f'{label}_{guid}.txt').read_text().splitlines()
    image_base = int(re.search(r'[Bb]ase (0x[0-9a-f]+)', '\n'.join(ls[:5]))[1],16)
    result = []
    for line in ls:
        m = re.match(r'^([0-9a-f]{8,16}): [0-9a-f]+\s+(.*?)\s{2,}(.*)',line)
        if not m:
            continue
        addr = int(m[1],16)-image_base
        instruction = line[39:93].strip()
        instruction = re.sub(r'0x[0-9a-f]+',lambda x: hex(int(x[0],16)-image_base) if image_base and image_base <= int(x[0],16) < image_base+0x100000 else x[0],instruction)
        result.append((addr,instruction))
    return result
a,b=stream('standard'),stream('donor')
matcher=difflib.SequenceMatcher(a=[i[1] for i in a],b=[i[1] for i in b],autojunk=False)
for tag,i,j,k,l in matcher.get_opcodes():
    if tag=='equal': continue
    print(tag)
    for addr,s in a[i:j]: print(f'- {addr:04x} {s}')
    for addr,s in b[k:l]: print(f'+ {addr:04x} {s}')
