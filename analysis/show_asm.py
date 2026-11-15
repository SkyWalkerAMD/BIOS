import sys
from pathlib import Path
import re
base = Path(__file__).resolve().parent / 'disassembly'
p = base / sys.argv[1]
lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
for line in p.read_text(encoding='utf-8').splitlines():
    m = re.match(r'([0-9a-f]{8}): ([0-9a-f]+)\s+(.*)', line)
    if m and lo <= int(m[1], 16) < hi:
        print(m[1], m[3])
