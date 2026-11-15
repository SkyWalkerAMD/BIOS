"""Resolve ARM ELF32 literal pool entries referenced by static pseudocode."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary', type=Path)
    ap.add_argument('decompile_directory', type=Path)
    args = ap.parse_args()
    raw = args.binary.read_bytes()
    assert raw[:6] == b'\x7fELF\x01\x01'
    assert struct.unpack_from('<H', raw, 18)[0] == 40
    phoff = struct.unpack_from('<I', raw, 28)[0]
    phsize, phnum = struct.unpack_from('<HH', raw, 42)
    maps = []
    for i in range(phnum):
        ptype, off, va, pa, filesz, memsz, flags, align = struct.unpack_from('<8I', raw, phoff+i*phsize)
        if ptype == 1:
            maps.append((va, off, filesz))
    def offset(va):
        for start, off, length in maps:
            if start <= va < start+length:
                return off+va-start
        return None
    def text(va):
        off = offset(va)
        if off is None:
            return None
        value = raw[off:off+1024].split(b'\0', 1)[0]
        if 2 <= len(value) < 1024 and all(32 <= c <= 126 or c in (9,10,13) for c in value):
            return value.decode('ascii')
        return None
    rows = []
    for p in sorted(args.decompile_directory.glob('*.c')):
        for key in sorted(set(re.findall(r'\b(?:DAT|PTR)_[0-9a-f]{8}\b', p.read_text()))):
            addr = int(key.rsplit('_',1)[1],16)
            off = offset(addr)
            if off is None or off+4 > len(raw):
                continue
            value = struct.unpack_from('<I',raw,off)[0]
            rows.append({'function_file':p.name, 'symbol':key, 'address':hex(addr),
                         'file_offset':hex(off), 'word':hex(value),
                         'direct_text':text(addr), 'pointer_text':text(value)})
    result = {'binary':str(args.binary.resolve()), 'sha256':hashlib.sha256(raw).hexdigest(),
              'load_segments':maps, 'entries':rows}
    (args.decompile_directory/'literal_pool.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'literal_count':len(rows),'resolved_strings':sum(bool(x['pointer_text']) for x in rows)}))

if __name__ == '__main__':
    main()
