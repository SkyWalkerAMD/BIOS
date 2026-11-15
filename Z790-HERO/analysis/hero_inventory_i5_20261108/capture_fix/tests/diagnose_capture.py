"""Locate a catalogue failure in a local raw SMBIOS capture; no hardware access."""
from pathlib import Path
import ctypes as c
import hashlib
import json
import sys
import zlib

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[2]
REFERENCE = ROOT / 'analysis/hero_inventory_20261108/dynamic_catalog'
sys.path.insert(0, str(REFERENCE))
from test_dynamic_catalog import Catalog


def diagnose(path):
    capture = Path(path).read_bytes()
    text = capture.decode('ascii').replace('\r\n', '\n')
    raw = bytes.fromhex(text.split('TABLE_HEX_BEGIN\n')[1].split('TABLE_HEX_END')[0])
    lib = c.CDLL(str(REFERENCE / 'build/catalog.dll'))
    lib.HeroInventoryBuild.argtypes = [c.c_void_p, c.c_uint32, c.c_uint8, c.c_uint8, c.POINTER(Catalog), c.c_void_p]
    lib.HeroInventoryBuild.restype = c.c_int
    work = c.create_string_buffer(lib.HeroInventoryScratchSize())
    data = c.create_string_buffer(raw)
    out = Catalog()
    result = lib.HeroInventoryBuild(data, len(raw), 3, 5, c.byref(out), work)
    records = []
    failures = []
    at = 0
    while at < len(raw):
        size = raw[at+1]
        end = raw.index(b'\0\0', at+size)+2
        r = {'type': raw[at], 'handle': int.from_bytes(raw[at+2:at+4], 'little'), 'offset': at, 'end': end, 'formatted_bytes': size}
        p = at+size
        index = 1
        while p < end-2:
            q = raw.index(b'\0', p)
            try:
                raw[p:q].decode('utf-8', errors='strict')
            except UnicodeDecodeError as e:
                failures.append({**r, 'string_index': index, 'string_offset': p, 'string_bytes': q-p,
                                 'bad_offset': p+e.start, 'reason': e.reason, 'raw_hex': raw[p:q].hex()})
            p = q+1
            index += 1
        records.append(r)
        at = end
    report = {'capture': str(Path(path).resolve()), 'capture_sha256': hashlib.sha256(capture).hexdigest(),
              'table_bytes': len(raw), 'table_crc32': f'{zlib.crc32(raw):08X}', 'table_sha256': hashlib.sha256(raw).hexdigest(),
              'reference_dll_sha256': hashlib.sha256((REFERENCE/'build/catalog.dll').read_bytes()).hexdigest(),
              'result': result, 'error_offset': out.error_offset, 'failing_record': next((r for r in records if r['offset'] <= out.error_offset < r['end']), None),
              'all_encoding_failures': failures, 'record_count': len(records)}
    (BASE/'tests/latest-source-diagnosis.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    diagnose(sys.argv[1])
