"""Windows guard-page check for source-table reads by the pure native library."""
import ctypes as c
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_dynamic_catalog import Catalog, block, table, ROOT

lib = c.CDLL(str(HERE / 'build/catalog.dll'))
lib.HeroInventoryBuild.argtypes = [c.c_void_p, c.c_uint32, c.c_uint8, c.c_uint8, c.POINTER(Catalog), c.c_void_p]
kernel = c.WinDLL('kernel32', use_last_error=True)
kernel.VirtualAlloc.argtypes = [c.c_void_p, c.c_size_t, c.c_uint32, c.c_uint32]
kernel.VirtualAlloc.restype = c.c_void_p
kernel.VirtualProtect.argtypes = [c.c_void_p, c.c_size_t, c.c_uint32, c.POINTER(c.c_uint32)]
kernel.VirtualFree.argtypes = [c.c_void_p, c.c_size_t, c.c_uint32]
capture = (ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_text('utf8')
actual = block(capture, 'TABLE')
cases = [(actual, 0), (table(), 0), (actual[:-1], 3), (table()[:-6], 3),
         (bytes([0, 255, 0, 0, 0, 0]), 3), (bytes([0,18,0,0]) + b'A'*100, 3),
         (b'\xff'*65536, 3), (b'\0'*5, 2)]
report = []
for data, wanted in cases:
    pages = (len(data)+4095)//4096
    total = (pages+1)*4096
    address = kernel.VirtualAlloc(None, total, 0x3000, 4)
    if not address: raise OSError(c.get_last_error())
    try:
        source = address + pages*4096 - len(data)
        c.memmove(source, data, len(data))
        previous = c.c_uint32()
        if not kernel.VirtualProtect(address, pages*4096, 2, c.byref(previous)): raise OSError(c.get_last_error())
        if not kernel.VirtualProtect(address+pages*4096, 4096, 1, c.byref(previous)): raise OSError(c.get_last_error())
        out = Catalog(); work = c.create_string_buffer(lib.HeroInventoryScratchSize())
        result = lib.HeroInventoryBuild(source, len(data), 3, 5, c.byref(out), work)
        assert result == wanted, (result, wanted)
        report.append({'source_bytes': len(data), 'result': result, 'next_page': 'NOACCESS', 'source': 'READONLY', 'passed': True})
    finally:
        if not kernel.VirtualFree(address, 0, 0x8000): raise OSError(c.get_last_error())
(HERE / 'build/read-bounds.json').write_text(json.dumps(report, indent=2)+'\n')
print(f'{len(report)} readonly-source/NOACCESS-boundary cases passed.')
