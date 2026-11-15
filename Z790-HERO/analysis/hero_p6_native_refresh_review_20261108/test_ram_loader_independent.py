"""Targeted independent PE edge cases; writes only this review directory."""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys
import zlib

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
BASE = ROOT / 'analysis/hero_p6_ramcheck_20261108'
path = BASE / 'tests/test_launcher_pe.py'
scope = {'__file__': str(path), '__name__': 'ram_loader_fixture_only'}
# Load the firmware-service fixture, not its tests or report-writing block.
text = path.read_text(encoding='utf-8')
exec(compile(text.split('\nrows=[]\n', 1)[0], str(path), 'exec'), scope)
Machine, DEFAULT, journal = (scope[n] for n in ('Machine', 'DEFAULT', 'journal'))
pe_bytes = (BASE / 'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
expected = 'ed1bb73ebbaef73cd646d7112e8ba19cc99b41e89e48b0217cbba12635682a41'
if hashlib.sha256(pe_bytes).hexdigest() != expected:
    raise ValueError('Review must be updated for a different launcher PE')

rows = []
def run(label, machine, token=None, loads=0, starts=0):
    output = machine.run()
    if machine.calls.count('Load') != loads or machine.calls.count('Start') != starts:
        raise AssertionError((label, output[-2000:]))
    if token and token not in output:
        raise AssertionError((label, output[-2000:]))
    rows.append({'case': label, 'passed': True, 'load_calls': loads, 'start_calls': starts})

for offset, value, name in [(0, 0x12345678, 'magic'), (4, 2, 'version'), (8, 143, 'declared size')]:
    blob = bytearray(journal())
    struct.pack_into('<I', blob, offset, value)
    struct.pack_into('<I', blob, 12, 0)
    struct.pack_into('<I', blob, 12, zlib.crc32(blob))
    run('reject valid-CRC journal with wrong ' + name, Machine(DEFAULT, bytes(blob)))

machine = Machine(DEFAULT, journal())
def historical_change(m, name, count):
    if name == 'HeroIpmiState' and count == 2:
        m.state = journal(results=True)
machine.mutate = historical_change
run('reject changed safe historical journal after entry', machine, 'LOAD_REFUSED_CHANGED_SINCE_ENTRY')

map_text = (BASE / 'build/BOOTX64.map').read_text()
symbols = {name: int(re.search(r'\b' + name + r'\s+([0-9A-Fa-f]{16})\b', map_text).group(1), 16)
           for name in ('audit_len', 'audit_bad')}
for symbol, value in [('audit_bad', 1), ('audit_len', 262144 - 147456 + 1)]:
    class CapacityMachine(Machine):
        def hook(self, uc, at, size, ctx):
            if self.stubs[at] == 'ReadKey' and self.keys and self.keys[0] == 'L':
                uc.mem_write(symbols[symbol], struct.pack('<I' if symbol == 'audit_bad' else '<Q', value))
            return super().hook(uc, at, size, ctx)
    run('refuse load with ' + symbol + ' exhausted', CapacityMachine(DEFAULT, journal()), 'LOAD REFUSED: insufficient space')

class NullHandle(Machine):
    def hook(self, uc, at, size, ctx):
        name = self.stubs[at]
        out = self.r64(uc.reg_read(scope['UC_X86_REG_RSP']) + 0x30) if name == 'Load' else 0
        super().hook(uc, at, size, ctx)
        if out:
            self.w64(out, 0)
run('LoadImage success with NULL handle refuses StartImage', NullHandle(DEFAULT, journal()), 'P6_LOAD_NULL_HANDLE', loads=1)

class NullApi(Machine):
    def hook(self, uc, at, size, ctx):
        name = self.stubs[at]
        out = uc.reg_read(scope['UC_X86_REG_R8']) if name == 'Locate' else 0
        super().hook(uc, at, size, ctx)
        if out:
            self.w64(out, 0)
            uc.reg_write(scope['UC_X86_REG_RAX'], 0)
run('success with NULL P6 API refuses load', NullApi(DEFAULT, journal()), 'LOAD_REFUSED_EXISTING_OR_INVALID_P6_API')

class MmioMap(Machine):
    def hook(self, uc, at, size, ctx):
        name = self.stubs[at]
        out = uc.reg_read(scope['UC_X86_REG_RDX']) if name == 'GetMap' else 0
        super().hook(uc, at, size, ctx)
        if out:
            uc.mem_write(out, struct.pack('<I', 11))
            uc.mem_write(out + 40, struct.pack('<I', 11))
run('MMIO-only memory map refuses identity dereference/load', MmioMap(DEFAULT, journal()), 'LOAD_IDENTITY=0x8000000000000021')

result = {'passed': True, 'cases': len(rows), 'launcher_sha256': expected, 'results': rows,
          'scope': 'Actual launcher instructions with inherited UEFI service fixtures; no actual P6 execution or hardware.'}
(OUT / 'ram-loader-independent-tests.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
