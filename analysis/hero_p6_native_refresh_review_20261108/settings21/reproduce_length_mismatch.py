"""Exact existing P6/AMITSE machine-code evidence; no hardware/NV access."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import struct
import sys

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
P6 = ROOT / 'analysis/hero_ipmi_p6_20261104'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

v = module('old_p6_for_length_review', P6 / 'verify_runtime.py')
n = module('native_amitse_for_length_review', P6 / 'native/emulate_native_variable.py')
source_log = ROOT / 'analysis/hero_ipmi_complete_live_20261108/hero71-p6-preflight.TXT'
raw = source_log.read_bytes()
payloads = [bytes.fromhex(x.decode()) for x in re.findall(rb'RAW=([0-9A-F]+)', raw)]
if len(payloads) != 2 or payloads[0] != payloads[1] or payloads[0] != v.cfg()[:21]:
    raise ValueError('Actual preflight fixture changed')
payload = payloads[0]
forms = (P6 / 'native/Setup-forms-P6.bin').read_bytes()
name = b'HeroIpmiSettings\0'
at = forms.index(name) - 26
decl = forms[at:at + 26 + len(name)]
if decl[:4] != b'\x26\x2b\x00\x3f':
    raise ValueError('Unexpected EFI varstore declaration')
attrs = struct.unpack_from('<I', decl, 20)[0]
size = struct.unpack_from('<H', decl, 24)[0]
meta = json.loads((P6 / 'native/native-payload.json').read_text())
extent = max(f['offset'] + f['width'] for f in meta['settings']['fields'])
if (attrs, size, extent) != (3, 32, 21):
    raise ValueError('Unexpected schema')
spf = (P6 / 'native/AMITSESetupData-P6.bin').read_bytes()
vs = int.from_bytes(spf[0x34:0x38], 'little')
start = vs + int.from_bytes(spf[vs + 4 + 119 * 4:vs + 8 + 119 * 4], 'little')
record = spf[start:start + 124]
if struct.unpack_from('<H', record, 0x78)[0] != 32:
    raise ValueError('SPF not declared32')

rows = []
for width in (21, 32):
    m = v.Machine(v.cfg()[:width])
    seed = m.call('p6_seed_settings')
    for callback in ('p6_apply_settings', 'p6_start_os_watchdog', 'p6_stop_os_watchdog'):
        m.call(callback)
    message = bytes(m.u.mem_read(m.functions['values'] + 40 * 160, 160)).split(b'\0', 1)[0].decode()
    if seed != (v.ERR(33) if width == 21 else 0) or m.nv_writes or m.dev.packets:
        raise AssertionError((width, hex(seed), m.nv_writes, m.dev.packets))
    rows.append({'kind': 'original_P6', 'wire_bytes': width, 'seed_status': f'{seed:016X}',
                 'nv_writes': 0, 'bmc_requests': 0, 'configuration_status': message})

native = n.Machine(record, payload)
length = 0x5007000
pointer = native.call(0x1A908, [119, length])
if not pointer or native.value(length) != 21 or native.read(pointer, 21) != payload or native.writes:
    raise AssertionError('Native getter did not preserve actual21')
rows.append({'kind': 'original_AMITSE_getter', 'declared_bytes': 32, 'actual_returned_bytes': 21,
             'rva': '0x1A908', 'calls': native.calls, 'passed': True})

class NativeSave(n.Machine):
    def code(self, mu, address, count, user):
        if address != self.set:
            return super().code(mu, address, count, user)
        a = [mu.reg_read(r) for r in n.REG]
        ident = self.identity(a[0], a[1])
        if a[2] != 3 or a[3] not in (21, 32):
            raise AssertionError('Unexpected save shape')
        b = self.read(self.arg5(), a[3])
        self.calls.append('SetVariable')
        self.writes.append({'name': ident[0], 'attributes': a[2], 'bytes': a[3], 'data_hex': b.hex()})
        self.data = b
        self.ret(0)

for width in (21, 32):
    native = NativeSave(record, payload)
    value = bytearray(v.cfg()[:width])
    value[3] = 12
    native.write(0x5006000, value)
    status = native.call(0x1AB7C, [119, 0x5006000, width])
    if status or native.data != value or len(native.writes) != 1 or native.writes[0]['bytes'] != width:
        raise AssertionError('Original AMITSE did not retain supplied width')
    rows.append({'kind': 'original_AMITSE_save', 'rva': '0x1AB7C', 'declared_bytes': 32,
                 'caller_supplied_bytes': width, 'actual_SetVariable': native.writes[0], 'passed': True})

result = {'passed': True, 'log_sha256': hashlib.sha256(raw).hexdigest(),
          'log_bytes': len(raw), 'actual_wire_bytes': 21,
          'ifr': {'offset': at, 'hex': decl.hex(), 'attributes': attrs, 'declared_bytes': size,
                  'defined_field_extent': extent, 'reserved_offsets': list(range(21, 32))},
          'spf_declared_bytes': 32,
          'original_p6_sha256': hashlib.sha256((P6 / 'HeroIpmiP6.efi').read_bytes()).hexdigest(),
          'original_amitse_sha256': n.EXPECTED_SHA,
          'results': rows,
          'limits': ['Original AMITSE get/save functions were invoked with explicit arguments. This does not establish why the full F10 path selected21, or execute F10 UI.',
                     'Both EFI services and BMC are local fixtures; no real variables or device operations.']}
(OUT / 'length-mismatch-evidence.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
