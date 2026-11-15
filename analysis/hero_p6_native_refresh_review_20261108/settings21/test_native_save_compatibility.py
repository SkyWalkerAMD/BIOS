"""Joint original-AMITSE save/new-P6 policy replay; all services are RAM mocks."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys
import zlib

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
OLD = ROOT / 'analysis/hero_ipmi_p6_20261104'
NEW = ROOT / 'analysis/hero_p6_settings21_20261108'
EXPECTED = '6a5e2c86f9e49ceefa47d8765cf45c585805f7ac164f07be07df6505100d8ffb'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

v = module('new_p6_compat_review', NEW / 'verify_runtime.py')
n = module('old_amitse_compat_review', OLD / 'native/emulate_native_variable.py')
if hashlib.sha256((NEW / 'HeroIpmiP6.efi').read_bytes()).hexdigest() != EXPECTED:
    raise ValueError('Unreviewed P6 revision')
spf = (OLD / 'native/AMITSESetupData-P6.bin').read_bytes()
vs = int.from_bytes(spf[0x34:0x38], 'little')
at = vs + int.from_bytes(spf[vs + 4 + 119 * 4:vs + 8 + 119 * 4], 'little')
record = spf[at:at + 124]

class NativeSave(n.Machine):
    def code(self, mu, address, size, user):
        if address != self.set:
            return super().code(mu, address, size, user)
        a = [mu.reg_read(r) for r in n.REG]
        self.identity(a[0], a[1])
        assert a[2] == 3 and a[3] in (21, 32)
        self.data = self.read(self.arg5(), a[3])
        self.calls.append('SetVariable')
        self.writes.append({'bytes': a[3], 'data_hex': self.data.hex()})
        self.ret(0)

def native_save(initial, next_value):
    m = NativeSave(record, initial)
    m.write(0x5006000, next_value)
    assert m.call(0x1AB7C, [119, 0x5006000, len(next_value)]) == 0
    assert m.data == next_value and len(m.writes) == 1
    return m.data

rows = []
# A real native-save-function output is fed to the driver's next boot; the
# current boot must not apply a setting edited after its initial snapshot.
m = v.Machine(v.cfg()[:21])
assert m.call('p6_seed_settings') == 0
m.vars['HeroIpmiSettings'] = (3, native_save(v.cfg()[:21], v.LAN[:21]))
m.call('p6_apply_settings')
assert not m.dev.packets and not m.nv_writes
later = m.next_boot()
later.boot()
assert later.dev.sim.lan[3] == bytes([172, 20, 1, 80]) and len(later.dev.mutations) == 7
assert len(later.vars['HeroIpmiSettings'][1]) == 21
assert all(name == 'HeroIpmiState' for name, _ in later.nv_writes)
later.no_leak()
rows.append({'case': 'native_save21_edit_deferred_current_boot_applies_next_boot', 'passed': True,
             'same_boot_bmc_requests': 0, 'next_boot_model_mutations': 7, 'wire_bytes_retained': 21})

# A width-only native save remains a conservative same-boot stop; it is valid
# on a fresh boot and does not cause a 21->32 migration or state creation.
m = v.Machine(v.cfg())
assert m.call('p6_seed_settings') == 0
m.vars['HeroIpmiSettings'] = (3, native_save(v.cfg(), v.cfg()[:21]))
m.call('p6_apply_settings')
assert not m.dev.packets and not m.nv_writes
later = m.next_boot()
later.boot()
assert not later.dev.packets and not later.nv_writes
assert later.vars == {'HeroIpmiSettings': (3, v.cfg()[:21])}
rows.append({'case': 'native_save32_to21_width_change_deferred_then_accepted_without_migration', 'passed': True})

# A valid legacy144 pending journal is not reset simply because settings are
# read from the newly supported21-byte representation.
pending = bytearray(144)
struct.pack_into('<IIIIII', pending, 0, 0x36504948, 1, 144, 0, 1, 1)
pending[24:56] = v.cfg()
pending[56:88] = v.LAN
struct.pack_into('<I', pending, 12, zlib.crc32(pending))
variables = {'HeroIpmiSettings': (3, v.cfg()[:21]), 'HeroIpmiState': (3, bytes(pending))}
m = v.Machine(variables=variables)
assert m.call('efi_main', v.IMAGE, m.st) == 0
for callback in ('on_setup', 'on_ready', 'on_before', 'on_after', 'on_shell'):
    m.call(callback, 0, 0)
assert m.vars == variables and not m.nv_writes and not m.dev.packets
rows.append({'case': 'supported21_does_not_unlock_or_rewrite_existing_valid_pending144_journal', 'passed': True})

source_changes = []
for p in (NEW / 'source').iterdir():
    if p.suffix in ('.c', '.h') and (OLD / 'source' / p.name).exists():
        if p.read_bytes() != (OLD / 'source' / p.name).read_bytes():
            source_changes.append(p.name)
assert set(source_changes) == {'driver.c', 'settings.c'}
for name in ['Setup-forms-P6.bin', 'native-payload.json']:
    assert (NEW / 'native' / name).read_bytes() == (OLD / 'native' / name).read_bytes()
result = {'passed': True, 'cases': len(rows), 'driver_sha256': EXPECTED,
          'ffs_sha256': hashlib.sha256((NEW / 'HeroIpmiNativeP6.ffs').read_bytes()).hexdigest(),
          'unchanged_embedded_forms_and_native_metadata': True, 'source_changes': source_changes, 'results': rows,
          'limits': ['Original AMITSE save function and new P6 instructions with mocked services; full F10 UI not executed.',
                     'All seven reported BMC mutations are synthetic model requests, never hardware actions.']}
(OUT / 'native-save-compatibility.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
