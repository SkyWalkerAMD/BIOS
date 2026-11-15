"""Actual frozen I5D PE: passive registration and late-SMBIOS lifecycle.

Reuses the existing read-only UEFI fixture definitions, not their test runners.
USB/network/TLS are service doubles. No hardware or native BDS is simulated.
"""
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import sys

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
BASE = ROOT / 'analysis/hero_inventory_i5_20261108/ip4_start_fix'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
fixture_path = BASE / 'tests/pe_fixture.py'
spec = importlib.util.spec_from_file_location('pe_fixture', fixture_path)
fixture = importlib.util.module_from_spec(spec)
sys.modules['pe_fixture'] = fixture
spec.loader.exec_module(fixture)
definitions = BASE / 'tests/test_binding_driver_pe.py'
tree = ast.parse(definitions.read_text(), filename=str(definitions))
keep = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == 'rows' for x in node.targets):
        break
    keep.append(node)
namespace = {'__file__': str(definitions), '__name__': 'independent_binding_fixture'}
exec(compile(ast.Module(body=keep, type_ignores=[]), str(definitions), 'exec'), namespace)
Machine = namespace['BindingMachine']
ERR = fixture.ERR
PINNED = '7e61197ec67770717c69fce2da8e531ac4b74b14c3a24cb7b635117a209ea5b3'
if hashlib.sha256(fixture.data).hexdigest() != PINNED:
    raise RuntimeError('Not the frozen I5D PE')


def native_call(machine, address, *values):
    regs = (fixture.UC_X86_REG_RCX, fixture.UC_X86_REG_RDX, fixture.UC_X86_REG_R8, fixture.UC_X86_REG_R9)
    for reg, value in zip(regs, values):
        machine.u.reg_write(reg, value)
    return machine.callback(address)


def supported(machine):
    return native_call(machine, machine.r64(machine.binding), machine.binding, 0x100, 0)


def start(machine):
    return native_call(machine, machine.r64(machine.binding + 8), machine.binding, 0x100, 0)


rows = []
m = Machine('success')
assert m.run() == 0
assert m.binding and m.api()[3] == 0 and m.api()[11:13] == (0, 0)
assert 'Connect' not in m.calls and 'ObserveUsb' not in m.calls
assert 'i5_prepare_network' not in m.calls and 'GET0' not in m.calls
rows.append(dict(case='entry_registers_only_even_with_valid_present_source_and_usb_fixture', passed=True,
                 state=m.api()[3], binding_starts=m.api()[11], core_runs=m.api()[12]))

assert supported(m) == 0
assert supported(m) == 0
assert m.api()[3] == 0 and m.api()[11:13] == (0, 0) and 'i5_prepare_network' not in m.calls
rows.append(dict(case='Supported_does_not_start_work_or_reconnect', passed=True))

assert start(m) == 0
assert m.api()[3] == 2 and m.api()[11:13] == (1, 1)
assert m.calls.count('GET0') == 1 and m.calls.count('GET1') == 1
rows.append(dict(case='explicit_native_Start_TPL4_runs_once', passed=True, result=hex(m.api()[4])))

m = Machine('success')
assert m.run() == 0
m.tpl = 8
assert start(m) == ERR(3)
assert m.api()[3] == 0 and m.api()[11:13] == (0, 0)
assert 'i5_prepare_network' not in m.calls
rows.append(dict(case='direct_Start_at_TPL8_refuses_without_consuming_core_run', passed=True))

m = Machine('missing')
assert m.run() == 0 and supported(m) == 0
assert start(m) == 0
first = m.api()
assert first[3] == 3 and first[11:13] == (1, 1)
assert first[4] == ERR(33) and 'i5_prepare_network' not in m.calls
# The exact same valid table was already staged in RAM; its configuration-table
# entry becomes present only now, as could happen after an early connection.
m.w64(m.st + 0x68, 1)
assert native_call(m, fixture.symbols['i5_capture_source']) == 0
before = list(m.calls)
assert supported(m) == ERR(3) and start(m) == ERR(3)
assert m.api()[3] == 3 and m.api()[11:13] == (1, 1)
assert 'i5_prepare_network' not in m.calls and 'GET0' not in m.calls
rows.append(dict(case='late_valid_SMBIOS_does_not_rearm_after_first_Start_failure', passed=True,
                 initial_result=hex(first[4]), subsequent_current_source_valid=True,
                 binding_starts=m.api()[11], core_runs=m.api()[12], final_state=m.api()[3]))

m = Machine('no_usb')
assert m.run() == 0 and supported(m) == ERR(3)
m.case = 'success'
assert supported(m) == 0
assert m.api()[3] == 0 and m.api()[11:13] == (0, 0)
rows.append(dict(case='USB_pair_becoming_visible_needs_later_BDS_Start_call', passed=True))

report = dict(passed=True, count=len(rows), cases=rows, pe_sha256=PINNED,
              fixture_sources={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (fixture_path, definitions)},
              actual_PE_entry_Supported_Start_and_SMBIOS_parser=True,
              native_BDS_dispatch_simulated=False, transport_is_mocked=True,
              hardware_access=False, writes_to_parent=False,
              scope='Confirms code lifecycle, including permanent same-boot refusal after early identity failure; does not establish whether HERO native boot encounters that ordering.')
(OUT / 'entry-lifecycle-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(dict(passed=True, cases=len(rows), late_source_failure_is_sticky=True)))
