"""Compare exact INTEGRATED03 and isolated revised entry machine code.

Fault injection retires discovery at provider-return boundaries. This verifies
defensive control flow, not native ACE TPL reachability or physical EBS ordering.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OLD = CASE.parent/'lock_1904_integrated03'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--integrated', action='store_true')
parser.add_argument('--expected-sha')
args = parser.parse_args()
if args.integrated and not args.expected_sha: parser.error('--integrated requires --expected-sha')
CANDIDATE = CASE/'driver' if args.integrated else HERE
build = json.loads((CANDIDATE/'build/build.json').read_text(encoding='utf8'))
assert sha(CANDIDATE/'build/AiTweakerLock1904.efi') == build['efi_sha256']
entry_hash = sha(CASE/'driver/entry.c')
if args.integrated:
    assert build['efi_sha256'] == args.expected_sha
    assert all(sha(CASE/p) == h for p, h in build['sources'].items())
    assert all(sha(ROOT/p) == h for p, h in build['external_sources'].items())
else:
    assert entry_hash == build['entry_source_sha256']
assert sha(OLD/'driver/build/AiTweakerLock1904.efi') == 'efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395'
script = OLD/'driver/verify_discovery.py'
source = script.read_text(encoding='utf8')
assert source.count('\nchecks = []') == 1 and source.count('\nreport =') == 1


def namespace(baseline):
    ns = {'__file__': str(script)}
    exec(compile(source.split('\nchecks = []', 1)[0], str(script), 'exec'), ns)
    if not baseline:
        symbols = {n: int(v, 16) for n, v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s', (CANDIDATE/'build/driver.map').read_text(encoding='utf8'), re.M)}
        ns['symbols'] = symbols
        ns['ns']['symbols'] = symbols
        ns['ns']['HERE'] = CANDIDATE
    return ns


def injected_vm(ns, retire_at, failed=False, oversized=False):
    parent = ns['DiscoveryVM']
    symbols, STOP, HEAP, q, d = [ns[n] for n in ['symbols', 'STOP', 'HEAP', 'q', 'd']]
    names = {ns['LOCATE']: 'LocateHandleBuffer', ns['HANDLE']: 'HandleProtocol',
             ns['FREE']: 'FreePool', ns['TIMER']: 'SetTimer', STOP+0x110: 'LocateProtocol',
             STOP+0x100: 'AllocatePages'}
    class FaultVM(parent):
        def __init__(self):
            self.retired_at = None
            self.later_calls = []
            self.all_provider_calls = []
            self.attach_intercepted = False
            super().__init__()
            if retire_at == 'AttachReturn':
                self.u.hook_add(ns['U'].UC_HOOK_CODE, self.hook, begin=symbols['attach_platform'], end=symbols['attach_platform'])
            if oversized:
                self.inventory = [0xabc1]*4097

        def hook(self, u, address, size, data):
            name = names.get(address)
            if name:
                self.all_provider_calls.append(name)
                if self.retired_at:
                    self.later_calls.append(name)
                if name == retire_at and not self.retired_at:
                    self.retired_at = name
                    u.mem_write(symbols['boot_services_ended'], d(1))
                    if failed:
                        self.ret((1<<63)|7)
                        return
            if address == symbols['attach_platform'] and retire_at == 'AttachReturn':
                self.retired_at = 'AttachReturn'
                self.attach_intercepted = True
                u.mem_write(symbols['boot_services_ended'], d(1))
                self.ret(0 if failed else 1)
                return
            super().hook(u, address, size, data)
    return FaultVM()


old_ns, new_ns = namespace(True), namespace(False)
checks = []
def check(name, value):
    assert value, name
    checks.append(name)


matrix = []
for point in ['LocateHandleBuffer', 'HandleProtocol', 'FreePool', 'LocateProtocol', 'AllocatePages', 'AttachReturn']:
    for failed in [False, True]:
        old = injected_vm(old_ns, point, failed); old.discover()
        new = injected_vm(new_ns, point, failed); new.discover()
        label = point+(' error return' if failed else ' success return')
        check(label+' trigger reached', old.retired_at == new.retired_at == point)
        check(label+' revised discovery makes no later provider calls', not new.later_calls)
        check(label+' revised discovery clears scanning', new.value('scanning') == 0)
        count = len(new.all_provider_calls); new.discover()
        check(label+' next notification remains retired', len(new.all_provider_calls) == count)
        matrix.append({'point': point, 'provider_failed': failed,
                       'baseline_calls_after_retirement': old.later_calls,
                       'revised_calls_after_retirement': new.later_calls})

check('old AllocatePages success path reproduces unsafe SetTimer', any(r['point']=='AllocatePages' and not r['provider_failed'] and r['baseline_calls_after_retirement']==['SetTimer'] for r in matrix))
check('old HandleProtocol retirement continues enumeration and free', any(r['point']=='HandleProtocol' and 'HandleProtocol' in r['baseline_calls_after_retirement'] and 'FreePool' in r['baseline_calls_after_retirement'] for r in matrix))

v = injected_vm(new_ns, 'FreePool', oversized=True); v.discover()
check('oversized inventory retirement returns without later provider calls', v.retired_at == 'FreePool' and not v.later_calls and v.value('scanning') == 0)
v = injected_vm(new_ns, 'SetTimer'); v.discover()
check('retirement within last SetTimer has no subsequent calls', v.retired_at == 'SetTimer' and not v.later_calls)

# Run all unchanged original discovery cases against the new actual EFI. Do not
# execute its report writer, which belongs to the frozen production directory.
ordinary_ns = namespace(False)
body = '\nchecks = []'+source.split('\nchecks = []', 1)[1].split('\nreport =', 1)[0]
exec(compile(body, str(script), 'exec'), ordinary_ns)
check('original 24 discovery checks remain passing', len(ordinary_ns['checks']) == 24)

inputs = [Path(__file__), HERE/'build_entry_review.py', CANDIDATE/'build/build.json', CANDIDATE/'build/driver.map',
          CASE/'driver/entry.c', script, OLD/'driver/verify_adapter.py',
          OLD/'driver/build/driver.map', CANDIDATE/'policy.json']
report = {'status': 'PASS_RETIRED_DISCOVERY_NO_FURTHER_BOOT_SERVICES',
          'checks': len(checks), 'check_names': checks, 'cases': matrix,
          'ordinary_discovery_checks': len(ordinary_ns['checks']),
          'ordinary_check_names': ordinary_ns['checks'],
          'baseline_efi_sha256': sha(OLD/'driver/build/AiTweakerLock1904.efi'),
          'review_efi_sha256': build['efi_sha256'], 'entry_source_sha256': entry_hash,
          'source_sha256': {str(p.relative_to(ROOT)): sha(p) for p in inputs},
          'scope': __doc__, 'production_entry_only_changed': True,
          'unified_driver_build_written': False, 'physical_run': False,
          'limits': ['Complete integrated04 driver executes.' if args.integrated else 'Only discovery caller behavior is changed; other production objects are frozen INTEGRATED03.',
                     'Guard, permissions, protocols and HII service bodies are explicit fixtures.',
                     'Injected retirement is a defensive boundary test; legal native ACE TPL reachability is not established.',
                     'efi_main event-registration lifetime and internal attach/service retirement behavior are outside this entry-only change.',
                     'Other component regressions and physical testing remain separate.']}
if args.integrated:
    report['driver_sha256'] = build['efi_sha256']
    report['production_entry_only_changed'] = False
    report['scope'] = 'Complete actual integrated04 EFI; inherited explicit firmware-provider fixtures; no production edits during verification.'
assert sha(CANDIDATE/'build/AiTweakerLock1904.efi') == build['efi_sha256']
assert sha(CASE/'driver/entry.c') == entry_hash
(HERE/('integrated_retirement_regression.json' if args.integrated else 'retirement_regression.json')).write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({k: report[k] for k in ['status', 'checks', 'ordinary_discovery_checks', 'review_efi_sha256', 'entry_source_sha256']}, indent=2))
