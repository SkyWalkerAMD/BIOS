"""Independent bounded review of final compiled discovery, without production edits.

Reuse only the published DiscoveryVM fixture definitions. Extend failure inputs
which the original discovery matrix does not cover; bind every external fixture
input and the exact final EFI. No firmware services execute on the Windows host.
"""
from pathlib import Path
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
DRIVER = CASE/'driver'
EXPECTED = 'efd421fb1fd7239e352eb20528c5f7836301ee3289986fc31474a6ba53959395'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(DRIVER/'build/AiTweakerLock1904.efi') == EXPECTED
manifest = json.loads((DRIVER/'build/build.json').read_text(encoding='utf8'))
assert manifest['efi_sha256'] == EXPECTED
assert all(sha(CASE/p) == h for p, h in manifest['sources'].items())
assert all(sha(ROOT/p) == h for p, h in manifest['external_sources'].items())
external = ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules'
inputs = [DRIVER/'entry.c', DRIVER/'platform.c', DRIVER/'verify_discovery.py',
          DRIVER/'verify_adapter.py', DRIVER/'policy.json',
          DRIVER/'build/AiTweakerLock1904.efi', DRIVER/'build/driver.map',
          DRIVER/'build/build.json', external/'AMITSE.efi', external/'Setup.efi', Path(__file__)]
binding = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
source = (DRIVER/'verify_discovery.py').read_text(encoding='utf8')
assert source.count('\nchecks = []') == 1
ns = {'__file__': str(DRIVER/'verify_discovery.py')}
exec(compile(source.split('\nchecks = []', 1)[0], str(DRIVER/'verify_discovery.py'), 'exec'), ns)
for name in ('DiscoveryVM', 'U', 'R', 'TSE', 'SETUP', 'HEAP', 'STOP', 'symbols', 'q', 'd', 'HANDLE', 'FREE', 'TIMER'):
    globals()[name] = ns[name]


class ReviewVM(DiscoveryVM):
    def __init__(self):
        self.fail_guard = False
        self.guard_calls = 0
        self.retire_during_allocation = False
        self.calls_after_retirement = []
        self.handle_calls = 0
        self.free_calls = 0
        super().__init__()

    def hook(self, u, address, size, data):
        if address == HANDLE:
            self.handle_calls += 1
            if self.arg(0) == 0xabc4:
                u.mem_write(self.arg(2), q(HEAP+0x1c2000))
                self.ret(0)
                return
        if address == FREE:
            self.free_calls += 1
        if address == symbols['install_variable_guard']:
            self.guard_calls += 1
            if self.fail_guard:
                self.ret(0)
                return
        if address == STOP+0x100 and self.retire_during_allocation:
            # Function-level adversarial callback fixture, not a claim that
            # normal ACE AllocatePages can invoke EBS at this callback TPL.
            u.mem_write(symbols['boot_services_ended'], d(1))
            self.retire_during_allocation = False
        if address == TIMER and self.value('boot_services_ended'):
            self.calls_after_retirement.append('BootServices.SetTimer')
        super().hook(u, address, size, data)


checks = []
def check(name, value):
    assert value, name
    checks.append(name)


for inventory, label in [([0xabc1, 0xabc2, 0xabc4], 'duplicate Setup'),
                         ([0xabc3, 0xabc2, 0xabc1], 'duplicate AMITSE reversed')]:
    v = ReviewVM(); v.inventory = inventory; v.discover()
    check(label+' rejects before publication', not v.patches and v.allocations == 0 and v.guard_calls == 0)
    check(label+' does not consume bounded attempts', v.value('attach_attempts') == 0 and v.value('attempted') == 0)
    v.inventory = [0xabc2, 0xabc1]; v.discover()
    check(label+' later unique inventory attaches independent of ordering', v.value('platform_ready') == 1)

v = ReviewVM(); v.inventory = [0xabc1]*4097; v.discover()
check('oversized inventory freed without dereferencing handles', v.free_calls == 1 and v.handle_calls == 0 and v.allocations == 0)

v = ReviewVM(); v.fail_guard = True; v.discover()
check('failed guard publication is terminal before AMITSE patches', v.guard_calls == 1 and not v.patches and v.value('attempted') == 1)
v.fail_guard = False; v.discover()
check('guard publication failure is not retried automatically', v.guard_calls == 1 and v.allocations == 1 and v.timer_cancels == 1)

v = ReviewVM(); original = bytes(v.u.mem_read(TSE+0x300, 1)); v.u.mem_write(TSE+0x300, bytes([original[0]^1]))
for _ in range(8): v.discover()
check('wrong exact text consumes at most three validation attempts', v.value('attach_attempts') == 3 and v.value('attempted') == 1)
check('wrong exact text never allocates or publishes', v.allocations == 0 and not v.patches and v.guard_calls == 0)

v = ReviewVM(); v.retire_during_allocation = True; v.discover()
check('retirement during allocation prevents target publication', not v.patches and v.guard_calls == 0 and v.value('platform_ready') == 0)
retirement_observation = {'trigger': 'fixture sets boot_services_ended while AllocatePages returns',
                          'calls_after_retirement': v.calls_after_retirement,
                          'driver_stops_attachment': v.value('attempted') == 1,
                          'scope': 'conditional control-flow issue; reachability on conforming ACE firmware is not established'}

assert all(sha(ROOT/p) == digest for p, digest in binding.items()), 'input changed during review'
report = {'status': 'PASS_EXTRA_BOUNDED_CASES_WITH_CONDITIONAL_OBSERVATION',
          'checks': len(checks), 'check_names': checks, 'driver_sha256': EXPECTED,
          'source_and_fixture_sha256': binding, 'retirement_observation': retirement_observation,
          'production_edits': False, 'physical_run': False,
          'limitations': ['Firmware providers, guard installation and permission services are explicit stubs.',
                          'Original discovery suite has 24 cases; this report adds independent omitted inputs.',
                          'The injected retirement does not establish legal TPL or native ACE provider reachability.',
                          'Stage5 first-visit deferral and multi-provider compatibility remain documented integration limits.']}
(HERE/'discovery_independent_review.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({k: report[k] for k in ('status', 'checks', 'driver_sha256', 'retirement_observation')}, indent=2))
