"""Exercise the actual RAM ISO EFI's owner, browser and handoff guards.

Providers are explicit Unicorn fixtures. This is not ASUS UI execution. HLT is
intercepted; privileged instructions never execute on the Windows host.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
OUT = HERE/'build'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--prepared', action='store_true', help='verify provisional EFI from prepare.json; no ISO exists')
args = parser.parse_args()
manifest_path = OUT/('prepare.json' if args.prepared else 'build.json')
build = json.loads(manifest_path.read_text(encoding='utf8'))
assert build['build_id'] == 'ACE1904-INTEGRATED04-RAM'
assert build['production_object_relink_exact_match']
assert sha(OUT/'BOOTX64.EFI') == build['efi_sha256']
assert sha(HERE/'ram_lock_test.c') == build['local_source_sha256']['ram_lock_test.c']
base_script = HERE.parent/'ebs_review/verify_ebs.py'
source = base_script.read_text(encoding='utf8')
assert source.count('\nchecks=[];cases=[]') == 1
ns = {'__file__': str(base_script)}
saved_argv = sys.argv
try:
    sys.argv = [str(base_script)]
    exec(compile(source.split('\nchecks=[];cases=[]', 1)[0], str(base_script), 'exec'), ns)
finally:
    sys.argv = saved_argv
ns['CANDIDATE_EFI'] = OUT/'BOOTX64.EFI'
ns['CANDIDATE_MAP'] = OUT/'ram_test.map'
for name in ('VM', 'U', 'R', 'C', 'HEAP', 'STOP', 'q', 'd', 'SET'):
    globals()[name] = ns[name]
TSE = 0x10000000
LOCATE = STOP+0x400


class RamVM(VM):
    def __init__(self):
        self.foreign = False
        self.unreadable = False
        self.stage_on_locate = None
        self.retire_on_locate = False
        self.maintenance_halt = False
        self.maintenance_hlt = None
        super().__init__()
        self.u.mem_map(TSE, 0xa2000)
        self.u.mem_write(self.symbols['tse_image'], q(TSE))
        self.u.mem_write(TSE+0x82628, d(7))
        self.u.mem_write(TSE+0x6b528, q(TSE+0x20f34)+q(TSE+0x2168c))
        self.u.mem_write(self.bs+0x140, q(LOCATE))
        code = bytes(self.u.mem_read(self.symbols['refuse_os_handoff'], 256))
        decoded = list(C.Cs(C.CS_ARCH_X86, C.CS_MODE_64).disasm(code, self.symbols['refuse_os_handoff']))
        self.maintenance_hlt = next(i.address for i in decoded if i.mnemonic == 'hlt')
        assert any(i.mnemonic == 'cli' and i.address < self.maintenance_hlt for i in decoded)
        for address in [LOCATE, self.symbols['memory_present'], self.maintenance_hlt]:
            self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)

    def hook(self, u, address, size, data):
        if address == self.maintenance_hlt:
            assert not u.reg_read(R.UC_X86_REG_EFLAGS) & 0x200
            self.halted = True
            self.maintenance_halt = True
            u.emu_stop()
            return
        if address == self.symbols.get('memory_present'):
            self.calls.append(address)
            start, count = self.arg(0), self.arg(1)
            okay = TSE <= start and start+count <= TSE+0xa2000
            if self.unreadable and start == TSE+0x6b528:
                okay = False
            self.ret(int(okay))
            return
        if address == LOCATE:
            self.calls.append(address)
            u.mem_write(self.arg(2), q(HEAP+0x9000 if self.foreign else TSE+0x6b528))
            if self.stage_on_locate is not None:
                u.mem_write(TSE+0x82628, d(self.stage_on_locate))
            if self.retire_on_locate:
                u.mem_write(self.symbols['boot_services_ended'], d(1))
            self.ret(0)
            return
        super().hook(u, address, size, data)

    def ram_length(self):
        # The optimizer can reduce private ram_size storage to a boolean.
        # Observe it through the compiled read callback, not its C layout.
        destination, length = HEAP+0xa000, HEAP+0xa100
        self.u.mem_write(length, q(0))
        self.call('ram_read', 0, destination, 128, length)
        return self.getq(length)


checks = []
def check(name, value):
    assert value, name
    checks.append(name)


v = RamVM()
check('exact idle interface and both native methods accepted', v.call('browser_ready') == 1)
check('accepted browser is the exact OEM object', v.getq(v.symbols['browser']) == TSE+0x6b528)
for kind in ['foreign', 'unreadable', 'wrong_send', 'wrong_callback', 'initial_stage5', 'stage5_during_locate', 'retired_during_locate']:
    v = RamVM()
    if kind == 'foreign': v.foreign = True
    if kind == 'unreadable': v.unreadable = True
    if kind == 'wrong_send': v.u.mem_write(TSE+0x6b528, q(STOP+0x1000))
    if kind == 'wrong_callback': v.u.mem_write(TSE+0x6b530, q(STOP+0x1000))
    if kind == 'initial_stage5': v.u.mem_write(TSE+0x82628, d(5))
    if kind == 'stage5_during_locate': v.stage_on_locate = 5
    if kind == 'retired_during_locate': v.retire_on_locate = True
    check(kind+' browser rejected', v.call('browser_ready') == 0 and v.getq(v.symbols['browser']) == 0)

data = HEAP+0x6000
for kind in ['outside', 'core_grant_only', 'owned', 'owned_busy', 'depth_overflow', 'self_test', 'self_test_retired', 'wrong_length']:
    v = RamVM(); v.u.mem_write(data, b'R'*128)
    core = v.symbols['password_core']
    v.u.mem_write(core+196, d(1))
    size = 128
    if kind == 'core_grant_only': v.u.mem_write(core+200, b'\1\1')
    if kind in ['owned', 'owned_busy', 'depth_overflow', 'wrong_length']: v.set_owner(1)
    if kind == 'owned_busy': v.u.mem_write(core+202, b'\1')
    if kind == 'depth_overflow': v.u.mem_write(v.symbols['loop_depth'], d(17))
    if kind in ['self_test', 'self_test_retired']: v.u.mem_write(v.symbols['ram_self_test'], d(1))
    if kind == 'self_test_retired': v.u.mem_write(v.symbols['boot_services_ended'], d(1))
    if kind == 'wrong_length': size = 127
    accepted = kind in ['owned', 'owned_busy', 'self_test']
    result = v.call('ram_persist', 0, data, size)
    check(kind+' RAM persistence authorization', (result == 0) == accepted)
    check(kind+' RAM record writes only when authorized', v.ram_length() == (128 if accepted else 0) and bytes(v.u.mem_read(v.symbols['ram_record'], 128)) == (b'R'*128 if accepted else bytes(128)))
    check(kind+' never invokes firmware variable service', not v.calls and not v.set_calls)

v = RamVM(); assert v.call('initialize_services') == 1
count = len(v.calls)
check('variable block requires dedicated resident EBS guard', v.call('block_variable_table') == 0 and len(v.calls) == count and v.getq(v.rt+0x58) == SET)
v.u.mem_write(v.symbols['ram_exit_event'], q(0xabc999))
check('maintenance table replacement succeeds after guard registration', v.call('block_variable_table') == 1)
check('both saved and live SetVariable point to deny callback', v.getq(v.rt+0x58) == v.getq(v.symbols['original_set_variable']) == v.symbols['deny_variable'])
check('maintenance replacement preserves valid RT CRC', v.call('local_runtime_crc_valid') == 1)
check('production guard installs over maintenance deny callback', v.call('install_variable_guard') == 1)
name = HEAP+0x7000; guid = name+0x100
v.u.mem_write(name, 'ordinary'.encode('utf-16le')+bytes(2)); v.u.mem_write(guid, bytes(16))
check('ordinary SetVariable write denied without firmware invocation', v.call('guarded_set', name, guid, 3, 0, 0) == (1<<63)|8 and v.var('blocked_writes') == 1 and not v.set_calls)
check('private credential write denied by production guard', v.call('guarded_set', v.symbols['credential_name'], v.symbols['credential_guid'], 3, 0, 0) == (1<<63)|15 and not v.set_calls)
v.set_owner(1); v.u.mem_write(v.symbols['password_core']+40, b'C'*128)
v.u.mem_write(data, b'R'*128); assert v.call('ram_persist', 0, data, 128) == 0
v.before()
check('production Before restores maintenance deny pointer and retires owner', v.getq(v.rt+0x58) == v.symbols['deny_variable'] and v.retired())
v.final()
check('production final itself uses no external services', not v.halted)
count = len(v.calls)
v.call('refuse_os_handoff', 0, 0)
check('maintenance final prevents OS handoff with unmapped BootServices', v.maintenance_halt and len(v.calls) == count)
check('maintenance final wipes separate RAM credential and self-test phase', v.ram_length() == 0 and v.var('ram_self_test') == 0 and bytes(v.u.mem_read(v.symbols['ram_record'], 128)) == bytes(128))

v = RamVM(); v.set_owner(1); v.u.mem_write(v.symbols['ram_self_test'], d(1))
v.u.mem_write(v.st+0x60, q(0xdead0000))
v.call('refuse_os_handoff', 0, 0)
check('maintenance callback also stops if delivered before production final', v.maintenance_halt and v.retired() and not v.calls)

report = {'status': 'PASS_COMPILED_RAM_FIXTURE', 'checks': len(checks), 'check_names': checks,
          'efi_sha256': sha(OUT/'BOOTX64.EFI'), 'iso_sha256': build.get('iso_sha256'),
          'production_driver_sha256': build['production_driver_sha256'],
          'sources': {str(p.relative_to(ROOT)): sha(p) for p in [Path(__file__), base_script, HERE/'ram_lock_test.c', OUT/'ram_test.map', manifest_path]},
          'provisional_efi_only': args.prepared,
          'physical_run': False, 'privileged_host_instructions_executed': False,
          'limits': ['Protocol and permission providers are explicit Unicorn fixtures, not ASUS services.',
                     'EBS payload is executed with an unmapped BootServices pointer; physical notification ordering is not established.',
                     'The test does not simulate native ASUS browser UI, persistence, SMM or cached variable pointers.']}
(OUT/('prepared_fixture_validation.json' if args.prepared else 'fixture_validation.json')).write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({k: report[k] for k in ['status', 'checks', 'efi_sha256', 'iso_sha256']}, indent=2))
