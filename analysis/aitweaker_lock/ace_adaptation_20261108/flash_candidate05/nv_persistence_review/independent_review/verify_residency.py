"""Independent actual-EFI residency, event, console and cancellation checks.

Reuses only the published local VM/provider helper, never its test matrix.
No BMC, host firmware, media build, source mutation or credential creation.
"""
from pathlib import Path
import datetime, hashlib, json, re, sys, struct, uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NV = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
HELPER = NV / 'verify_nv_guard.py'
prefix = HELPER.read_text(encoding='utf8').split('\nchecks=[]', 1)[0]
ns = {'__file__': str(HELPER), '__name__': 'nv_provider_helper_only'}
exec(compile(prefix, str(HELPER), 'exec'), ns)
NvVM, U, R, C = [ns[x] for x in ('NvVM', 'U', 'R', 'C')]
BASE, HEAP, STOP, ERR, q, d, sha = [ns[x] for x in ('BASE', 'HEAP', 'STOP', 'ERR', 'q', 'd', 'sha')]
OUT = NV / 'stage1/build'
manifest = json.loads((OUT / 'build.json').read_text(encoding='utf8'))
BEFORE_GUID = '8be0e274-3970-4b44-80c5-1ab9502f3bfc'

class ResidencyVM(NvVM):
    def __init__(self):
        self.extra = {}; self.trace = []; self.messages = []; self.input_queue = []
        self.retire_read = False; self.retire_stall = False; self.retire_output = False
        self.handle_fail = False; self.readable = True; self.pool_next = HEAP + 0x50000
        self.ticks = 1000000
        super().__init__()
        # The inherited old fixture keys private symbols by name. Resolve all
        # independently tested symbols by object as well, notably both print().
        rows = re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s+(\S+)',
                          (OUT / 'nv_test.map').read_text(encoding='utf8'), re.M)
        self.qualified = {(name, obj): int(addr, 16) for name, addr, obj in rows}
        self.li = HEAP + 0x11000
        self.out = HEAP + 0x12000; self.input = HEAP + 0x12100; self.mode = HEAP + 0x12200
        self.cpu = HEAP + 0x12300
        self.u.mem_write(self.st + 48, q(self.input)); self.u.mem_write(self.st + 64, q(self.out))
        self.u.mem_write(self.out + 72, q(self.mode)); self.u.mem_write(self.mode, struct.pack('<iiiiiB3x', 1, 0, 7, 4, 2, 0))
        self.u.mem_write(self.cpu + 0x40, d(1))
        for name in ['HandleProtocol', 'LocateProtocol', 'ReadKey', 'OutputString', 'Attribute', 'Clear',
                     'Cursor', 'CursorEnable', 'Stall', 'Allocate', 'Free', 'Timer']:
            address = STOP + 0x1000 + len(self.extra) * 0x10
            self.extra[name] = address
            self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)
        for offset, name in [(0x98, 'HandleProtocol'), (0x140, 'LocateProtocol'), (0xf8, 'Stall'),
                             (0x40, 'Allocate'), (0x48, 'Free')]:
            self.u.mem_write(self.bs + offset, q(self.extra[name]))
        for offset, name in [(8, 'OutputString'), (40, 'Attribute'), (48, 'Clear'), (56, 'Cursor'), (64, 'CursorEnable')]:
            self.u.mem_write(self.out + offset, q(self.extra[name]))
        self.u.mem_write(self.input + 8, q(self.extra['ReadKey']))
        self.u.mem_write(self.cpu + 0x30, q(self.extra['Timer']))
        self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=self.symbols['memory_present'], end=self.symbols['memory_present'])
        code = list(C.Cs(C.CS_ARCH_X86, C.CS_MODE_64).disasm(
            bytes(self.u.mem_read(self.symbols['refuse_os_handoff'], 128)), self.symbols['refuse_os_handoff']))
        self.app_halt = next(i.address for i in code if i.mnemonic == 'hlt')
        assert any(i.mnemonic == 'cli' and i.address < self.app_halt for i in code)
        self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=self.app_halt, end=self.app_halt)

    def sym(self, name, obj='nv_maintenance.obj'):
        return self.qualified[(name, obj)]

    def console_text(self, p):
        out = bytearray()
        for index in range(4096):
            unit = bytes(self.u.mem_read(p + 2 * index, 2))
            if unit == b'\0\0': return out.decode('utf-16le')
            out += unit
        raise AssertionError('Unterminated console text')

    def hook(self, u, a, size, data):
        if hasattr(self, 'app_halt') and a == self.app_halt:
            assert not u.reg_read(R.UC_X86_REG_EFLAGS) & 0x200
            self.halted = True; u.emu_stop(); return
        if a == self.symbols.get('memory_present'):
            self.trace.append('MemoryMappingFixture'); self.ret(int(self.readable)); return
        service = next((name for name, address in self.extra.items() if address == a), None)
        if service is None:
            super().hook(u, a, size, data); return
        self.trace.append(service)
        if service == 'HandleProtocol':
            if self.handle_fail: self.ret(ERR(7)); return
            assert self.arg(0) == 0xcafe
            u.mem_write(self.arg(2), q(self.li)); self.ret(0); return
        if service == 'LocateProtocol':
            guid = bytes(u.mem_read(self.arg(0), 16))
            if guid == uuid.UUID('26baccb1-6f42-11d4-bce7-0080c73c8881').bytes_le:
                u.mem_write(self.arg(2), q(self.cpu)); self.ret(0); return
            self.ret(ERR(14)); return
        if service == 'Allocate':
            address = self.pool_next; self.pool_next += (self.arg(1) + 15) & ~15
            assert self.pool_next < HEAP + 0x1f0000
            u.mem_write(self.arg(2), q(address)); self.ret(0); return
        if service == 'Timer':
            self.ticks += 100000
            u.mem_write(self.arg(2), q(self.ticks))
            if self.arg(3): u.mem_write(self.arg(3), q(1000000))
            self.ret(0); return
        if service == 'ReadKey':
            assert self.input_queue, 'Fixture keyboard queue exhausted'
            status, scan, ch = self.input_queue.pop(0)
            if not status: u.mem_write(self.arg(1), struct.pack('<HH', scan, ch))
            if self.retire_read: u.mem_write(self.symbols['boot_services_ended'], d(1))
            self.ret(status); return
        if service == 'Stall':
            assert self.arg(0) in (1000, 100000)
            if self.retire_stall: u.mem_write(self.symbols['boot_services_ended'], d(1))
            self.ret(0); return
        if service == 'OutputString':
            self.messages.append(self.console_text(self.arg(1)))
            if self.retire_output: u.mem_write(self.symbols['boot_services_ended'], d(1))
            self.ret(0); return
        self.ret(0)

    def residency(self):
        assert self.call('make_resident', 0xcafe) == 1
        assert self.call('initialize_services') == 1
        assert self.call('publish_runtime_guards') == 1
        return self

    def retired_locally(self):
        core = self.symbols['password_core']
        return (self.getd(self.symbols['boot_services_ended']) == 1 and
                self.getd(self.symbols['console_retired']) == 1 and
                self.getd(self.symbols['console_depth']) == 0 and
                self.getq(self.symbols['console_token']) == 0 and
                bytes(self.u.mem_read(core + 200, 2)) == bytes(2) and
                bytes(self.u.mem_read(core + 40, 128)) == bytes(128) and
                self.state()['retired'] == 1 and not self.state()['armed'])


rows = []
def result(label, condition, **details):
    assert condition, label
    rows.append({'case': label, 'result': 'PASS', **details})

for fault in ['HandleProtocol', 'UnreadableLoadedImage', 'CreateFinalEvent', 'CreateBeforeEvent', 'NoCreateEventEx', 'UnloadPatch']:
    v = ResidencyVM()
    if fault == 'HandleProtocol': v.handle_fail = True
    if fault == 'UnreadableLoadedImage': v.readable = False
    if fault == 'CreateFinalEvent': v.create_fail = True
    if fault == 'CreateBeforeEvent': v.create_ex_fail = True
    if fault == 'NoCreateEventEx': v.u.mem_write(v.bs + 0x170, q(0))
    if fault == 'UnloadPatch': v.patch_fail = 1
    r = v.call('make_resident', 0xcafe)
    expected_resident = fault in ['CreateBeforeEvent', 'NoCreateEventEx', 'UnloadPatch']
    result('residency failure ' + fault, r == 0 and bool(v.var('resident')) == expected_resident and not v.native_sets,
           installed_callbacks=len(v.events), stays_resident=bool(v.var('resident')), native_variable_writes=0)

v = ResidencyVM().residency()
app_events = [e for e in v.events if e['callback'] == v.symbols['refuse_os_handoff']]
result('actual registration binds both early and final halt callbacks',
       len(app_events) == 2 and any(e['type'] == 0x201 and e['tpl'] == 16 for e in app_events) and
       any(e['type'] == 0x200 and e['tpl'] == 16 and e.get('group') == BEFORE_GUID for e in app_events), events=app_events)
result('actual runtime publication binds guard reset capsule and valid CRC',
       v.getq(v.rt + 0x58) == v.symbols['guarded_set'] and
       v.getq(v.symbols['original_set_variable']) == v.symbols['nv_guard_set'] and
       v.getq(v.rt + 0x68) == v.symbols['refuse_reset'] and
       v.getq(v.rt + 0x70) == v.symbols['refuse_capsule'] and v.call('local_runtime_crc_valid') == 1 and
       v.getq(v.li + 0x58) == v.symbols['refuse_unload'] and not v.native_sets)

for missing in ['maintenance_exit_event', 'maintenance_before_event', 'resident']:
    v = ResidencyVM(); v.u.mem_write(v.symbols['maintenance_exit_event'], q(1))
    v.u.mem_write(v.symbols['maintenance_before_event'], q(2)); v.u.mem_write(v.symbols['resident'], d(1))
    v.u.mem_write(v.symbols[missing], d(0) if missing == 'resident' else q(0))
    result('no publication without ' + missing, v.call('publish_runtime_guards') == 0 and not v.patches)

for label, function, args in [('Before event', 'refuse_os_handoff', (1, 0)), ('Final event', 'refuse_os_handoff', (2, 0)),
                              ('ResetSystem', 'refuse_reset', (0, 0, 0, 0))]:
    v = ResidencyVM().residency()
    core = v.symbols['password_core']; v.u.mem_write(core + 40, b'X' * 128)
    v.u.mem_write(core + 200, b'\1\1'); v.u.mem_write(v.symbols['console_depth'], d(1))
    v.u.mem_write(v.symbols['console_token'], q(1))
    before = len(v.calls), len(v.trace)
    v.u.mem_write(v.st + 0x60, q(0xdead0000)); v.u.mem_write(v.st + 48, q(0xdead1000)); v.u.mem_write(v.st + 64, q(0xdead2000))
    value = v.call(function, *args)
    # nv_status() is local; the assertion intentionally leaves all providers
    # inaccessible while checking callback retirement and zeroization.
    halted = v.halted
    retired = v.retired_locally()
    result(label + ' halts with no services and wipes owner/credential', value is None and halted and retired and
           before == (len(v.calls), len(v.trace)) and not v.native_sets)

v = ResidencyVM().residency(); v.call('before_exiting', 0, 0)
result('production Before first returns only the still-resident strict gate',
       v.getq(v.rt + 0x58) == v.symbols['nv_guard_set'] and v.call('local_runtime_crc_valid') == 1 and v.var('boot_services_ended') == 1)
count = len(v.calls), len(v.trace); v.call('refuse_os_handoff', 0, 0); halted = v.halted
result('application Before after production Before still stops locally', halted and count == (len(v.calls), len(v.trace)))

v = ResidencyVM().residency(); count = len(v.calls), len(v.trace)
result('UnloadImage is refused without services', v.call('refuse_unload', 0xcafe) == ERR(15) and count == (len(v.calls), len(v.trace)))
result('UpdateCapsule is refused without services', v.call('refuse_capsule', 0xdead0000, 1, 0) == ERR(8) and count == (len(v.calls), len(v.trace)))

v = ResidencyVM(); v.input_queue = [(ERR(6), 0, 0), (0, 0, ord('Q'))]
r = v.call('read_key')
result('application keyboard NOT_READY yields then returns the actual key', r == ord('Q') << 16 and v.trace == ['ReadKey', 'Stall', 'ReadKey'])
for label, setting, status in [('already retired', 'initial', 0), ('successful read retires', 'read', 0),
                                ('NOT_READY read retires', 'read', ERR(6)), ('Stall retires', 'stall', ERR(6))]:
    v = ResidencyVM(); v.input_queue = [(status, 0, ord('Q'))]
    if setting == 'initial': v.u.mem_write(v.symbols['boot_services_ended'], d(1))
    if setting == 'read': v.retire_read = True
    if setting == 'stall': v.retire_stall = True
    v.call('read_key'); halted = v.halted
    expected = [] if setting == 'initial' else ['ReadKey'] if setting == 'read' else ['ReadKey', 'Stall']
    result('application keyboard ' + label + ' stops at service boundary', halted and v.trace == expected and not v.native_sets)

for label in ['show_log', 'stopped', 'print']:
    v = ResidencyVM(); v.u.mem_write(v.symbols['boot_services_ended'], d(1))
    address = v.sym(label); v.call(address, 0xdead0000); halted = v.halted
    result('retired application ' + label + ' halts before output', halted and not v.trace and not v.native_sets)
v = ResidencyVM(); v.retire_output = True; p = HEAP + 0x19000; v.u.mem_write(p, 'Status only'.encode('utf-16le') + b'\0\0')
v.call(v.sym('print'), p); halted = v.halted
result('output retirement cannot return to application', halted and v.trace == ['OutputString'])

for label, keys in [('ESC cancellation', [(0, 0x17, 0)]),
                    ('short input rejected', [(0, 0, ord('x')), (0, 0, 13), (0, 0, ord('x')), (0, 0, 13), (0, 0, 13)])]:
    v = ResidencyVM(); assert v.initialize() == 1
    assert v.call('nv_activate') == 1 and v.call('begin_console_session') == 1
    assert v.call('nv_begin_action', 1) == 1; v.input_queue = keys
    r = v.call('manage_password', 0)
    v.call('nv_end_action')
    text = ''.join(v.messages)
    result('actual frozen password UI ' + label + ' performs no write', r == 0 and not v.native_sets and
           v.call('platform_session_owned') == 1 and not bytes(v.u.mem_read(v.symbols['password_core'] + 201, 1))[0],
           stars_displayed=text.count('*'), plaintext_logged=False, keyboard_events=v.trace.count('ReadKey'))

report = {'status': 'PASS_ACTUAL_NV_EFI_RESIDENCY_INPUT_AND_CANCEL_PATHS', 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'cases': len(rows), 'rows': rows, 'efi_sha256': sha(OUT / 'BOOTX64.EFI'),
          'build_manifest_sha256': sha(OUT / 'build.json'), 'production_driver_sha256': manifest['production_driver_sha256'],
          'sources': {str(p.relative_to(ROOT)): sha(p) for p in [Path(__file__), HELPER, ns['helper'], OUT / 'nv_test.map']},
          'real_code': ['make_resident', 'initialize_services', 'publish_runtime_guards', 'install_variable_guard', 'before_exiting',
                        'refuse_os_handoff', 'refuse_unload', 'refuse_reset', 'refuse_capsule', 'read_key', 'print',
                        'show_log retirement branch', 'stopped retirement branch', 'manage_password cancellation/rejection'],
          'fixtures': ['UEFI provider return values and RAM variable store', 'readable/writable page and patch-memory helper',
                       'console input/output and text mode methods', 'CPU timer', 'GOP absence; no framebuffer capture'],
          'limitations': ['This is local instruction execution, not physical firmware persistence or a whole boot.',
                          'The production password cryptographic success path is covered by the separate builder-owned fixture, not these cancellation tests.',
                          'No unrelated asynchronous callback at every instruction is modeled.',
                          'Final HLT is intercepted in Unicorn; no host halt, reset, BMC or NVRAM access occurred.'],
          'production_or_harness_sources_modified': False, 'media_created': False, 'hardware_access': False}
path = HERE / 'residency_validation.json'
path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'cases': len(rows), 'efi_sha256': report['efi_sha256'], 'output': str(path)}))
