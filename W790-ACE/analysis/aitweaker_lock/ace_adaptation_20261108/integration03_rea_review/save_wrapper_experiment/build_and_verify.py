"""Actual compiled save-scope prototype + original ACE machine-code replay.

All firmware patches exist only in the Unicorn memory fixture. No original PE,
production source, BIOS container, physical machine, or BMC is modified.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile
import unicorn
from unicorn import x86_const as x86

ZIG = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
ORIGINAL = ROOT / 'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules/AMITSE.efi'
PIN = '99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5'
BUILD = HERE / 'build'
DLL = BUILD / 'save_scope.dll'
TSE, ARENA, STACK, STOP, CODE, TRAMP = (0x10000000, 0x20000000, 0x30000000,
                                      0x40000000, 0x50000000, 0x60000000)
DENIED, DEVICE_ERROR = 0x800000000000000f, 0x8000000000000007
sha = lambda data: hashlib.sha256(data).hexdigest()


def build():
    BUILD.mkdir(exist_ok=True)
    env = os.environ.copy()
    env['ZIG_GLOBAL_CACHE_DIR'] = str(HERE / '.zig-global')
    env['ZIG_LOCAL_CACHE_DIR'] = str(HERE / '.zig-local')
    obj = BUILD / 'save_scope.obj'
    commands = [
        [str(ZIG), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc',
         '-isystem', str(ZIG.parent / 'lib/include'), '-std=c11', '-O2',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone',
         '-Wall', '-Wextra', '-Werror', '-c', str(HERE / 'save_scope.c'), '-o', str(obj)],
        [str(ZIG), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64',
         '/dynamicbase', '/fixed:no', '/nxcompat', '/timestamp:0',
         '/map:' + str(BUILD / 'save_scope.map'), '/out:' + str(DLL), str(obj)],
    ]
    logs = []
    for command in commands:
        r = subprocess.run(command, cwd=HERE, env=env, capture_output=True, text=True,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        logs.append({'command': command, 'returncode': r.returncode,
                     'stdout': r.stdout, 'stderr': r.stderr})
        if r.returncode:
            (HERE / 'build_log.json').write_text(json.dumps(logs, indent=2) + '\n')
            raise RuntimeError('compile/link failed')
    pe = pefile.PE(str(DLL))
    assert not pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
    result = {'status': 'PASS_IMPORT_FREE_EXPERIMENT_BUILD', 'commands_and_logs': logs,
              'source_sha256': sha((HERE / 'save_scope.c').read_bytes()),
              'dll_sha256': sha(DLL.read_bytes()), 'imports': [],
              'exports': {s.name.decode(): hex(s.address) for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}}
    (HERE / 'build_log.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


class NativeFixture:
    def __init__(self, variable_count=1):
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.exports = {}
        source = ORIGINAL.read_bytes()
        assert sha(source) == PIN
        original_pe = pefile.PE(data=source)
        original_map = original_pe.get_memory_mapped_image()
        self.original_prologue = original_map[0x142ac:0x142be]
        assert self.original_prologue.hex() == '40555356574154415541564157488d6c24e1'
        for file, base in ((ORIGINAL, TSE), (DLL, CODE)):
            pe = pefile.PE(str(file))
            if base == CODE:
                self.exports = {s.name.decode(): base+s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols}
            pe.relocate_image(base)
            mapped = pe.get_memory_mapped_image()
            self.uc.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
            self.uc.mem_write(base, mapped)
        self.uc.mem_map(ARENA, 0x10000)
        self.uc.mem_map(STACK, 0x40000)
        self.uc.mem_map(STOP, 0x1000)
        self.uc.mem_write(STOP, b'\xc3')
        self.uc.mem_map(TRAMP, 0x1000)
        jump = lambda target: b'\xff\x25\x00\x00\x00\x00' + struct.pack('<Q', target)
        self.uc.mem_write(TRAMP, self.original_prologue + jump(TSE + 0x142be))
        self.uc.mem_write(TSE + 0x142ac, jump(self.exports['save_wrapper']) + b'\x90' * 4)
        self.setq('save_original', TRAMP)
        self.setq('fixture_save_entry', TSE + 0x142ac)
        self.q(TSE + 0x82748, ARENA)
        self.q(TSE + 0x92270, ARENA + 0x1000)
        self.uc.mem_write(ARENA + 0x1000, struct.pack('<II', 1, 0))
        self.q(TSE + 0x92b08, ARENA + 0x1200)
        # Ordinary records use native RT.SetVariable. Indices zero/one avoid
        # special BootOrder/DriverOrder native paths in this fixture.
        table, record, cache, value, rt = [ARENA+x for x in (0x2000, 0x2100, 0x3000, 0x3200, 0x4000)]
        self.q(TSE + 0x92278, table)
        self.uc.mem_write(table, struct.pack('<I', variable_count))
        self.expected_io_arguments = []
        for index in range(variable_count):
            target, data = record + index*0x100, value + index*0x10
            self.uc.mem_write(table+4+index*4, struct.pack('<I', 0x100+index*0x100))
            self.uc.mem_write(target, bytes.fromhex('11111111222233334444555555555555'))
            self.uc.mem_write(target + 16, ('FixtureValue'+str(index)+'\0').encode('utf-16-le'))
            self.uc.mem_write(target + 0x60, struct.pack('<I', 7))
            self.uc.mem_write(target + 0x68, struct.pack('<I', 0x1000))
            self.q(cache + index*16, data)
            self.q(cache + index*16 + 8, 8)
            self.q(data, 0x123456789abcdef0 + index)
            self.expected_io_arguments.append([target+16, target, 7, 8, data])
        self.q(TSE + 0x82650, cache)
        self.q(TSE + 0x824d8, rt)
        self.q(rt + 0x58, self.exports['fixture_set_variable'])
        self.q(ARENA + 0x30, ARENA + 0x5000)
        self.uc.mem_write(TSE + 0x82738, b'\x7a')
        self.uc.mem_write(TSE + 0x82740, b'\x00\x00')
        self.native_body_entries = 0
        self.native_commit_entries = 0
        self.native_commit_statuses = []
        self.native_save_returns = []
        self.io_arguments = []
        self.stub_calls = []
        self.trampoline_arguments = []
        self.stub_rvas = {0x19ef4: 0, 0x32484: 0, 0x322b4: 0,
                          0x64e4: 0, 0x5ab8: 0, 0x29d14: 0, 0x11d8c: 0,
                          0x5cc40: 0, 0x5b0c: 0}
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self.hook)

    def q(self, address, value):
        self.uc.mem_write(address, struct.pack('<Q', value))

    def setq(self, name, value):
        self.q(self.exports[name], value)

    def setd(self, name, value):
        self.uc.mem_write(self.exports[name], struct.pack('<I', value))

    def get(self, name, size=4):
        return int.from_bytes(self.uc.mem_read(self.exports[name], size), 'little')

    def hook(self, uc, address, size, data):
        if address == STOP:
            uc.emu_stop()
            return
        if address == TRAMP:
            self.trampoline_arguments.append([hex(uc.reg_read(r)) for r in
                (x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9)])
        if address == TSE + 0x142be:
            self.native_body_entries += 1
        if address == TSE + 0x111b4:
            self.native_commit_entries += 1
        if address == TSE + 0x11257:
            self.native_commit_statuses.append(uc.reg_read(x86.UC_X86_REG_RAX))
        if address == self.exports['fixture_set_variable']:
            regs = (x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9)
            args = [uc.reg_read(r) for r in regs]
            rsp = uc.reg_read(x86.UC_X86_REG_RSP)
            args.append(int.from_bytes(uc.mem_read(rsp+0x28, 8), 'little'))
            assert args in self.expected_io_arguments
            self.io_arguments.append([hex(v) for v in args])
        if address == TSE + 0x148df:
            self.native_save_returns.append(uc.reg_read(x86.UC_X86_REG_RAX) & 255)
        if address - TSE in self.stub_rvas:
            rva = address - TSE
            self.stub_calls.append(hex(rva))
            rsp = uc.reg_read(x86.UC_X86_REG_RSP)
            ret = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(x86.UC_X86_REG_RAX, self.stub_rvas[rva])
            uc.reg_write(x86.UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(x86.UC_X86_REG_RIP, ret)

    def call(self, address, args, check_canaries=True):
        rsp = STACK + 0x3f000 - 8
        self.q(rsp, STOP)
        nonvolatile = (x86.UC_X86_REG_RBX, x86.UC_X86_REG_RBP, x86.UC_X86_REG_RSI,
                       x86.UC_X86_REG_RDI, x86.UC_X86_REG_R12, x86.UC_X86_REG_R13,
                       x86.UC_X86_REG_R14, x86.UC_X86_REG_R15)
        canaries = {r: 0x1111000000000000 + n * 0x100010001 for n, r in enumerate(nonvolatile)}
        for reg, value in canaries.items():
            self.uc.reg_write(reg, value)
        xmm = {getattr(x86, 'UC_X86_REG_XMM' + str(n)): int.from_bytes(bytes([n]) * 16, 'little')
               for n in range(6, 16)}
        for reg, value in xmm.items():
            self.uc.reg_write(reg, value)
        self.uc.reg_write(x86.UC_X86_REG_RSP, rsp)
        self.uc.reg_write(x86.UC_X86_REG_RFLAGS, 0x202)
        for reg, value in zip((x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8,
                               x86.UC_X86_REG_R9), args):
            self.uc.reg_write(reg, value)
        self.uc.emu_start(address, STOP + 1, timeout=2_000_000, count=100000)
        assert self.uc.reg_read(x86.UC_X86_REG_RIP) == STOP
        if check_canaries:
            assert all(self.uc.reg_read(reg) == value for reg, value in (canaries | xmm).items())
        assert self.uc.reg_read(x86.UC_X86_REG_RSP) == rsp + 8
        return self.uc.reg_read(x86.UC_X86_REG_RAX)

    def invoke(self, name, rva, status, mark):
        self.setq('fixture_status', status)
        self.setd('fixture_mark_denial', mark)
        previous = self.get('original_calls')
        result = self.call(TSE + rva, [ARENA if name == 'F10' else 0, 0x22, 0x33, 0x44])
        assert self.get('save_top', 8) == 0 and self.get('save_depth') == 0
        assert self.get('original_calls') == self.native_body_entries
        assert self.native_commit_entries == self.get('fixture_calls')
        return {'name': name, 'entry': hex(rva), 'io_status': hex(status), 'explicit_guard_denial': bool(mark),
                'return': hex(result), 'return_AL': result & 255,
                'exit_byte': self.uc.mem_read(ARENA + 0x5a, 1)[0],
                'reset_flags': list(self.uc.mem_read(TSE + 0x82740, 2)),
                'save_stay_state_82738': self.uc.mem_read(TSE + 0x82738, 1)[0],
                'scope_head_after': self.get('save_top', 8), 'scope_depth_after': self.get('save_depth'),
                'scope_max_depth': self.get('max_depth_seen'),
                'wrapper_entries': self.get('wrapper_entries'), 'original_calls': self.get('original_calls'),
                'original_calls_this_invocation': self.get('original_calls') - previous,
                'native_body_entries': self.native_body_entries, 'native_commit_entries': self.native_commit_entries,
                'native_commit_statuses': [hex(v) for v in self.native_commit_statuses],
                'verified_original_RT_arguments': self.io_arguments.copy(),
                'native_unmodified_save_AL_observations': self.native_save_returns.copy(),
                'last_denial': hex(self.get('last_denial', 8)),
                'trampoline_arguments': self.trampoline_arguments.copy(),
                'preserved_nonvolatile_registers_and_stack': True,
                'declared_OEM_stub_calls': self.stub_calls.copy()}


def verify():
    rows = []
    entries = [('F10', 0x330f8), ('ExitSave', 0x44060), ('ResetSave', 0x44090),
               ('StaySave', 0x440fc), ('CommonSave', 0x142ac)]
    for name, entry in entries:
        for mode, status, mark in (('success', 0, 0), ('guard_denial', DENIED, 1),
                                    ('legacy_backend_error_unmarked', DEVICE_ERROR, 0)):
            fixture = NativeFixture()
            row = fixture.invoke(name, entry, status, mark)
            row['mode'] = mode
            expected = int(not mark)
            assert row['original_calls'] == row['native_commit_entries'] == 1
            assert row['native_unmodified_save_AL_observations'] == [1]
            if name in ('F10', 'ExitSave', 'ResetSave'):
                assert row['exit_byte'] == expected and row['reset_flags'] == [expected, expected]
            elif name == 'StaySave':
                assert row['exit_byte'] == 0 and row['reset_flags'] == [0, expected]
                assert row['save_stay_state_82738'] == 0
            else:
                assert row['return_AL'] == expected
                assert row['trampoline_arguments'] == [['0x0', '0x22', '0x33', '0x44']]
            rows.append(row)
    # Real vendor initialization has no browser session in this fixture and is
    # never denied just because of that. Even legacy unmarked errors retain ABI.
    for status in (0, DEVICE_ERROR):
        fixture = NativeFixture()
        row = fixture.invoke('VendorInitializerWithoutSession', 0x5ef44, status, 0)
        assert row['return'] == '0x0' and row['original_calls'] == 1
        rows.append(row)
    # Nested denial is recorded by the compiled innermost scope then propagated.
    for inner_mark in (0, 1):
        fixture = NativeFixture()
        fixture.setd('fixture_nested_once', 1)
        fixture.setq('fixture_nested_status', DENIED if inner_mark else 0)
        fixture.setd('fixture_nested_mark', inner_mark)
        row = fixture.invoke('CommonSaveNested', 0x142ac, 0, 0)
        assert row['return_AL'] == int(not inner_mark)
        assert row['original_calls'] == row['native_commit_entries'] == 2
        assert row['scope_max_depth'] == 2
        assert row['native_unmodified_save_AL_observations'] == [1, 1]
        row['nested_explicit_denial'] = bool(inner_mark)
        rows.append(row)
    # A prior unowned marker cannot poison a later save, and a fresh attempt
    # does not inherit the failure of a previous completed attempt.
    fixture = NativeFixture()
    fixture.call(fixture.exports['save_record_denial'], [DENIED, 0, 0, 0])
    assert fixture.get('unscoped_denials') == 1
    row = fixture.invoke('UnscopedDenialThenSuccess', 0x142ac, 0, 0)
    assert row['return_AL'] == 1
    rows.append(row)
    fixture = NativeFixture()
    failed = fixture.invoke('FirstAttemptDenied', 0x142ac, DENIED, 1)
    assert failed['return_AL'] == 0
    rows.append(failed)
    recovered = fixture.invoke('FreshAttemptSuccess', 0x142ac, 0, 0)
    assert recovered['return_AL'] == 1 and recovered['original_calls_this_invocation'] == 1
    rows.append(recovered)
    # A later unrelated commit is retained after the first explicit denial;
    # reporting false therefore does not imply an all-or-nothing transaction.
    fixture = NativeFixture(variable_count=2)
    fixture.setd('fixture_first_only', 1)
    partial = fixture.invoke('FirstDeniedSecondUnrelatedSuccess', 0x142ac, DENIED, 1)
    assert partial['native_commit_statuses'] == [hex(DENIED), '0x0']
    assert partial['native_commit_entries'] == 2 and partial['original_calls'] == 1
    assert partial['return_AL'] == 0 and partial['native_unmodified_save_AL_observations'] == [1]
    rows.append(partial)
    # Exceeding the bounded tracking depth still calls the original iterator
    # exactly once for every actual invocation and marks the outer result false.
    fixture = NativeFixture()
    fixture.setd('fixture_nested_once', 16)
    fixture.setq('fixture_nested_status', 0)
    fixture.setd('fixture_nested_mark', 0)
    overflow = fixture.invoke('SeventeenNestedSaves', 0x142ac, 0, 0)
    assert overflow['original_calls'] == overflow['native_commit_entries'] == 17
    assert overflow['scope_max_depth'] == 16 and fixture.get('overflow_count') == 1
    assert overflow['return_AL'] == 0
    rows.append(overflow)
    report = {
        'status': 'PASS_COMPILED_EXPERIMENT_WITH_ORIGINAL_ACE_SAVE_PATHS',
        'classification': 'ISOLATED_UNICORN_FEASIBILITY_NOT_PRODUCTION_OR_HARDWARE_ACCEPTANCE',
        'script_sha256': sha(Path(__file__).read_bytes()), 'source_sha256': sha((HERE / 'save_scope.c').read_bytes()),
        'dll_sha256': sha(DLL.read_bytes()), 'original_amitse_sha256': PIN,
        'cases': len(rows), 'rows': rows,
        'preservation': {'production_source_changed': False, 'original_module_file_changed': False,
                          'device_access': False, 'original_calls_suppressed': 0,
                          'authorization_added': False, 'write_or_cache_rollback_claimed': False},
        'native_code_executed': ['original ACE F10/SaveExit/SaveReset/SaveStay callers',
                                 'actual compiled scope wrapper and marker',
                                 'in-memory original 18-byte trampoline',
                                 'complete original SaveIterator', 'original VariableCommit',
                                 'original vendor initializer control flow'],
        'fixtures': ['one/two-entry variable tables with direct RT path', 'Runtime SetVariable result and explicit marker',
                    'confirmation success', 'OEM page-leave/notify/post-save functions',
                    'vendor default population', 'native cache refresh after successful commit'],
        'observations': [
            'Every regular invocation executes the original save body once; observed original save AL remains one even for the denied fixture.',
            'The compiled wrapper changes only final feedback for an explicit denial, and native F10/SaveExit/SaveReset then retain the browser.',
            'Unmarked backend errors intentionally preserve the legacy result in this smallest experiment.',
            'Vendor initialization without a browser session remains callable and returns the original success result in the covered fixtures.',
            'Nested denial propagates; independent subsequent save starts clean; out-of-scope denial does not poison it.',
            'A two-variable save still reaches a successful second commit after the first is denied, then reports false; no transactional rollback is implied.',
            'SaveStay still clears native state byte 0x82738; the experiment deliberately does not claim complete UI feedback.',
        ],
        'limitations': [
            'This DLL is not deployable firmware and has no integration, installation transaction, identity checks, EBS cleanup, or live error message.',
            'Only one/two synthetic ordinary direct-RT records are exercised. HII routing, actual variable sets, BootOrder/DriverOrder paths and live NVRAM are not covered.',
            'The fixture marker represents a deliberate production guard denial; it is not a test of the existing production guard implementation.',
            'The current experiment assumes serialized same-CPU UEFI UI calls. Cross-CPU concurrency and asynchronous lifetime interactions require separate design.',
            'Four register arguments are forwarded. No claim is made about unknown private callers requiring additional stack parameters.',
            'Unrelated writes and OEM post-save effects are preserved; no atomic save or rollback is provided.',
            'SaveStay state restoration, retained dirty caches, and user-visible message behavior remain separate work.',
        ],
    }
    out = HERE / 'verification.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'cases': len(rows), 'output': str(out),
                      'sha256': sha(out.read_bytes()), 'dll_sha256': report['dll_sha256']}, indent=2))


if __name__ == '__main__':
    build()
    verify()
