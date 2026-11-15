"""Original ACE cache refresh + failed save -> successful retry experiment.

Unlike the first feasibility fixture this executes original cache reread/free,
OEM save callback dispatcher and its two actual handlers, protocol notification
calls, and post-save reconnect logic. Only UEFI services/device protocols and
confirmation/page-leave are local fixtures. Nothing reaches a physical device.
"""
import importlib.util
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ace_save_prototype', HERE / 'build_and_verify.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
U = base.x86
ERR = lambda n: 0x8000000000000000 | n


class StateFixture(base.NativeFixture):
    def __init__(self, repair_flags, wrap_stay, reconnect):
        super().__init__()
        self.repair_flags, self.wrap_stay, self.reconnect = repair_flags, wrap_stay, reconnect
        self.bs = base.ARENA + 0x6000
        self.heap = base.ARENA + 0x8000
        self.freed, self.service_calls, self.writes = [], [], []
        self.target_name = base.ARENA + 0x2110
        self.value_size = 8
        self.target_guid = bytes(self.uc.mem_read(base.ARENA + 0x2100, 16))
        self.key = self.key_at(self.target_name, base.ARENA + 0x2100)
        self.edited = bytes(self.uc.mem_read(base.ARENA + 0x3200, 8))
        self.persisted = {self.key: (7, bytes.fromhex('1020304050607080'))}
        self.initial_persisted = self.persisted[self.key][1]
        for rva in (0x11d8c, 0x29d14, 0x5ab8, 0x64e4, 0x32484):
            self.stub_rvas.pop(rva)
        self.uc.mem_write(base.ARENA + 0x1000, struct.pack('<I', 0))  # no validation questions
        self.q(base.TSE + 0x824c8, self.bs)
        self.q(base.TSE + 0x82a68, self.bs)
        self.q(base.ARENA + 0x4048, base.STOP + 0x100)  # RT.GetVariable
        self.service_map = {0x100: 'GetVariable', 0x110: 'AllocatePool', 0x120: 'FreePool',
                            0x130: 'CopyMem', 0x140: 'SetMem', 0x150: 'InstallProtocol',
                            0x160: 'UninstallProtocol', 0x170: 'LocateProtocol',
                            0x180: 'GetPackageListHandle', 0x190: 'DisconnectController',
                            0x1a0: 'ConnectController'}
        for offset, stub in ((0x40, 0x110), (0x48, 0x120), (0x160, 0x130), (0x168, 0x140),
                             (0x80, 0x150), (0x90, 0x160), (0x140, 0x170),
                             (0x110, 0x190), (0x108, 0x1a0)):
            self.q(self.bs+offset, base.STOP+stub)
        self.uc.mem_write(base.STOP+0x100, b'\xc3' * 0x200)
        self.setq('fixture_target_name', self.target_name)
        if repair_flags:
            self.setq('fixture_dirty_82789', base.TSE + 0x82789)
            self.setq('fixture_dirty_82738', base.TSE + 0x82738)
        self.setq('save_stay_original', base.TSE + 0x440fc)
        self.cached_before = self.readq(base.TSE+0x6bb18)
        if wrap_stay:
            assert self.cached_before == base.TSE+0x440fc
            original = bytes(self.uc.mem_read(base.TSE+0x440fc, 16))
            assert original.hex() == '4883ec28488d0d09740200e8a001fdff'
            jump = lambda target: b'\xff\x25\0\0\0\0'+struct.pack('<Q',target)
            # Preserve the original LEA result and direct-call target with
            # explicit position-independent gateway instructions.
            gateway = (original[:4] + b'\x48\xb9'+struct.pack('<Q',base.TSE+0x6b510)
                       + b'\xff\x15\x02\0\0\0\xeb\x08'+struct.pack('<Q',base.TSE+0x142ac)
                       + jump(base.TSE+0x4410c))
            assert len(gateway) == 44
            self.uc.mem_write(base.TRAMP+0x80, gateway)
            self.setq('save_stay_original', base.TRAMP+0x80)
            self.uc.mem_write(base.TSE+0x440fc, jump(self.exports['save_stay_wrapper'])+b'\x90\x90')
        self.cached_after = self.readq(base.TSE+0x6bb18)
        assert self.cached_after == self.cached_before  # static slot untouched
        for offset, target in ((0x200, self.cached_before), (0x280, self.cached_after)):
            # x64 indirect-call fixture uses the copied original entry pointer.
            stub = b'\x48\x83\xec\x28\xff\x15\x16\0\0\0\x48\x83\xc4\x28\xc3'
            self.uc.mem_write(base.TRAMP+offset, stub+b'\x90'*(32-len(stub))+struct.pack('<Q',target))
        self.uc.mem_write(base.TSE + 0x82789, b'\x01')
        self.uc.mem_write(base.TSE + 0x82738, b'\x01')
        if reconnect:
            self.q(base.TSE+0x828a0, base.ARENA+0x5800)
            self.q(base.ARENA+0x5800, 0x76543210)
            self.q(base.ARENA+0x5808, 0)
            self.q(base.TSE+0x825d8, base.ARENA+0x5900)
            self.q(base.ARENA+0x5950, base.STOP+0x180)
        else:
            self.q(base.TSE+0x828a0, 0)
        self.uc.mem_write(base.TSE+0x82970, b'\0')

    def key_at(self, name, guid):
        units = bytearray()
        for index in range(128):
            unit = bytes(self.uc.mem_read(name+2*index, 2))
            if unit == b'\0\0':
                break
            units.extend(unit)
        else:
            raise AssertionError('fixture variable name lacks bounded terminator')
        return (bytes(self.uc.mem_read(guid, 16)).hex(), units.decode('utf-16-le'))

    def readq(self, address):
        return int.from_bytes(self.uc.mem_read(address, 8), 'little')

    def return_service(self, result):
        rsp = self.uc.reg_read(U.UC_X86_REG_RSP)
        self.uc.reg_write(U.UC_X86_REG_RAX, result)
        self.uc.reg_write(U.UC_X86_REG_RSP, rsp+8)
        self.uc.reg_write(U.UC_X86_REG_RIP, self.readq(rsp))

    def hook(self, uc, address, size, data):
        if address-base.STOP in self.service_map:
            name = self.service_map[address-base.STOP]
            rcx, rdx, r8, r9 = [uc.reg_read(r) for r in
                                (U.UC_X86_REG_RCX, U.UC_X86_REG_RDX, U.UC_X86_REG_R8, U.UC_X86_REG_R9)]
            self.service_calls.append(name)
            result = 0
            if name == 'GetVariable':
                key = self.key_at(rcx, rdx)
                item = self.persisted.get(key)
                if item is None:
                    result = ERR(14)
                else:
                    attributes, value = item
                    capacity = self.readq(r9)
                    buffer = self.readq(uc.reg_read(U.UC_X86_REG_RSP)+0x28)
                    self.q(r9, len(value))
                    if r8:
                        uc.mem_write(r8, struct.pack('<I', attributes))
                    if not buffer or capacity < len(value):
                        result = ERR(5)
                    else:
                        uc.mem_write(buffer, value)
            elif name == 'AllocatePool':
                assert 0 < rdx < 4096 and self.heap+rdx < base.ARENA+0x10000
                self.q(r8, self.heap)
                self.heap += (rdx+15) & ~15
            elif name == 'FreePool':
                self.freed.append(hex(rcx))
            elif name == 'CopyMem':
                assert r8 < 4096
                uc.mem_write(rcx, bytes(uc.mem_read(rdx, r8)))
            elif name == 'SetMem':
                assert rdx < 4096
                uc.mem_write(rcx, bytes([r8 & 255])*rdx)
            elif name == 'InstallProtocol':
                self.q(rcx, 0x12345000)
            elif name == 'LocateProtocol':
                result = ERR(14)  # OEM optional protocol in 0x39708 absent.
            elif name == 'GetPackageListHandle':
                self.q(r8, 0x12345600)
            self.return_service(result)
            return
        if address == self.exports['fixture_set_variable']:
            args = [uc.reg_read(r) for r in
                    (U.UC_X86_REG_RCX, U.UC_X86_REG_RDX, U.UC_X86_REG_R8, U.UC_X86_REG_R9)]
            args.append(self.readq(uc.reg_read(U.UC_X86_REG_RSP)+0x28))
            key = self.key_at(args[0], args[1])
            assert args[3] <= 4096
            status = self.get('fixture_status', 8) if key == self.key else 0
            payload = bytes(uc.mem_read(args[4], args[3]))
            if not status & (1 << 63):
                self.persisted[key] = (args[2], payload)
            self.writes.append({'name': key[1], 'status': hex(status), 'bytes': payload.hex(),
                                'protected_fixture': key == self.key})
            if key == self.key:
                assert args[:4] == [self.target_name, base.ARENA+0x2100, 7, self.value_size]
                assert args[4] == self.readq(base.ARENA+0x3000)
            self.expected_io_arguments.append(args)
        super().hook(uc, address, size, data)

    def attempt(self, caller, denied):
        self.setq('fixture_status', base.DENIED if denied else 0)
        self.setd('fixture_mark_denial', int(denied))
        before_writes, before_services = len(self.writes), len(self.service_calls)
        before_native, before_freed = self.native_body_entries, len(self.freed)
        entry = (base.TRAMP+0x200 if caller == 'SaveStayCachedBefore' else
                 base.TRAMP+0x280 if caller == 'SaveStayCachedAfter' else
                 self.readq(base.TSE+0x6bb18) if caller == 'SaveStay' else
                 base.TSE + (0x330f8 if caller == 'F10' else 0x142ac))
        result = self.call(entry, [base.ARENA if caller == 'F10' else 0, 0, 0, 0])
        pointer, length = self.readq(base.ARENA+0x3000), self.readq(base.ARENA+0x3008)
        assert self.get('save_top', 8) == self.get('save_action_top', 8) == self.get('save_depth') == 0
        assert self.native_body_entries-before_native == 1
        return {'caller': caller, 'denied': denied, 'return': hex(result),
                'cache_pointer': hex(pointer), 'cache_length': length,
                'cache_bytes': bytes(self.uc.mem_read(pointer, length)).hex(),
                'persisted_protected': self.persisted[self.key][1].hex(),
                'changed_82789': self.uc.mem_read(base.TSE+0x82789, 1)[0],
                'unsaved_82738': self.uc.mem_read(base.TSE+0x82738, 1)[0],
                'exit_byte': self.uc.mem_read(base.ARENA+0x5a, 1)[0],
                'reset_flags': list(self.uc.mem_read(base.TSE+0x82740, 2)),
                'writes': self.writes[before_writes:], 'services': self.service_calls[before_services:],
                'freed': self.freed[before_freed:], 'repair_flags': self.repair_flags,
                'save_stay_wrapper': self.wrap_stay, 'reconnect_fixture': self.reconnect,
                'scope_heads_empty': True, 'original_iterator_calls': 1}


def main():
    rows = []
    # Counterexamples retain the current minimum-wrapper behavior.
    f = StateFixture(False, False, False)
    row = f.attempt('F10', True)
    assert row['changed_82789'] == 0 and row['cache_bytes'] == f.edited.hex()
    row['classification'] = 'COUNTEREXAMPLE_COMMON_AL_ONLY_LOSES_CHANGED_FLAG'
    rows.append(row)
    f = StateFixture(True, False, False)
    row = f.attempt('SaveStay', True)
    assert row['changed_82789'] == 1 and row['unsaved_82738'] == 0
    row['classification'] = 'COUNTEREXAMPLE_COMMON_FLAG_REPAIR_PRECEDES_SAVESTAY_CLEAR'
    rows.append(row)
    for caller in ('F10', 'CommonSave', 'SaveStay', 'SaveStayCachedBefore', 'SaveStayCachedAfter'):
        for reconnect in (False, True):
            f = StateFixture(True, True, reconnect)
            first = f.attempt(caller, True)
            assert first['cache_pointer'] == hex(base.ARENA+0x3200)
            assert first['cache_bytes'] == f.edited.hex()
            assert first['persisted_protected'] == f.initial_persisted.hex()
            assert first['changed_82789'] == first['unsaved_82738'] == 1
            assert not first['freed']
            assert [w['status'] for w in first['writes'] if w['protected_fixture']] == [hex(base.DENIED)]
            assert any(not w['protected_fixture'] and w['status'] == '0x0' for w in first['writes'])
            second = f.attempt(caller, False)
            assert second['cache_bytes'] == second['persisted_protected'] == f.edited.hex()
            assert second['cache_pointer'] != first['cache_pointer']
            assert hex(base.ARENA+0x3200) in second['freed']
            assert second['changed_82789'] == 0
            if caller.startswith('SaveStay'):
                assert second['unsaved_82738'] == 0
            assert second['services'].count('GetVariable') >= 3
            if reconnect:
                assert 'DisconnectController' in first['services'] and 'ConnectController' in first['services']
            rows.append({'classification': 'FAILED_THEN_SUCCESSFUL_RETRY', 'first': first, 'retry': second})
    report = {
        'status': 'PASS_ORIGINAL_CACHE_RETENTION_AND_COMPILED_DIRTY_FEEDBACK_EXPERIMENT',
        'case_groups': len(rows), 'save_attempts': 22, 'rows': rows,
        'script_sha256': base.sha(Path(__file__).read_bytes()),
        'source_sha256': base.sha((HERE/'save_scope.c').read_bytes()),
        'dll_sha256': base.sha(base.DLL.read_bytes()), 'original_AMITSE_sha256': base.PIN,
        'production_or_device_changes': False,
        'observations': [
            'Rejected native VariableCommit never invokes original cache refresh and leaves the edited buffer and descriptor intact in the covered original flow.',
            'On a later successful commit the actual original 0x11d8c/0x11d48/0x10f40/0x13e4 path reads persisted bytes, frees the old cache, and installs the replacement.',
            'The original iterator does not filter the next commit by changed flags: the exact edited data is submitted on retry.',
            'AL-only feedback loses 0x82789. Common iterator repair alone still loses 0x82738 after SaveStay returns.',
            'The compiled common wrapper plus a SaveStay entry wrapper at 0x440fc preserve both flags on deliberate denial, without suppressing original calls.',
            'SaveStay uses a relocated 44-byte gateway for its 16-byte prefix. The original 0x6bb18 slot stays unchanged; pointers copied before or after patching both reach the entry wrapper.',
            'Actual OEM save callback 0x3cbdc updates an unrelated save-count variable even in a denied save. This is preserved and is not transaction rollback.',
        ],
        'native_additions_over_initial_fixture': ['0x11d8c', '0x11d48', '0x10f40', '0x13e4',
                                                  '0x5958', '0x3eea8', '0x5a54', '0x5ab8',
                                                  '0x6370', '0x3cbdc', '0x39708', '0x64e4', '0x29d14', '0x32484'],
        'limits': [
            'This remains a local experiment with synthetic variable records and UEFI service/device fixtures.',
            'Protocol notification calls execute, but arbitrary external registrants are not run. Optional OEM protocol at 0x39708 is absent in the fixture.',
            'Reconnect calls execute with no external cache mutation, and dynamic UI rebuild flag 0x82970 is zero. Full live ASUS cache and HII reconfiguration still require hardware observation.',
            'Cached pointer tests use explicit x64 indirect-call fixtures; the whole original 0x82970 dynamic UI rebuild is not replayed. Unknown private mid-function entries and cross-CPU concurrency are not exhausted.',
            'A production integration must validate current module ownership, data pointers, rollback state and EBS lifetime before restoring flags.',
            'No preservation of already-committed unrelated NVRAM values, no complete rollback, and no visible error dialog are claimed.',
        ],
    }
    out=HERE/'retry_state_verification.json'
    out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'groups': len(rows), 'attempts':22,
                      'output':str(out), 'sha256':base.sha(out.read_bytes())},indent=2))


if __name__ == '__main__':
    main()
