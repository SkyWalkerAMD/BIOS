"""Offline ARM emulation. Every external operation is an in-memory mock.

No network, host /conf files, or BMC operations are performed. This executes
bounded functions extracted from the official image in Unicorn, not on hardware.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'analysis'))
from bmc_arm_inspect import Elf32
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

LIBROOT = ROOT / 'analysis/bmc_1_3_13_official/selected-rootfs/usr/local/lib'
LIBRARIES = {
    'cmd': (LIBROOT / 'libipmipdkcmds.so.13.0.0',
            'cc104323a4813a4b00bb19d2c016c486a5f3634c584d27652372c773d8b78e44'),
    'getter': (LIBROOT / 'libipmi.so.13.10.0',
               '67d5a25782d517fe269b013ffc67c7789714f0ad0ad1ca6e0914f9a9553ba90e'),
    'stack': (LIBROOT / 'libipmistack.so.13.13.0', None),
}
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)
REQ, RESP, DATA, STACK, STOP = 0x680000, 0x681000, 0x690000, 0x800000, 0x880000


def arm_imm(word):
    value, rotate = word & 255, ((word >> 8) & 15) * 2
    return ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff if rotate else value


class Emulation:
    def __init__(self, key, files=None, nvr_fail=False, file_short_write=None):
        path, digest = LIBRARIES[key]
        if digest:
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        self.elf = Elf32(path)
        self.u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.u.mem_map(0, 0x900000)
        for s in self.elf.sections:
            if s['flags'] & 2 and s['size'] and s['type'] != 8:
                self.u.mem_write(s['addr'], self.elf.data[s['off']:s['off'] + s['size']])
        self.globals, self.plt = {}, {}
        self.files = dict(files or {})
        self.calls, self.nvr_calls, self.memcpy_sizes = [], [], []
        self.nvr_fail, self.file_short_write = nvr_fail, file_short_write
        self.streams, self.fdpos = {}, {}
        self.bad_copy = None
        for a, r in self.elf.relocs.items():
            if r['type'] != 2:
                continue
            if r['value']:
                value = r['value']
            else:
                self.globals.setdefault(r['symbol'], 0x500000 + len(self.globals) * 0x1000)
                value = self.globals[r['symbol']]
            addend = struct.unpack('<I', self.elf.read(a, 4))[0]
            self.u.mem_write(a, struct.pack('<I', (value + addend) & 0xffffffff))
        for sec in self.elf.sections:
            if sec['name'] != '.plt':
                continue
            # PLT first entry has a different size; recognize exact ARM stubs.
            for a in range(sec['addr'], sec['addr'] + sec['size'] - 11, 4):
                x, y, z = struct.unpack('<III', self.elf.read(a, 12))
                if (x & 0xfffff000) != 0xe28fc000 or (y & 0xfffff000) != 0xe28cc000:
                    continue
                if (z & 0xfffff000) != 0xe5bcf000:
                    continue
                got = a + 8 + arm_imm(x) + arm_imm(y) + (z & 0xfff)
                self.plt[a] = self.elf.relocs[got]['symbol']
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def cstr(self, addr, bound=256):
        value = bytes(self.u.mem_read(addr, bound))
        assert b'\0' in value
        return value.split(b'\0')[0].decode('ascii')

    def hook(self, uc, addr, size, user):
        name = self.plt.get(addr)
        if name is None:
            return
        a = [uc.reg_read(r) for r in REGS]
        self.calls.append({'name': name, 'args': a})
        result = 0
        if name in ('pthread_mutex_lock', 'pthread_mutex_unlock', 'file_lock_read',
                    'file_lock_write', 'file_unlock', 'IsCardInFlashMode',
                    'IDBG_LINUXAPP_DbgOut'):
            pass
        elif name == 'getpid':
            result = 123
        elif name == '__errno_location':
            result = 0x6f0000
        elif name == 'strerror':
            result = 0x6f0100
            uc.mem_write(result, b'mock error\0')
        elif name == 'memset':
            assert a[2] <= 4096
            uc.mem_write(a[0], bytes([a[1] & 255]) * a[2])
            result = a[0]
        elif name == 'memcpy':
            self.memcpy_sizes.append(a[2])
            if a[2] > 4096:
                self.bad_copy = {'destination': a[0], 'source': a[1], 'size': a[2]}
                uc.emu_stop()
                return
            uc.mem_write(a[0], bytes(uc.mem_read(a[1], a[2])))
            result = a[0]
        elif name in ('API_ReadNVR', 'API_WriteNVR'):
            path, offset, count, data = self.cstr(a[0]), a[1], a[2], a[3]
            self.nvr_calls.append({'operation': name, 'path': path, 'offset': offset, 'count': count})
            if self.nvr_fail:
                result = 0xffffffff
            elif name == 'API_ReadNVR':
                value = self.files.get(path, b'')[offset:offset + count]
                if value:
                    uc.mem_write(data, value)
                result = len(value)
            else:
                # This mock records even malformed caller lengths but never
                # copies more than the bounded synthetic request allocation.
                if count <= 4096:
                    value = bytes(uc.mem_read(data, count))
                    old = self.files.get(path, b'')
                    self.files[path] = old[:offset] + value + old[offset + count:]
                result = count
        elif name == 'fopen':
            path, mode = self.cstr(a[0]), self.cstr(a[1])
            assert mode == 'rb'
            if path in self.files:
                result = 0x6c0000 + 16 * (len(self.streams) + 1)
                self.streams[result] = path
                self.fdpos[result] = 0
        elif name == 'fread':
            path = self.streams[a[3]]
            value = self.files[path][:a[1] * a[2]]
            if value:
                uc.mem_write(a[0], value)
            result = len(value) // a[1]
        elif name == 'fclose':
            assert a[0] in self.streams
        elif name == 'sigwrap_open_mode':
            path = self.cstr(a[0])
            assert a[1] in (0, 0x42)
            if a[1] == 0 and path not in self.files:
                result = 0xffffffff
            else:
                if a[1] == 0x42:
                    self.files.setdefault(path, b'')
                result = len(self.streams) + 3
                self.streams[result] = path
                self.fdpos[result] = 0
        elif name == 'lseek':
            assert a[2] == 0
            self.fdpos[a[0]] = a[1]
            result = a[1]
        elif name in ('sigwrap_read', 'sigwrap_write'):
            path = self.streams[a[0]]
            offset = self.fdpos[a[0]]
            if name == 'sigwrap_read':
                value = self.files[path][offset:offset + a[2]]
                if value:
                    uc.mem_write(a[1], value)
                result = len(value)
            else:
                count = a[2] if self.file_short_write is None else min(a[2], self.file_short_write)
                old = self.files[path]
                value = bytes(uc.mem_read(a[1], count))
                self.files[path] = old[:offset] + value + old[offset + count:]
                result = count
            self.fdpos[a[0]] += result
        elif name == 'sigwrap_close':
            assert a[0] in self.streams
        else:
            raise AssertionError(('Unexpected external operation', name, a))
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    def execute(self, function, args, fifth=0):
        for r, v in zip(REGS, args):
            self.u.reg_write(r, v)
        self.u.reg_write(UC_ARM_REG_SP, STACK)
        self.u.reg_write(UC_ARM_REG_LR, STOP)
        self.u.mem_write(STACK, struct.pack('<I', fifth))
        self.u.emu_start(self.elf.byname[function]['value'], STOP, count=20000)
        if self.bad_copy:
            return None
        assert self.u.reg_read(UC_ARM_REG_PC) == STOP, 'instruction budget exhausted'
        assert self.u.reg_read(UC_ARM_REG_SP) == STACK
        return self.u.reg_read(UC_ARM_REG_R0)

    def command(self, function, payload):
        self.u.mem_write(REQ, payload or b'\0')
        self.u.mem_write(RESP, b'\xa5' * 512)
        n = self.execute(function, [REQ, len(payload), RESP, 0])
        assert n <= 512
        return bytes(self.u.mem_read(RESP, n))

    def getter(self):
        self.u.mem_write(RESP, b'\0' * 1024)
        result = self.execute('LIBIPMI_HL_Get_BIOSINFO', [0, 30, RESP, 0])
        return result, {name: self.cstr(RESP + offset) for name, offset in
                        [('version', 0), ('date', 32), ('model', 64)]} if not self.bad_copy else None

    def nvr_file(self, operation, path, payload=b'', count=None, offset=0):
        self.u.mem_write(REQ, path.encode('ascii') + b'\0')
        self.u.mem_write(DATA, payload or b'\xa5' * 1024)
        return self.execute('ReadWriteNVR', [REQ, DATA, offset, len(payload) if count is None else count], operation)


def verify():
    cases = []

    def done(name, **details):
        cases.append({'case': name, 'passed': True, **details})

    paths = ['/conf/biosinfo.fru', '/conf/sysinfo.fru', '/conf/mbinfo.fru']
    for selector, path in enumerate(paths):
        v = b'0123456789'
        em = Emulation('cmd', {path: v})
        response = em.command('Oemreaddmiinfo', bytes([selector, 2, 0, 5]))
        assert response == b'\0\x05' + v[2:7]
        assert em.nvr_calls == [{'operation': 'API_ReadNVR', 'path': path, 'offset': 2, 'count': 5}]
        done('read_selector_' + str(selector), response=response.hex(), call=em.nvr_calls[0])
        em = Emulation('cmd', {path: b'OLD_' * 8})
        response = em.command('Oemwritedmiinfo', bytes([selector]) + v)
        assert response == b'\0\x0a'
        assert em.nvr_calls == [{'operation': 'API_WriteNVR', 'path': path, 'offset': 0, 'count': 10}]
        done('write_selector_' + str(selector), response=response.hex(), call=em.nvr_calls[0])

    for bad in (b'', b'\0', b'\0\0\0', b'\0\0\0\x10\0'):
        em = Emulation('cmd')
        response = em.command('Oemreaddmiinfo', bad)
        assert response[0] == 0xc7 and not em.nvr_calls
        done('read_bad_length_' + str(len(bad)), response=response.hex())
    for fn, payload in [('Oemreaddmiinfo', b'\x03\0\0\x20'), ('Oemwritedmiinfo', b'\x03abc')]:
        em = Emulation('cmd')
        response = em.command(fn, payload)
        assert response == b'\0\0' and not em.nvr_calls
        done(fn + '_invalid_selector_noop')
    em = Emulation('cmd', nvr_fail=True)
    assert em.command('Oemwritedmiinfo', b'\0abc') == b'\x81\xa5'
    done('write_error_count_byte_uninitialized')
    em = Emulation('cmd')
    response = em.command('Oemwritedmiinfo', b'')
    assert em.nvr_calls[0]['count'] == 65535
    done('empty_write_underflow_observed_not_safe', call=em.nvr_calls[0], response=response.hex())

    version_date = b'3107\0' + b'11/28/2025\0'
    board = b'ASUSTeK COMPUTER INC.\0ROG MAXIMUS Z790 HERO\0Rev 1.xx\0\0'
    em = Emulation('getter', {paths[0]: version_date, paths[2]: board})
    result, fields = em.getter()
    assert result == 0 and fields == {'version': '3107', 'date': '11/28/2025', 'model': 'ROG MAXIMUS Z790 HERO'}
    assert em.memcpy_sizes == [5, 11, len(fields['model'])]
    done('dashboard_valid_terminated_payload', fields=fields, copies=em.memcpy_sizes)
    for present in ({}, {paths[0]: version_date}):
        em = Emulation('getter', present)
        result, _ = em.getter()
        assert result == 1
        done('getter_missing_file_' + str(len(present)))
    for empty in (b'', b'\0', b'A\0\0'):
        em = Emulation('getter', {paths[0]: version_date, paths[2]: empty})
        result, fields = em.getter()
        assert result == 0 and fields['model'] == '' and not em.bad_copy
        done('getter_empty_mbinfo_' + str(len(empty)), fields=fields)
    em = Emulation('getter', {paths[0]: version_date, paths[2]: b'A\0' + b'B' * 253})
    em.getter()
    assert em.bad_copy and em.bad_copy['size'] == 0xfffffffe
    done('getter_unterminated_second_string_fills_255_bytes', blocked_mock_memcpy=em.bad_copy)
    em = Emulation('stack')
    assert em.nvr_file(2, paths[0], count=64) == 0
    assert em.files == {paths[0]: b''}
    assert [c['args'][1] for c in em.calls if c['name'] == 'sigwrap_open_mode'] == [0, 0x42]
    done('read_missing_file_default_creates_empty', calls=[c['name'] for c in em.calls])
    em = Emulation('stack', {paths[0]: b'abcdef'})
    assert em.nvr_file(1, paths[0], b'12') == 2
    assert em.files[paths[0]] == b'12cdef'
    assert not any(c['name'] in ('fsync', 'ftruncate', 'truncate') for c in em.calls)
    done('write_default_preserves_existing_tail', resulting_file_hex=em.files[paths[0]].hex(), calls=[c['name'] for c in em.calls])
    em = Emulation('stack', file_short_write=2)
    assert em.nvr_file(1, paths[0], b'12345') == 2
    assert em.files[paths[0]] == b'12'
    done('short_write_returned_without_retry')
    identity_file = HERE.parent / 'identity-from-live-smbios.json'
    identity = json.loads(identity_file.read_text(encoding='utf-8'))
    source = ROOT / identity['source']
    assert hashlib.sha256(source.read_bytes()).hexdigest() == identity['source_sha256']
    records = {record['type']: record for record in identity['records']}

    def fields_from_type(kind, offsets):
        record = records[kind]
        formatted = bytes.fromhex(record['formatted'])
        values = []
        for offset in offsets:
            index = formatted[offset]
            assert 1 <= index <= len(record['strings'])
            value = record['strings'][index - 1].encode('ascii')
            assert value and b'\0' not in value and len(value) < 100
            values.append(value)
        return values

    actual_bios = fields_from_type(0, [5, 8])
    actual_board = fields_from_type(2, [4, 5, 6, 7])
    assert len(actual_bios[0]) == 4 and len(actual_bios[1]) == 10
    payload0 = b'\0'.join(actual_bios) + b'\0'
    payload2 = b'\0'.join(actual_board) + b'\0'
    assert len(payload0) == 16 and 0 < len(payload2) < 192
    em = Emulation('cmd')
    assert em.command('Oemwritedmiinfo', b'\x02' + payload2) == bytes([0, len(payload2)])
    assert em.command('Oemwritedmiinfo', b'\x00' + payload0) == bytes([0, len(payload0)])
    get = Emulation('getter', em.files)
    result, fields = get.getter()
    assert result == 0 and fields == {
        'version': actual_bios[0].decode('ascii'), 'date': actual_bios[1].decode('ascii'),
        'model': actual_board[1].decode('ascii'),
    }
    done('actual_71_source_exact_four_type2_strings_and_type0', source_sha256=identity['source_sha256'],
         field_values=fields, source_payload_sizes={'bios': len(payload0), 'mb': len(payload2)},
         source_payload_sha256={'bios': hashlib.sha256(payload0).hexdigest(),
                                'mb': hashlib.sha256(payload2).hexdigest()})
    out = {
        'status': 'OFFLINE_BOUNDED_ARM_EMULATION_ONLY', 'passed': len(cases),
        'external_operations': 'All mocked in memory; no network or real BMC files',
        'hardware_not_modelled': ['runtime library/config changes', 'IPMI LAN privilege/transport limits',
                                 'power loss/persistence after close', 'concurrent REST reads'],
        'sources': {k: {'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                    for k, (p, _) in LIBRARIES.items()}, 'cases': cases,
    }
    (HERE / 'dashboard-backend-emulation.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    print('Dashboard backend ARM:', len(cases), 'offline scenarios passed')


if __name__ == '__main__':
    verify()
