"""Build and execute the actual freestanding C gate as a local no-import DLL."""
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]


class Gate(c.Structure):
    _fields_ = [(name, c.c_uint32) for name in ('version', 'mode', 'phase', 'count', 'index', 'readbacks', 'active_kind', 'bulk_ack')]
    _fields_.append(('sequence', c.c_uint64))


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = BASE / 'native/build'; out.mkdir(parents=True, exist_ok=True)
        zig = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
        env = os.environ.copy()
        env['ZIG_GLOBAL_CACHE_DIR'] = str(out / 'zig-global')
        env['ZIG_LOCAL_CACHE_DIR'] = str(out / 'zig-local')
        exports = ('HeroInvGateSize', 'HeroInvInit', 'HeroInvBegin', 'HeroInvAcknowledge', 'HeroInvReadback', 'HeroInvFinalReadback')
        commands = [[str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc', '-std=c11',
                     '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                     '-mno-red-zone', '-c', str(BASE / 'native/publish_gate.c'), '-o', str(out / 'publish_gate.obj')],
                    [str(zig), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/opt:ref',
                     '/timestamp:0', '/out:' + str(out / 'publish_gate.dll'), str(out / 'publish_gate.obj'),
                     *['/export:' + name for name in exports]]]
        for cmd in commands:
            subprocess.run(cmd, check=True, env=env, cwd=BASE, capture_output=True)
        lib = c.CDLL(str(out / 'publish_gate.dll'))
        lib.HeroInvGateSize.restype = c.c_uint32
        ptr = c.POINTER(Gate)
        lib.HeroInvInit.argtypes = [ptr, c.c_uint32, c.c_uint32]
        lib.HeroInvBegin.argtypes = [ptr, c.c_uint32, c.c_uint64, c.c_uint32]
        lib.HeroInvAcknowledge.argtypes = [ptr, c.c_uint32, c.c_int, c.c_uint64]
        lib.HeroInvReadback.argtypes = [ptr, c.c_int, c.c_int, c.c_uint64]
        lib.HeroInvFinalReadback.argtypes = [ptr, c.c_int, c.c_int, c.c_int, c.c_uint64]
        cls.lib = lib
        (out / 'build.json').write_text(json.dumps({'mode': 'offline-native-gate-only', 'commands': commands,
             'dll_sha256': hashlib.sha256((out / 'publish_gate.dll').read_bytes()).hexdigest(),
             'source_sha256': hashlib.sha256((BASE / 'native/publish_gate.c').read_bytes()).hexdigest()}, indent=2) + '\n')

    def init(self, mode=1, count=1):
        g = Gate()
        self.assertEqual(self.lib.HeroInvGateSize(), c.sizeof(g))
        self.assertEqual(self.lib.HeroInvInit(c.byref(g), mode, count), 1)
        return g

    def test_all_binding_and_durable_intent_checks_required(self):
        g = self.init()
        for bit in range(8):
            self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 1, 255 ^ (1 << bit)), 0)
            self.assertEqual(g.phase, 1)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 1, 255), 1)

    def test_one_in_flight_and_stale_result_rejected(self):
        g = self.init()
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 10, 255), 1)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 11, 255), 0)
        self.assertEqual(self.lib.HeroInvAcknowledge(c.byref(g), 200, 0, 10), 0)
        self.assertEqual(self.lib.HeroInvAcknowledge(c.byref(g), 200, 0, 11), 1)
        self.assertEqual(g.phase, 3)

    def test_timeout_then_matching_readback_holds(self):
        g = self.init()
        self.lib.HeroInvBegin(c.byref(g), 1, 1, 255)
        self.lib.HeroInvAcknowledge(c.byref(g), 0, 1, 2)
        self.assertEqual(g.phase, 4)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 3, 255), 0)
        self.lib.HeroInvReadback(c.byref(g), 1, 1, 3)
        self.assertEqual(g.phase, 7)
        self.assertEqual(g.index, 0)

    def test_bad_response_cannot_assume_rollback(self):
        for status in (202, 400, 401, 403, 404, 409, 412, 428, 429, 500, 503):
            g = self.init(); self.lib.HeroInvBegin(c.byref(g), 1, 1, 255)
            self.lib.HeroInvAcknowledge(c.byref(g), status, 0, 2)
            self.assertEqual(g.phase, 5)
            self.lib.HeroInvReadback(c.byref(g), 1, 1, 3)
            self.assertEqual(g.phase, 7)

    def test_readback_retries_bounded_and_never_replay(self):
        g = self.init(); self.lib.HeroInvBegin(c.byref(g), 1, 1, 255)
        self.lib.HeroInvAcknowledge(c.byref(g), 204, 0, 2)
        for seq in range(3, 6): self.lib.HeroInvReadback(c.byref(g), 1, 0, seq)
        self.assertEqual(g.phase, 8)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 6, 255), 0)

    def test_two_operations_need_individual_and_final_readback(self):
        g = self.init(count=2)
        for index in range(2):
            seq = index * 3
            self.lib.HeroInvBegin(c.byref(g), index + 1, seq + 1, 255)
            self.lib.HeroInvAcknowledge(c.byref(g), 200, 0, seq + 2)
            self.lib.HeroInvReadback(c.byref(g), 1, 1, seq + 3)
        self.assertEqual(g.phase, 6)
        self.lib.HeroInvFinalReadback(c.byref(g), 1, 1, 0, 7)
        self.assertEqual(g.phase, 9)

    def test_bulk_ack_order_and_warning_result(self):
        g = self.init(mode=2, count=2)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 4, 1, 255), 0)
        self.lib.HeroInvBegin(c.byref(g), 3, 1, 255)
        self.lib.HeroInvAcknowledge(c.byref(g), 201, 0, 2)
        self.assertEqual(g.bulk_ack, 1)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 4, 3, 255), 1)
        self.lib.HeroInvAcknowledge(c.byref(g), 200, 0, 4)
        self.lib.HeroInvReadback(c.byref(g), 1, 1, 5)
        self.lib.HeroInvFinalReadback(c.byref(g), 1, 1, 1, 6)
        self.assertEqual(g.phase, 10)

    def test_bulk_lost_post_never_reaches_bootcomplete(self):
        g = self.init(mode=2, count=2)
        self.lib.HeroInvBegin(c.byref(g), 3, 1, 255)
        self.lib.HeroInvAcknowledge(c.byref(g), 0, 1, 2)
        self.assertEqual(g.bulk_ack, 0)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 4, 3, 255), 0)

    def test_noop_still_requires_fresh_final_verification(self):
        g = self.init(count=0)
        self.assertEqual(g.phase, 6)
        self.assertEqual(self.lib.HeroInvBegin(c.byref(g), 1, 1, 255), 0)
        self.lib.HeroInvFinalReadback(c.byref(g), 1, 1, 0, 1)
        self.assertEqual(g.phase, 9)


if __name__ == '__main__':
    unittest.main()
