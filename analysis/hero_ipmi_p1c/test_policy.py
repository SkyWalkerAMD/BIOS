"""Exercise the compiled transport gate, including all NetFn/command pairs.

Only a host DLL is loaded; this test has no UEFI or hardware I/O dependency.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import subprocess

P = Path(__file__).resolve().parent
ROOT = P.parents[1]
subprocess.run([
    str(ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'), 'lld-link',
    '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/timestamp:0',
    '/export:p1_read_allowed', '/out:' + str(P / 'policy_test.dll'),
    str(P / 'command_policy.obj'),
], check=True)
gate = C.CDLL(str(P / 'policy_test.dll')).p1_read_allowed
gate.argtypes = [C.c_uint8, C.c_uint8, C.c_void_p, C.c_size_t]
gate.restype = C.c_int
cases = 0


def check(fn, cmd, request, expected, length=None):
    global cases
    buf = C.create_string_buffer(request) if request is not None else None
    n = len(request or b'') if length is None else length
    assert bool(gate(fn, cmd, buf, n)) == expected, (fn, cmd, request, n)
    cases += 1


for fn in range(256):
    for cmd in range(256):
        check(fn, cmd, None, (fn, cmd) in {
            (6, 1), (6, 4), (6, 0x25), (6, 0x2f), (0x0a, 0x40)})
for channel in range(256):
    check(6, 0x42, bytes([channel]), 1 <= channel <= 11)
    for selector in range(256):
        check(0x0c, 2, bytes([channel, selector, 0, 0]),
              1 <= channel <= 11 and selector in (3, 4, 5, 6, 12))
for selector in (3, 4, 5, 6, 12):
    for bad in range(1, 256):
        check(0x0c, 2, bytes([1, selector, bad, 0]), False)
        check(0x0c, 2, bytes([1, selector, 0, bad]), False)
for record in (0, 1, 0x1234, 0xfffe, 0xffff):
    check(0x0a, 0x43, bytes([0, 0, record & 255, record >> 8, 0, 255]), True)
for index in (0, 1, 4, 5):
    for value in range(256):
        request = bytearray([0, 0, 0, 0, 0, 255])
        request[index] = value
        check(0x0a, 0x43, bytes(request), value == (255 if index == 5 else 0))
for fn, cmd, request in [(6, 1, b''), (6, 0x42, b'\1'),
                         (0x0c, 2, b'\1\3\0\0'),
                         (0x0a, 0x43, b'\0\0\0\0\0\xff')]:
    for n in range(10):
        check(fn, cmd, request + b'\0' * 16, n == len(request), length=n)
        if n:
            check(fn, cmd, None, False, length=n)
# Explicit mutations, including syntactically valid-looking setter payloads.
for fn, cmd, request in [(6, 2, b''), (6, 3, b''), (6, 0x22, b''),
                         (6, 0x24, b'\x44\0\0\0\x64\0'),
                         (6, 0x2e, b'\x0f'), (0x0c, 1, b'\1\4\2'),
                         (0x0a, 0x47, b'\0\0CLR\xaa'),
                         (0x30, 0x92, b'\0\0')]:
    check(fn, cmd, request, False)
report = dict(passed=True, cases=cases, scope='compiled C transport whitelist only',
              dll_sha256=hashlib.sha256((P / 'policy_test.dll').read_bytes()).hexdigest(),
              checks=['all 65536 zero-length NetFn/command pairs',
                      'all 65536 LAN channel/selector pairs',
                      'LAN block/set selector rejection, malformed lengths and null pointers',
                      'SEL reservation/offset/read length boundaries',
                      'reset, watchdog start/set, LAN set, SEL clear and OEM writes denied'])
(P / 'policy-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
