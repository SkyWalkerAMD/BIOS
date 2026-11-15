"""Exercise the compiled freestanding C, with independent Python crypto oracles.

All credentials and entropy in this file are public TEST FIXTURES. This harness
only writes local test artifacts. It does not call firmware/NVRAM interfaces.
"""
from __future__ import annotations

import ctypes as C
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import random
import struct
import time

from build_core import build, HERE, OUT

OK, DENIED, ARG, OUTSIDE, STALE, CREDENTIAL, UNCONFIGURED, RATE, STORAGE, ENTROPY, CLOCK, BUSY, CANCELLED, EXHAUSTED = range(14)
MODE_UNCONFIGURED, ENABLED, DISABLED, FAULT = range(4)
ROUNDS = 600_000
MAX_ROUNDS = 2_000_000
U64_MAX = (1 << 64) - 1
PW = b"public-test-password-A"
NEW_PW = b"public-test-password-B"
WRONG_PW = b"public-wrong-password"
READ = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t))
PERSIST = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)
ENTROPY_CB = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)
NOW = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(C.c_uint64))


class Env(C.Structure):
    _fields_ = [("opaque", C.c_void_p), ("read", READ), ("persist", PERSIST),
                ("entropy", ENTROPY_CB), ("now_ms", NOW)]


class Core(C.Structure):
    _fields_ = [("env", Env), ("record", C.c_ubyte * 128),
                ("session_token", C.c_uint64), ("last_now_ms", C.c_uint64),
                ("retry_after_ms", C.c_uint64), ("failed_attempts", C.c_uint32),
                ("mode", C.c_uint32), ("active", C.c_ubyte),
                ("unlocked", C.c_ubyte), ("busy", C.c_ubyte),
                ("clock_valid", C.c_ubyte)]


def load() -> C.CDLL:
    lib = C.CDLL(str(OUT / "password_core_test.dll"))
    ptr = C.POINTER(Core)
    signatures = {
        "ap_init": (C.c_int, [ptr, C.POINTER(Env)]),
        "ap_fault": (None, [ptr]),
        "ap_session_begin": (C.c_uint64, [ptr]),
        "ap_session_end": (None, [ptr]),
        "ap_can_enter": (C.c_int, [ptr]),
        "ap_unlock": (C.c_int, [ptr, C.c_uint64, C.c_void_p, C.c_size_t]),
        "ap_set_password": (C.c_int, [ptr, C.c_uint64, C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]),
        "ap_clear_password": (C.c_int, [ptr, C.c_uint64, C.c_void_p, C.c_size_t]),
        "ap_cancel": (C.c_int, [ptr, C.c_uint64]),
        "ap_retry_remaining_ms": (C.c_uint64, [ptr]),
        "ap_record_valid": (C.c_int, [C.c_void_p, C.c_size_t]),
        "ap_secure_zero": (None, [C.c_void_p, C.c_size_t]),
        "ap_constant_equal": (C.c_int, [C.c_void_p, C.c_void_p, C.c_size_t]),
        "ap_sha256": (None, [C.c_void_p, C.c_size_t, C.c_void_p]),
        "ap_hmac_sha256": (None, [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p]),
        "ap_pbkdf2_sha256": (C.c_int, [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t, C.c_uint32, C.c_void_p]),
    }
    for name, (result, args) in signatures.items():
        fn = getattr(lib, name)
        fn.restype, fn.argtypes = result, args
    return lib


def buf(data: bytes | None):
    return None if data is None else C.create_string_buffer(data, max(1, len(data)))


def signed_record(*, password=PW, salt=bytes(range(32)), rounds=ROUNDS,
                  generation=1, disabled=False) -> bytes:
    """Independent reference serializer and KDF; no C calls."""
    prefix = struct.pack("<8sHHIIIQ", b"AITWKP01", 1, 128,
                         0 if disabled else 1, 0 if disabled else 1,
                         0 if disabled else rounds, generation)
    payload = (bytes(64) if disabled else salt +
               hashlib.pbkdf2_hmac("sha256", password, salt, rounds, 32))
    record = prefix + payload
    assert len(record) == 96
    return record + hashlib.sha256(record).digest()


class Fixture:
    """Fake atomic storage, test entropy, monotonic clock; all injectable."""
    def __init__(self, stored=None):
        self.core = Core()
        self.stored = stored
        self.read_error = False
        self.read_override = None
        self.read_size = None
        self.persist_fail = False
        self.persist_uncertain = False
        self.entropy_fail = False
        self.entropy_bytes = None
        self.now_fail = False
        self.now_fail_calls = set()
        self.now = 100_000
        self.now_step = 0
        self.reads = self.writes = self.entropy_calls = self.now_calls = 0
        self.callback_errors = []
        self.events = []
        self.on_entropy = self.on_persist = self.on_now = None
        self.callbacks = (READ(self.read), PERSIST(self.persist),
                          ENTROPY_CB(self.entropy), NOW(self.clock))
        self.env = Env(None, *self.callbacks)
        self.init_status = None

    def initialize(self):
        self.init_status = LIB.ap_init(C.byref(self.core), C.byref(self.env))
        return self.init_status

    def read(self, opaque, target, capacity, actual):
        self.reads += 1
        if self.read_error:
            actual[0] = 0
            return 2
        if self.stored is None:
            actual[0] = 0 if self.read_size is None else self.read_size
            return 1 if self.read_override is None else self.read_override
        actual[0] = len(self.stored) if self.read_size is None else self.read_size
        C.memmove(target, self.stored, min(capacity, len(self.stored)))
        return 0 if self.read_override is None else self.read_override

    def action(self, name):
        fn = getattr(self, name)
        setattr(self, name, None)
        if fn:
            try:
                fn()
            except Exception as error:
                self.callback_errors.append(repr(error))

    def persist(self, opaque, source, length):
        self.writes += 1
        self.action("on_persist")
        if self.persist_uncertain:
            self.stored = C.string_at(source, length)
            LIB.ap_fault(C.byref(self.core))
            return 1
        if self.persist_fail:
            return 1
        self.stored = C.string_at(source, length)
        return 0

    def entropy(self, opaque, target, length):
        self.entropy_calls += 1
        self.action("on_entropy")
        if self.entropy_fail:
            return 1
        # Deliberately deterministic TEST ONLY data, never a production source.
        sample = self.entropy_bytes
        if sample is None:
            sample = hashlib.sha256(b"test-only-entropy" +
                self.entropy_calls.to_bytes(8, "little")).digest()
        if len(sample) != length:
            self.callback_errors.append("entropy request length mismatch")
            return 1
        C.memmove(target, sample, length)
        return 0

    def clock(self, opaque, output):
        self.now_calls += 1
        self.action("on_now")
        if self.now_fail or self.now_calls in self.now_fail_calls:
            return 1
        output[0] = self.now
        self.now = min(U64_MAX, self.now + self.now_step)
        return 0

    def begin(self):
        return LIB.ap_session_begin(C.byref(self.core))

    def end(self):
        LIB.ap_session_end(C.byref(self.core))

    def access(self):
        return bool(LIB.ap_can_enter(C.byref(self.core)))

    def unlock(self, password=PW, token=None):
        return LIB.ap_unlock(C.byref(self.core), self.core.session_token if token is None else token,
                             buf(password), 0 if password is None else len(password))

    def set(self, replacement=NEW_PW, current=None, token=None):
        return LIB.ap_set_password(C.byref(self.core), self.core.session_token if token is None else token,
                                   buf(current), 0 if current is None else len(current),
                                   buf(replacement), 0 if replacement is None else len(replacement))

    def clear(self, current=PW, token=None):
        return LIB.ap_clear_password(C.byref(self.core), self.core.session_token if token is None else token,
                                     buf(current), 0 if current is None else len(current))

    def cancel(self, token=None):
        return LIB.ap_cancel(C.byref(self.core), self.core.session_token if token is None else token)

    def remaining(self):
        return LIB.ap_retry_remaining_ms(C.byref(self.core))

    def ready(self):
        CHECK(self.initialize(), OK, "fixture accepts independent reference record")
        self.begin()
        return self

    def snapshot(self):
        return (self.stored, bytes(self.core.record), self.core.mode,
                self.core.unlocked, self.core.failed_attempts, self.core.retry_after_ms)


COUNT = 0
RESULTS = []
TIMINGS = {}


def CHECK(actual, expected=True, label=""):
    global COUNT
    COUNT += 1
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def group(name, fn):
    before = COUNT
    started = time.perf_counter()
    fn()
    result = {"name": name, "status": "PASS", "assertions": COUNT - before,
              "seconds": round(time.perf_counter() - started, 3)}
    RESULTS.append(result)
    print(json.dumps(result), flush=True)


def crypto_vectors():
    output = C.create_string_buffer(32)
    sha_vectors = [(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                   (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                   (b"a" * 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")]
    for data, expected in sha_vectors:
        LIB.ap_sha256(buf(data), len(data), output)
        CHECK(output.raw.hex(), expected, "SHA-256 known answer")
    rng = random.Random(0x1904)
    for n in [1, 7, 8, 31, 32, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 8193] + [rng.randrange(0, 4096) for _ in range(20)]:
        data = rng.randbytes(n)
        LIB.ap_sha256(buf(data), n, output)
        CHECK(output.raw, hashlib.sha256(data).digest(), "SHA-256 Python/OpenSSL oracle")
    hmac_vectors = [(b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
                    (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
                    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")]
    for key, data, expected in hmac_vectors:
        LIB.ap_hmac_sha256(buf(key), len(key), buf(data), len(data), output)
        CHECK(output.raw.hex(), expected, "RFC 4231 HMAC-SHA256 known answer")
    for keylen, size in [(0, 0), (1, 55), (32, 56), (63, 64), (64, 65), (65, 1024), (128, 32), (131, 37)]:
        key, data = rng.randbytes(keylen), rng.randbytes(size)
        LIB.ap_hmac_sha256(buf(key), keylen, buf(data), size, output)
        CHECK(output.raw, hmac.new(key, data, "sha256").digest(), "HMAC independent oracle")
    expected_pbkdf2 = {
        1: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        2: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        4096: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
    }
    for rounds, expected in expected_pbkdf2.items():
        CHECK(LIB.ap_pbkdf2_sha256(buf(b"password"), 8, buf(b"salt"), 4, rounds, output), 0)
        CHECK(output.raw.hex(), expected, "PBKDF2-HMAC-SHA256 known answer")
        CHECK(output.raw, hashlib.pbkdf2_hmac("sha256", b"password", b"salt", rounds, 32))
    for pwlen, saltlen, rounds in [(0, 0, 1), (1, 1, 19), (64, 32, 257), (65, 64, 33), (128, 0, 31), (24, 32, ROUNDS), (16, 32, MAX_ROUNDS)]:
        password, salt = rng.randbytes(pwlen), rng.randbytes(saltlen)
        started = time.perf_counter()
        CHECK(LIB.ap_pbkdf2_sha256(buf(password), pwlen, buf(salt), saltlen, rounds, output), 0)
        elapsed = time.perf_counter() - started
        if rounds >= ROUNDS:
            TIMINGS[f"pbkdf2_{rounds}_native_seconds"] = round(elapsed, 4)
        CHECK(output.raw, hashlib.pbkdf2_hmac("sha256", password, salt, rounds, 32), "PBKDF2 boundary/oracle")
    for password, plen, salt, slen, rounds in [(None, 1, b"salt", 4, 1), (b"x", 1, None, 1, 1),
            (b"x" * 129, 129, b"salt", 4, 1), (PW, len(PW), b"x" * 65, 65, 1),
            (PW, len(PW), b"salt", 4, 0), (PW, len(PW), b"salt", 4, MAX_ROUNDS + 1),
            (PW, len(PW), b"salt", 4, 0xFFFFFFFF)]:
        C.memset(output, 0xA5, 32)
        CHECK(LIB.ap_pbkdf2_sha256(buf(password), plen, buf(salt), slen, rounds, output), -1)
        CHECK(output.raw, bytes(32), "Invalid KDF work/length clears output")
    CHECK(LIB.ap_pbkdf2_sha256(buf(PW), len(PW), buf(b"salt"), 4, 1, None), -1)
    for n in [0, 1, 32, 127, 256]:
        secret = C.create_string_buffer(b"\xa5" * max(1, n), max(1, n))
        LIB.ap_secure_zero(secret, n)
        CHECK(secret.raw[:n], bytes(n), "secure zero postcondition")
        data = rng.randbytes(n)
        CHECK(LIB.ap_constant_equal(buf(data), buf(data), n), 1)
        for index in range(n):
            changed = bytearray(data)
            changed[index] ^= 1
            CHECK(LIB.ap_constant_equal(buf(data), buf(bytes(changed)), n), 0, "comparison checks every byte")


def records_and_faults():
    CHECK(LIB.ap_record_valid(buf(BASE), 128), 1)
    CHECK(LIB.ap_record_valid(buf(DISABLED_RECORD), 128), 1)
    CHECK(LIB.ap_record_valid(None, 128), 0)
    for length in [0, 1, 127, 129, 1024]:
        CHECK(LIB.ap_record_valid(buf(BASE), length), 0)
    for index in range(128):
        for bit in range(8):
            altered = bytearray(BASE)
            altered[index] ^= 1 << bit
            CHECK(LIB.ap_record_valid(buf(bytes(altered)), 128), 0, "single-bit corruption rejected")
    for offset, replacement in [(8, b"\x02\x00"), (10, b"\x7f\x00"),
            (12, struct.pack("<I", 2)), (16, struct.pack("<I", 2)),
            (20, struct.pack("<I", ROUNDS - 1)), (20, struct.pack("<I", MAX_ROUNDS + 1)),
            (24, bytes(8)), (32, bytes(32)), (32, b"\xa5" * 32), (64, bytes(32))]:
        altered = bytearray(BASE)
        altered[offset:offset + len(replacement)] = replacement
        altered[96:] = hashlib.sha256(altered[:96]).digest()
        CHECK(LIB.ap_record_valid(buf(bytes(altered)), 128), 0, "semantic format check despite valid checksum")
        f = Fixture(bytes(altered))
        CHECK(f.initialize(), CREDENTIAL)
        f.begin()
        CHECK(f.access(), False)
        CHECK(f.unlock(), CREDENTIAL)
        CHECK(f.set(current=PW), CREDENTIAL)
        CHECK(f.clear(), CREDENTIAL)
        CHECK(f.writes, 0)
    for offset, replacement in [(16, struct.pack("<I", 1)), (20, struct.pack("<I", ROUNDS)), (32, b"x"), (64, b"x")]:
        altered = bytearray(DISABLED_RECORD)
        altered[offset:offset + len(replacement)] = replacement
        altered[96:] = hashlib.sha256(altered[:96]).digest()
        CHECK(LIB.ap_record_valid(buf(bytes(altered)), 128), 0)
    for stored, force_error, override, size in [(BASE, True, None, None),
            (BASE[:127], False, None, None), (BASE + b"x", False, None, None),
            (None, False, 0, None), (None, False, None, 1), (BASE, False, 99, None)]:
        f = Fixture(stored)
        f.read_error, f.read_override, f.read_size = force_error, override, size
        CHECK(f.initialize(), CREDENTIAL)
        CHECK(f.core.mode, FAULT)
        CHECK(bytes(f.core.record), bytes(128))
        f.begin()
        CHECK(f.access(), False)
    for missing_callback in range(4):
        f = Fixture(BASE)
        callbacks = list(f.callbacks)
        callbacks[missing_callback] = [READ, PERSIST, ENTROPY_CB, NOW][missing_callback]()
        bad_env = Env(None, *callbacks)
        CHECK(LIB.ap_init(C.byref(f.core), C.byref(bad_env)), ARG)
        f.begin()
        CHECK(f.access(), False)


def session_and_authentication():
    f = Fixture(BASE)
    CHECK(f.initialize(), OK)
    CHECK(f.access(), False)
    CHECK(f.unlock(), OUTSIDE)
    CHECK(f.set(current=PW), OUTSIDE)
    CHECK(f.clear(), OUTSIDE)
    token1 = f.begin()
    CHECK(token1, 1)
    CHECK(f.access(), False)
    CHECK(f.cancel(), CANCELLED)
    CHECK(f.access(), False)
    for invalid in [None, b"", b"x" * 7, b"x" * 129]:
        CHECK(f.unlock(invalid), ARG)
        CHECK(f.access(), False)
    CHECK(f.unlock(WRONG_PW), DENIED)
    CHECK(f.core.failed_attempts, 1)
    CHECK(f.access(), False)
    CHECK(f.remaining(), 5000)
    CHECK(f.unlock(), RATE)
    f.end()
    CHECK(f.access(), False)
    token2 = f.begin()
    CHECK(token2, 2)
    CHECK(f.core.failed_attempts, 1)
    CHECK(f.unlock(token=token1), STALE)
    CHECK(f.cancel(token1), STALE)
    CHECK(f.unlock(), RATE)
    f.now += 4999
    CHECK(f.unlock(), RATE)
    CHECK(f.remaining(), 1)
    f.now += 1
    CHECK(f.unlock(), OK)
    CHECK(f.access(), True)
    CHECK(f.core.failed_attempts, 0)
    CHECK(f.remaining(), 0)
    CHECK(f.unlock(WRONG_PW), OK, "already unlocked session does not request another password")
    CHECK(f.cancel(), CANCELLED)
    CHECK(f.access(), True, "canceling a management dialog does not revoke a prior valid unlock")
    f.end()
    CHECK(f.access(), False)
    CHECK(f.cancel(), OUTSIDE)
    f.begin()
    CHECK(f.access(), False)
    CHECK(f.unlock(token=token2), STALE)
    CHECK(f.unlock(), OK)
    CHECK(f.access(), True)
    LIB.ap_fault(C.byref(f.core))
    CHECK(f.access(), False)
    f.begin()
    CHECK(f.unlock(), CREDENTIAL)
    CHECK(f.access(), False)
    CHECK(f.writes, 0)
    CHECK(f.callback_errors, [])


def enrollment_change_clear():
    f = Fixture()
    CHECK(f.initialize(), UNCONFIGURED)
    f.begin()
    CHECK(f.access(), False)
    CHECK(f.unlock(), UNCONFIGURED)
    CHECK(f.clear(), UNCONFIGURED)
    for replacement in [None, b"", b"x" * 7, b"x" * 129]:
        CHECK(f.set(replacement), ARG)
        CHECK(f.writes, 0)
    CHECK(f.set(PW, current=b"unexpected"), ARG)
    f.entropy_fail = True
    CHECK(f.set(PW), ENTROPY)
    CHECK(f.core.mode, MODE_UNCONFIGURED)
    CHECK(f.writes, 0)
    f.entropy_fail = False
    f.persist_fail = True
    CHECK(f.set(PW), STORAGE)
    CHECK(f.core.mode, MODE_UNCONFIGURED)
    CHECK(f.stored, None)
    CHECK(f.access(), False)
    f.persist_fail = False
    CHECK(f.set(PW), OK)
    CHECK(f.core.mode, ENABLED)
    CHECK(f.access(), False, "setting password does not grant session access")
    CHECK(len(f.stored), 128)
    CHECK(f.stored, signed_record(password=PW, salt=f.stored[32:64]))
    CHECK(PW in f.stored, False, "only verifier persisted")
    CHECK(f.set(NEW_PW), ARG, "existing credential requires current password")
    CHECK(f.unlock(), OK)
    CHECK(f.access(), True)
    old = f.snapshot()
    CHECK(f.set(NEW_PW, current=WRONG_PW), DENIED)
    CHECK(f.stored, old[0])
    CHECK(f.access(), True)
    f.now += 5000
    for entropy in [bytes(32), b"\xff" * 32, f.stored[32:64]]:
        f.entropy_bytes = entropy
        previous = f.snapshot()
        CHECK(f.set(NEW_PW, current=PW), ENTROPY)
        CHECK(f.snapshot(), previous, "failed entropy preserves credential/unlock/rate state")
    f.entropy_bytes = None
    f.entropy_fail = True
    previous = f.snapshot()
    CHECK(f.set(NEW_PW, current=PW), ENTROPY)
    CHECK(f.snapshot(), previous)
    f.entropy_fail = False
    f.persist_fail = True
    previous = f.snapshot()
    CHECK(f.set(NEW_PW, current=PW), STORAGE)
    CHECK(f.snapshot(), previous, "atomic update failure preserves old credential and unlock")
    CHECK(f.clear(), STORAGE)
    CHECK(f.snapshot(), previous, "atomic clear failure preserves old credential and unlock")
    f.persist_fail = False
    CHECK(f.set(NEW_PW, current=PW), OK)
    CHECK(f.access(), False)
    CHECK(f.stored, signed_record(password=NEW_PW, salt=f.stored[32:64], generation=2))
    CHECK(f.stored[32:64] != old[0][32:64], True)
    CHECK(f.unlock(PW), DENIED)
    CHECK(f.access(), False)
    f.now += 5000
    CHECK(f.unlock(NEW_PW), OK)
    saved = f.stored
    CHECK(f.clear(PW), DENIED)
    CHECK(f.stored, saved)
    f.now += 5000
    CHECK(f.clear(NEW_PW), OK)
    CHECK(f.stored, signed_record(disabled=True, generation=3))
    CHECK(f.core.mode, DISABLED)
    CHECK(f.access(), True)
    CHECK(NEW_PW in f.stored, False)
    writes = f.writes
    CHECK(f.clear(None), OK)
    CHECK(f.writes, writes)
    CHECK(f.clear(PW), ARG)
    f.end()
    CHECK(f.access(), False)
    reloaded = Fixture(f.stored)
    CHECK(reloaded.initialize(), OK)
    CHECK(reloaded.access(), False)
    reloaded.begin()
    CHECK(reloaded.access(), True)
    CHECK(reloaded.set(PW), OK)
    CHECK(reloaded.stored, signed_record(password=PW, salt=reloaded.stored[32:64], generation=4))
    CHECK(reloaded.access(), False)
    missing_after_enrollment = Fixture()
    CHECK(missing_after_enrollment.initialize(), UNCONFIGURED)
    missing_after_enrollment.begin()
    CHECK(missing_after_enrollment.access(), False, "deleted variable cannot become disabled/unlocked")
    CHECK(f.callback_errors, [])
    CHECK(reloaded.callback_errors, [])


def clocks_and_limits():
    f = Fixture(BASE).ready()
    f.now_fail = True
    CHECK(f.unlock(), CLOCK)
    CHECK(f.access(), False)
    CHECK(f.remaining(), U64_MAX)
    f.now_fail = False
    CHECK(f.unlock(WRONG_PW), DENIED)
    f.now -= 1
    CHECK(f.unlock(), CLOCK)
    CHECK(f.access(), False)
    f.now += 5001
    CHECK(f.unlock(), OK)
    f = Fixture(BASE).ready()
    f.now_step = 10_000
    CHECK(f.unlock(WRONG_PW), DENIED)
    CHECK(f.core.retry_after_ms, 115_000, "retry delay starts after KDF, not before it")
    f = Fixture(BASE).ready()
    f.now_fail_calls = {2}
    CHECK(f.unlock(WRONG_PW), CLOCK)
    CHECK(f.access(), False)
    f = Fixture(BASE).ready()
    f.now = U64_MAX - 3
    CHECK(f.unlock(WRONG_PW), DENIED)
    CHECK(f.core.retry_after_ms, U64_MAX)
    f.now = U64_MAX
    CHECK(f.unlock(), RATE, "deadline arithmetic never wraps open")
    CHECK(f.remaining(), U64_MAX)
    f = Fixture(BASE).ready()
    f.core.failed_attempts = 0xFFFFFFFF
    CHECK(f.unlock(WRONG_PW), DENIED)
    CHECK(f.core.failed_attempts, 0xFFFFFFFF)
    f = Fixture(signed_record(generation=U64_MAX)).ready()
    CHECK(f.set(current=PW), EXHAUSTED)
    CHECK(f.clear(), EXHAUSTED)
    CHECK(f.writes, 0)
    CHECK(f.access(), False)
    f.core.session_token = U64_MAX
    CHECK(f.begin(), 0)
    CHECK(f.core.mode, FAULT)
    CHECK(f.access(), False)
    for password in [b"x" * 8, b"x" * 128, "界面内独立密码".encode("utf-16-le"), b"ab\0cd\0ef\0gh"]:
        f = Fixture(signed_record(password=password)).ready()
        CHECK(f.unlock(password), OK, "bounded password bytes; no implicit truncation/normalization")
        CHECK(f.access(), True)
    CHECK(C.sizeof(Core), 208, "documented x64 ABI layout")


def callback_session_boundaries():
    f = Fixture(BASE).ready()
    f.on_now = f.end
    CHECK(f.unlock(), OUTSIDE)
    CHECK(f.access(), False)
    CHECK(f.writes, 0)
    f = Fixture(BASE).ready()
    f.on_entropy = f.begin
    previous = f.stored
    CHECK(f.set(current=PW), STALE)
    CHECK(f.stored, previous)
    CHECK(f.access(), False)
    CHECK(f.writes, 0)
    f = Fixture(BASE).ready()
    f.on_entropy = lambda: f.events.append(f.unlock())
    CHECK(f.set(current=PW), OK)
    CHECK(f.events, [BUSY], "reentrant authentication denied while changing credential")
    CHECK(f.access(), False)
    f = Fixture(BASE).ready()
    f.on_persist = f.end
    CHECK(f.set(current=PW), OK, "committed credential remains authoritative after session ends")
    CHECK(f.access(), False)
    CHECK(f.core.active, 0)
    CHECK(f.stored, signed_record(password=NEW_PW, salt=f.stored[32:64], generation=2))
    f.begin()
    CHECK(f.unlock(NEW_PW), OK)
    f = Fixture(BASE).ready()
    f.persist_fail = True
    f.on_persist = f.begin
    CHECK(f.set(current=PW), STORAGE)
    CHECK(f.stored, BASE)
    CHECK(f.access(), False, "write failure cannot restore unlock from old session")
    f = Fixture(BASE).ready()
    f.persist_uncertain = True
    CHECK(f.set(current=PW), STORAGE)
    CHECK(f.core.mode, FAULT, "adapter uncertain write signals persistent fault")
    CHECK(f.access(), False)
    f.begin()
    CHECK(f.access(), False)
    CHECK(f.unlock(), CREDENTIAL)
    CHECK(f.callback_errors, [])


if __name__ == "__main__":
    build_report = build()
    LIB = load()
    BASE = signed_record()
    DISABLED_RECORD = signed_record(disabled=True)
    started = time.perf_counter()
    for name, fn in [("SHA256_HMAC_PBKDF2_known_answers_and_oracles", crypto_vectors),
                     ("record_corruption_versions_and_storage_read_failures", records_and_faults),
                     ("actual_session_unlock_cancel_stale_dialog_and_rate_limit", session_and_authentication),
                     ("enrollment_authenticated_change_clear_atomic_failure", enrollment_change_clear),
                     ("clock_failures_bounds_and_counter_exhaustion", clocks_and_limits),
                     ("callback_session_boundaries_reentrancy_and_uncertain_write", callback_session_boundaries)]:
        group(name, fn)
    report = {
        "status": "PASS",
        "utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Compiled freestanding x64 C core, fake storage/entropy/clock callbacks; no real NVRAM access; not firmware hook or hardware validation",
        "assertions": COUNT,
        "seconds": round(time.perf_counter() - started, 3),
        "groups": RESULTS,
        "timings": TIMINGS,
        "sources": build_report["sources"],
        "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "dll": build_report["artifacts"]["password_core_test.dll"],
        "dll_import_directory": build_report["import_directory"],
        "reference_oracles": ["Python hashlib.sha256", "Python hmac.new(..., sha256)",
                              "Python hashlib.pbkdf2_hmac(sha256)", "fixed SHA256 / RFC 4231 HMAC / PBKDF2 known answers"],
        "specification_sources": ["https://www.rfc-editor.org/rfc/rfc8018",
                                  "https://www.rfc-editor.org/rfc/rfc4231",
                                  "https://csrc.nist.gov/pubs/fips/180-4/upd1/final",
                                  "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
    }
    (HERE / "test_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "assertions": COUNT,
                      "seconds": report["seconds"], "timings": TIMINGS}), flush=True)
