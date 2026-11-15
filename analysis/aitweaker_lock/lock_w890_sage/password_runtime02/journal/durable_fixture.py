"""Off-host, current-user encrypted journal for an explicitly owned W890 test.

No firmware, KVM, input injection, network, or printing of secrets is provided.
The journal must be durably published before a controller types either password.
After a lost commit result the controller tries the two saved candidates through
the separate, exact-namespace, known-password recovery backend. Keep the journal
until that backend has independently confirmed absence. This module never
deletes a journal or treats a local metadata change as firmware cleanup.
"""
from pathlib import Path
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
import secrets
import struct
import uuid

MAGIC = b'W890-FIXTURE-02\0'
DOMAIN = b'W890-0603-EXACT-NAMESPACE-RECOVERY-02\0'
NAME = 'AiTweakerPasswordW890V1'
GUID = '7aa1505b-ef11-4c41-9002-427f826903e6'
SETUP = 'c1cf9d755c2ea043d44f19fdf4009cf8b12b03f85e8939034de19ee18251b72e'
TSE = '43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
MAX = 32768


class JournalError(ValueError):
    pass


class Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def binding(target):
    if not isinstance(target, str) or not 1 <= len(target) <= 128 or any(ord(x) < 33 or ord(x) > 126 for x in target):
        raise JournalError('A bounded explicit target identifier is required')
    return {'board': 'Pro WS W890E-SAGE SE', 'bios': '0603', 'target': target,
            'name': NAME, 'guid': GUID, 'attributes': 3, 'record_bytes': 128,
            'setup_sha256': SETUP, 'amitse_sha256': TSE, 'revision': 2}


def _crypt(data, context, decrypt):
    if os.name != 'nt' or not isinstance(data, bytes) or not 1 <= len(data) <= MAX:
        raise JournalError('Bounded data and Windows current-user DPAPI are required')
    buffers = []
    def blob(value):
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        buffers.append(buffer)
        return Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    incoming, entropy = blob(data), blob(DOMAIN + context)
    outgoing = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p,
                          ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    operation.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try:
        # UI_FORBIDDEN, deliberately not LOCAL_MACHINE.
        if not operation(ctypes.byref(incoming), None, ctypes.byref(entropy), None, None, 1, ctypes.byref(outgoing)):
            raise JournalError('DPAPI rejected journal or binding')
        if not outgoing.pbData or not 1 <= outgoing.cbData <= MAX:
            raise JournalError('Invalid DPAPI output')
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        for buffer in buffers:
            ctypes.memset(buffer, 0, len(buffer))
        if outgoing.pbData:
            if outgoing.cbData <= MAX:
                ctypes.memset(outgoing.pbData, 0, outgoing.cbData)
            kernel.LocalFree(outgoing.pbData)


def _publish(path, data):
    """Write only ciphertext, flush, then publish without replacing any journal."""
    path = Path(path).absolute()
    if path.exists() or not path.parent.is_dir():
        raise JournalError('Journal already exists or parent directory is missing')
    temporary = path.with_name(path.name + '.partial-' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    kernel.MoveFileExW.restype = wintypes.BOOL
    # WRITE_THROUGH; no REPLACE_EXISTING. A race creating the destination fails.
    if not kernel.MoveFileExW(str(temporary), str(path), 8):
        raise JournalError('Could not publish encrypted journal; encrypted partial retained')
    with path.open('rb') as stream:
        if not hmac.compare_digest(stream.read(MAX + 1), data):
            raise JournalError('Published journal read-back mismatch; do not type any password')


def prepare(path, target):
    """Publish both recovery candidates first; return public metadata only."""
    bind = binding(target)
    payload = {'binding': bind, 'id': uuid.uuid4().hex,
               'before': 'W890-' + secrets.token_urlsafe(32),
               'after': 'W890-' + secrets.token_urlsafe(32)}
    plain = canonical(payload)
    wrapped = MAGIC + struct.pack('<I', len(plain)) + hashlib.sha256(plain).digest() + plain
    ciphertext = _crypt(wrapped, canonical(bind), False)
    _publish(path, ciphertext)
    restored = open_fixture(path, target)
    if restored != payload:
        raise JournalError('Journal plaintext read-back mismatch; do not type any password')
    return {'id': payload['id'], 'binding': bind, 'path': str(Path(path).absolute()),
            'ciphertext_sha256': hashlib.sha256(ciphertext).hexdigest(), 'status': 'DURABLE_BEFORE_TYPING'}


def open_fixture(path, target):
    """Return secrets only in caller memory. Never send the result to a logger."""
    bind = binding(target)
    with Path(path).open('rb') as stream:
        ciphertext = stream.read(MAX + 1)
    wrapped = _crypt(ciphertext, canonical(bind), True)
    head = len(MAGIC) + 4 + 32
    if len(wrapped) < head or not hmac.compare_digest(wrapped[:len(MAGIC)], MAGIC):
        raise JournalError('Invalid journal envelope')
    length = struct.unpack_from('<I', wrapped, len(MAGIC))[0]
    plain = wrapped[head:]
    if not 1 <= length <= 4096 or length != len(plain) or not hmac.compare_digest(hashlib.sha256(plain).digest(), wrapped[len(MAGIC)+4:head]):
        raise JournalError('Invalid journal envelope integrity')
    payload = json.loads(plain)
    if set(payload) != {'binding', 'id', 'before', 'after'} or payload['binding'] != bind:
        raise JournalError('Invalid journal binding')
    if not isinstance(payload['id'], str) or len(payload['id']) != 32 or any(c not in '0123456789abcdef' for c in payload['id']):
        raise JournalError('Invalid journal identifier')
    for key in ['before', 'after']:
        value = payload[key]
        if not isinstance(value, str) or not 8 <= len(value) <= 128 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise JournalError('Invalid recovery candidate')
    if hmac.compare_digest(payload['before'], payload['after']):
        raise JournalError('Recovery candidates unexpectedly equal')
    return payload

# Python immutable objects cannot be reliably wiped. This protects the stored
# journal under the Windows user account, not a compromised running process.
# It is an implemented durable controller prerequisite, not a KVM controller.
