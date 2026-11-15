"""Current-user Windows DPAPI codec for a future test-fixture journal.

Library only: no CLI, no file/network/firmware access, no plaintext logging.
This is not a recovery tool or permission to set a firmware password.
API references:
https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
"""
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import os
import struct

MAGIC=b'SAGEFIXTURE01\x00\x00\x00'
DOMAIN=b'SAGE1904-OWNED-TEST-FIXTURE-DPAPI01\x00'
MAX_PLAINTEXT=4096
MAX_CIPHERTEXT=32768


class CodecError(ValueError):
    pass


class Blob(ctypes.Structure):
    _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data):
    buf=(ctypes.c_ubyte*len(data)).from_buffer_copy(data)
    return Blob(len(data),ctypes.cast(buf,ctypes.POINTER(ctypes.c_ubyte))),buf


def _operation(data,context,decrypt):
    if os.name!='nt':
        raise CodecError('Windows current-user DPAPI required')
    if not isinstance(context,bytes) or not 1<=len(context)<=1024:
        raise CodecError('Bounded nonempty context bytes required')
    crypt=ctypes.WinDLL('crypt32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    function=crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.POINTER(Blob),
                       ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    function.restype=wintypes.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    kernel.LocalFree.restype=ctypes.c_void_p
    incoming,inbuf=_blob(data)
    entropy,entbuf=_blob(DOMAIN+context)
    outgoing=Blob()
    try:
        # UI_FORBIDDEN=1; LOCAL_MACHINE=4 is deliberately never set.
        if not function(ctypes.byref(incoming),None,ctypes.byref(entropy),None,None,1,ctypes.byref(outgoing)):
            raise CodecError('DPAPI operation failed; no data returned')
        if not outgoing.pbData or not 1<=outgoing.cbData<=MAX_CIPHERTEXT:
            raise CodecError('Unexpected DPAPI result length')
        return ctypes.string_at(outgoing.pbData,outgoing.cbData)
    finally:
        ctypes.memset(inbuf,0,len(inbuf))
        ctypes.memset(entbuf,0,len(entbuf))
        if outgoing.pbData:
            if outgoing.cbData<=MAX_CIPHERTEXT:
                ctypes.memset(outgoing.pbData,0,outgoing.cbData)
            kernel.LocalFree(outgoing.pbData)


def protect(plaintext,context):
    if not isinstance(plaintext,bytes) or not 1<=len(plaintext)<=MAX_PLAINTEXT:
        raise CodecError('Bounded nonempty plaintext bytes required')
    wrapped=MAGIC+struct.pack('<I',len(plaintext))+hashlib.sha256(plaintext).digest()+plaintext
    return _operation(wrapped,context,False)


def unprotect(ciphertext,context):
    if not isinstance(ciphertext,bytes) or not 32<=len(ciphertext)<=MAX_CIPHERTEXT:
        raise CodecError('Bounded ciphertext bytes required')
    wrapped=_operation(ciphertext,context,True)
    head=len(MAGIC)+4+32
    if len(wrapped)<head or not hmac.compare_digest(wrapped[:len(MAGIC)],MAGIC):
        raise CodecError('Invalid fixture envelope')
    size=struct.unpack_from('<I',wrapped,len(MAGIC))[0]
    if not 1<=size<=MAX_PLAINTEXT or len(wrapped)!=head+size:
        raise CodecError('Invalid fixture envelope size')
    plaintext=wrapped[head:]
    digest=wrapped[len(MAGIC)+4:head]
    if not hmac.compare_digest(digest,hashlib.sha256(plaintext).digest()):
        raise CodecError('Invalid fixture envelope integrity')
    return plaintext

# Copies in Python immutable bytes cannot be guaranteed wiped. No claim of
# complete process-memory zeroization or resistance to a compromised user
# session is made. The caller must not log returned plaintext or delete the
# durable journal before separate firmware absence has been verified.
