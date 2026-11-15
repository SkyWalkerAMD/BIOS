"""One-frame, pure offline compatibility proposal; no backend or transport.

Caller must have independently verified TLS/tunnel/F1 authentication and must
commit consumed=True exactly once on this same owned session. This function
does not authenticate credentials or permit any disk operation. All outputs
are new immutable bytes. It neither imports nor changes the existing engine.
"""
from dataclasses import dataclass
import struct

class LegacyTurReject(ValueError):
    pass

@dataclass(frozen=True)
class LegacyTurReply:
    response: bytes
    consumed: bool = True
    opens_or_touches_image: bool = False
    permits_other_legacy_frames: bool = False

def respond_once(auth_reply: bytes, request: bytes, *, authenticated: bool,
                 consumed: bool) -> LegacyTurReply:
    """Reply only to the exact first legacy TUR shape after verified F1.

    The session key at28..31 is copied only into the response header. It is not
    decoded, logged, hashed separately or copied into padding. Incoming header
    checksum is not claimed to provide authentication; TLS/session are external.
    """
    if authenticated is not True or consumed is not False:
        raise LegacyTurReject('inactive or already consumed legacy TUR window')
    if type(auth_reply) is not bytes or type(request) is not bytes:
        raise LegacyTurReject('immutable byte frames required')
    if len(auth_reply)!=108 or len(request)!=108:
        raise LegacyTurReject('only exact108-byte frames supported')
    if request[:8]!=b'IUSB    ' or request[:32]!=auth_reply[:32]:
        raise LegacyTurReject('session header mismatch')
    # Fixed physical32-byte header. Only checksum and session key may be
    # nonzero outside signature/76-byte length; all other fields pin the
    # actually observed zero legacy mode, single HD instance and sequence0.
    if request[8:11]!=b'\0'*3 or request[16:28]!=b'\0'*12:
        raise LegacyTurReject('unsupported legacy header fields')
    if struct.unpack_from('<I',request,12)[0]!=76:
        raise LegacyTurReject('frame payload length mismatch')
    if auth_reply[41]!=0xf1 or request[41]!=0:
        raise LegacyTurReject('not the F1 to TUR transition')
    if request[:41]!=auth_reply[:41] or request[42:]!=auth_reply[42:]:
        raise LegacyTurReject('TUR differs from pinned authentication reply')
    if request[32:62]!=b'\0'*30 or request[62]!=1 or request[63:]!=b'\0'*45:
        raise LegacyTurReject('unsupported TUR CDB/status/retained tail')

    # Native copies62 input bytes and returns61 (zero SCSI result data).
    # Stock Java preBuffered uses61-headerLen(0), then adds physical32:
    # final response93B, IUSB payload61. Start clean: do not mimic its retained
    # old output buffer, which could expose old bytes at61..92.
    reply=bytearray(93)
    reply[:32]=request[:32]
    struct.pack_into('<I',reply,12,61)
    reply[19]=0x80
    # IUSBHeader.write includes the prior checksum in its full current-limit
    # sum. Fresh remaining capacity is zero, so summing93 is equivalent to the
    # reviewed131134-byte Java buffer. Do not replace with a guessed CRC rule.
    reply[11]=(-sum(reply))&255
    assert reply[61:]==b'\0'*32
    assert reply[28:32]==request[28:32]
    return LegacyTurReply(bytes(reply))

if __name__=='__main__':
    raise SystemExit('Pure offline function only; no transport or backend CLI.')
