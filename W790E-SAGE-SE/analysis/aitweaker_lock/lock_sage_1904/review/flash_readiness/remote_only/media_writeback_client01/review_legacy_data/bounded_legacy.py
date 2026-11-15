"""Pure legacy HDMEDIA framing for one externally authenticated, pinned image.

No network, filesystem, ctypes, native-library or backend imports. A caller
owns TLS, verifies authentication and the literal image, commits next_session
BEFORE an I/O operation, and stops on exceptions. Plans do not execute I/O.
"""
from dataclasses import dataclass, field, replace
import struct

IMAGE_BYTES=16777216
IMAGE_SHA256='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
SECTOR=512
BLOCKS=32768
MAX_FRAME=131134  # Actual Java ByteBuffer capacity, not a rounded guess.
MAX_READ_SECTORS=255  # 256*512+93 would be131165 and overflow that capacity.
MAX_WRITE_SECTORS=256
WRITE_BUDGET=1048576
MAX_COMMANDS=8192
OPCODES=frozenset([0x00,0x1a,0x1b,0x1e,0x25,0x28,0x2a,0x35,0xa8,0xf3,0xf4,0xf6,0xf7])

class Reject(ValueError):
    """Fixed public messages only; never include payloads or session keys."""

@dataclass(frozen=True)
class Session:
    auth_header: bytes=field(repr=False)
    auth_tail: bytes=field(repr=False)
    image_sha256: str=IMAGE_SHA256
    image_bytes: int=IMAGE_BYTES
    reserved_write_bytes: int=0
    commands: int=0
    active: bool=True

@dataclass(frozen=True)
class Plan:
    session: Session=field(repr=False)
    request: bytes=field(repr=False)
    canonical: bytes=field(repr=False)
    next_session: Session=field(repr=False)
    opcode: int
    action: str
    lba: int=0
    count: int=0
    write_data: bytes=field(default=b'',repr=False)
    response_data_bytes: int=0
    fixed_data: bytes|None=field(default=None,repr=False)
    status: int=0
    declared_response_bytes: int=0
    padding_kind: str='none'
    opaque_direction: int=0

def _bytes(v):
    if type(v) is not bytes:raise Reject('immutable bytes required')

def _u32(b,o):return struct.unpack_from('<I',b,o)[0]

def _auth(a):
    _bytes(a)
    if len(a)!=108 or a[:8]!=b'IUSB    ' or a[8:11]!=b'\0'*3 or _u32(a,12)!=76:
        raise Reject('unreviewed legacy authentication frame')
    if a[16:28]!=b'\0'*12 or a[32:41]!=b'\0'*9 or a[41]!=0xf1 or a[42:62]!=b'\0'*20 or a[62]!=1 or a[63:]!=b'\0'*45:
        raise Reject('unreviewed authenticated session profile')

def bind_session(auth_reply: bytes, *, tls_verified: bool, authenticated: bool,
                 image_sha256: str, image_bytes: int) -> Session:
    if tls_verified is not True or authenticated is not True:
        raise Reject('externally verified TLS and authentication required')
    if image_sha256!=IMAGE_SHA256 or type(image_bytes) is not int or image_bytes!=IMAGE_BYTES:
        raise Reject('only the fixed disposable image profile is permitted')
    _auth(auth_reply)
    return Session(auth_reply[:32],auth_reply[61:])

def _session(s):
    if type(s) is not Session or s.active is not True:raise Reject('inactive session')
    if s.image_sha256!=IMAGE_SHA256 or s.image_bytes!=IMAGE_BYTES:raise Reject('image profile changed')
    if type(s.reserved_write_bytes) is not int or not 0<=s.reserved_write_bytes<=WRITE_BUDGET:
        raise Reject('invalid reserved write budget')
    if type(s.commands) is not int or not 0<=s.commands<MAX_COMMANDS:raise Reject('command bound reached')
    _bytes(s.auth_header);_bytes(s.auth_tail)
    if len(s.auth_header)!=32 or s.auth_tail!=b'\0\1'+b'\0'*45:raise Reject('invalid session profile')
    # Reconstruct only the already verified F1 profile for structural checking.
    a=s.auth_header+b'\0'*9+b'\xf1'+b'\0'*20+s.auth_tail[1:]
    _auth(a)

def _header(s,r):
    _bytes(r)
    if not 61<=len(r)<=MAX_FRAME:raise Reject('frame size bound')
    if r[:8]!=b'IUSB    ' or r[8:11]!=b'\0'*3 or _u32(r,12)!=len(r)-32:
        raise Reject('invalid physical32-byte legacy envelope')
    if r[16:24]!=s.auth_header[16:24] or r[28:32]!=s.auth_header[28:32]:
        raise Reject('session instance or opaque key mismatch')
    if _u32(r,53)!=0:raise Reject('request status must be clear')

def _nonwrite_tail(s,r):
    if _u32(r,57)!=0:raise Reject('unexpected request data length')
    if len(r)==61:return 'none'
    if len(r)==62 and r[61]==0:return 'single-zero'
    if len(r)==108 and r[61:] in (s.auth_tail,b'\0'*47):
        return 'fixed-auth-tail' if r[61:]==s.auth_tail else 'fixed-zero-tail'
    raise Reject('unreviewed non-WRITE padding')

def _cdb(op,c):
    # Native image path ignores SCSI direction@40. I/O direction below is
    # exclusively determined by opcode; opaque direction cannot turn a read
    # into a write. CDB flags/addresses/counts are separately bounded.
    if op in (0x28,0x2a):
        if c[1]&~0x18 or c[6] or any(c[9:]):raise Reject('unsupported READ10/WRITE10 flags or control')
        return int.from_bytes(c[2:6],'big'),int.from_bytes(c[7:9],'big')
    if op==0xa8:
        if c[1]&~0x18 or any(c[10:]):raise Reject('unsupported READ12 flags or control')
        return int.from_bytes(c[2:6],'big'),int.from_bytes(c[6:10],'big')
    if op==0x1a:
        if c[1] not in (0,8) or c[2]&0xc0 or c[3] or any(c[5:]):raise Reject('unsupported MODE SENSE6 form')
    elif op in (0x1b,0x1e):
        if any(c[1:4]) or c[4]>(3 if op==0x1b else 1) or any(c[5:]):raise Reject('unsupported media control CDB')
    elif any(c[1:]):raise Reject('unsupported control CDB fields')
    return 0,0

def normalize_request(session: Session, request: bytes) -> Plan:
    """Validate before backend access; caller must commit returned next_session.

    Non-WRITE padding is discarded only for finite61/62/108-byte shapes. WRITE
    never uses this rule: it must be exactly61+count*512 and declaration must
    match. Request metadata@32 and@40 never chooses a target or operation.
    """
    _session(session);_header(session,request)
    op=request[41]
    if op not in OPCODES:raise Reject('opcode outside bounded whitelist')
    c=request[41:53];lba,count=_cdb(op,c)
    read_length=struct.unpack_from('<Q',request,32)[0]
    action='control';fixed=b'';expected=0;status=0;declared=0;write=b''
    next_used=session.reserved_write_bytes
    if op in (0x28,0x2a,0xa8):
        maximum=MAX_WRITE_SECTORS if op==0x2a else MAX_READ_SECTORS
        if not 1<=count<=maximum or not 0<=lba<BLOCKS or count>BLOCKS-lba:
            raise Reject('LBA/count exceeds pinned image or wire bounds')
        amount=count*SECTOR
        if read_length not in (0,amount):raise Reject('requested length contradicts bounded CDB')
        if op==0x2a:
            if len(request)!=61+amount or _u32(request,57)!=amount:raise Reject('WRITE requires exact declaration and payload')
            next_used+=amount
            if next_used>WRITE_BUDGET:raise Reject('total write reservation exceeds1MiB')
            write=request[61:];action='write';padding='none'
        else:
            padding=_nonwrite_tail(session,request);action='read';fixed=None;expected=declared=amount
    else:
        padding=_nonwrite_tail(session,request)
        if op==0x25:fixed=struct.pack('>II',BLOCKS-1,SECTOR)
        elif op==0x1a:fixed=b'\x03\0\0\0'  # Actual native behavior even allocation0.
        elif op==0x35:action='flush'
        elif op in (0xf3,0xf4,0xf6):
            status=0x200501
            if op==0xf4:fixed=b'\x80'  # Java appends USB-image drive type.
            if op==0xf6:action='reply_then_stop'
        elif op==0xf7:action='stop_without_reply'
        expected=len(fixed);declared=0 if op==0xf4 else expected
        allowed={0,expected}
        if op==0x1a:allowed.add(c[4])
        if read_length not in allowed:raise Reject('control read length contradicts command')
    canonical=bytearray(request[:61]+write)
    canonical[8:11]=b'\x01\0\x20';canonical[17:20]=b'\x05\x01\0'
    struct.pack_into('<I',canonical,12,len(canonical)-32)
    # Canonical is internal only. Actual original header/CDB are preserved in
    # Plan and restored by serializer; do not send this frame to the server.
    canonical[11]=0;canonical[11]=(-sum(canonical))&255
    nxt=replace(session,reserved_write_bytes=next_used,commands=session.commands+1,
                active=op not in (0xf6,0xf7))
    return Plan(session,request,bytes(canonical),nxt,op,action,lba,count,write,
                expected,fixed,status,declared,padding,request[40])

def serialize_response(plan: Plan, data: bytes|None=None, *, operation_succeeded: bool=True) -> bytes|None:
    """Serialize only successful external I/O or fixed control responses.

    For read supply exactly count*512 bytes; for write/flush call only after
    durable backend operation and its local checks succeeded. Short/failing
    operations must close the session, not be converted into success packets.
    Every response starts in zeroed memory; opaque key stays only in header.
    """
    if type(plan) is not Plan or normalize_request(plan.session,plan.request)!=plan:
        raise Reject('altered or invalid plan')
    if operation_succeeded is not True:raise Reject('external operation failed')
    if plan.action=='stop_without_reply':
        if data not in (None,b''):raise Reject('session stop carries no data')
        return None
    if data is None:
        if plan.fixed_data is None:raise Reject('read result required')
        data=plan.fixed_data
    _bytes(data)
    if len(data)!=plan.response_data_bytes or (plan.fixed_data is not None and data!=plan.fixed_data):
        raise Reject('response data length or fixed content mismatch')
    n=93+len(data)
    if n>MAX_FRAME:raise Reject('legacy response exceeds Java capacity')
    out=bytearray(n);out[:53]=plan.request[:53]
    struct.pack_into('<I',out,53,plan.status)
    struct.pack_into('<I',out,57,plan.declared_response_bytes)
    out[61:61+len(data)]=data
    if plan.opcode==0xf4:
        # HarddiskRedir.run position11/putInt31 before adding drive type at61;
        # that sets the old header checksum byte to31. Java later rewrites
        # DataPacketLen, so only this seed survives into checksum calculation.
        out[11]=31
    struct.pack_into('<I',out,12,n-32);out[19]=0x80
    out[11]=(-sum(out))&255
    assert out[61+len(data):]==b'\0'*32
    assert out[28:32]==plan.request[28:32]
    return bytes(out)

if __name__=='__main__':
    raise SystemExit('Pure framing library only: no network, image or deployment CLI.')
