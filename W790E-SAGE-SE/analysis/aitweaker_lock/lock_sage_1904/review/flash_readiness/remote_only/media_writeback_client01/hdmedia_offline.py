"""Bounded Java HDMEDIA protocol engine, with NO network or device connector.

Parent must own TLS and web/KVM authentication. This module cannot log in,
connect, mount media, reset, alter BMC settings, or flash anything. The only
disk backend opens the literal WRITEBACK02.img path, with pinned identity.
It is not opened by importing this module or running the offline tests.
"""
from pathlib import Path
import hashlib
import os
import re
import stat
import struct

HERE = Path(__file__).resolve().parent
PINNED_IMAGE = HERE.parent / 'media_writeback_review/blank_test/WRITEBACK02.img'
PINNED_SIZE = 16 * 1024 * 1024
PINNED_SHA256 = 'df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
SECTOR = 512
MAX_SECTORS = 256
MAX_FRAME = 131134
MAX_WRITE_BUDGET = 1024 * 1024  # Disposable first writeback test, not full backup.


class Reject(Exception):
    """A fixed public reason, never request bytes, tokens, or remote strings."""


def checked_ascii(value, maximum, pattern):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise Reject('field length rejected')
    if re.fullmatch(pattern, value) is None:
        raise Reject('field encoding rejected')
    return value.encode('ascii')


def single_port_requests(host, web_cookie, web_port=443):
    """Two exact Java plaintext records carried INSIDE parent-owned TLS.

    TLS handshake/certificate identity and server success grammar are deliberately
    outside this offline engine. No literal negative hd_port is used as a port.
    """
    h = checked_ascii(host, 253, r'[A-Za-z0-9.:-]+')
    c = checked_ascii(web_cookie, 256, r'[A-Za-z0-9_=.%-]+')
    if web_port != 443:
        raise Reject('only reviewed HTTPS web port 443 is configured')
    return (b'CONNECT ' + h + b':443 HTTPS/1.1\r\n cookie ' + c + b'\r\n\r\n',
            b'JVIEWER HDMEDIA cookie ' + c + b'\r\n\r\n')


class TunnelGate:
    """No invented success reply. Parent must pin an independently observed one.

    Stock Java treats any non-ERROR reply as success. That behavior is insufficient
    evidence for an exact parser. Offline tests supply a visibly synthetic reply.
    """
    def __init__(self, exact_success_reply=None):
        self.expected = exact_success_reply
        self.accepted = False
        self.failed = False

    def accept(self, reply):
        if self.failed or self.accepted or self.expected is None:
            self.failed = True
            raise Reject('tunnel success grammar not established')
        if not isinstance(reply, bytes) or len(reply) > 4096 or reply != self.expected or b'ERROR' in reply:
            self.failed = True
            raise Reject('tunnel response rejected')
        self.accepted = True


def block_range(lba, count):
    if type(lba) is not int or type(count) is not int or lba < 0 or count < 0 or count > MAX_SECTORS:
        raise Reject('block range rejected')
    if lba > PINNED_SIZE // SECTOR or count > PINNED_SIZE // SECTOR - lba:
        raise Reject('block range rejected')
    return lba * SECTOR, count * SECTOR


class MemoryImage:
    """Offline synthetic backend; mutation stays in an in-process image copy."""
    def __init__(self, data):
        if len(data) != PINNED_SIZE:
            raise Reject('image size rejected')
        self.data = bytearray(data)
        self.closed = False
        self.reads = self.writes = self.written_bytes = 0

    def _check(self):
        if self.closed or len(self.data) != PINNED_SIZE:
            raise Reject('image unavailable')

    def read(self, lba, count):
        self._check(); start, size = block_range(lba, count)
        self.reads += 1
        return bytes(self.data[start:start+size])

    def write(self, lba, count, data):
        self._check(); start, size = block_range(lba, count)
        if len(data) != size or self.written_bytes + size > MAX_WRITE_BUDGET:
            raise Reject('write length or budget rejected')
        self.data[start:start+size] = data
        self.writes += 1; self.written_bytes += size
        if self.read(lba, count) != data:
            raise Reject('writeback verification failed')

    def flush(self): self._check()
    def close(self): self.closed = True


def validate_literal_image_path(path):
    """Reject before opening. The client has no arbitrary-path configuration."""
    if not isinstance(path, Path) or str(path) != str(PINNED_IMAGE):
        raise Reject('non-pinned image path rejected')
    if not path.is_absolute() or path.name != 'WRITEBACK02.img':
        raise Reject('non-pinned image path rejected')
    text = str(path)
    if text.startswith(('\\\\', '//', '\\??\\')) or ':' in text[2:]:
        raise Reject('device, UNC or stream path rejected')
    for p in (path, *path.parents):
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode) or getattr(s, 'st_file_attributes', 0) & 0x400:
            raise Reject('symlink or reparse point rejected')
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size != PINNED_SIZE:
        raise Reject('regular image identity rejected')
    return s


class PinnedImage:
    """Only literal local regular file; no native vendor library or disk pass-through.

    Not exercised against the real pinned file by offline tests. The explicit
    factory is for later parent-controlled use, after authentication succeeds.
    """
    def __init__(self):
        before = validate_literal_image_path(PINNED_IMAGE)
        flags = os.O_RDWR | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        self.fd = os.open(PINNED_IMAGE, flags)
        self.closed = False; self.written_bytes = 0; self.locked = False
        try:
            after = os.fstat(self.fd)
            self.identity = (after.st_dev, after.st_ino)
            if self.identity != (before.st_dev, before.st_ino):
                raise Reject('opened image identity changed')
            self._check()
            if os.name != 'nt':
                raise Reject('exclusive Windows image lock required')
            import msvcrt
            os.lseek(self.fd, 0, os.SEEK_SET)
            msvcrt.locking(self.fd, msvcrt.LK_NBLCK, PINNED_SIZE)
            self.locked = True
            os.lseek(self.fd, 0, os.SEEK_SET)
            contents = os.read(self.fd, PINNED_SIZE)
            if len(contents) != PINNED_SIZE or hashlib.sha256(contents).hexdigest() != PINNED_SHA256:
                raise Reject('image baseline rejected')
        except Exception:
            self.close()
            raise

    def _check(self):
        if self.closed: raise Reject('image closed')
        s = os.fstat(self.fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size != PINNED_SIZE:
            raise Reject('image size or identity changed')
        if (s.st_dev, s.st_ino) != self.identity:
            raise Reject('image handle changed')

    def read(self, lba, count):
        self._check(); start, size = block_range(lba, count)
        os.lseek(self.fd, start, os.SEEK_SET)
        out = os.read(self.fd, size)
        if len(out) != size:
            self.close(); raise Reject('short image read')
        return out

    def write(self, lba, count, data):
        self._check(); start, size = block_range(lba, count)
        if len(data) != size or self.written_bytes + size > MAX_WRITE_BUDGET:
            raise Reject('write length or budget rejected')
        try:
            os.lseek(self.fd, start, os.SEEK_SET)
            if os.write(self.fd, data) != size:
                raise Reject('short image write')
            self.written_bytes += size
            os.fsync(self.fd)
            self._check()
            if self.read(lba, count) != data:
                raise Reject('writeback verification failed')
        except Exception:
            self.close()
            raise

    def flush(self): self._check(); os.fsync(self.fd)

    def close(self):
        if not self.closed:
            self.closed = True
            # Closing the owned handle releases its byte-range lock.
            os.close(self.fd)


class VendorWriter:
    """Reproduce reviewed IUSBHeader.write + preBuffered Java serialization.

    The Java checksum runs over the ByteBuffer's current limit, which is the
    entire retained 131134-byte capacity on final send. It includes the old
    checksum. This intentionally mirrors the artifact, not an assumed standard.
    """
    def __init__(self): self.buffer = bytearray(MAX_FRAME)

    def header_write(self, data_len, limit, template=None):
        if not 32 <= limit <= MAX_FRAME or not 0 <= data_len <= MAX_FRAME-32:
            raise Reject('header length rejected')
        if template is None:
            h = bytearray(32); h[:8] = b'IUSB    '; h[8:11] = b'\x01\x00\x20'
            h[17:20] = b'\x05\x01\x80'
        else:
            if len(template) != 32: raise Reject('header template rejected')
            h = bytearray(template); h[19] = 0x80
        struct.pack_into('<I', h, 12, data_len)
        self.buffer[:32] = h
        self.buffer[11] = -sum(self.buffer[:limit]) & 255

    def finalize(self, length):
        self.header_write(length-32, MAX_FRAME, bytes(self.buffer[:32]))
        return bytes(self.buffer[:length])

    def auth(self, token, token_type=0, instance=0):
        t = checked_ascii(token, 64 if token_type == 0 else 208, r'[A-Za-z0-9_=.%-]+')
        if token_type not in (0, 1) or instance != 0:
            raise Reject('unreviewed token type or requested HD instance')
        length = 160 if token_type == 0 else 272
        self.header_write(length-32, length)
        self.buffer[41] = 0xf2; self.buffer[62] = 0
        self.buffer[63:63+len(t)] = t
        self.buffer[22] = 0x80; self.buffer[23] = instance
        return self.finalize(length)

    def media_info(self):
        self.header_write(290, 322)
        self.buffer[41] = 0xf8
        self.buffer[62:322] = struct.pack('<I', 4) + b'WRITEBACK02.img\0'.ljust(256, b'\0')
        return self.finalize(322)

    def response(self, request, data=b'', status=0, transfer_length=None):
        if len(request) < 61 or len(data) > 131072:
            raise Reject('response bounds rejected')
        # Match native first 62-byte copy; zero missing optional padding byte.
        self.buffer[:62] = request[:62].ljust(62, b'\0')
        struct.pack_into('<I', self.buffer, 53, status)
        struct.pack_into('<I', self.buffer, 57, len(data) if transfer_length is None else transfer_length)
        self.buffer[61:61+len(data)] = data
        return self.finalize(61+len(data))


def parse_frame(frame):
    if not isinstance(frame, bytes) or not 61 <= len(frame) <= MAX_FRAME:
        raise Reject('frame size rejected')
    if frame[:8] != b'IUSB    ' or frame[8:11] != b'\x01\x00\x20':
        raise Reject('IUSB header rejected')
    if struct.unpack_from('<I', frame, 12)[0] != len(frame)-32:
        raise Reject('IUSB length mismatch')
    if frame[17] != 5 or frame[18] != 1 or frame[19] != 0:
        raise Reject('unreviewed IUSB protocol or direction')
    return frame[41]


class FrameDecoder:
    def __init__(self): self.buffer = bytearray(); self.failed = False
    def feed(self, chunk):
        if self.failed: raise Reject('decoder stopped')
        try:
            if not isinstance(chunk, bytes) or len(chunk) > MAX_FRAME:
                raise Reject('input chunk rejected')
            self.buffer.extend(chunk)
            if len(self.buffer) > MAX_FRAME*2: raise Reject('stream buffer bound')
            result = []
            while len(self.buffer) >= 32:
                if self.buffer[:8] != b'IUSB    ' or self.buffer[8:11] != b'\x01\x00\x20':
                    raise Reject('stream header rejected')
                size = struct.unpack_from('<I', self.buffer, 12)[0]+32
                if not 61 <= size <= MAX_FRAME: raise Reject('stream length rejected')
                if len(self.buffer) < size: break
                frame = bytes(self.buffer[:size]); del self.buffer[:size]
                parse_frame(frame); result.append(frame)
            return result
        except Exception:
            self.failed = True; self.buffer.clear(); raise
    def eof(self):
        self.failed = True
        if self.buffer: self.buffer.clear(); raise Reject('truncated IUSB frame')


class IUSBEngine:
    def __init__(self, backend_factory):
        self.factory = backend_factory; self.image = None
        self.writer = VendorWriter(); self.state = 'NEW'; self.instance = None

    def start(self, tunnel_gate, token, token_type=0):
        if self.state != 'NEW' or not tunnel_gate.accepted or tunnel_gate.failed:
            self.stop(); raise Reject('unaccepted tunnel')
        try:
            first = self.writer.auth(token, token_type)
            second = self.writer.media_info()
            self.state = 'AUTH_PENDING'
            return first, second
        except Exception:
            self.stop(); raise

    def stop(self):
        self.state = 'STOPPED'
        if self.image is not None: self.image.close()

    def handle(self, frame):
        try:
            opcode = parse_frame(frame)
            if self.state == 'AUTH_PENDING':
                if opcode != 0xf1 or len(frame) != 108 or frame[62] != 1:
                    raise Reject('media authentication rejected')
                self.instance = frame[23]
                self.image = self.factory()  # First possible image open/read here.
                self.state = 'ACTIVE'
                return None
            if self.state != 'ACTIVE' or frame[23] != self.instance:
                raise Reject('inactive or wrong media instance')
            if opcode in (0xf1, 0xf2, 0xf7): raise Reject('session state changed')
            if opcode == 0xf6: self.stop(); return None
            if opcode in (0x28, 0xa8, 0x2a):
                lba = struct.unpack_from('>I', frame, 43)[0]
                count = struct.unpack_from('>H', frame, 48)[0] if opcode != 0xa8 else struct.unpack_from('>I', frame, 47)[0]
                _, size = block_range(lba, count)
                declared = struct.unpack_from('<I', frame, 57)[0]
                if opcode == 0x2a:
                    if declared != size or len(frame) != 61+size:
                        raise Reject('write payload length mismatch')
                    self.image.write(lba, count, frame[61:])
                    return self.writer.response(frame)
                if declared != 0 or len(frame) not in (61, 62) or (len(frame) == 62 and frame[61] != 0):
                    raise Reject('unexpected read request payload')
                data = self.image.read(lba, count)
                if len(data) != size: raise Reject('short backend read')
                return self.writer.response(frame, data)
            if len(frame) not in (61, 62) or struct.unpack_from('<I', frame, 57)[0] != 0:
                raise Reject('unexpected control payload')
            if opcode == 0x00: return self.writer.response(frame)
            if opcode == 0x25: return self.writer.response(frame, struct.pack('>II', PINNED_SIZE//512-1, 512))
            if opcode == 0x1a: return self.writer.response(frame, b'\x03\x00\x00\x00'[:frame[45]])
            if opcode == 0x35: self.image.flush(); return self.writer.response(frame)
            if opcode in (0x1b, 0x1e): return self.writer.response(frame)
            # Vendor image dispatch rejects unsupported SCSI/vendor requests.
            # F4 additionally carries the selected virtual USB drive type byte.
            if opcode == 0xf4: return self.writer.response(frame, b'\x80', 0x200501, transfer_length=0)
            return self.writer.response(frame, status=0x200501)
        except Exception:
            self.stop()
            raise


if __name__ == '__main__':
    raise SystemExit('Offline library only. No connection, disk mutation, or deployment CLI exists.')
