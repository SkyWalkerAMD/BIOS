"""Test actual parser C and delivered PE; no physical hardware or networking."""
from pathlib import Path
import ctypes as c
import hashlib
import importlib.util
import json
import re
import struct
import sys
import uuid
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
sys.path.insert(0, str(ROOT / 'tools/kvm-pydeps'))
import decode_captures as decoder
from unicorn.x86_const import *
from PIL import Image
import zxingcpp


class Entry(c.Structure):
    _fields_ = [('address', c.c_uint64)] + [(n, c.c_uint32) for n in ('bound', 'count', 'kind', 'length', 'major', 'minor', 'docrev')]


class Table(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('used', 'count', 'end_offset', 'crc')] + [('types', c.c_uint32 * 256)]


def rec(t, handle, formatted=b'', strings=()):
    return bytes([t, 4 + len(formatted)]) + struct.pack('<H', handle) + formatted + (b'\0'.join(strings) + b'\0\0' if strings else b'\0\0')


DATA = b''.join([
    rec(0, 0, bytes([1, 2]) + bytes(12), [b'AMI', b'3107']),
    rec(1, 1, bytes([1, 2, 3, 4]) + bytes(range(16)), [b'ASUS', b'HERO', b'1', b'SERIAL']),
    rec(2, 2, bytes([1, 2, 3, 4]), [b'ASUS', b'ROG MAXIMUS Z790 HERO', b'1', b'BOARD']),
    rec(4, 4, bytes(38), [b'Intel', b'i9-14900KS']),
    rec(17, 17, bytes(36), [b'DIMM_A2', b'JEDEC', b'ABC123']),
    rec(41, 41, bytes(7), [b'Ethernet']),
    rec(127, 0xFFFF),
])


def entry3(data=DATA, address=0x400000, bound=None):
    b = bytearray(b'_SM3_\0' + bytes([24, 3, 6, 0, 1, 0]) + struct.pack('<IQ', len(data) if bound is None else bound, address))
    b[5] = (-sum(b)) & 255
    return bytes(b)


def entry2(data=DATA, address=0x400000, count=7):
    b = bytearray(31)
    b[:4] = b'_SM_';b[5:8] = bytes([31, 2, 8]);b[16:21] = b'_DMI_'
    struct.pack_into('<HIH', b, 22, len(data), address, count)
    b[21] = (-sum(b[16:])) & 255;b[4] = (-sum(b)) & 255
    return bytes(b)


def main():
    rows = []
    def passed(name): rows.append({'case': name, 'passed': True})
    lib = c.CDLL(str(HERE / 'capture_test.dll'))
    lib.smbios_entry.argtypes = [c.c_void_p, c.c_size_t, c.c_uint, c.POINTER(Entry)]
    lib.smbios_entry.restype = c.c_int
    lib.smbios_table.argtypes = [c.c_void_p, c.c_size_t, c.c_uint, c.POINTER(Table)]
    lib.smbios_table.restype = c.c_int
    def parse_entry(b, kind):
        out = Entry();buf = c.create_string_buffer(b)
        return lib.smbios_entry(buf, len(b), kind, c.byref(out)), out
    def parse_table(b, expected=0):
        out = Table();buf = c.create_string_buffer(b)
        return lib.smbios_table(buf, len(b), expected, c.byref(out)), out
    for kind, raw in [(3, entry3()), (2, entry2())]:
        s, e = parse_entry(raw, kind);assert s == 0 and e.address == 0x400000 and e.bound == len(DATA)
        passed('valid_entry_' + str(kind))
        for n in range(len(raw)):
            assert parse_entry(raw[:n], kind)[0] != 0
        passed('all_truncated_entry_lengths_' + str(kind))
        corrupt = bytearray(raw);corrupt[4 if kind == 2 else 5] ^= 1
        assert parse_entry(bytes(corrupt), kind)[0] == 4;passed('entry_checksum_' + str(kind))
    for name, raw, expected in [
        ('table_bound_over_cap', entry3(bound=262145), 6),
        ('table_address_zero', entry3(address=0), 5),
        ('table_address_wrap', entry3(address=(1 << 64) - 4), 5),
    ]:
        assert parse_entry(raw, 3)[0] == expected;passed(name)
    status, meta = parse_table(DATA, 7)
    assert status == 0 and meta.used == len(DATA) and meta.count == 7 and meta.crc == zlib.crc32(DATA)
    assert meta.types[0] == meta.types[1] == meta.types[2] == meta.types[4] == meta.types[17] == meta.types[41] == meta.types[127] == 1
    passed('table_full_raw_types_strings_and_crc')
    assert parse_table(DATA + b'UNEXPORTED-PADDING', 7)[1].used == len(DATA)
    passed('sm3_maximum_size_not_exported_as_used_length')
    for name, raw, expected, error in [
        ('count_mismatch', DATA, 8, 10),
        ('missing_type127', DATA[:-6], 0, 9),
        ('bad_formatted_length', bytes([0, 3]) + DATA[2:], 0, 7),
        ('unterminated_strings', bytes([0, 4, 0, 0]) + b'A' * 12, 0, 8),
        ('bad_type127_length', rec(127, 0xFFFF, b'X'), 0, 7),
    ]:
        assert parse_table(raw, expected)[0] == error;passed(name)
    for n in range(1, len(DATA)):
        assert parse_table(DATA[:n])[0] != 0
    passed('all_truncated_table_lengths_refused')
    maximum = bytes([128, 4, 0, 0]) + b'A' * (262144 - 12) + b'\0\0' + rec(127, 0xFFFF)
    assert len(maximum) == 262144 and parse_table(maximum, 2)[0] == 0
    assert parse_table(maximum + b'X')[0] != 0;passed('exact_256k_limit_and_overflow_rejected')

    # The existing strict service-double harness is read as a library; its main
    # is never run and its artifact path is redirected only inside this process.
    spec = importlib.util.spec_from_file_location('audit_base', ROOT / 'analysis/hero_ipmi_p6_20261104/collector/verify_app.py')
    base = importlib.util.module_from_spec(spec);spec.loader.exec_module(base);base.P = HERE
    class Machine(base.Machine):
        def __init__(self, keys, kind=3, absent=False, malformed=False, writable=False, bad_marker=False):
            super().__init__(keys=keys, resident=False, p6_resident=False, writable=writable, bad_marker=bad_marker)
            self.rawptr = self.alloc(DATA)
            ep = bytearray(entry3(address=self.rawptr) if kind == 3 else entry2(address=self.rawptr))
            if malformed: ep[5 if kind == 3 else 4] ^= 1
            eptr = self.alloc(bytes(ep))
            guid = 'f2fd1544-9794-4a2c-992e-e5bbcf20e394' if kind == 3 else 'eb9d2d31-2d88-11d3-9a16-0090273fc14d'
            tab = self.alloc(uuid.UUID(guid).bytes_le + struct.pack('<Q', eptr))
            self.w64(self.st + 0x68, 0 if absent else 1);self.w64(self.st + 0x70, tab)
        def hook(self, u, address, size, data):
            name = self.stubs.get(address)
            if name and (name.startswith('R2') or name.startswith('P6')): raise AssertionError('Resident core access forbidden')
            if name not in ('FileOpen', 'FileRead'): return super().hook(u, address, size, data)
            self.calls.append(name)
            rsp = u.reg_read(UC_X86_REG_RSP);assert rsp % 16 == 8
            a,b,dest,mode = [u.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
            status = 0
            if name == 'FileRead':
                assert a == self.marker
                value = b'WRONG\r\n' if self.bad_marker else b'HERO-SMBIOS-I1\r\n'
                assert self.r64(b) >= len(value);self.w64(b, len(value));u.mem_write(dest, value)
            else:
                path = self.wide(dest)
                if path == '\\HERO_INV.TAG':
                    assert mode == 1;self.w64(b, self.marker)
                elif re.fullmatch(r'\\INV[0-9]{3}\.TXT', path):
                    if mode == 1:
                        if path in self.files:self.w64(b, self.file)
                        else:status = base.ERR(14)
                    else:
                        assert mode == 0x8000000000000003 and path not in self.files
                        if self.writable:
                            self.created=True;self.files[path]=bytearray();self.file_name=path;self.pos=0;self.w64(b,self.file)
                        else:status = base.ERR(8)
                else:raise AssertionError(path)
            u.reg_write(UC_X86_REG_RAX,status)
            for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)

    samples = []
    for name, options, expected_status in [
        ('startup_enter_escape_do_not_exit', dict(keys='\r\x1bq\rqq'), 0),
        ('sm3_qr_fallback_raw_export', dict(keys='sc\x1bqq'), 0),
        ('sm2_text_raw_export', dict(keys='sr\x1bqq', kind=2), 0),
        ('absent_table_stays_for_capture', dict(keys='sr\x1bqq', absent=True), base.ERR(33)),
        ('bad_checksum_stays_for_capture', dict(keys='sr\x1bqq', malformed=True), base.ERR(33)),
        ('usb_new_files_no_overwrite', dict(keys='sllqq', writable=True), 0),
        ('iso_l_is_write_protected', dict(keys='slqq'), 0),
        ('bad_usb_marker_no_write', dict(keys='slqq', writable=True, bad_marker=True), 0),
    ]:
        m = Machine(**options);s, out = m.run();assert s == expected_status, (name, hex(s))
        assert 'HERO SMBIOS I1 - FIRST TEXT / WAITING FOR S' in out
        assert 'HERO SMBIOS I1 RETURNING TO FIRMWARE' in out and not m.keys
        if 'raw_export' in name:
            rawlog = out.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode()
            assert rawlog.startswith(b'HERO-SMBIOS-I1\r\nRUN=') and b'CAPTURE_VALID=01' in rawlog
            table_bytes = bytes.fromhex(rawlog.split(b'TABLE_HEX_BEGIN\r\n')[1].split(b'TABLE_HEX_END')[0].decode())
            assert table_bytes == DATA
            samples.append(rawlog)
        if name == 'usb_new_files_no_overwrite':
            assert set(m.files) == {'\\INV000.TXT','\\INV001.TXT'} and m.files['\\INV000.TXT'] == m.files['\\INV001.TXT']
            samples.append(bytes(m.files['\\INV000.TXT']))
        elif 'marker' in name or name.startswith('iso_l'):assert not m.files
        assert not any('FORBIDDEN' in x or x.startswith('R2') or x.startswith('P6') for x in m.calls)
        passed('actual_pe_' + name)

    lib.kvm_make_frame.argtypes=[c.c_void_p,c.c_size_t,c.c_uint,c.c_void_p,c.c_size_t];lib.kvm_make_frame.restype=c.c_size_t
    lib.kvm_encode_frame.argtypes=[c.c_void_p,c.c_size_t,c.c_uint,c.c_void_p,c.c_void_p];lib.kvm_encode_frame.restype=c.c_int
    lib.qrcodegen_getSize.argtypes=[c.c_void_p];lib.qrcodegen_getSize.restype=c.c_int
    lib.qrcodegen_getModule.argtypes=[c.c_void_p,c.c_int,c.c_int];lib.qrcodegen_getModule.restype=c.c_bool
    def frame(data,page):
        src=c.create_string_buffer(data);dest=c.create_string_buffer(4096)
        n=lib.kvm_make_frame(src,len(data),page,dest,len(dest));assert n
        return bytes(dest[:n])
    for i, sample in enumerate(samples):
        frames=[frame(sample,p) for p in range((len(sample)+511)//512)]
        assert decoder.assemble(list(reversed(frames)))[0] == sample
        passed('exact_export_frame_roundtrip_' + str(i))
    huge = b'Z' * 786432
    last = frame(huge, 1535);assert decoder.parse_frame(last)['page']==1536
    dest=c.create_string_buffer(4096);src=c.create_string_buffer(huge+b'X')
    assert lib.kvm_make_frame(src,786433,0,dest,4096)==0
    passed('frame_limit_last_page_four_digits_and_overflow')
    sample=samples[0];src=c.create_string_buffer(sample);qr=c.create_string_buffer(4096);tmp=c.create_string_buffer(4096)
    assert lib.kvm_encode_frame(src,len(sample),0,qr,tmp)
    size=lib.qrcodegen_getSize(qr);scale=4;image=Image.new('RGB',((size+8)*scale,)*2,'white')
    for y in range(size):
        for x in range(size):
            if lib.qrcodegen_getModule(qr,x,y):
                for dy in range(scale):
                    for dx in range(scale):image.putpixel(((x+4)*scale+dx,(y+4)*scale+dy),(0,0,0))
    image.save(HERE/'synthetic-qr-page.png')
    found=zxingcpp.read_barcodes(image,formats=zxingcpp.BarcodeFormat.QRCode)
    assert len(found)==1 and bytes(found[0].bytes)==frame(sample,0)
    passed('compiled_c_QR_decodes_exact_bytes')
    (HERE/'synthetic-capture.TXT').write_bytes(sample)
    result={'all_passed':True,'count':len(rows),'cases':rows,
            'app_sha256':hashlib.sha256((HERE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
            'dll_sha256':hashlib.sha256((HERE/'capture_test.dll').read_bytes()).hexdigest(),
            'limits':['Synthetic tables/UEFI services; no target hardware execution.','CRC32 detects accidental corruption and is not authentication.']}
    (HERE/'verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'all_passed':True,'count':len(rows),'app_sha256':result['app_sha256']}))


if __name__=='__main__':main()
