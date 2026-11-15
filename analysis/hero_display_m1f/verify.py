"""Execute final M1f EFI bytes with strict synthetic UEFI service doubles.

No target machine, device, network or runtime variable is accessed. All firmware
services other than the explicit metadata/console allowlist fail the test.
"""
from pathlib import Path
import sys, struct, re, uuid, json, hashlib, zlib
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

ERR = lambda n: 0x8000000000000000 | n
P64 = lambda n: struct.pack('<Q', n)
GOP = '9042a9de-23dc-4a38-96fb-7aded080516a'
BROWSER = 'b9d4c360-bcfb-4f9b-9298-53c136982258'
LOADED = '5b1b31a1-9562-11d2-8e3f-00a0c969723b'

class Machine:
    def __init__(self, keys='dr!q\r', fault=None):
        self.keys = list(keys); self.fault = fault
        self.u = Uc(UC_ARCH_X86, UC_MODE_64)
        for address, size in ((0x100000, 0x100000), (0x600000, 0x800000),
                              (0x1400000, 0x100000), (0x1700000, 0x100000),
                              (0x2000000, 0x200000)):
            self.u.mem_map(address, size)
        pe = pefile.PE(str(OUT / 'payload/EFI/BOOT/BOOTX64.EFI'))
        self.entry = 0x100000 + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pe.relocate_image(0x100000)
        self.u.mem_write(0x100000, pe.get_memory_mapped_image())
        self.heap = 0x600000; self.next_stub = 0x1400000
        self.stubs = {}; self.guard = []; self.allocations = set(); self.freed = []
        self.output = ''; self.calls = []; self.protocols = []; self.actions = []
        self.st = 0x1700000; self.bs = self.st + 0x1000; self.rt = self.st + 0x2000
        self.textout = self.st + 0x3000; self.textin = self.st + 0x4000
        self.w64(self.st, 0x5453595320494249)
        for off, ptr in ((0x28, 0x1111), (0x30, self.textin), (0x38, 0x2222),
                         (0x40, self.textout), (0x58, self.rt), (0x60, self.bs)):
            self.w64(self.st + off, ptr)
        for off in range(0x18, 0x178, 8): self.stub(self.bs + off, 'FORBIDDEN_BS_' + hex(off))
        for off in range(0x18, 0x90, 8): self.stub(self.rt + off, 'FORBIDDEN_RT_' + hex(off))
        for off, name in ((0x48, 'FreePool'), (0x60, 'WaitEvent'), (0x98, 'HandleProtocol'),
                          (0xf8, 'Stall'), (0x100, 'Watchdog'), (0x138, 'LocateHandles'),
                          (0x140, 'LocateProtocol')):
            self.stub(self.bs + off, name)
        for off, name in ((8, 'Output'), (0x18, 'TextQuery'), (0x20, 'FORBIDDEN_TEXT_SETMODE'),
                          (0x28, 'Attribute'), (0x30, 'Clear'), (0x40, 'Cursor')):
            self.stub(self.textout + off, name)
        self.stub(self.textin + 8, 'ReadKey'); self.w64(self.textin + 16, 0x1234)
        self.text_mode = self.alloc(struct.pack('<iiiiiB3x', 3, 0, 7, 0, 0, 1))
        self.w64(self.textout + 0x48, self.text_mode)
        width, height = {'small': (320, 200), 'large': (7680, 4320)}.get(fault, (1280, 800))
        self.info_bytes = struct.pack('<9I', 0, width, height, 1, 0, 0, 0, 0, width)
        self.info = self.alloc(self.info_bytes)
        self.mode = self.alloc(struct.pack('<IIQQQQ', 3, 9 if fault == 'bad_current' else 0,
                              0 if fault == 'null_info' else self.info,
                              4 if fault == 'short_info' else 36, 0, width * height * 4))
        self.gop = self.alloc(bytes(32)); self.stub(self.gop, 'GopQuery')
        self.stub(self.gop + 8, 'FORBIDDEN_GOP_SETMODE'); self.stub(self.gop + 16, 'FORBIDDEN_GOP_BLT')
        self.w64(self.gop + 24, 0 if fault == 'null_mode' else self.mode)
        if fault == 'null_blt': self.w64(self.gop + 16, 0)
        self.browser = self.alloc(bytes(16)); self.stub(self.browser, 'FORBIDDEN_SENDFORM')
        self.send_address = self.r64(self.browser)
        if fault == 'null_send': self.w64(self.browser, 0)
        self.loaded = self.alloc(bytes(96))
        self.w64(self.loaded + 0x40, self.send_address - 0x100)
        self.w64(self.loaded + 0x48, {'short_owner': 0x120, 'huge_owner': 0x40000001}.get(fault, 0x200))
        if fault == 'owner_not_found': self.w64(self.loaded + 0x40, self.send_address + 1)
        self.u.hook_add(UC_HOOK_CODE, self.hook)

    def alloc(self, data, firmware=False):
        ptr = self.heap + 16; self.heap += (len(data) + 47) & ~15
        assert self.heap < 0xe00000
        self.u.mem_write(ptr - 16, b'\xa5' * 16 + bytes(data) + b'\xa5' * 16)
        self.guard.append((ptr, len(data)))
        if firmware: self.allocations.add(ptr)
        return ptr

    def w64(self, ptr, value): self.u.mem_write(ptr, P64(value))
    def r64(self, ptr): return struct.unpack('<Q', self.u.mem_read(ptr, 8))[0]
    def guid(self, ptr): return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(ptr, 16))))
    def wide(self, ptr):
        data = bytearray()
        for i in range(4096):
            pair = bytes(self.u.mem_read(ptr + 2 * i, 2))
            if pair == b'\0\0': return data.decode('utf-16le')
            data.extend(pair)
        raise AssertionError('unterminated text')
    def stub(self, slot, name):
        ptr = self.next_stub; self.next_stub += 16
        self.w64(slot, ptr); self.stubs[ptr] = name; self.u.mem_write(ptr, b'\xc3')

    def hook(self, u, addr, size, user):
        name = self.stubs.get(addr)
        if name is None: return
        rsp = u.reg_read(UC_X86_REG_RSP); assert rsp % 16 == 8, name
        a, b, c, d = [u.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        fifth = self.r64(rsp + 0x28); result = 0; self.calls.append(name)
        assert not name.startswith('FORBIDDEN'), name
        if name == 'Output':
            self.output += self.wide(b)
            if self.fault == 'output_error': result = ERR(7)
        elif name == 'ReadKey':
            if self.fault == 'input_error': result = ERR(7)
            elif self.fault == 'input_not_ready' and 'WaitEvent' not in self.calls: result = ERR(6)
            else:
                assert self.keys, ('input loop exhausted', self.output[-500:])
                k = self.keys.pop(0); self.actions.append((k, len(self.calls)))
                u.mem_write(b, struct.pack('<HH', 0x17 if k == '!' else 0, 0 if k == '!' else ord(k)))
        elif name == 'WaitEvent': assert a == 1 and self.r64(b) == 0x1234; self.w64(c, 0)
        elif name == 'Attribute': assert b in (7, 15)
        elif name == 'Clear': pass
        elif name == 'Cursor': assert b in (0, 1)
        elif name == 'Watchdog': assert a == b == c == d == 0
        elif name == 'Stall': assert a == 5000000
        elif name == 'TextQuery':
            if self.fault == 'text_query_error': result = ERR(7)
            else: self.w64(c, 80); self.w64(d, 25)
        elif name == 'HandleProtocol':
            guid = self.guid(b); self.protocols.append(guid)
            assert guid in (GOP, LOADED)
            if guid == GOP:
                if self.fault == 'no_gop' or self.fault == 'no_conout_gop' and a == 0x2222: result = ERR(14)
                else: self.w64(c, self.gop)
            else: self.w64(c, self.loaded)
        elif name == 'LocateProtocol':
            guid = self.guid(a); self.protocols.append(guid)
            assert guid in (GOP, BROWSER)
            if guid == GOP:
                if self.fault == 'no_gop': result = ERR(14)
                else: self.w64(c, self.gop)
            elif self.fault == 'no_browser': result = ERR(14)
            else: self.w64(c, self.browser)
        elif name == 'LocateHandles':
            assert a == 2 and c == 0; guid = self.guid(b); self.protocols.append(guid)
            assert guid in (GOP, LOADED)
            fail = (guid == GOP and self.fault in ('no_gop', 'enum_gop_error')) or (guid == LOADED and self.fault == 'enum_loaded_error')
            if fail: result = ERR(14)
            else:
                n = 999 if guid == GOP and self.fault == 'many_gops' else 9999 if guid == LOADED and self.fault == 'many_images' else 1
                allocated_n = min(n, 8 if guid == GOP else 1024)
                buf = self.alloc(P64(0x4444 if guid == GOP else 0x5555) * allocated_n, True)
                self.w64(d, n); self.w64(fifth, buf)
                if self.fault == 'many_images': self.w64(self.loaded + 0x40, self.send_address + 1)
        elif name == 'GopQuery':
            assert a == self.gop and b == 0
            if self.fault == 'query_error': result = ERR(7)
            else:
                buf = self.alloc(self.info_bytes, True); self.w64(c, 36); self.w64(d, buf)
        elif name == 'FreePool':
            assert a in self.allocations and a not in self.freed, ('invalid free', hex(a))
            self.freed.append(a)
        else: raise AssertionError(('unexpected service', name))
        u.reg_write(UC_X86_REG_RAX, result)
        for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11):
            u.reg_write(r, 0xcccccccccccccccc)

    def run(self):
        rsp = 0x21f0000 - 8; stop = 0x14f0000
        self.w64(rsp, stop); self.u.reg_write(UC_X86_REG_RSP, rsp)
        self.u.reg_write(UC_X86_REG_RCX, 0x3333); self.u.reg_write(UC_X86_REG_RDX, self.st)
        self.u.emu_start(self.entry, stop, count=25000000)
        assert self.u.reg_read(UC_X86_REG_RIP) == stop, 'instruction limit'
        assert self.calls[0] == 'Output'
        for ptr, size in self.guard:
            assert bytes(self.u.mem_read(ptr - 16, 16)) == b'\xa5' * 16
            assert bytes(self.u.mem_read(ptr + size, 16)) == b'\xa5' * 16
        assert set(self.freed) == self.allocations, 'unreleased firmware-owned allocations'
        return self.u.reg_read(UC_X86_REG_RAX)

def main():
    rows = []
    def passed(name): rows.append(dict(case=name, passed=True)); print(name, 'PASS', flush=True)
    for label, keys in (('quit', 'qq'), ('esc', '!!'), ('P_S_do_not_open_forms', 'psqq'),
                        ('repeat_D_is_noop', 'ddq\r'), ('capture_before_D', 'r!q\r'),
                        ('text_navigation_and_final', 'drnnnp!qr!\r'), ('uppercase', 'DR!Q\r')):
        m = Machine(keys); assert m.run() == 0
        assert m.calls.count('GopQuery') == (1 if 'd' in keys.lower() else 0)
        passed(label)
    m = Machine(); assert m.run() == 0
    start = next(n for key, n in m.actions if key == 'r'); end = next(n for key, n in m.actions if key == '!')
    assert not set(m.calls[start:end]) & {'GopQuery', 'HandleProtocol', 'LocateProtocol', 'LocateHandles', 'FreePool'}
    assert 'BROWSER_SENDFORM_RVA=0x0000000000000100' in m.output
    expected_crc = zlib.crc32(bytes(m.u.mem_read(m.send_address, 64)))
    assert f'BROWSER_FIRST64_CRC32=0x{expected_crc:016X}' in m.output
    data = m.output.split('KVM_LOG_BEGIN\r\n', 1)[1].split('KVM_LOG_END\r\n', 1)[0].encode('ascii')
    assert data.startswith(b'HERO-HII-M1F-KVM\r\nRUN=') and data.endswith(b'SNAPSHOT_END\r\n')
    assert f'BYTES {len(data)}  CRC {zlib.crc32(data):08X}' in m.output
    assert 'Q: QR' not in m.output
    passed('R_pure_text_and_exact_snapshot_browser_identity')
    for fault in ('no_gop', 'no_conout_gop', 'small', 'large', 'null_mode', 'null_info',
                  'short_info', 'null_blt', 'bad_current', 'query_error', 'enum_gop_error',
                  'enum_loaded_error', 'no_browser', 'null_send', 'owner_not_found',
                  'short_owner', 'huge_owner', 'many_gops', 'many_images', 'text_query_error'):
        m = Machine(fault=fault); assert m.run() == 0
        assert 'DISPLAY_INVENTORY_COMPLETE=0x0000000000000000' in m.output and 'TEXT PAGE' in m.output
        if fault in ('small', 'large'): assert 'M1D_SIZE_ACCEPTED=0x0000000000000000' in m.output
        if fault in ('null_mode', 'bad_current'): assert 'GopQuery' not in m.calls
        if fault in ('short_owner', 'huge_owner', 'owner_not_found'): assert 'BROWSER_FIRST64_CRC32' not in m.output
        if fault == 'many_gops': assert m.calls.count('GopQuery') == 8 and 'GOP08_' not in m.output
        if fault == 'many_images': assert m.calls.count('HandleProtocol') == 1026
        passed(fault)
    m = Machine('dc!q\r', 'no_gop'); assert m.run() == 0 and 'TEXT PAGE' in m.output
    passed('C_without_GOP_falls_back_to_text')
    m = Machine('q\r', 'input_not_ready'); assert m.run() == 0 and m.calls.count('WaitEvent') == 1
    passed('input_wait_event')
    for fault in ('input_error', 'output_error'):
        m = Machine(fault=fault); assert m.run() == ERR(7) and m.calls.count('Stall') == 1
        assert 'GopQuery' not in m.calls
        passed(fault + '_bounded')
    report = dict(image_sha256=hashlib.sha256((OUT / 'payload/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
                  all_passed=True, count=len(rows), cases=rows,
                  limits=['Synthetic UEFI service behavior cannot establish the target HERO firmware root cause.',
                          'Graphical capture is separately exercised in read-only optical OVMF boots.'])
    (OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('ALL PASS', len(rows), flush=True)

if __name__ == '__main__': main()
