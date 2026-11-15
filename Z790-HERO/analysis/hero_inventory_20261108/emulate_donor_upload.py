"""Offline-only execution of Creator's real inventory multipart/PATCH builder.

Every firmware service and transport boundary is stubbed. No host/BMC network
operation is possible. The target PE remains immutable; output is protocol
evidence under this investigation directory.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

TARGET = ROOT / 'analysis/hero_remote_bios_r3/reference/AB78D6A5-7E2A-47AA-9F32-780793C0DADB.efi'
EXPECTED = 'e1fd4b36c4bf60386b06d1b8fbe8c323735f1c1c110c2cb6ac0bf6e75df7d4b4'
IMAGE = 0x100000
HEAP = 0x400000
STACK = 0x700000
END = 0x900000
FREE = END + 0x100


def run(payload, finish=False, legacy_patch_uri=None, legacy_post_uri=None):
    assert not (legacy_patch_uri and legacy_post_uri)
    legacy_uri = legacy_patch_uri or legacy_post_uri
    raw = TARGET.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    pe = pefile.PE(data=raw)
    vm = Uc(UC_ARCH_X86, UC_MODE_64)
    vm.mem_map(IMAGE, 0x30000)
    vm.mem_write(IMAGE, pe.get_memory_mapped_image())
    vm.mem_map(HEAP, 0x200000)
    vm.mem_map(STACK, 0x10000)
    vm.mem_map(END, 0x1000)
    alloc = HEAP + 0x10000
    headers = {}
    requests = []
    calls = []

    def q(addr):
        return struct.unpack('<Q', bytes(vm.mem_read(addr, 8)))[0]

    def cstr(addr, wide=False):
        b = bytearray()
        size = 2 if wide else 1
        for n in range(8192):
            v = bytes(vm.mem_read(addr + n * size, size))
            if v == b'\0' * size:
                return b.decode('utf-16le' if wide else 'ascii')
            b.extend(v)
        raise AssertionError('unterminated string')

    def return_to_caller(result=0):
        sp = vm.reg_read(UC_X86_REG_RSP)
        vm.reg_write(UC_X86_REG_RAX, result)
        vm.reg_write(UC_X86_REG_RSP, sp + 8)
        vm.reg_write(UC_X86_REG_RIP, q(sp))

    def hook(vm, address, size, _):
        nonlocal alloc
        if address == END:
            vm.emu_stop()
            return
        if address == FREE:
            calls.append('FreePool')
            return_to_caller()
            return
        rva = address - IMAGE
        if rva not in (0x1888C, 0x18950, 0x15AD4, 0x15C2C, 0x18A80, 0x188D4, 0x280, 0x1784C):
            return
        a, b, c, d = [vm.reg_read(r) for r in (UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9)]
        calls.append(hex(rva))
        if rva == 0x1784C:  # cJSON serialization supplied by the already-validated offline composer
            assert legacy_patch_uri is not None
            return_to_caller(HEAP)
            return
        if rva == 0x1888C:  # header container initialization
            vm.mem_write(a + 8, struct.pack('<Q', HEAP + 0x8000))
        elif rva == 0x18950:
            headers[cstr(b)] = cstr(c)
        elif rva == 0x15AD4:
            p = alloc
            alloc += (a + 31) & ~31
            assert alloc < HEAP + 0x200000
            vm.mem_write(p, b'\0' * a)
            return_to_caller(p)
            return
        elif rva == 0x15C2C:
            assert cstr(c) == '%d'
            value = str(d).encode() + b'\0'
            assert len(value) <= b
            vm.mem_write(a, value)
        elif rva == 0x280:
            vm.mem_write(a, bytes(vm.mem_read(b, c)))
        elif rva == 0x18A80:
            sp = vm.reg_read(UC_X86_REG_RSP)
            body = q(sp + 0x28)
            status = q(sp + 0x48)
            n = int(headers['Content-Length'])
            requests.append({'uefi_method': b, 'uri': cstr(c, True),
                             'headers': dict(headers), 'body': bytes(vm.mem_read(body, n)).decode(),
                             'body_length': n})
            vm.mem_write(status, struct.pack('<I', 3))  # EFI_HTTP_STATUS_200_OK
        return_to_caller()

    vm.mem_write(IMAGE + 0x1E070, struct.pack('<Q', HEAP + 0x1000))
    vm.mem_write(HEAP + 0x1048, struct.pack('<Q', FREE))
    data = payload.encode('utf8')
    vm.mem_write(HEAP, data + b'\0')
    sp = STACK + 0xF000 - 8
    vm.mem_write(sp, struct.pack('<Q', END))
    vm.reg_write(UC_X86_REG_RSP, sp)
    vm.reg_write(UC_X86_REG_RCX, HEAP + 0x2000)
    if legacy_uri is not None:
        vm.mem_write(HEAP + 0x6000, (legacy_uri + '\0').encode('utf-16le'))
        vm.reg_write(UC_X86_REG_RDX, HEAP + 0x6000)
        vm.reg_write(UC_X86_REG_R8, HEAP + 0x7000 if legacy_patch_uri else HEAP)
    else:
        vm.reg_write(UC_X86_REG_RDX, HEAP)
        vm.reg_write(UC_X86_REG_R8, len(data))
    vm.reg_write(UC_X86_REG_R9, len(data) if legacy_post_uri else int(finish))
    vm.hook_add(UC_HOOK_CODE, hook)
    entry = 0x3428 if legacy_patch_uri else 0x19384 if legacy_post_uri else 0x24D4
    vm.emu_start(IMAGE + entry, END, count=100000)
    assert vm.reg_read(UC_X86_REG_RAX) == 0
    assert len(requests) == 1
    req = requests[0]
    assert req['body_length'] == len(req['body'].encode('utf8'))
    assert req['uri'] == (legacy_uri or '/redfish/v1/Oem/Ami/InventoryData')
    assert req['uefi_method'] == (2 if finish or legacy_patch_uri is not None else 1)
    return {'request': req, 'stubbed_calls': calls}


def main():
    minimal = '{"GroupCrcList":{},"RedfishVersion":"1.8.0","RtpVersion":"1.8.a","Systems":[{}],"Chassis":[{}]}'
    upload = run(minimal)
    finish = run('{"BootComplete":true}', True)
    legacy = run('{"BiosVersion":"OFFLINE-SYNTHETIC"}', legacy_patch_uri='/redfish/v1/Systems/Self')
    legacy_post = run('{"Id":"OFFLINE-SYNTHETIC"}', legacy_post_uri='/redfish/v1/Systems/Self/Processors')
    prefix = ('------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n'
              'Content-Disposition: form-data; name="static_file"; filename="inventory.json"\r\n'
              'Content-Type: application/xml;charset=utf-16\r\n\r\n')
    suffix = '\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n'
    assert upload['request']['body'] == prefix + minimal + suffix
    assert finish['request']['body'] == '{"BootComplete":true}'
    assert legacy['request']['headers']['OData-Version'] == '4.0'
    result = {'mode': 'offline-native-emulation-stubbed-transport', 'target_sha256': EXPECTED,
              'entry_rva': ['0x24d4', '0x3428', '0x19384'], 'tests_passed': 4,
              'scope': 'Validates donor request envelope only; no BMC parser acceptance is asserted.',
              'multipart': upload, 'boot_complete': finish, 'legacy_patch': legacy, 'legacy_post': legacy_post}
    p = BASE / 'donor-upload-emulation.json'
    p.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'tests_passed': 4, 'multipart_bytes': upload['request']['body_length'],
                      'boot_complete_bytes': finish['request']['body_length']}))


if __name__ == '__main__':
    main()
