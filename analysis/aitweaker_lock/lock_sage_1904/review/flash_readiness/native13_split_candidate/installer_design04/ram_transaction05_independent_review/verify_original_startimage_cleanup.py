"""Read-only native tail replay; never boots or invokes a firmware service."""
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
N13 = HERE.parent.parent
ROOT = next(p for p in HERE.parents if (p / 'tools' / 'pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'tools' / 'pydeps'))
import capstone
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

CORE = N13 / 'boot_context' / 'DxeCore.original.efi'
EXPECTED = 'd8684ae913fe44bfcb950c0635299465d7813b1f60407a733f7cce34e50f584d'
BASE, RECORD, STACK = 0x10000000, 0x20000000, 0x30000000
ERR7 = 0x8000000000000007


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def replay(status, image_type, handle):
    pe = pefile.PE(str(CORE))
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
    u.mem_map(BASE, size)
    u.mem_write(BASE, pe.get_memory_mapped_image())
    u.mem_map(RECORD, 0x1000)
    u.mem_map(STACK, 0x10000)

    def put64(a, x):
        u.mem_write(a, struct.pack('<Q', x))

    put64(RECORD + 8, handle)
    put64(RECORD + 0x10, image_type)
    put64(RECORD + 0x68, 0x40000000)  # embedded LoadedImage.ImageBase
    put64(RECORD + 0x88, 0x40000000)  # core-owned allocation base
    put64(RECORD + 0x90, 16)          # core-owned allocation pages
    put64(RECORD + 0xa8, status)
    # Empty core lists; helper services below are explicit host models.
    put64(BASE + 0x17c40, BASE + 0x17c40)
    put64(BASE + 0x17b48, 0)
    u.reg_write(UC_X86_REG_RBX, RECORD)
    u.reg_write(UC_X86_REG_RSP, STACK + 0x8008)
    calls, stopped = [], []

    def return_value(value):
        sp = u.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', u.mem_read(sp, 8))[0]
        u.reg_write(UC_X86_REG_RAX, value)
        u.reg_write(UC_X86_REG_RSP, sp + 8)
        u.reg_write(UC_X86_REG_RIP, ret)

    def on_code(uc, address, length, unused):
        rva = address - BASE
        if rva == 0x8957:
            stopped.append(True)
            uc.emu_stop()
            return
        if rva == 0x7e94:
            calls.append({'native': 'CoreUnloadAndCloseImage', 'rva': '0x7e94',
                          'record': uc.reg_read(UC_X86_REG_RCX),
                          'free_image_pages': uc.reg_read(UC_X86_REG_RDX) & 255})
            return  # Execute this exact original routine, not a stub.
        if rva == 0xacc8:
            calls.append({'model': 'LocateHandleBuffer', 'returns': 'EFI_NOT_FOUND'})
            return_value(0x800000000000000e)
        elif rva == 0x4d1c:
            guid = str(uuid.UUID(bytes_le=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RDX), 16))))
            calls.append({'model': 'UninstallProtocolInterface', 'guid': guid,
                          'interface': uc.reg_read(UC_X86_REG_R8)})
            return_value(0)
        elif rva == 0x7178:
            calls.append({'model': 'FreePages', 'base': uc.reg_read(UC_X86_REG_RCX),
                          'pages': uc.reg_read(UC_X86_REG_RDX)})
            return_value(0)
        elif rva == 0xbbe8:
            calls.append({'model': 'FreePool', 'buffer': uc.reg_read(UC_X86_REG_RCX)})
            return_value(0)

    u.hook_add(UC_HOOK_CODE, on_code)
    u.emu_start(BASE + 0x892b, BASE + size, count=10000)
    assert stopped and u.reg_read(UC_X86_REG_RAX) == status
    expected_cleanup = bool(status >> 63) or image_type == 0xa
    freed = any(c.get('model') == 'FreePool' and c.get('buffer') == RECORD for c in calls)
    assert freed == expected_cleanup
    uninstalled = any(c.get('guid') == '5b1b31a1-9562-11d2-8e3f-00a0c969723b'
                      and c.get('interface') == RECORD + 0x28 for c in calls)
    assert uninstalled == bool(expected_cleanup and handle)
    assert any(c.get('model') == 'FreePages' for c in calls) == expected_cleanup
    return {'status': hex(status), 'image_type': image_type, 'has_handle': bool(handle),
            'record_freed': freed, 'embedded_loaded_image_uninstalled': uninstalled,
            'returned_original_status': True, 'calls': calls, 'result': 'PASS'}


def main():
    assert sha(CORE) == EXPECTED
    pe = pefile.PE(str(CORE))
    assert pe.get_qword_at_rva(0x15e90 + 0x48) == 0xbbe8
    assert pe.get_qword_at_rva(0x15e90 + 0x30) == 0x7178
    assert pe.get_qword_at_rva(0x15e90 + 0x90) == 0x4d1c
    cases = [replay(status, kind, handle) for status, kind, handle in (
        (0, 0xb, 1), (ERR7, 0xb, 1), (0, 0xa, 1), (ERR7, 0xb, 0))]
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    asm = []
    for start, end in ((0x892b, 0x8957), (0x7e94, 0x81b9)):
        asm.append(f'RVA {start:#x}..{end:#x}')
        asm.extend(f'{i.address:08x}  {i.bytes.hex():28s} {i.mnemonic} {i.op_str}'
                   for i in cs.disasm(pe.get_data(start, end-start), start))
    assembly = HERE / 'original_startimage_cleanup.asm.txt'
    assembly.write_text('\n'.join(asm) + '\n', encoding='utf-8')
    result = {
        'status': 'PASS', 'native_cases': len(cases), 'input': str(CORE), 'input_sha256': EXPECTED,
        'script_sha256': sha(Path(__file__)), 'assembly_sha256': sha(assembly),
        'scope': 'Original 1904 StartImage post-entry status branch and original unload routine; EFI allocation/protocol helper effects modeled, no image entry or firmware executed.',
        'facts': {
            'error_branch_rva': '0x8935', 'cleanup_call_rva': '0x8943',
            'loaded_image_protocol_embedded_at_private_record_offset': '0x28',
            'loaded_image_uninstall_call_rva': '0x80f4',
            'record_freepool_tail_rva': '0x81b4',
            'bs_table_rva': '0x15e90',
            'freepool_slot': '0x48 -> 0xbbe8', 'freepages_slot': '0x30 -> 0x7178',
            'uninstallprotocol_slot': '0x90 -> 0x4d1c',
        },
        'conclusion': 'An EFI_ERROR from the provider entry makes the original Core uninstall and free its embedded LoadedImage metadata. Adapter rollback must use its own cached validated image span and must not dereference the former interface pointer.',
        'limits': ['A bounded post-entry path replay, not complete Core loader or physical hardware validation.',
                   'UEFI helper calls are recorded models; no allocation or protocol database on a real system was changed.'],
        'cases': cases,
    }
    out = HERE / 'original_startimage_error_cleanup.json'
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'PASS', 'cases': len(cases), 'result_sha256': sha(out)}))


if __name__ == '__main__':
    main()
