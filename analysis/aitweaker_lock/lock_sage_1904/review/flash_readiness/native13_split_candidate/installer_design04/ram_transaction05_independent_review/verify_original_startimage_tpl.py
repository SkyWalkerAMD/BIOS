"""Original Core save/restore-TPL excerpts; no firmware or device execution."""
from pathlib import Path
import hashlib
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
import capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

CORE = HERE.parent.parent / 'boot_context/DxeCore.original.efi'
EXPECTED = 'd8684ae913fe44bfcb950c0635299465d7813b1f60407a733f7cce34e50f584d'
BASE, RECORD, STACK = 0x10000000, 0x20000000, 0x30000000
q = lambda x: struct.pack('<Q', x)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    assert sha(CORE) == EXPECTED
    pe = pefile.PE(str(CORE))
    assert pe.get_qword_at_rva(0x15e90 + 0x20) == 0xcc98
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ranges = [(0x880c, 0x882d), (0x88af, 0x88d5)]
    listing = '\n'.join(f'{i.address:05x}: {i.bytes.hex():26s} {i.mnemonic} {i.op_str}'
                        for start, end in ranges for i in cs.disasm(pe.get_data(start, end-start), start))
    assembly = HERE / 'original_startimage_tpl_restore.asm.txt'
    assembly.write_text(listing + '\n', encoding='utf-8')
    cases = []
    for entry_tpl in (4, 8, 31):
        u = Uc(UC_ARCH_X86, UC_MODE_64)
        u.mem_map(BASE, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        u.mem_write(BASE, pe.get_memory_mapped_image())
        u.mem_map(RECORD, 0x1000)
        u.mem_map(STACK, 0x10000)
        u.mem_write(BASE + 0x16b30, q(entry_tpl))
        u.reg_write(UC_X86_REG_RBX, RECORD)
        u.reg_write(UC_X86_REG_RSP, STACK + 0x8008)
        calls = []
        def stop_or_restore(uc, address, size, unused):
            if address == BASE + 0xcc98:
                calls.append(uc.reg_read(UC_X86_REG_RCX))
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop_or_restore)
        u.emu_start(BASE + 0x880c, BASE + 0x882d, count=100)
        saved = struct.unpack('<Q', u.mem_read(RECORD + 0xa0, 8))[0]
        assert saved == entry_tpl
        u.mem_write(BASE + 0x16b30, q(31))  # simulated callee returns at higher TPL
        u.emu_start(BASE + 0x88c9, BASE + 0x88d5, count=100)
        assert calls == [entry_tpl]
        cases.append({'entry_tpl': entry_tpl, 'saved_in_image_record': saved,
                      'shared_post_entry_block_calls_restore_tpl_with': calls[0], 'status': 'PASS'})
    result = {
        'status': 'PASS_ORIGINAL_CORE_NATIVE_EXCERPTS', 'cases': cases,
        'original_core_sha256': EXPECTED, 'script_sha256': sha(Path(__file__)),
        'assembly_sha256': sha(assembly),
        'facts': {
            'current_tpl_rva': '0x16b30', 'save_from_global_rva': '0x880c',
            'image_private_saved_tpl_offset': '0xa0', 'save_to_record_rva': '0x8826',
            'post_entry_shared_restore_argument_rva': '0x88c9',
            'unconditional_restore_call_rva': '0x88d0',
            'restore_function_and_boot_services_slot': '0xcc98 == BootServices[0x20]',
        },
        'conclusion': 'The exact original Core saves the calling TPL and its shared post-entry return block unconditionally invokes RestoreTPL with that saved value before subsequent cleanup. This is concrete support for the standard StartImage caller-TPL contract in the pinned Core.',
        'limits': [
            'The three cases execute two exact instruction excerpts; the entry, Exit/longjmp and the RestoreTPL implementation itself are not executed here.',
            'No blanket claim is made for arbitrary OEM SendForm/protocol callbacks, pre-entry allocation failures, all firmware services, or hostile service-table replacement.',
            'Application and provider ending checks are separately required after every service boundary.',
        ],
    }
    out = HERE / 'original_startimage_tpl_restore.json'
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'checks': len(cases), 'sha256': sha(out)}))

if __name__ == '__main__': main()
