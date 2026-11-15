"""Recreate local-only source, dispatch, field, and default I/O evidence."""
from pathlib import Path
import hashlib
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'analysis'))
from bmc_arm_inspect import Elf32


def source(path):
    data = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def cstr(elf, va):
    return elf.read(va, 256).split(b'\0')[0].decode('ascii')


def main():
    selected = ROOT / 'analysis/bmc_1_3_13_official/selected-rootfs'
    paths = {
        'rest': selected / 'usr/local/bin/spx_restservice',
        'getter': selected / 'usr/local/lib/libipmi.so.13.10.0',
        'oem': selected / 'usr/local/lib/libipmipdkcmds.so.13.0.0',
        'pdk': selected / 'usr/local/lib/libipmipdk.so.13.8.0',
        'stack': selected / 'usr/local/lib/libipmistack.so.13.13.0',
        'api': HERE / 'extracted/libipmipdkapi.so.13.1.0',
    }
    elfs = {k: Elf32(p) for k, p in paths.items()}
    functions = {
        'rest': ['getInformation_func'],
        'getter': ['LIBIPMI_HL_Get_BIOSINFO'],
        'oem': ['PDKGetOEMMsgHndlrMap', 'PDK_GetNetFnHndlr',
                'Oemreaddmiinfo', 'Oemwritedmiinfo'],
        'stack': ['ReadWriteNVR', 'InitPDKHooks', 'GetPDK_Path'],
        'api': ['API_ReadNVR', 'API_WriteNVR'],
    }
    symbol_evidence = []
    for lib, names in functions.items():
        for name in names:
            s = elfs[lib].byname[name]
            output = HERE / (name + '.arm.txt')
            output.write_text(elfs[lib].disasm(name), encoding='utf-8')
            symbol_evidence.append({'library': lib, 'name': name,
                                    'va': hex(s['value']), 'bytes': s['size'],
                                    'disassembly': str(output.relative_to(ROOT))})
    e = elfs['oem']
    assert e.byname['oem_MsgHndlrTbl']['value'] == 0x160b0
    assert struct.unpack('<I', e.read(0x160f0, 4))[0] == 0x30
    assert e.relocs[0x160f4]['symbol'] == 'g_ASUS_OEM_CmdHndlr'
    command_rows = []
    for va, command, name in [(0x2a644, 3, 'Oemreaddmiinfo'), (0x2a654, 4, 'Oemwritedmiinfo')]:
        row = e.read(va, 16)
        assert row[0] == command
        assert e.relocs[va + 4]['symbol'] == name
        command_rows.append({'command': command, 'record_va': hex(va), 'bytes_hex': row.hex(),
                             'handler_relocation': e.relocs[va + 4]})
    selector_paths = {str(i): cstr(e, va) for i, va in enumerate([0x17378, 0x1738c, 0x173a0])}
    assert selector_paths == {'0': '/conf/biosinfo.fru', '1': '/conf/sysinfo.fru', '2': '/conf/mbinfo.fru'}
    field_names = {hex(va): cstr(elfs['rest'], va) for va in [0x156e5c, 0x156e68, 0x156e74, 0x156e80]}
    init = elfs['stack'].byname['g_PDKInitialize']
    found = []
    for off in range(0, init['size'], 258):
        row = elfs['stack'].read(init['value'] + off, 258)
        if row[2:].split(b'\0')[0] == b'PDK_ReadWriteNVR':
            index = struct.unpack('<H', row[:2])[0]
            assert index == 198
            found.append({'record_va': hex(init['value'] + off), 'index': index,
                          'handle_byte_offset': hex(index * 4), 'symbol': 'PDK_ReadWriteNVR'})
    assert len(found) == 1
    assert 'PDK_ReadWriteNVR' not in elfs['pdk'].byname
    out = {
        'scope': 'OFFLINE_OFFICIAL_BMC_1_3_13_STATIC_EVIDENCE',
        'method': 'ELF symbol/relocation parsing and Capstone ARM disassembly; bounded Unicorn emulation in separate report',
        'rea_limitation': 'Existing REA Windows backend rejects this ARM ELF; no REA decompilation claimed for these ARM files',
        'sources': {k: source(p) for k, p in paths.items()},
        'symbols': symbol_evidence,
        'dispatch': {'netfn': 48, 'netfn_record_va': '0x160f0',
                     'handler_table_relocation_va': '0x160f4', 'commands': command_rows},
        'selector_paths': selector_paths,
        'request': {
            'read_cmd03': {'length': 4, 'fields': ['selector', 'offset low byte', 'offset high byte', 'requested count'],
                           'success_data': 'count byte then that many bytes; IPMI completion byte is separate'},
            'write_cmd04': {'fields': ['selector', 'file prefix bytes'], 'offset': 0,
                            'length_calculation': '(request_length - 1) & 0xffff',
                            'success_data': 'written byte count modulo 256; require exact small expected length',
                            'request_max': 'No explicit bound in handler. Overall LAN/message-layer maximum is not established here.',
                            'empty_request': 'unsafe length underflow; must reject in caller'},
        },
        'rest_getter': {
            'json_field_literals': field_names,
            'version': 'copies file bytes [0:5] into output+0',
            'date': 'copies file bytes [5:16] into output+32',
            'model': 'for a well-formed string list, the second NUL-terminated string in first 255 bytes of mbinfo into output+64',
            'valid': 'getter return0 sets BIOSVaild1; file existence/readability alone is not semantic validity',
            'empty_mbinfo': 'emulated: returns empty model safely; earlier preliminary underflow inference corrected',
            'malformed': 'full 255-byte buffer with first NUL but no terminating NUL for second string may underflow copy length',
        },
        'default_nvr': {
            'read': 'O_RDONLY first; on open failure falls back to O_RDWR|O_CREAT(0x42), so missing file can be created empty',
            'write': 'O_RDWR|O_CREAT(0x42), lseek(offset), one write, close; existing tail is retained',
            'no_truncate': True, 'no_fsync_in_function': True, 'no_automatic_short_write_retry': True,
            'hook': found[0], 'official_pdk_defines_hook': False,
            'runtime_limit': 'Official image/default config checked, not a dump of the running process or persistence test',
        },
    }
    (HERE / 'backend-protocol-evidence.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    # Correct an early exploratory filename: 0x2168 is an API library PLT stub,
    # not a standalone NVR implementation.
    (HERE / 'NVR-file-io.arm.txt').write_text(
        'Correction: libipmipdkapi VA0x2168 is a PLT stub for ReadWriteNVR.\n'
        'ARM immediate decoding resolves GOT0x1707C, R_ARM_JUMP_SLOT ReadWriteNVR.\n'
        'Actual implementation: libipmistack ReadWriteNVR VA0xBEE8; see ReadWriteNVR.arm.txt.\n', encoding='utf-8')
    print('OEM 0x30/0x03 + 0x30/0x04 dispatch and REST fields verified:', field_names)


if __name__ == '__main__':
    main()
