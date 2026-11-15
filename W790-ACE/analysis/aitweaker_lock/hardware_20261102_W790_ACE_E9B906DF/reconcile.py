"""Reconcile the immutable P3 capture with publisher-verified W790 ACE 1904.

Static parsing only. Does not execute firmware, call firmware services, or
change the captured log. All addresses in derived output are module RVAs.
"""
from pathlib import Path
import collections
import hashlib
import json
import re
import struct
import sys
import uuid
import zlib

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parent.parent
sys.path[:0] = [str(ROOT / 'tools/pydeps'), str(BASE)]
import capstone
import pefile
from inspect_forms import QUESTIONS


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    raw = (HERE / 'AITWK-P3-W790-ACE-E9B906DF.TXT').read_bytes()
    manifest = json.loads((HERE / 'capture_manifest.json').read_text(encoding='utf-8'))
    assert len(raw) == manifest['bytes'] == 4582
    assert f'{zlib.crc32(raw):08X}' == manifest['crc32'] == 'E9B906DF'
    assert hashlib.sha256(raw).hexdigest() == manifest['sha256']
    log = raw.decode('ascii')
    meta = json.loads((HERE / 'module_metadata.json').read_text(encoding='utf-8'))
    inv = json.loads((BASE / 'official_W790_ACE_1904/W790_ACE_1904/inventory.json').read_text(encoding='utf-8'))
    modules = {m['guid']: m for m in inv['modules']}
    matches = {}
    for name, crc, rva, size, entry in re.findall(
        r'(Setup|AMITSE) text_crc32=0x([A-F0-9]+) text_rva=0x([A-F0-9]+) text_size=0x([A-F0-9]+) entry=0x([A-F0-9]+)', log
    ):
        expected = meta[name]
        values = {'text_crc32': crc, 'text_rva': hex(int(rva, 16)),
                  'text_size': hex(int(size, 16)), 'entry': hex(int(entry, 16))}
        checks = {k: values[k] == expected[k] for k in values}
        assert all(checks.values())
        matches[name] = {'runtime': values, 'static_sha256': expected['sha256'],
                         'field_matches': checks, 'all_fields_match': True}
    assert set(matches) == {'Setup', 'AMITSE'}

    owners = []
    for name, guid, rva in re.findall(r'((?:ConfigAccess|FormBrowser2)\.\w+) ([A-F0-9-]{36}) RVA=0x([A-F0-9]+)', log):
        mod = modules.get(guid)
        owners.append({'interface': name, 'owner_guid': guid,
                       'static_owner_name': mod.get('name') if mod else None,
                       'rva': hex(int(rva, 16)),
                       'owner_code_fingerprint_matched': guid in {meta['Setup']['guid'], meta['AMITSE']['guid']}})

    packs = json.loads((HERE / 'modules/Setup_IFR.json').read_text(encoding='utf-8'))
    recs = [r for p in packs for r in p['records']]
    forms = {r['form_id']: r for r in recs if r['op'] == 1}
    roots = [r for r in forms.values() if r.get('title') == 'Ai Tweaker']
    assert len(roots) == 1 and roots[0]['form_id'] == 0x2714
    refs = [r for r in recs if r['op'] == 15 and 'target_form' in r and not r.get('target_formset')]
    reached, todo = set(), [0x2714]
    while todo:
        f = todo.pop()
        if f in reached:
            continue
        reached.add(f)
        todo.extend(r['target_form'] for r in refs if r.get('form') == f and r['target_form'] in forms)
    questions = [r for r in recs if r['op'] in QUESTIONS and r.get('form') in reached]
    brief = {
        'root': roots[0],
        'formset_guid': next(r['guid'] for r in recs if r['op'] == 14),
        'total_static_forms': len(forms),
        'reachable_forms_by_local_ifr_ref': [{k: forms[f][k] for k in ('form_id', 'title', 'offset')} for f in sorted(reached)],
        'reachable_questions_count': len(questions),
        'question_varstores': dict(collections.Counter(r['varstore_id'] for r in questions)),
        'password_questions_in_all_setup_forms': [r for r in recs if r['op'] == 8],
        'password_questions_reachable_from_ai_tweaker': [r for r in questions if r['op'] == 8],
        'incoming_local_refs': [r for r in refs if r['target_form'] in reached and r.get('form') not in reached],
        'scope': 'Static local IFR REF reachability only; vendor top tabs, Favorites/search/profile flows are not proven by this graph.',
    }
    write_json(HERE / 'forms_1904.json', brief)

    # RVA 0x27d40 is the RIP-relative static dispatch table referenced by
    # the hardware-observed Setup Callback at 0x1534 (see 0x15b1..0x160b).
    setup_pe = pefile.PE(str(HERE / 'modules/Setup.efi'))
    dispatch = []
    for n in range(1000):
        entry = setup_pe.get_data(0x27d40 + n * 16, 16)
        assert len(entry) == 16
        flags, qid, pad, fn = struct.unpack('<IHHQ', entry)
        if not fn:
            break
        assert 0x2c0 <= fn < 0x2c0 + 0x2746f
        dispatch.append({'index': n, 'flags': hex(flags), 'question_id': hex(qid),
                         'reserved': pad, 'function_rva': hex(fn)})
    else:
        raise AssertionError('Static dispatch table terminator not reached')
    assert len(dispatch) == 945
    write_json(HERE / 'callback_dispatch_table.json', dispatch)

    guid_targets = {
        'AmiTseSetupEnterGuid': '71202eee-5f53-40d9-ab3d-9e0c26d96657',
        'FormBrowser2': 'b9d4c360-bcfb-4f9b-9298-53c136982258',
        'HiiConfigAccess': '330d4706-f2a0-4e4f-a369-b66fa8d54385',
    }
    indexes = {}
    for name in ('Setup', 'AMITSE', 'PasswordSupport'):
        data = (HERE / f'modules/{name}.efi').read_bytes()
        assert hashlib.sha256(data).hexdigest() == meta[name]['sha256']
        pe = pefile.PE(data=data)
        dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        dis.detail = True
        dis.skipdata = True
        xrefs, starts, lines = {}, {pe.OPTIONAL_HEADER.AddressOfEntryPoint}, []
        for sec in pe.sections:
            if not sec.Characteristics & 0x20000000:
                continue
            pad = True
            for ins in dis.disasm(sec.get_data(), sec.VirtualAddress):
                lines.append(f'{ins.address:08x}  {ins.mnemonic:8s} {ins.op_str}')
                if pad and ins.mnemonic != 'int3':
                    starts.add(ins.address)
                pad = ins.mnemonic == 'int3'
                if not ins.id:
                    continue
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                        target, kind = ins.address + ins.size + op.mem.disp, 'rip_relative'
                    elif ins.mnemonic in ('call', 'jmp') and op.type == capstone.x86.X86_OP_IMM:
                        target, kind = op.imm, ins.mnemonic
                        if kind == 'call':
                            starts.add(target)
                    else:
                        continue
                    xrefs.setdefault(hex(target), []).append({'rva': hex(ins.address), 'kind': kind,
                                                              'instruction': f'{ins.mnemonic} {ins.op_str}'})
        guids = []
        for label, guid in guid_targets.items():
            for match in re.finditer(re.escape(uuid.UUID(guid).bytes_le), data):
                rva = pe.get_rva_from_offset(match.start())
                guids.append({'name': label, 'guid': guid, 'rva': hex(rva), 'refs': xrefs.get(hex(rva), [])})
        result = {'coordinate_system': 'RVA, not physical address', 'sha256': meta[name]['sha256'],
                  'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                  'heuristic_function_starts': sorted(starts),
                  'boundary_limit': 'Padding/direct-call heuristics are not authoritative function boundaries.',
                  'refs': xrefs, 'target_guids': guids}
        write_json(HERE / f'modules/{name}_code_index.json', result)
        (HERE / f'modules/{name}_disassembly.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        indexes[name] = {'image_base': result['image_base'], 'guid_refs': guids}

    result = {
        'board': 'ASUS Pro WS W790-ACE', 'user_reported_version': '1904',
        'capture_integrity': {'pages': 6, 'bytes': len(raw), 'crc32': manifest['crc32'], 'sha256': manifest['sha256']},
        'official_zip_sha256': inv['package']['zip_sha256'],
        'publisher_hash_matches': inv['package']['official_zip_hash_match'],
        'runtime_module_matches': matches,
        'runtime_interface_owners': owners,
        'original_collection_status': 'PARTIAL',
        'original_warning_count': 5,
        'warning_explanation': [
            {'count': 2, 'cause': 'UNKNOWN_BUILD for Setup and AMITSE; 1904 absent from the original probe profiles',
             'offline_resolution': 'Both observed .text fingerprints match official 1904 exactly'},
            {'count': 1, 'cause': 'known_modules != 3 because neither of those profile lookups succeeded',
             'offline_resolution': 'Same version-profile mismatch; not a third missing module'},
            {'count': 1, 'cause': 'DBF338FE HII driver handle is NULL, even though status is EFI_SUCCESS',
             'offline_resolution': 'Still an inventory limitation'},
            {'count': 1, 'cause': '52B3B56E ConfigAccess returns EFI_UNSUPPORTED (0x8000000000000003)',
             'offline_resolution': 'Still an inventory limitation'},
        ],
        'static_guid_refs': indexes,
        'setup_callback_static_dispatch': {'table_rva': '0x27d40', 'entry_bytes': 16,
                                          'entries': len(dispatch),
                                          'unique_targets': len({x['function_rva'] for x in dispatch}),
                                          'ai_tweaker_entry_question_3_present': any(int(x['question_id'], 16) == 3 for x in dispatch),
                                          'limit': 'A separate dynamic list is also consulted; this table is not the entire callback population.'},
        'password_lock_implemented': False,
        'firmware_writes_performed': False,
        'hardware_scope': 'One W790-ACE 1904 P3 diagnostic capture only; no password or UI-hook validation.',
    }
    write_json(HERE / 'reconciliation.json', result)
    print(json.dumps({'matched_modules': list(matches), 'interface_entries': len(owners),
                      'forms': len(forms), 'ai_tweaker_reachable_forms': len(reached),
                      'ai_tweaker_questions': len(questions),
                      'ai_tweaker_password_controls': len(brief['password_questions_reachable_from_ai_tweaker']),
                      'setup_password_controls': len(brief['password_questions_in_all_setup_forms']),
                      'indexes': indexes}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
