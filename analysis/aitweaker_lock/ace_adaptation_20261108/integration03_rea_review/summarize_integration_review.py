"""Evidence ledger for the independent ACE integration review."""
import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile

sha = lambda data: hashlib.sha256(data).hexdigest()


def read(directory, label):
    path = directory / 'responses' / (label + '.json')
    document = json.loads(path.read_text(encoding='utf-8'))
    assert 'error' not in document
    result = document['result']
    assert not result.get('isError')
    content = result.get('structuredContent')
    if content is None:
        content = json.loads(next(c['text'] for c in result['content'] if c['type'] == 'text'))
    return content, path


def ledger(directory, labels, byte_labels, close_label):
    provenance = json.loads((directory / 'provenance.json').read_text())
    target = Path(provenance['target'])
    source = target.read_bytes()
    digest = sha(source)
    assert digest == provenance['target_sha256']
    mapped = pefile.PE(data=source).get_memory_mapped_image()
    functions, reads = [], []
    for label in labels:
        ev, path = read(directory, label)
        result = ev['normalized_result']
        assert ev['subject']['digest']['sha256'] == digest
        (directory / (label + '.c')).write_text(result['pseudocode'], encoding='utf-8')
        functions.append({'response': str(path.relative_to(HERE)), 'response_sha256': sha(path.read_bytes()),
                          'evidence_id': ev['evidence_id'], 'procedure': result['procedure'],
                          'provider': ev['provider'], 'analysis_profile_digest': ev['analysis_profile']['digest'],
                          'canonical_seed_sha256': ev['analysis_profile']['parameters']['analysis_seeds']['sha256'],
                          'relationship_coverage': ev['relationship_coverage'], 'limitations': ev['limitations']})
    for label in byte_labels:
        ev, path = read(directory, label)
        result = ev['normalized_result']
        start = int(result['address'], 16)
        data = bytes.fromhex(result['bytes_hex'])
        assert result['complete'] and data == mapped[start:start+len(data)]
        reads.append({'response': str(path.relative_to(HERE)), 'evidence_id': ev['evidence_id'],
                      'rva': result['address'], 'bytes': len(data), 'sha256': sha(data),
                      'equals_original_mapped_PE': True})
    close, close_path = read(directory, close_label)
    seed = Path(provenance['seed_path'])
    assert sha(seed.read_bytes()) == provenance['seed_sha256']
    canonical = '\n'.join(line for line in seed.read_text().splitlines() if line.strip() and not line.startswith('#')) + '\n'
    assert sha(canonical.encode()) == functions[0]['canonical_seed_sha256']
    return {'target': {'path': str(target), 'sha256': digest, 'bytes': len(source)},
            'provenance': str((directory / 'provenance.json').relative_to(HERE)),
            'functions': functions, 'read_bytes_verified': reads,
            'seed_identity': {'raw_file_sha256': provenance['seed_sha256'],
                              'raw_scope': 'Full seeds.tsv file bytes including comments',
                              'canonical_sha256': sha(canonical.encode()),
                              'canonical_scope': 'Effective TSV rows with LF and final LF; comments/blank lines removed'},
            'close': {'response': str(close_path.relative_to(HERE)), 'result': close,
                      'response_sha256': sha(close_path.read_bytes()), 'owned_process_exit': 0}}


def main():
    tse_ledger = ledger(HERE,
        ['002-protocol-installer', '003-boot-manager', '004-save-iterator', '005-variable-commit',
         '006-f10-save-exit', '007-vendor-initializer', '008-save-stay'],
        ['009-loop-stage4-bytes', '010-save-loop-bytes'], '012-close')
    core_ledger = ledger(HERE / 'core_rea',
        ['002-exit-boot-services', '003-notify-signal-list', '004-create-event-ex', '005-restore-tpl'],
        ['006-ebs-bytes'], '008-close')
    inventory = json.loads((HERE / 'ace_original_module_inventory.json').read_text())
    mapped = {}
    for key in ('AMITSE', 'OriginalBds', 'OriginalDxeCore'):
        source = ROOT / inventory['selected'][key]
        mapped[key] = pefile.PE(str(source)).get_memory_mapped_image()
    tse, bds = mapped['AMITSE'], mapped['OriginalBds']
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    ranges = {}
    for module, name, start, end in (
        ('AMITSE', 'ProtocolInstaller', 0x2624, 0x272b),
        ('AMITSE', 'BootManagerSetupCall', 0x2b21, 0x2b6d),
        ('AMITSE', 'BrowserStage4', 0xe208, 0xe27d),
        ('AMITSE', 'BrowserStage5', 0xe6a5, 0xe6b0),
        ('OriginalBds', 'DispatchTableLoop', 0x2817, 0x283f),
        ('OriginalBds', 'EndOfDxeHandler', 0x194c, 0x19e0),
        ('OriginalBds', 'BootManagerCall', 0x269c, 0x26c9),
    ):
        ranges[name] = {'module': module, 'start': hex(start), 'end_exclusive': hex(end),
                        'bytes_sha256': sha(mapped[module][start:end]),
                        'instructions': [{'rva': hex(i.address), 'bytes': i.bytes.hex(),
                                          'instruction': i.mnemonic + ' ' + i.op_str}
                                         for i in cs.disasm(mapped[module][start:end], start)]}
    table = []
    for index in range(256):
        value = struct.unpack_from('<Q', bds, 0x1b8c0 + index*8)[0]
        if not value:
            break
        table.append(hex(value))
    assert len(table) == 67 and table.index('0x194c') == 9 and table.index('0x25ec') == 65
    slots = []
    for rva, expected in ((0x6ab40, 0x2780), (0x6b528, 0x20f34), (0x6b530, 0x2168c)):
        value = struct.unpack_from('<Q', tse, rva)[0]
        assert value == expected
        slots.append({'slot': hex(rva), 'value': hex(value), 'bytes': tse[rva:rva+8].hex()})
    guids = []
    for module, rva, expected in (
        ('AMITSE', 0x6a780, '8a91b1e1-56c7-4adc-abeb-1c2ca1729eff'),
        ('AMITSE', 0x6a8c0, 'b9d4c360-bcfb-4f9b-9298-53c136982258'),
        ('OriginalBds', 0x1a810, '02ce967a-dd7e-4ffc-9ee7-810cf0470880'),
        ('OriginalBds', 0x1a9f8, '8a91b1e1-56c7-4adc-abeb-1c2ca1729eff'),
    ):
        assert mapped[module][rva:rva+16] == uuid.UUID(expected).bytes_le
        guids.append({'module': module, 'rva': hex(rva), 'guid': expected})
    source_snapshot = []
    for name in ('entry.c', 'platform.c', 'services.c'):
        path = HERE.parent / 'lock_1904_integrated03/driver' / name
        data = path.read_bytes()
        source_snapshot.append({'path': str(path), 'sha256_at_review': sha(data),
                                'line_count': len(data.splitlines()), 'not_modified': True})
    attach = {
        'status': 'STATIC_ACE_ENTRY_TIMING_REVIEW',
        'original_BDS_sha256': sha((ROOT / inventory['selected']['OriginalBds']).read_bytes()),
        'protocol_slots': slots, 'guid_literals': guids,
        'bds_dispatch': {'table_rva': '0x1b8c0', 'entry_count': 67, 'entries': table,
                         'end_of_dxe_handler_index': 9, 'boot_manager_handler_index': 65,
                         'qualification': 'Original normal BDS table order, not a guarantee about every OEM path or driver success'},
        'source_snapshot': source_snapshot,
        'observations': [
            'ProtocolInstaller at 0x2624 publishes exact FormBrowser2 interface 0x6b528 with methods 0x20f34 and 0x2168c.',
            'BootManager at 0x2b48 writes stage4 and then calls BrowserLoop at 0x2b65 -> 0xe208.',
            'BrowserLoop writes stage4 itself at 0xe232 and calls InstallMultipleProtocolInterfaces at 0xe277 before stage5 at 0xe6a5.',
            'Thus a stage4 notification can run after the original BrowserLoop prologue has already executed; stage4 alone does not establish ownership of that invocation.',
            'The reviewed current discovery source waits for exact ACE-owned FormBrowser2 methods and allows three pre-publication attach attempts; after publication_attempted it is terminal.',
            'The reviewed current gate code continues denying protected callbacks without loop ownership; only the real BrowserLoop wrapper opens an authentication session.',
        ],
        'recommendations': [
            'Keep retries limited to verified pre-publication failures. Never clear attempted after a possible code/pointer publication.',
            'Do not fabricate a browser session from stage4 or stage5 observations; a late invocation must remain unauthenticated until the next actual wrapped entry.',
            'Use normal EndOfDxe/FormBrowser2 readiness to improve first-entry attachment, while retaining the distinction between expected ordering and guaranteed driver success.',
            'For guaranteed protection when the optional DXE is missing or never loads, a separate permanently resident selective original-module guard is required. Dynamic discovery alone cannot establish that property.',
            'Do not blanket-block BootManager/BDS to solve missing-provider protection; preserve ordinary boot and verified unrelated UI.',
        ],
        'unknowns': ['Actual first Del/F2 initialization timing and every early/OEM alternate entry are not observed by this local static review.',
                     'SAGE cold-entry native patch design is guidance, not an accepted ACE binary port.',
                     'Pre-publication retry safety does not prove every rollback or page-attribute restoration under arbitrary firmware callbacks.'],
        'disassembly': ranges,
    }
    (HERE / 'ace_attach_entry_review.json').write_text(json.dumps(attach, indent=2) + '\n')
    core_support = json.loads((HERE / 'ace_before_exit_core_support.json').read_text())
    save_design = json.loads((HERE / 'ace_save_hook_design.json').read_text())
    report = {
        'status': 'PASS_STATIC_REA_AND_BOUNDED_ORIGINAL_NATIVE_REVIEW',
        'classification': 'ACE1904_ORIGINAL_BYTES_NOT_HARDWARE_ACCEPTANCE',
        'ownership': {'output_directory': str(HERE), 'production_files_changed': False, 'device_access': False},
        'rea_runtime': {'version': '6.8.0', 'provider': 'Ghidra 12.1.4',
                        'execution_scope': 'Two local stdio analysis sessions; scoped local loopback permission for the Windows Ghidra bridge',
                        'sessions_closed': True},
        'amitse_session': tse_ledger, 'dxe_core_session': core_ledger,
        'entry_review': {'path': 'ace_attach_entry_review.json', 'sha256': sha((HERE / 'ace_attach_entry_review.json').read_bytes())},
        'core_support': {'path': 'ace_before_exit_core_support.json', 'status': core_support['status'],
                         'sha256': sha((HERE / 'ace_before_exit_core_support.json').read_bytes()),
                         'cases': len(core_support['native_emulation_cases']), 'event_registrations': 15},
        'save_design': {'path': 'ace_save_hook_design.json', 'status': save_design['status'],
                        'sha256': sha((HERE / 'ace_save_hook_design.json').read_bytes()),
                        'caller_branch_cases': 8, 'native_commit_tail_cases': 3,
                        'production_implementation': False},
        'observations': [
            'ACE and SAGE DxeCore whole-file hashes differ; fresh ACE REA and native replay independently establish BeforeExit double dispatch and retry semantics.',
            'ACE FormBrowser2 interface identity and stage4-inside-loop possibility are corroborated by original machine instructions and new REA.',
            'ACE SaveIterator ignores the return of VariableCommit and sets AL true after the normal tail; all three explicitly supplied per-variable statuses produced true.',
            'Original F10, SaveExit and SaveReset callers do not request exit/reset when the supplied common-save AL is false.',
            'Original SaveStay still clears state byte 0x82738 on false; common-save feedback alone does not fix its complete UI state.',
            'Original vendor initialization calls the same SaveIterator and must remain permitted to run under existing selective write policy.',
        ],
        'inferences': [
            'The minimum next experimental feedback change can wrap one common SaveIterator entry and record explicit existing-guard denials; a second native commit hook is optional for broader backend-error aggregation.',
            'Actual installed callback denial without ownership plus early successful discovery can protect known late attachment cases, but optional-DXE absence requires a separate native guard architecture.',
        ],
        'unknowns': [
            'No new integrated production save wrapper has been built or accepted by this report.',
            'Bounded original-native fixtures are not a full ASUS UI, physical hardware, firmware deployment, persistence or rollback test.',
            'All static indirect-call coverage and seed-name limitations remain in the full REA Evidence responses.',
            'A false save result cannot undo unrelated writes or OEM post-save side effects already performed.',
        ],
    }
    out = HERE / 'integration03_review_summary.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'output': str(out), 'sha256': sha(out.read_bytes()),
                      'function_evidence_records': len(tse_ledger['functions']) + len(core_ledger['functions']),
                      'bytes_compared': sum(r['bytes'] for r in tse_ledger['read_bytes_verified'] + core_ledger['read_bytes_verified']),
                      'sessions_closed': True}, indent=2))


if __name__ == '__main__':
    main()
