"""Read-only independent replay of frozen sampler DLL and diagnostic decoder.

Outputs only in this review directory. It does not rebuild or edit its subject.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
SUBJECT = BASE / 'spf_sampler06'
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))


def binding(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wire(record):
    return struct.pack('<5Q3IQ3HI', *record.values())


def main():
    inputs = [SUBJECT / n for n in ('sampler.c', 'sampler.h', 'build.py',
              'verify.py', 'decode.py', 'build/build.json', 'build/tests.json',
              'build/spf_sampler_test.dll')]
    before = [binding(p) for p in inputs]
    original = json.loads((SUBJECT / 'build/tests.json').read_text())
    build = json.loads((SUBJECT / 'build/build.json').read_text())
    assert original['dll_sha256'] == before[-1]['sha256'] == build['dll_sha256']
    assert original['passed'] and original['count'] == len(original['checks'])
    for name, digest in build['sources'].items():
        assert binding(SUBJECT / 'source' / name)['sha256'] == digest
        if name in ('sampler.c', 'sampler.h'):
            assert binding(SUBJECT / name)['sha256'] == digest
    for item in build['inputs']:
        assert binding(item['path'])['sha256'] == item['sha256']
    verifier = load('s7_subject_verifier', SUBJECT / 'verify.py')
    decoder = load('s7_subject_decoder', SUBJECT / 'decode.py')
    for case in original['checks']:
        verifier.one(case['case'], int(case['base'], 16))
    assert json.loads(json.dumps(verifier.checks)) == original['checks'], 'Replay differs from subject report'

    checks = []
    decoded_cases = []
    for case in verifier.checks:
        a, b = wire(case['a']), wire(case['b'])
        result = decoder.decode_pair(a, b)
        assert result['authorization'] is False
        assert result['observations_equal'] == (a == b)
        for slot in ('a', 'b'):
            for i, key in enumerate(decoder.FIELDS):
                assert result[slot]['fields'][key] == (
                    case[slot][key] if case[slot]['status_mask'] & (1 << i) else None)
        if case['case'] == 'candidate_nonzero':
            assert 'computed_guid_read_relative_only' not in result['a']['derived']
        if case['case'] in ('normal', 'candidate_low_zero'):
            assert result['a']['derived']['computed_guid_read_relative_only'] == 0xf4ce6
            assert not result['a']['derived']['computed_guid_read_within_declared_size']
            assert not result['a']['derived']['computed_address_was_dereferenced']
        if case['case'] == 'header_parent_nonzero':
            assert result['a']['derived']['known_header_would_skip_guid_read']
            assert 'computed_guid_read_relative_only' not in result['a']['derived']
        decoded_cases.append({'case': case['case'], 'base': case['base'],
                              'equal': result['observations_equal'],
                              'both_complete': result['both_reads_complete'],
                              'authorization': False})
    checks.append({'check': 'All actual DLL cases decode, preserve unavailable-as-None, and never authorize',
                   'passed': True, 'cases': len(decoded_cases)})

    normal = wire(verifier.checks[0]['a'])

    def reject(name, data=None, second=None):
        try:
            if second is None:
                decoder.decode_snapshot(data)
            else:
                decoder.decode_pair(data, second)
        except ValueError as exc:
            checks.append({'check': name, 'passed': True, 'rejection': str(exc)})
        else:
            raise AssertionError(name + ' was accepted')

    def change(offset, fmt, value, raw=normal):
        data = bytearray(raw)
        struct.pack_into(fmt, data, offset, value)
        return bytes(data)

    mask = struct.unpack_from('<I', normal, 66)[0]
    reject('truncated_wire', normal[:-1])
    reject('oversized_wire', normal + b'\x00')
    reject('reserved_status_bit', change(66, '<I', mask | (1 << 31)))
    reject('nonzero_unavailable_field', change(66, '<I', mask & ~(1 << 0)))
    reject('valid_fields_without_code_observation', change(66, '<I', mask & ~decoder.CODE))
    reject('complete_without_all_fields', change(66, '<I', mask & ~(1 << 9)))
    reject('both_candidate_flags', change(66, '<I', mask | decoder.NONZERO))
    reject('candidate_flag_disagrees_low32', change(52, '<Q', 1))
    reject('count_flag_disagrees_count', change(44, '<I', 378))
    reject('header_flag_disagrees_size', change(40, '<I', 0xf245b))
    reject('pointer_flag_disagrees_source_pages', change(8, '<Q', 0x70000064))
    reject('different_fields_without_instability', normal, change(24, '<Q', 0x80001000))
    reject('one_sided_instability', normal, change(66, '<I', mask | decoder.UNSTABLE))
    flagged = change(66, '<I', mask | decoder.UNSTABLE)
    reject('identical_fields_both_spuriously_unstable', flagged, flagged)

    assert [binding(p) for p in inputs] == before, 'Subject changed during review'
    report = {'status': 'PASS_LOCAL_COMPILED_CORE_AND_DECODER_ONLY',
              'actual_dll_replay_cases': len(verifier.checks),
              'decoder_checks': checks, 'decoded_cases': decoded_cases,
              'bindings': before,
              'limits': [
                  'Uses actual compiled sampler/h6_probe/SHA. Memory and allocator callbacks remain explicit host models.',
                  'Reads exactly the subject verifier allowlist; this is not a UEFI memory-map/page-table carrier test.',
                  'No device, firmware flashing, business callback, variable service or original parser entry was executed.',
                  'A/B consistency and declaration bounds are diagnostic observations, not lifetime, allocation ownership or initial-parser proofs.',
                  'Delta07 runtime adapter, actual EFI artifact and transported output are outside this report.'
              ]}
    (HERE / 'independent_tests.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'dll_replay_cases': len(verifier.checks),
                      'decoder_rejection_cases': len(checks) - 1}, indent=2))


if __name__ == '__main__':
    main()
