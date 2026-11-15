"""Check frozen inputs, actual EFI reports and their complete diagnostic logs.

This verifier only reads the carrier directory. Reports go to this review dir.
It does not execute firmware, connect hardware, or loosen a target selection.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import struct
import sys
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
D7 = BASE / 'diagnostic_delta07'
sys.path.insert(0, str(D7))
from transport import parse
from decode_packet import CPU, NVME, SOCKET


def binding(p):
    p = Path(p)
    data = p.read_bytes()
    return {'path': str(p.relative_to(ROOT)), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def main():
    paths = [D7 / f for f in ('collector.c', 'build.py', 'transport.py', 'decode_packet.py',
             'delta_core.c', 'delta_core.h', 'verify_efi.py', 'build/efi_tests.json')]
    before = [binding(p) for p in paths]
    tests = json.loads(paths[-1].read_text())
    assert tests['passed'] and tests['count'] == len(tests['cases'])
    main_efi = D7 / 'build/BOOTX64.EFI'
    assert tests['shipping_efi_sha256'] == binding(main_efi)['sha256']
    baselines = {g: (BASE / 'foreign_hii05/blobs' / f'{name}_0.forms.bin').read_bytes()
                 for g, name in ((CPU, 'GetCpuInfo'), (NVME, 'NvmeDynamicSetup'),
                                 (SOCKET, 'SocketSetup'))}
    build_checks = []
    for rel in ('build', 'build/lab', 'build/lab_huge'):
        out = D7 / rel
        build = json.loads((out / 'build.json').read_text())
        assert build['efi_sha256'] == binding(out / 'BOOTX64.EFI')['sha256']
        for name, digest in build['sources'].items():
            assert binding(out / 'source' / name)['sha256'] == digest, (rel, name)
        for name in ('collector.c', 'delta_core.c', 'delta_core.h'):
            assert build['sources'][name] == binding(D7 / name)['sha256']
        for name in ('sampler.c', 'sampler.h'):
            assert build['sources'][name] == binding(BASE / 'spf_sampler06' / name)['sha256']
        for name in ('core.c', 'core.h', 'runtime.c', 'runtime.h', 'memory.c', 'memory.h',
                     'known_profiles.h', 'password_crypto.c', 'kvm.c', 'probe_core.c'):
            assert build['sources'][name] == binding(BASE / 'diagnostic_hii06/source' / name)['sha256']
        for item in build['inputs']:
            assert binding(item['path'])['sha256'] == item['sha256'], item['path']
        build_checks.append({'build': rel, 'source_count': len(build['sources']),
                             'input_count': len(build['inputs']),
                             'metadata': binding(out / 'build.json'),
                             'efi': binding(out / 'BOOTX64.EFI')})
        paths += [out / 'build.json', out / 'BOOTX64.EFI']

    reviewed_cases = []
    complete_shipping_spf = False
    normal_log = None
    normal_selection = None
    for case in tests['cases']:
        name = case['case']
        if name.startswith('shipping'):
            out = D7 / 'build'
            selection_path = D7 / 'selection_hardware02.json'
        elif name == 'huge_socket':
            out = D7 / 'build/lab_huge'
            selection_path = out / 'SYNTHETIC-selection.json'
        else:
            out = D7 / 'build/lab'
            selection_path = out / 'SYNTHETIC-selection.json'
        assert case['passed'] and case['efi_sha256'] == binding(out / 'BOOTX64.EFI')['sha256']
        logpath = out / 'efi_cases' / f'{name}.txt'
        log = logpath.read_bytes()
        selection = json.loads(selection_path.read_text())
        payload = selection['payload']
        decoded = parse(log, payload['targets'], bytes.fromhex(payload['source_log_sha256']),
                        bytes.fromhex(selection['selection_sha256']), baselines, 15360)
        assert case['selection_sha256'] == selection['selection_sha256']
        assert case['bytes'] == len(log) <= 15360
        assert case['pages'] == (len(log) + 767) // 768 <= 20
        assert case['exported'] == len(decoded['objects'])
        assert case['omitted'] == decoded['omitted'] and case['refused'] == decoded['refused']
        assert case['spf'] == decoded['spf']
        if name.startswith('shipping') and decoded['spf']['carrier_state'] == 'COMPLETE_OBSERVATION':
            complete_shipping_spf = True
        if name == 'normal':
            normal_log, normal_selection = log, selection
        reviewed_cases.append({'case': name, 'log': binding(logpath),
            'efi_sha256': case['efi_sha256'], 'pages': case['pages'],
            'spf_state': decoded['spf']['carrier_state'],
            'spf_complete': decoded['spf']['both_reads_complete'],
            'source_observation': decoded['spf']['a']['fields']['source'],
            'declared_spf_read_count': len(case['spf_reads']),
            'actual_diagnostic_authority': False})
        paths += [logpath, selection_path]

    assert complete_shipping_spf, 'Exact target-selection EFI still lacks a complete SPF observation test'
    core_tests = json.loads((BASE / 'spf_sampler06/build/tests.json').read_text())
    measured = core_tests['checks'][0]
    raw = struct.pack('<5Q3IQ3HI', *measured['a'].values()) + struct.pack('<5Q3IQ3HI', *measured['b'].values())

    def spfline(data):
        return ('D7 SPF A=' + data[:70].hex().upper() + ' B=' + data[70:].hex().upper() +
                f' CRC={zlib.crc32(data):08X} SHA=' + hashlib.sha256(data).hexdigest() +
                ' E=COMPLETE_OBSERVATION\r\n').encode()

    log = re.sub(rb'D7 SPF .*?\r\n', lambda _: spfline(raw), normal_log, count=1)
    payload = normal_selection['payload']

    def decode(data):
        return parse(data, payload['targets'], bytes.fromhex(payload['source_log_sha256']),
                     bytes.fromhex(normal_selection['selection_sha256']), baselines, 15360)

    assert decode(log)['spf']['carrier_state'] == 'COMPLETE_OBSERVATION'
    errors = []
    error_flags = {'PROFILE': 20, 'UNREADABLE': 21, 'INVALID': 22, 'PROBE': 23}
    for label, bit in error_flags.items():
        data = bytearray(raw)
        for off in (66, 136):
            struct.pack_into('<I', data, off, struct.unpack_from('<I', data, off)[0] | (1 << bit))
        errors.append(('complete_with_' + label, re.sub(rb'D7 SPF .*?\r\n', lambda _: spfline(bytes(data)), log, count=1)))
    errors += [
        ('complete_but_map_refused', log.replace(b'MAP=READY', b'MAP=REFUSED', 1)),
        ('complete_but_two_modules', log.replace(b'TSE_COUNT=1', b'TSE_COUNT=2', 1)),
        ('complete_but_no_module', log.replace(b'TSE_COUNT=1', b'TSE_COUNT=0', 1)),
    ]
    reject_checks = []
    for name, bad in errors:
        try:
            decode(bad)
        except ValueError as exc:
            reject_checks.append({'case': name, 'rejected': True, 'error': str(exc)})
        else:
            raise AssertionError(name + ' still accepted')
    assert [binding(p) for p in paths[:len(before)]] == before
    report = {'status': 'PASS_REVIEWED_CARRIER_ARTIFACT_AND_TRANSPORT_BINDINGS',
        'shipping_efi': binding(main_efi), 'build_checks': build_checks,
        'actual_efi_report_cases': reviewed_cases,
        'exact_shipping_spf_positive_present': complete_shipping_spf,
        'independent_transport_consistency_rejections': reject_checks,
        'bindings': [binding(p) for p in dict.fromkeys(paths)],
        'limitations': [
            'Actual EFI tests are the component author reports independently read and re-decoded here; they were not re-executed by this verifier.',
            'Their UEFI services, HII contents, CPU observations and identity page tables are explicit models, and SHA256 is a disclosed oracle in EFI tests.',
            'The separate core review executes compiled SHA and h6_probe on original bytes; no MATCH boolean substitutes for the measured profile in the carrier.',
            'LAB content-selection positives are separate binaries. The exact hardware-selection carrier SPF positive is checked separately.',
            'No hardware or first-parser entry was exercised by this independent review. No execution authorization or flashability is established.'
        ]}
    target = HERE / 'carrier_tests_review.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': binding(target),
                      'efi_report_cases': len(reviewed_cases),
                      'independent_decoder_rejections': len(reject_checks)}, indent=2))


if __name__ == '__main__':
    main()
