"""Generate the independent component review; no subject files are written."""
from pathlib import Path
import hashlib
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile


def binding(path):
    p = Path(path)
    data = p.read_bytes()
    return {'path': str(p.relative_to(ROOT)), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def main():
    # Correct the initial display-only disassembly window to an instruction
    # boundary. This changes only this review's own evidence, not any original.
    design_path = HERE / 'design_static_review.json'
    design = json.loads(design_path.read_text())
    original = BASE / 'navigation/modules/AMITSE.efi'
    pe = pefile.PE(str(original))
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    raw = pe.get_data(0x407d4, 0x3f)
    window = {'rva': '0x407d4', 'bytes': raw.hex(), 'instructions': [
        f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in cs.disasm(raw, 0x407d4)]}
    design['assembly'] = [window if int(x['rva'], 16) in (0x407d0, 0x407d4) else x
                          for x in design['assembly']]
    design_path.write_text(json.dumps(design, indent=2) + '\n')

    tests_path = HERE / 'independent_tests.json'
    tests = json.loads(tests_path.read_text())
    assert tests['status'] == 'PASS_LOCAL_COMPILED_CORE_AND_DECODER_ONLY'
    for b in tests['bindings']:
        assert binding(ROOT / b['path']) == b, b['path']
    source_paths = [BASE / 'spf_sampler06' / f for f in
                    ('sampler.c', 'sampler.h', 'build.py', 'decode.py', 'verify.py',
                     'build/build.json', 'build/tests.json', 'build/spf_sampler_test.dll')]
    source_paths += [BASE / 'diagnostic_hii06/source' / f for f in
                     ('core.c', 'core.h', 'known_profiles.h', 'password_core.h',
                      'password_crypto.c')]
    source_paths += [BASE / 'diagnostic_hii06/component_manifest.json',
                     design_path, tests_path, HERE / 'verify_independent.py',
                     HERE / 'write_review.py']
    source_paths += [ROOT / x['path'] for x in design['sources']]
    paths = list(dict.fromkeys(source_paths))
    findings = [
        {'id': 'FIXED_PROFILE_MEASURED', 'result': 'PASS',
         'evidence': 'capture calls real h6_profile(fixed AMITSE GUID) and h6_probe for each A/B snapshot, with exact 0xDE000 image size; actual normalized SHA and relocation checks are linked. No caller MATCH argument exists.'},
        {'id': 'SOURCE_VS_CURRENT', 'result': 'PASS',
         'evidence': 'Five fixed globals read independently: BAB20/BAB10/BAB18 supply source values, BABC0/BAAF0 are recorded only. Original 19CF8/40FFF/407D4 instruction windows support that distinction.'},
        {'id': 'READ_BOUNDS_AND_POINTERS', 'result': 'PASS_IN_HOST_CONTRACT',
         'evidence': 'Read helper checks base, overflow, extent/off/n and <=8B scratch. Fixed 0x48 header bootstrap precedes exact header declaration/layout/relationships; subsequent fixed offsets remain inside 0xF245C. Pointer relationship failure prevents following source_pages or source_guids. Host must check actual current mapping/readability.'},
        {'id': 'NO_CANDIDATE_FOLLOW', 'result': 'PASS',
         'evidence': 'Only source+0x650 is sampled as the original page0 HII field. Low32 is categorized but never dereferenced. Current pointers are not followed. Decoder computes 0xF4CE6 as arithmetic only for zero candidate and zero parent; nonzero candidate or parent does not trigger that derivation.'},
        {'id': 'VALIDITY_NOT_MEASURED_ZERO', 'result': 'PASS',
         'evidence': 'Twelve independent field bits; scratch is copied into output only after successful host copy, preventing failed partial copies from leaving apparent measurements. Decoder emits None for missing fields and rejects nonzero invalid fields.'},
        {'id': 'PAIR_STABILITY', 'result': 'PASS_FOR_OBSERVATIONS',
         'evidence': 'Full packed 70B snapshots including status/validity are compared before adding instability bits. Tests include changed code, current pointer, candidate and availability. This does not prove lifetime, synchronous atomicity, or first-parser timing.'},
        {'id': 'NO_NATIVE_WRITES', 'result': 'PASS_AT_COMPONENT_INTERFACE',
         'evidence': 'Only host copy/alloc/free callbacks are accepted. No variable service, Setup/business callback or candidate mutation is invoked. Allocator scratch and output writes are part of the diagnostic, not writes to the observed original image/SPF.'},
        {'id': 'DECODER_CONSISTENCY', 'result': 'PASS_TESTED_CASES',
         'evidence': 'All 35 actual DLL records decode with preserved independent availability; 14 inconsistent or malformed records reject. Decoder never returns authorization.'},
    ]
    report = {
        'status': 'NO_BLOCKING_FINDING_IN_LOCAL_COMPONENT_REVIEW_CARRIER_PENDING',
        'scope': 'Independent local read-only SPF sampler core, fixed-profile measurement, build binding, and packed diagnostic decoder; not a device or release approval.',
        'component_dll_sha256': tests['bindings'][-1]['sha256'],
        'findings': findings,
        'tests': {'actual_compiled_dll_replays': tests['actual_dll_replay_cases'],
                  'decoder_actual_record_cases': len(tests['decoded_cases']),
                  'decoder_rejection_cases': len(tests['decoder_checks']) - 1,
                  'report': binding(tests_path)},
        'bindings': [binding(p) for p in paths],
        'pending_carrier_checks': [
            'Actual Delta07 H6_HOST copy validates current page mapping/readability before each copy; module lookup rechecks LoadedImage identity and fixed GUID without substituting a cached MATCH boolean.',
            'Carrier always preserves both exact 70B records, independent invalid bits and errors; whole-line logging must not turn truncation into partial accepted records.',
            'Actual carrier compilation/source provenance binds the reviewed sampler/core and all runtime adapters; entry, output and VM tests must bind that same EFI.',
            'Physical post-Setup scalar values are unavailable in this review. They cannot establish initial parser call state or remove the existing parser release block.',
        ],
        'limits': tests['limits'] + [
            'Exact profile/declaration and mapped range checks do not prove allocation extent or ownership. No source pointer is considered execution authority.',
            'This review does not approve firmware modification, flashing, original parser patching, password operation or business callbacks.',
        ]
    }
    target = HERE / 'component_review.json'
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'report': binding(target)}, indent=2))


if __name__ == '__main__':
    main()
