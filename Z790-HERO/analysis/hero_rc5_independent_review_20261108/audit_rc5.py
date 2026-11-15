"""Offline RC5 review; writes only this independent review directory.

The container checker below does not import the candidate builder or its parser.
Builder/verifier imports are used separately to exercise their real entrypoints.
"""
from pathlib import Path
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import struct
import sys
import unittest
import uuid

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
SOURCE = ROOT / 'analysis/hero_ipmi_rc5_20261108'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
BASE, LENGTH = 0x12D1000, 0x9F0000
WRAPPER = '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
R2 = '89924765-f984-4ad3-839b-51fdce378d88'
P6 = '261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
LZMA_GUID = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'
R3_FFS = ROOT / 'analysis/hero_sensor_r3_20261108/HeroIpmiCoreR3.ffs'
R3_PE = ROOT / 'analysis/hero_sensor_r3_20261108/USB/EFI/HERO/HeroIpmiR3.efi'
BASELINE = ROOT / 'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/HERO-3107-IPMI-SECTIONFIX-LATEST-UNSIGNED.CAP'
OFFICIAL = ROOT / 'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
PINNED = {
    'baseline': '66420b42a5251a1209cac9865d3a1d8d5f1e03e512b4b9ce98ba0d29b81be131',
    'official': 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a',
    'r3_ffs': 'c266e208438880fc31a868a8c4cd4230cb892b63ec04c7a798cb71db66acce78',
    'r3_pe': '7b715068892c7603a02648fb3739b7e90a79504634a1717e6c7ed49b5f9e6921',
    'dxe': '5a4a8d96f7de6f714fd4d91e5579d701e4e4a6394b7dc46968d6cb1f07f8efcf',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, obj):
    (OUT / name).write_text(json.dumps(obj, indent=2) + '\n', encoding='utf-8')


def check(ok, message):
    if not ok:
        raise ValueError(message)


def guid(b):
    return str(uuid.UUID(bytes_le=b))


def aligned(n, size):
    return (n + size - 1) // size * size


def sections(data):
    """Exact final section end, not a permissive final-padding parser."""
    check(bool(data), 'empty section stream')
    result = []
    at = 0
    while True:
        check(len(data) - at >= 4, 'partial section header at final end')
        size = int.from_bytes(data[at:at + 3], 'little')
        header = 4
        if size == 0xFFFFFF:
            check(len(data) - at >= 8, 'short extended section')
            size = struct.unpack_from('<I', data, at + 4)[0]
            header = 8
        check(header <= size <= len(data) - at, 'section exceeds stream')
        end = at + size
        result.append({'type': data[at + 3], 'offset': at, 'head': header,
                       'data': data[at:end], 'body': data[at + header:end]})
        if end == len(data):
            return result
        at = aligned(end, 4)
        check(at < len(data), 'padding after last section')
        check(data[end:at] == bytes(at - end), 'nonzero inter-section padding')


def volume(data):
    check(len(data) >= 72 and data[40:44] == b'_FVH', 'FV signature')
    size = struct.unpack_from('<Q', data, 32)[0]
    header_bytes = struct.unpack_from('<H', data, 48)[0]
    check(size == len(data) and 56 <= header_bytes <= size and not header_bytes % 2,
          'FV header bounds')
    check(sum(struct.unpack('<' + 'H' * (header_bytes // 2), data[:header_bytes])) % 65536 == 0,
          'FV checksum')
    total = 0
    terminated = False
    for pos in range(56, header_bytes - 7, 8):
        count, width = struct.unpack_from('<II', data, pos)
        if count == width == 0:
            terminated = True
            break
        check(count > 0 and width > 0, 'invalid FV block map')
        total += count * width
    check(terminated and total == size, 'FV block map extent')
    ext = struct.unpack_from('<H', data, 52)[0]
    if ext:
        check(ext + 20 <= size, 'FV extension header')
        ext_size = struct.unpack_from('<I', data, ext + 16)[0]
        check(20 <= ext_size <= size - ext, 'FV extension size')
    erase = 255 if struct.unpack_from('<I', data, 44)[0] & 0x800 else 0
    at = aligned(header_bytes, 8)
    result, order = {}, []
    while at + 24 <= size and data[at:at + 24] != bytes([erase]) * 24:
        raw = data[at:at + 24]
        n = int.from_bytes(raw[20:23], 'little')
        check(not raw[19] & 1 and 24 <= n < 0xFFFFFF and n <= size - at, 'FFS size')
        check((sum(raw) - raw[17] - raw[23]) % 256 == 0, 'FFS header checksum')
        check(raw[23] ^ erase == 7, 'FFS state')
        check(((raw[19] >> 3) & 7) == 0, 'unexpected FFS alignment attribute')
        body = data[at + 24:at + n]
        if raw[19] & 0x40:
            check((sum(body) + raw[17]) % 256 == 0, 'FFS payload checksum')
        else:
            check(raw[17] == 0xAA, 'FFS fixed checksum')
        g = guid(raw[:16])
        check(g not in result, 'duplicate FFS GUID')
        result[g] = {'data': data[at:at + n], 'offset': at, 'bytes': n, 'type': raw[18]}
        order.append(g)
        after = aligned(at + n, 8)
        check(data[at + n:after] == bytes([erase]) * (after - at - n), 'FFS alignment fill')
        at = after
    check(data[at:] == bytes([erase]) * (size - at), 'FV erased tail')
    return dict(files=result, order=order, header=data[:aligned(header_bytes, 8)],
                free_bytes=size - at, used_bytes=at)


def image(path):
    cap = path.read_bytes()
    check(len(cap) == 33558528, 'CAP size')
    outer = volume(cap[BASE:BASE + LENGTH])
    wrapped = sections(outer['files'][WRAPPER]['data'][24:])
    check(len(wrapped) == 1 and wrapped[0]['type'] == 2, 'wrapper section shape')
    part = wrapped[0]
    body = part['body']
    check(len(body) >= 33 and guid(body[:16]) == LZMA_GUID, 'guided wrapper GUID')
    dataoff, attributes = struct.unpack_from('<HH', body, 16)
    check(dataoff == part['head'] + 20 and attributes == 1, 'guided attributes/data offset')
    compressed = part['data'][dataoff:]
    plain = lzma.decompress(compressed, format=lzma.FORMAT_ALONE)
    check(struct.unpack_from('<Q', compressed, 5)[0] == len(plain), 'LZMA declared size')
    parts = sections(plain)
    check(len(parts) == 2 and parts[1]['type'] == 0x17, 'exact inner wrapper shape')
    inner = volume(parts[1]['body'])
    return dict(cap=cap, outer=outer, inner=inner, wrapper=wrapped, parts=parts,
                compressed=compressed, plain=plain)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


def entry(ffs, role='sensors_dashboard'):
    b = ffs.read_bytes()
    pe = sections(b[24:])[1]['body']
    return {'guid': guid(b[:16]), 'path': str(ffs.relative_to(ROOT)),
            'sha256': sha(b), 'pe_sha256': sha(pe), 'role': role}


def capture_verify(verifier, directory):
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            verifier.verify(directory.resolve())
        return {'accepted': True, 'output': output.getvalue()}
    except Exception as exc:
        return {'accepted': False, 'exception': type(exc).__name__, 'detail': str(exc)}


def run_native_validator(body):
    import pefile
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_R11
    source = ROOT / 'analysis/hero_ipmi_r2_followup_20261108/dispatch-audit/DxeCore.efi'
    raw = source.read_bytes()
    check(sha(raw) == PINNED['dxe'], 'target DxeCore hash')
    code = pefile.PE(data=raw).get_memory_mapped_image()
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    u.mem_map(0x100000, 0x20000)
    u.mem_write(0x100000, code)
    u.mem_map(0x200000, 0x2000)
    u.mem_map(0x300000, aligned(len(body) + 1, 4096))
    u.mem_write(0x300000, body)
    u.reg_write(UC_X86_REG_RSP, 0x201000)
    u.mem_write(0x201048, struct.pack('<Q', len(body)))
    u.reg_write(UC_X86_REG_R11, 0x300000)
    outcome = []
    def hook(uc, address, size, user):
        if address in (0x10E636, 0x10E62A):
            outcome.append(address == 0x10E636)
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(0x10E5C4, 0x10E63A, count=100000)
    check(len(outcome) == 1, 'validator path did not terminate')
    return outcome[0]


def check_candidate(candidate):
    import pefile
    old, new = image(BASELINE), image(candidate)
    official = OFFICIAL.read_bytes()
    for name, path in (('baseline', BASELINE), ('official', OFFICIAL), ('r3_ffs', R3_FFS), ('r3_pe', R3_PE)):
        check(sha(path.read_bytes()) == PINNED[name], 'pinned input ' + name)
    for ref in (old['cap'], official):
        check(new['cap'][:BASE] == ref[:BASE] and new['cap'][BASE + LENGTH:] == ref[BASE + LENGTH:],
              'outside DXE changed')
    check(new['cap'][:4096] == official[:4096], 'original capsule header changed')
    unchanged = []
    for layer, changed in (('outer', {WRAPPER}), ('inner', {R2})):
        check(old[layer]['order'] == new[layer]['order'], layer + ' FFS order changed')
        check(old[layer]['header'] == new[layer]['header'], layer + ' FV header changed')
        for g, f in old[layer]['files'].items():
            same = f['data'] == new[layer]['files'][g]['data']
            check(same == (g not in changed), 'unexpected FFS change or missing replacement: ' + g)
            if same:
                unchanged.append({'layer': layer, 'guid': g, 'sha256': sha(f['data']), 'bytes': f['bytes']})
    check(old['parts'][0]['data'] == new['parts'][0]['data'], 'non-FV wrapper section changed')
    check(old['parts'][1]['type'] == new['parts'][1]['type'], 'inner FV section type')
    ffs = new['inner']['files'][R2]['data']
    check(ffs == R3_FFS.read_bytes(), 'not exact frozen R3 FFS')
    ss = sections(ffs[24:])
    check([s['type'] for s in ss] == [0x13, 0x10, 0x15], 'R3 section type order')
    check(ss[1]['body'] == R3_PE.read_bytes(), 'R3 PE exact payload')
    p6 = new['inner']['files'][P6]['data']
    sections(p6[24:])
    pe = pefile.PE(data=ss[1]['body'])
    check(pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Magic == 0x20B,
          'R3 x64 PE32+')
    check(pe.OPTIONAL_HEADER.Subsystem == 11 and not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'), 'R3 subsystem/imports')
    check(pe.verify_checksum() and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0, 'PE checksum/relocations')
    native = {'r3_exact': run_native_validator(ffs[24:]),
              'r3_two_zero_tail': run_native_validator(ffs[24:] + b'\0\0'),
              'p6_exact': run_native_validator(p6[24:]),
              'p6_two_zero_tail': run_native_validator(p6[24:] + b'\0\0')}
    check(native == {'r3_exact': True, 'r3_two_zero_tail': False, 'p6_exact': True, 'p6_two_zero_tail': False},
          'native target DxeCore validation disagreement')
    save('unchanged-ffs.json', unchanged)
    result = dict(passed=True, candidate=str(candidate.relative_to(ROOT)), candidate_sha256=sha(new['cap']),
                  independently_implemented_parser=True, parser_imports_builder=False,
                  baseline_sha256=sha(old['cap']), official_sha256=sha(official),
                  outside_dxe_exact=True, capsule_header_exact=True,
                  changed_inner=[R2], changed_outer=[WRAPPER], no_additions=True,
                  all_existing_ffs_order_preserved=True, unrelated_ffs_exact=len(unchanged),
                  p6_ffs_sha256=sha(p6), r3_ffs_sha256=sha(ffs), r3_pe_sha256=sha(ss[1]['body']),
                  wrapper_non_fv_section_exact=True, native_validator=native,
                  native_dxecore_sha256=PINNED['dxe'], inner_free=new['inner']['free_bytes'],
                  outer_free=new['outer']['free_bytes'], hardware_flashing_performed=False,
                  limitation='Structural and target-machine-code section checks; this file is a review-only artifact, not a release.')
    save('independent-byte-audit.json', result)
    return old, new, result


def make_negative(name, cap, manifest, source_report):
    directory = OUT / name
    directory.mkdir(exist_ok=True)
    path = directory / (name + '.CAP')
    path.write_bytes(cap)
    raw = (json.dumps(manifest, indent=2) + '\n').encode()
    (directory / 'integration-manifest.json').write_bytes(raw)
    report = dict(source_report, candidate=str(path.relative_to(ROOT)), candidate_sha256=sha(cap),
                  manifest_sha256=sha(raw))
    (directory / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return directory


def main():
    source_hashes = {name: sha((SOURCE / name).read_bytes()) for name in ('build_candidate.py', 'verify_candidate.py', 'test_builder_guards.py')}
    snapshot = OUT / 'reviewed-snapshot'
    snapshot.mkdir(exist_ok=True)
    for name in source_hashes:
        (snapshot / name).write_bytes((SOURCE / name).read_bytes())
    save('reviewed-source-hashes.json', source_hashes)
    # Import real modules at original paths so their ROOT resolution is unchanged.
    builder = module('build_candidate', SOURCE / 'build_candidate.py')
    verifier = module('verify_candidate', SOURCE / 'verify_candidate.py')
    builder.HERE = OUT
    tests = module('rc5_root_guard_tests', SOURCE / 'test_builder_guards.py')
    output = io.StringIO()
    test_result = unittest.TextTestRunner(stream=output, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(tests.GuardTests))
    (OUT / 'root-guard-tests.txt').write_text(output.getvalue())
    check(test_result.wasSuccessful(), 'root guard suite failed')
    manifest = {'build_id': 'R3-REVIEW-ONLY', 'modules': [entry(R3_FFS)],
                'purpose': 'Independent offline review artifact; never flash this directory.'}
    manifest_path = OUT / 'review-manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        report = builder.build(manifest_path)
    (OUT / 'build-output.txt').write_text(output.getvalue())
    candidate = ROOT / report['candidate']
    approved = capture_verify(verifier, candidate.parent)
    check(approved['accepted'], 'real frozen R3 candidate rejected by root verifier: ' + str(approved))
    old, new, independent = check_candidate(candidate)
    cases = []
    def approval_case(name, modules, expected):
        try:
            verifier.approved_modules(modules)
            accepted = True
        except Exception as exc:
            accepted = False
            error = type(exc).__name__ + ': ' + str(exc)
        else:
            error = ''
        cases.append(dict(name=name, accepted=accepted, expected=expected, passed=accepted == expected, detail=error))
    good = entry(R3_FFS)
    approval_case('exact_frozen_R3', [good], True)
    for field, value in [('guid', P6), ('guid', WRAPPER), ('sha256', '0' * 64),
                         ('pe_sha256', '0' * 64), ('role', 'inventory'), ('role', 'unknown'),
                         ('path', '../not-an-artifact.ffs')]:
        changed = dict(good)
        changed[field] = value
        approval_case('wrong_' + field + '_' + value[:16], [changed], False)
    approval_case('empty_modules', [], False)
    approval_case('duplicate_sensor', [good, good], False)
    approval_case('unapproved_inventory', [good, dict(good, role='inventory', guid=P6)], False)
    old_r2_path = OUT / 'old-R2.ffs'
    old_r2_path.write_bytes(old['inner']['files'][R2]['data'])
    old_p6_path = OUT / 'old-P6.ffs'
    old_p6_path.write_bytes(old['inner']['files'][P6]['data'])
    approval_case('self_consistent_old_R2', [entry(old_r2_path)], False)
    approval_case('self_consistent_old_P6_as_sensor', [entry(old_p6_path)], False)
    # Full verifier regression for unchanged image + internally consistent manifest.
    for name, old_path in [('NEGATIVE-OLD-R2', old_r2_path), ('NEGATIVE-P6-AS-SENSOR', old_p6_path)]:
        nm = {'build_id': name, 'modules': [entry(old_path)]}
        directory = make_negative(name, old['cap'], nm, report)
        verdict = capture_verify(verifier, directory)
        cases.append({'name': name, 'expected': False, 'accepted': verdict['accepted'],
                      'passed': not verdict['accepted'], 'detail': verdict.get('detail', '')})
    # A correct R3 payload but altered unrelated wrapper metadata. This isolates
    # wrapper preservation from the role/hash checks without altering any module.
    prefix = new['parts'][0]['data']
    check(len(prefix) > new['parts'][0]['head'], 'no prefix byte for wrapper counterexample')
    altered = bytearray(prefix)
    altered[-1] ^= 1
    plain = builder.base.pack_sections([bytes(altered), new['parts'][1]['data']])
    scratch = OUT / 'negative-wrapper-compression'
    scratch.mkdir(exist_ok=True)
    wrapped = builder.base.rebuild_file(new['outer']['files'][WRAPPER]['data'], builder.guided(plain, scratch))
    outer, _ = builder.base.pack_fv(new['cap'][BASE:BASE + LENGTH], {WRAPPER: wrapped})
    altered_cap = new['cap'][:BASE] + outer + new['cap'][BASE + LENGTH:]
    directory = make_negative('NEGATIVE-WRAPPER-PREFIX', altered_cap, manifest, report)
    verdict = capture_verify(verifier, directory)
    cases.append({'name': 'unrelated_wrapper_prefix_modified', 'expected': False,
                  'accepted': verdict['accepted'], 'passed': not verdict['accepted'],
                  'detail': verdict.get('detail', ''), 'candidate': str(directory.relative_to(ROOT))})
    save('verifier-regressions.json', {'reviewed_hashes': source_hashes, 'cases': cases})
    final_hashes = {name: sha((SOURCE / name).read_bytes()) for name in source_hashes}
    save('audit-summary.json', dict(
        source_hashes=source_hashes, source_hashes_at_end=final_hashes,
        source_unchanged_during_review=source_hashes == final_hashes,
        root_guard_suite={'passed': test_result.wasSuccessful(), 'tests': test_result.testsRun},
        actual_candidate=independent, approval_tests=len(cases),
        rejected_negative_cases=sum(c['passed'] for c in cases if not c['expected']),
        unresolved_verifier_cases=[c for c in cases if not c['passed']],
        all_child_output_confined_to=str(OUT), hardware_access=False))
    print(json.dumps({'review_summary': str(OUT / 'audit-summary.json'), 'candidate_sha256': sha(candidate.read_bytes()),
                      'regression_cases': len(cases), 'unresolved': [c['name'] for c in cases if not c['passed']]}))


if __name__ == '__main__':
    main()
