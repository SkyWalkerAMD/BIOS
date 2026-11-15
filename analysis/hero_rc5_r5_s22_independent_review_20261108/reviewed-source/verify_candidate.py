"""Independent read-back of a generated candidate, using the review FV parser."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys
import uuid

if not __debug__:
    raise RuntimeError('Optimized Python disables required assertions; run without -O or PYTHONOPTIMIZE')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103'))
from container_review import read_image, sections, decode, BASE, SIZE, WRAPPER

BASELINE_SHA = '66420b42a5251a1209cac9865d3a1d8d5f1e03e512b4b9ce98ba0d29b81be131'
BASELINE = ROOT / 'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/HERO-3107-IPMI-SECTIONFIX-LATEST-UNSIGNED.CAP'
OFFICIAL = ROOT / 'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
R2_GUID = '89924765-f984-4ad3-839b-51fdce378d88'
P6_GUID = '261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
R4_FFS_SHA = 'be0d4f23272f8c98266629a9e10b1f36f47c35477eb997b3ce44525d230fc792'
R4_PE_SHA = '81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4'
# Deliberately separate pins from the builder. A manifest/report/artifact name
# can never authorize its own hash. No P6 release means all candidates fail.
P6_RELEASE = {
    'sha256': '554e210cca3de3bc337f944e7126f244d1ffcd67bb81089662f6d3ae78f2ad1b',
    'pe_sha256': 'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75',
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def approved_modules(modules):
    assert isinstance(modules, list) and len(modules) == 2
    assert all(isinstance(e, dict) for e in modules)
    sensors = [e for e in modules if e.get('role') == 'sensors_dashboard']
    native = [e for e in modules if e.get('role') == 'native_ipmi']
    assert len(sensors) == len(native) == 1, 'Only R5 + native P6; inventory/additions forbidden'
    sensor = sensors[0]
    assert sensor['guid'].lower() == R2_GUID
    assert sensor['sha256'] == R4_FFS_SHA and sensor['pe_sha256'] == R4_PE_SHA
    assert P6_RELEASE is not None, 'Native P6 release not independently frozen'
    assert native[0]['guid'].lower() == P6_GUID
    for field in ('sha256', 'pe_sha256'):
        assert native[0][field] == P6_RELEASE[field], 'Unapproved native P6 executable'
    for e in modules:
        source = (ROOT / e['path']).resolve()
        assert source.is_relative_to(ROOT) and source.is_file()
    return {e['guid'].lower(): e for e in modules}


def preserved_wrapper(before, after):
    old_file = before['outer_files'][WRAPPER]['data']
    new_file = after['outer_files'][WRAPPER]['data']
    for start, end in ((0, 16), (17, 20), (23, 24)):
        assert old_file[start:end] == new_file[start:end], 'Wrapper FFS identity, type, attributes or state changed'
    old_outer = sections(old_file[24:])
    new_outer = sections(new_file[24:])
    assert len(old_outer) == len(new_outer) == 1
    old_stream, old_compression = decode(old_outer[0])
    new_stream, new_compression = decode(new_outer[0])
    for key in ('guid', 'data_offset', 'attributes', 'properties', 'decoded_bytes'):
        assert old_compression[key] == new_compression[key]
    old_parts, new_parts = sections(old_stream), sections(new_stream)
    assert len(old_parts) == len(new_parts)
    assert [s['type'] for s in old_parts] == [s['type'] for s in new_parts]
    old_fv, = [s for s in old_parts if s['type'] == 0x17]
    new_fv, = [s for s in new_parts if s['type'] == 0x17]
    assert (old_fv['offset'], old_fv['head'], len(old_fv['body'])) == (new_fv['offset'], new_fv['head'], len(new_fv['body']))
    start = old_fv['offset'] + old_fv['head']
    end = start + len(old_fv['body'])
    assert old_stream[:start] == new_stream[:start], 'Wrapper prefix or FV section header changed'
    assert old_stream[end:] == new_stream[end:], 'Wrapper suffix or padding changed'


def strict_new_driver(blob):
    offset = 24
    out = []
    while True:
        assert offset + 4 <= len(blob), 'Missing section header / stray final padding'
        count = int.from_bytes(blob[offset:offset + 3], 'little')
        header = 4
        if count == 0xffffff:
            assert offset + 8 <= len(blob)
            count = struct.unpack_from('<I', blob, offset + 4)[0]
            header = 8
        assert count >= header and count <= len(blob) - offset
        end = offset + count
        out.append((blob[offset + 3], blob[offset + header:end]))
        if end == len(blob):
            break
        next_offset = (end + 3) // 4 * 4
        assert next_offset < len(blob), 'Final section padding is not a new section'
        assert blob[end:next_offset] == bytes(next_offset - end)
        offset = next_offset
    assert [typ for typ, body in out] == [0x13, 0x10, 0x15]
    depex = out[0][1]
    pos = depth = 0
    dependencies = []
    while pos < len(depex):
        op = depex[pos]
        pos += 1
        if op == 2:
            assert pos + 16 <= len(depex)
            dependencies.append(str(uuid.UUID(bytes_le=depex[pos:pos + 16])))
            pos += 16
            depth += 1
        elif op in (3, 4):
            assert depth >= 2
            depth -= 1
        elif op == 5:
            assert depth >= 1
        elif op in (6, 7):
            depth += 1
        elif op == 8:
            assert depth == 1 and pos == len(depex)
        else:
            raise AssertionError('Unreviewed DEPEX opcode')
    assert depex[-1] == 8
    return out, dependencies


def verify(directory):
    manifest_file = directory / 'integration-manifest.json'
    report = json.loads((directory / 'build-report.json').read_text(encoding='utf-8'))
    manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    assert report['schema'] == 'hero-rc5-ipmi-only-container-2'
    assert report['build_id'] == manifest['build_id'] == directory.name
    wanted = approved_modules(manifest['modules'])
    assert sha(manifest_file.read_bytes()) == report['manifest_sha256']
    candidate = (ROOT / report['candidate']).resolve()
    assert candidate.parent == directory and candidate.suffix == '.CAP'
    assert candidate.name == 'HERO-3107-IPMI-' + manifest['build_id'] + '-UNSIGNED.CAP'
    old, new = read_image(BASELINE), read_image(candidate)
    official = OFFICIAL.read_bytes()
    assert sha(old['cap']) == BASELINE_SHA
    assert sha(new['cap']) == report['candidate_sha256']
    assert len(new['cap']) == len(old['cap']) == len(official) == 33558528
    assert report['candidate_bytes'] == len(new['cap'])
    for reference in (old['cap'], official):
        assert new['cap'][:BASE] == reference[:BASE]
        assert new['cap'][BASE + SIZE:] == reference[BASE + SIZE:]
    preserved_wrapper(old, new)
    assert len(wanted) == len(manifest['modules'])
    changes, additions = [], []
    for layer in ('outer', 'inner'):
        before, after = old[layer + '_files'], new[layer + '_files']
        assert list(after) == list(before), 'FFS order/membership changed; additions forbidden'
        assert old[layer + '_info']['header_sha256'] == new[layer + '_info']['header_sha256']
        assert set(before) == set(after), 'Firmware file removed or added'
        for guid, entry in before.items():
            if entry['data'] != after[guid]['data']:
                if layer == 'outer':
                    assert guid == WRAPPER
                else:
                    assert guid in wanted and guid in (R2_GUID, P6_GUID)
                    changes.append(guid)
    assert len(changes) == 2 and set(changes) == {R2_GUID, P6_GUID}, 'Exactly frozen R4 and native P6 must change'
    assert not additions and set(wanted) == {R2_GUID, P6_GUID}
    assert set(report['changed_inner_ffs']) == set(changes) and not report['added_inner_ffs']
    assert report['inventory_included'] is False and report['new_guid_additions_allowed'] is False
    payloads = []
    for guid, wanted_entry in wanted.items():
        assert guid not in new['outer_files']
        ffs = new['inner_files'][guid]['data']
        assert sha(ffs) == wanted_entry['sha256']
        assert ffs == (ROOT / wanted_entry['path']).read_bytes()
        ss, deps = strict_new_driver(ffs)
        assert sha(ss[1][1]) == wanted_entry['pe_sha256']
        payloads.append(dict(guid=guid, ffs_sha256=sha(ffs), pe_sha256=sha(ss[1][1]),
                             dependencies=deps, ui=ss[2][1].decode('utf-16-le').rstrip('\0')))
    result = dict(passed=True, candidate_sha256=sha(new['cap']),
                  independent_parser='container_review.py; no builder import',
                  changed_inner_ffs=changes, added_inner_ffs=additions,
                  all_unrelated_files_preserved=True, original_platform_regions_preserved=True,
                  wrapper_non_fv_bytes_preserved=True, original_ffs_order_preserved=True,
                  fv_checksums_alignment_erase_fill_valid=True, strict_final_section_valid=True,
                  exact_payloads=payloads, inner=new['inner_info'], outer=new['outer_info'],
                  inventory_included=False, exactly_two_existing_ipmi_cores_replaced=True,
                  hardware_flashing_performed=False,
                  scope='Offline structural read-back only; runtime evidence is separate.')
    (directory / 'independent-container-verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('directory', type=Path)
    verify(p.parse_args().directory.resolve())
