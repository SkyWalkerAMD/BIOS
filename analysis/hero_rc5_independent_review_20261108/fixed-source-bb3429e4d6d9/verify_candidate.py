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
R3_FFS_SHA = 'c266e208438880fc31a868a8c4cd4230cb892b63ec04c7a798cb71db66acce78'
R3_PE_SHA = '7b715068892c7603a02648fb3739b7e90a79504634a1717e6c7ed49b5f9e6921'
# Filled only after a distinct inventory release artifact has passed its
# required checks. A manifest cannot approve its own executable payload.
INVENTORY_RELEASE = None


def sha(b):
    return hashlib.sha256(b).hexdigest()


def approved_modules(modules):
    assert isinstance(modules, list) and 1 <= len(modules) <= 2
    sensors = [e for e in modules if e.get('role') == 'sensors_dashboard']
    inventory = [e for e in modules if e.get('role') == 'inventory']
    assert len(sensors) == 1 and len(sensors) + len(inventory) == len(modules)
    sensor = sensors[0]
    assert sensor['guid'].lower() == R2_GUID
    assert sensor['sha256'] == R3_FFS_SHA and sensor['pe_sha256'] == R3_PE_SHA
    if inventory:
        assert len(inventory) == 1 and INVENTORY_RELEASE is not None, 'Inventory release not approved'
        for field in ('guid', 'sha256', 'pe_sha256'):
            assert inventory[0][field] == INVENTORY_RELEASE[field]
        assert inventory[0]['guid'].lower() != R2_GUID
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
    assert sha(manifest_file.read_bytes()) == report['manifest_sha256']
    candidate = (ROOT / report['candidate']).resolve()
    assert candidate.parent == directory and candidate.suffix == '.CAP'
    old, new = read_image(BASELINE), read_image(candidate)
    official = OFFICIAL.read_bytes()
    assert sha(old['cap']) == BASELINE_SHA
    assert sha(new['cap']) == report['candidate_sha256']
    assert len(new['cap']) == len(old['cap']) == len(official) == 33558528
    for reference in (old['cap'], official):
        assert new['cap'][:BASE] == reference[:BASE]
        assert new['cap'][BASE + SIZE:] == reference[BASE + SIZE:]
    preserved_wrapper(old, new)
    wanted = approved_modules(manifest['modules'])
    assert len(wanted) == len(manifest['modules'])
    changes, additions = [], []
    for layer in ('outer', 'inner'):
        before, after = old[layer + '_files'], new[layer + '_files']
        assert list(after)[:len(before)] == list(before), 'Existing FFS order changed'
        assert old[layer + '_info']['header_sha256'] == new[layer + '_info']['header_sha256']
        assert set(before) <= set(after), 'A firmware file was removed'
        for guid, entry in before.items():
            if entry['data'] != after[guid]['data']:
                if layer == 'outer':
                    assert guid == WRAPPER
                else:
                    assert guid in wanted and wanted[guid]['role'] == 'sensors_dashboard'
                    changes.append(guid)
        for guid in set(after) - set(before):
            assert layer == 'inner' and guid in wanted and wanted[guid]['role'] == 'inventory'
            additions.append(guid)
    assert changes == [R2_GUID], 'Exactly the frozen sensor core must replace R2'
    assert set(additions) == set(wanted) - {R2_GUID}, 'Every approved inventory driver must be newly added'
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
                  hardware_flashing_performed=False,
                  scope='Offline structural read-back only; runtime evidence is separate.')
    (directory / 'independent-container-verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('directory', type=Path)
    verify(p.parse_args().directory.resolve())
