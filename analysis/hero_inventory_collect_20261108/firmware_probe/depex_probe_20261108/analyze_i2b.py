"""Offline identity/dependency facts from the exact I2B capture; writes this folder only."""
from pathlib import Path
import ast
import hashlib
import json
import uuid
import zlib

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
LIVE = ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-fw-i2b.TXT'
OLD = ROOT / 'analysis/hero_ipmi_p6_20261104/firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP.dump-441b61136974'
ARCHIVE = ROOT / 'analysis/hero_ipmi_p6_20261104/review-20261108/container-441b61136974/P6-RC4.CAP'
NAMES = {
    '30cfe3e7-3de1-4586-be20-deaba1b3b793': 'PciEnumerationComplete',
    '6441f818-6362-4e44-b570-7dba31dd2453': 'VariableWriteArch',
    'ef9fc172-a1b2-4693-b327-6d32fc416042': 'HiiDatabase',
    '0fd96974-23aa-4cdc-b9cb-98d17750322a': 'HiiString',
}


def digest(data):
    return dict(bytes=len(data), crc32=f'{zlib.crc32(data):08X}',
                sha256=hashlib.sha256(data).hexdigest())


def file_fact(path):
    return dict(path=path.relative_to(ROOT).as_posix(), **digest(path.read_bytes()))


def one(paths):
    paths = list(paths)
    assert len(paths) == 1, paths
    return paths[0]


def sections(body):
    result = []
    pos = 0
    while pos < len(body):
        if len(body) - pos < 4:
            assert not any(body[pos:]), 'nonzero tail'
            break
        size = int.from_bytes(body[pos:pos+3], 'little')
        kind = body[pos+3]
        assert size not in (0, 0xFFFFFF) and size >= 4
        assert size <= len(body) - pos
        end = pos + size
        result.append((kind, body[pos+4:end]))
        aligned = (end + 3) & ~3
        assert not any(body[end:min(aligned, len(body))])
        pos = aligned
    return result


def depex(data):
    """Validate the PUSH/AND/END subset actually present, including operand bounds."""
    pos = 0
    stack = []
    tokens = []
    while pos < len(data):
        opcode = data[pos]
        pos += 1
        if opcode == 2:
            assert pos + 16 <= len(data)
            guid = str(uuid.UUID(bytes_le=data[pos:pos+16]))
            pos += 16
            stack.append(NAMES.get(guid, guid))
            tokens.append(dict(op='PUSH', guid=guid, name=NAMES.get(guid)))
        elif opcode == 3:
            assert len(stack) >= 2
            right, left = stack.pop(), stack.pop()
            stack.append(f'({left} AND {right})')
            tokens.append(dict(op='AND'))
        elif opcode == 8:
            assert pos == len(data) and len(stack) == 1
            tokens.append(dict(op='END'))
            return dict(valid=True, hex=data.hex().upper(), tokens=tokens,
                        expression=stack[0])
        else:
            raise AssertionError(f'unexpected opcode {opcode:#x}')
    raise AssertionError('missing END')


def source_deps(path):
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == 'deps' for t in node.targets):
            deps = ast.literal_eval(node.value)
            data = b''
            for i, guid in enumerate(deps):
                data += b'\x02' + uuid.UUID(guid).bytes_le + (b'\x03' if i else b'')
            return data + b'\x08'
    raise AssertionError('no deps assignment')


def module(path, *, raw_body=False):
    data = path.read_bytes()
    if raw_body:
        body = data
    else:
        assert len(data) >= 24 and int.from_bytes(data[20:23], 'little') == len(data)
        assert data[18] == 7 and not data[19] & 1
        body = data[24:]
    parts = sections(body)
    pe = one(p for t, p in parts if t == 0x10)
    dx = one(p for t, p in parts if t == 0x13)
    return dict(source=file_fact(path), body=digest(body), pe=digest(pe), depex=depex(dx))


def parse_live(raw):
    fields, records, apis = {}, [], {}
    index = None
    record = None
    api_target = None
    for line in raw.decode('ascii').splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key == 'FP_FV_INDEX':
            index = int(value, 16)
            record = None
        elif key == 'FP_FV_TARGET':
            record = dict(fv_index=index, target=value)
            records.append(record)
        elif key == 'FP_API_TARGET':
            api_target = value
            record = None
        elif key == 'FP_API_LOCATE_STATUS':
            apis[api_target] = value
        if record is not None:
            # Keep only one-valued facts, not the repeated per-section fields.
            if not key.startswith('FP_FV_SECTION_'):
                record[key] = value
        fields[key] = value
    successful = {r['target']: r for r in records if r.get('FP_FV_READFILE_STATUS') == '0000000000000000'}
    assert len(successful) == 2
    assert all(r['fv_index'] == 6 and r['FP_FV_LOCAL_PARSE_STATUS'] == '0000000000000000'
               and r['FP_FV_BODY_PREALLOC_STATUS'] == '0000000000000000'
               for r in successful.values())
    return fields, successful, apis


def matches(local, live):
    return dict(
        body_size=local['body']['bytes'] == int(live['FP_FV_BODY_BYTES'], 16),
        body_crc32=int(local['body']['crc32'], 16) == int(live['FP_FV_BODY_CRC32'], 16),
        pe_size=local['pe']['bytes'] == int(live['FP_FV_PE_BYTES'], 16),
        pe_crc32=int(local['pe']['crc32'], 16) == int(live['FP_FV_PE_CRC32'], 16),
        depex=local['depex']['hex'] == live['FP_FV_DEPEX_HEX'])


def main():
    raw = LIVE.read_bytes()
    assert digest(raw) == dict(bytes=6495, crc32='A58AC3DF',
        sha256='4f12cee70e9f0a0339b0d114927f7a46bcdf45322bc66ab7e3119d223d41e3b6')
    fields, live, apis = parse_live(raw)
    old_p6 = one(OLD.rglob('534 HeroIpmiNativeP6/body.bin'))
    local = {
        'R2': module(ROOT / 'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs'),
        'P6_archived_441b61136974': module(old_p6, raw_body=True),
        'P5_RC2_RC3': module(ROOT / 'analysis/hero_ipmi_p5/HeroIpmiNativeP5.ffs'),
        'P6_current_local': module(ROOT / 'analysis/hero_ipmi_p6_20261104/HeroIpmiNativeP6.ffs'),
    }
    comparisons = {name: matches(m, live['R2' if name == 'R2' else 'P5_P6'])
                   for name, m in local.items()}
    assert all(comparisons['R2'].values())
    assert all(comparisons['P6_archived_441b61136974'].values())
    assert not comparisons['P5_RC2_RC3']['pe_crc32']
    assert not comparisons['P6_current_local']['pe_crc32']
    build_paths = {
        'R2': ROOT / 'analysis/hero_ipmi_r2/build.py',
        'P5_P6': ROOT / 'analysis/hero_ipmi_p6_20261104/build_runtime.py',
    }
    parsed_depex = {}
    for name, record in live.items():
        captured = bytes.fromhex(record['FP_FV_DEPEX_HEX'])
        parsed_depex[name] = depex(captured)
        parsed_depex[name]['matches_current_builder_deps_bytes'] = source_deps(build_paths[name]) == captured
        parsed_depex[name]['current_builder'] = file_fact(build_paths[name])
        assert parsed_depex[name]['matches_current_builder_deps_bytes']
    archive = file_fact(ARCHIVE)
    assert archive['sha256'] == '441b61136974278a0c6fc0d46edc159c1f1557c981ae9e4a4b42b67eb65fba0f'
    result = dict(
        scope='Offline analysis of an already captured hardware log; no network or firmware mutation.',
        capture=file_fact(LIVE),
        loaded_image_observations={k: int(fields[k], 16) for k in (
            'FP_LOADED_HANDLE_COUNT', 'FP_LOADED_SCANNED', 'FP_LOADED_PROTOCOL_UNREADABLE',
            'FP_LOADED_PATH_UNREADABLE', 'FP_LOADED_NULL_FILEPATHS', 'FP_LOADED_NONMATCHING_PATHS',
            'FP_LOADED_FV_FILEPATHS', 'FP_R2_LOADED_MATCHES', 'FP_P5_P6_LOADED_MATCHES',
            'FP_ENUM_OR_READ_INCOMPLETE')},
        api_locate_status=apis, live_successful_files=live,
        local_reference_files=local, comparisons=comparisons,
        local_archive=archive, dependency_validation=parsed_depex,
        established=[
            'At capture time both target GUID files exist in visible FV index 6; saying R2 is absent is false.',
            'ReadFile with a bounded preallocated buffer succeeded for both files; fallback was not used.',
            'Live size+CRC32 of body and PE, plus exact DEPEX bytes, match local R2 and archived early-RC4 P6.',
            'The live P5/P6 fingerprint differs from local RC2/RC3 P5 and the newer local P6 build.',
            'The captured dependency bytecode is well-formed PUSH/AND/END with correct GUID byte order.',
            'P6 depends on HiiString; HiiPackageList is not an operand in these captured dependencies.',
            'No matching LoadedImage FV filepath and no target API were found at this capture point.',
        ],
        limitations=[
            'Only live CRC32, sizes, DEPEX and metadata were captured. No live module SHA256 or whole-SPI/CAP hash was captured.',
            'The local archive SHA256 identifies the reference file only; these module fingerprints do not prove the whole installed firmware equals that CAP.',
            'CRC32 is not collision resistant. The evidence supports reference correspondence, not cryptographic identity of live code.',
            'LoadedImage/API absence does not distinguish never dispatched, entry failure/unload, or later removal by itself.',
            'I2B did not query the dependency protocols. A missing VariableWriteArch protocol is still a hypothesis.',
            'Protocol presence in an application-stage follow-up cannot reconstruct the earlier DXE dispatcher timeline.',
            'A success status with NULL interface is a valid architectural-marker result and must count as present.',
        ],
        next_step='Integrate standalone depex_probe.c into I3a D diagnostics; 5 LocateProtocol and one bounded GetVariable only. Do not remove dependencies or change SPI from these observations alone.',
    )
    (OUT / 'i2b-analysis.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(capture=result['capture'], comparisons=comparisons,
                         depex={k: v['expression'] for k, v in parsed_depex.items()}), indent=2))


if __name__ == '__main__':
    main()
