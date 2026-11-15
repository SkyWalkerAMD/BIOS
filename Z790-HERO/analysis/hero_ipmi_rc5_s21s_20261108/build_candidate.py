"""Assemble IPMI-only RC5: exactly the frozen R4 and native-P6 replacements.

This is an offline container operation. It never opens a device, changes a
signing policy, or claims that an output has passed a hardware flash test.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import lzma
import struct
import subprocess
import sys
import uuid

if not __debug__:
    raise RuntimeError('Optimized Python disables required assertions; run without -O or PYTHONOPTIMIZE')

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
BASELINE = ROOT / 'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/HERO-3107-IPMI-SECTIONFIX-LATEST-UNSIGNED.CAP'
BASELINE_SHA = '66420b42a5251a1209cac9865d3a1d8d5f1e03e512b4b9ce98ba0d29b81be131'
WRAPPER = '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
R2 = '89924765-f984-4ad3-839b-51fdce378d88'
P6 = '261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
R4_FFS_SHA = '3b3665040f28e374b0056fd98a7b1b283f6baaeb77067f34e3d701564fb04ed3'
R4_PE_SHA = 'a3036261c18bd66b158844a6818cf828b54af002dbb9ecf45d8dbc97a5317b2f'
# Frozen native21B S21S: FROZEN-CORE-UTF8.json; 53+35+17 author PE checks.
# Exact AfterBoot hardware evidence is separate; first SetupEnter/F10/flash remain pending.
# No manifest may approve its own executable payload or add a new release.
P6_RELEASE = {
    'sha256': '75f2f92feaaeccc1eadccf2beda02d7f2d3dc34ffa9058a62928d16009b7a63b',
    'pe_sha256': '401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66',
}
P5 = ROOT / 'analysis/hero_ipmi_p5'
spec = importlib.util.spec_from_file_location('hero_container_builder', P5 / 'build_candidate.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def workspace_file(relative):
    p = (ROOT / relative).resolve()
    if not p.is_relative_to(ROOT) or not p.is_file():
        raise ValueError('Artifact must be an existing workspace file')
    return p


def approved_entry(entry):
    if not isinstance(entry, dict):
        raise ValueError('Module must be an object')
    role = entry.get('role')
    if role == 'sensors_dashboard':
        wanted = dict(guid=R2, sha256=R4_FFS_SHA, pe_sha256=R4_PE_SHA)
    elif role == 'native_ipmi':
        if P6_RELEASE is None:
            raise ValueError('Native P6 release is not frozen; no CAP may be generated')
        wanted = dict(guid=P6, sha256=P6_RELEASE['sha256'], pe_sha256=P6_RELEASE['pe_sha256'])
    else:
        raise ValueError('IPMI-only build rejects inventory and unknown roles')
    for key, expected in wanted.items():
        actual = entry.get(key)
        if key == 'guid' and isinstance(actual, str):
            actual = actual.lower()
        if actual != expected:
            raise ValueError('Unapproved release identity/hash: ' + key)


def approved_module_set(modules):
    if not isinstance(modules, list) or len(modules) != 2:
        raise ValueError('Require exactly R4 sensors/Dashboard and native P6 IPMI')
    if any(not isinstance(e, dict) for e in modules):
        raise ValueError('Each module must be an object')
    roles = [e.get('role') for e in modules]
    if roles.count('native_ipmi') != 1 or roles.count('sensors_dashboard') != 1:
        raise ValueError('Only one sensor core and one native IPMI core; no inventory/additions')
    for entry in modules:
        approved_entry(entry)
    if {e['guid'].lower() for e in modules} != {R2, P6}:
        raise ValueError('New or duplicate GUIDs are forbidden')


def strict_sections(blob):
    """Reject even zero padding after the last section (AMI ReadSection rule)."""
    result = []
    pos = 0
    while pos < len(blob):
        if len(blob) - pos < 4:
            raise ValueError('Trailing bytes after final section')
        size = int.from_bytes(blob[pos:pos + 3], 'little')
        header = 4
        if size == 0xffffff:
            if len(blob) - pos < 8:
                raise ValueError('Truncated extended section')
            size = struct.unpack_from('<I', blob, pos + 4)[0]
            header = 8
        if size < header or pos + size > len(blob):
            raise ValueError('Section extent is outside its stream')
        result.append((blob[pos + 3], blob[pos + header:pos + size]))
        end = pos + size
        if end == len(blob):
            return result
        pos = (end + 3) & ~3
        if pos >= len(blob) or any(blob[end:pos]):
            raise ValueError('Invalid section alignment or final padding')
    raise ValueError('Empty section stream')


def driver_artifact(entry):
    approved_entry(entry)
    p = workspace_file(entry['path'])
    data = p.read_bytes()
    if sha(data) != entry['sha256']:
        raise ValueError('Driver artifact hash mismatch')
    if len(data) < 24 or int.from_bytes(data[20:23], 'little') != len(data):
        raise ValueError('Invalid FFS size')
    if data[18:20] != b'\x07\x00' or data[17] != 0xaa or data[23] != 0xf8:
        raise ValueError('Expected a standard, uncompressed-header DXE driver FFS')
    if (sum(data[:17]) + sum(data[18:23])) & 255:
        raise ValueError('Invalid FFS checksum')
    guid = str(uuid.UUID(bytes_le=data[:16]))
    if guid != entry['guid'].lower():
        raise ValueError('FFS GUID does not match the manifest')
    ss = strict_sections(data[24:])
    if [s[0] for s in ss] != [0x13, 0x10, 0x15]:
        raise ValueError('New core must contain DEPEX, PE32, UI in that order')
    pe = ss[1][1]
    if sha(pe) != entry['pe_sha256'] or pe[:2] != b'MZ' or len(pe) < 0x40:
        raise ValueError('Unexpected PE payload')
    off = struct.unpack_from('<I', pe, 0x3c)[0]
    if off + 94 > len(pe) or pe[off:off + 4] != b'PE\0\0':
        raise ValueError('Invalid PE header')
    if struct.unpack_from('<H', pe, off + 4)[0] != 0x8664:
        raise ValueError('Only x64 UEFI images are supported')
    if struct.unpack_from('<H', pe, off + 24)[0] != 0x20b:
        raise ValueError('Expected PE32+')
    if struct.unpack_from('<H', pe, off + 24 + 68)[0] != 11:
        raise ValueError('Expected EFI boot-service driver subsystem')
    return guid, data, dict(path=str(p.relative_to(ROOT)), sha256=sha(data),
                            pe_sha256=sha(pe), ffs_bytes=len(data), pe_bytes=len(pe),
                            depex_hex=ss[0][1].hex(), role=entry['role'])


def guided(plain, out):
    raw = out / 'wrapper-stream.bin'
    encoded = out / 'wrapper-stream.lzma'
    raw.write_bytes(plain)
    subprocess.run([str(P5 / 'host-lzma/encode.exe'), str(raw), str(encoded)], check=True)
    z = encoded.read_bytes()
    if lzma.decompress(z, format=lzma.FORMAT_ALONE) != plain:
        raise ValueError('Compression round trip failed')
    if struct.unpack_from('<Q', z, 5)[0] != len(plain):
        raise ValueError('Incorrect LZMA declared length')
    return base.make_section(2, base.LZMA_GUID + struct.pack('<HH', 24, 1) + z)


def build(manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    original = BASELINE.read_bytes()
    if sha(original) != BASELINE_SHA:
        raise ValueError('Baseline changed')
    modules = manifest.get('modules', [])
    approved_module_set(modules)
    parsed = [driver_artifact(e) for e in modules]
    if len({g for g, _, _ in parsed}) != len(parsed):
        raise ValueError('Duplicate driver GUID')
    label = manifest.get('build_id', '')
    if not label or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-' for c in label):
        raise ValueError('Invalid build identifier')
    out = HERE / label
    if out.exists():
        raise ValueError('Build directory already exists; preserve it and choose a new identifier')
    outer = original[base.BASE:base.BASE + base.LENGTH]
    outer_before = {f['guid']: f['data'] for f in base.files(outer)[0]}
    wrapper = outer_before[WRAPPER]
    ws = strict_sections(wrapper[24:])
    if len(ws) != 1 or ws[0][0] != 2 or ws[0][1][:16] != base.LZMA_GUID:
        raise ValueError('Unexpected DXE wrapper')
    parts = strict_sections(lzma.decompress(ws[0][1][20:], format=lzma.FORMAT_ALONE))
    if len(parts) != 2 or parts[1][0] != 0x17:
        raise ValueError('Unexpected inner firmware volume')
    inner = parts[1][1]
    inner_before = {f['guid']: f['data'] for f in base.files(inner)[0]}
    replacements = {}
    for guid, data, meta in parsed:
        if guid not in inner_before or guid in outer_before or guid not in (R2, P6):
            raise ValueError('Both approved cores must replace existing inner FFS; additions forbidden')
        if inner_before[guid] == data:
            raise ValueError('Both approved IPMI cores must actually change')
        replacements[guid] = data
    newinner, ii = base.pack_fv(inner, replacements, [])
    inner_after = {f['guid']: f['data'] for f in base.files(newinner)[0]}
    assert list(inner_before) == list(inner_after)
    assert all(inner_after[g] == b for g, b in inner_before.items() if g not in replacements)
    out.mkdir(exist_ok=True)
    rebuilt = base.pack_sections([base.make_section(parts[0][0], parts[0][1]),
                                  base.make_section(0x17, newinner)])
    newwrapper = base.rebuild_file(wrapper, guided(rebuilt, out))
    newouter, oi = base.pack_fv(outer, {WRAPPER: newwrapper})
    outer_after = {f['guid']: f['data'] for f in base.files(newouter)[0]}
    assert list(outer_after) == list(outer_before)
    assert all(outer_after[g] == b for g, b in outer_before.items() if g != WRAPPER)
    cap = original[:base.BASE] + newouter + original[base.BASE + base.LENGTH:]
    assert len(cap) == len(original) == 33558528
    assert cap[:base.BASE] == original[:base.BASE]
    assert cap[base.BASE + base.LENGTH:] == original[base.BASE + base.LENGTH:]
    name = 'HERO-3107-IPMI-' + label + '-UNSIGNED.CAP'
    destination = out / name
    if destination.exists() and destination.read_bytes() != cap:
        raise ValueError('Use a new build identifier for changed firmware')
    destination.write_bytes(cap)
    report = dict(schema='hero-rc5-ipmi-only-container-2', build_id=label,
                  baseline=str(BASELINE.relative_to(ROOT)), baseline_sha256=BASELINE_SHA,
                  candidate=str(destination.relative_to(ROOT)), candidate_sha256=sha(cap),
                  candidate_bytes=len(cap), manifest_sha256=sha(manifest_path.read_bytes()),
                  modules={g: m for g, _, m in parsed},
                  changed_inner_ffs=list(replacements), added_inner_ffs=[],
                  inner_free_bytes=ii['new_free'], outer_free_bytes=oi['new_free'],
                  unrelated_ffs_byte_identical=True, p6_native_ipmi_replaced=True,
                  inventory_included=False, new_guid_additions_allowed=False,
                  outside_dxe_byte_identical=True, strict_new_driver_sections=True,
                  original_capsule_header_preserved=True, modified_payload_asus_signature_valid=False,
                  hardware_flash_validated=False, official_asus_release=False,
                  note='Runtime and field evidence must be supplied separately; packaging does not prove hardware behavior.')
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (out / 'integration-manifest.json').write_bytes(manifest_path.read_bytes())
    print(json.dumps(report, indent=2))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('manifest', type=Path)
    build(p.parse_args().manifest.resolve())
