"""Offline RC3 assembly: byte-identical P5 RC2 plus byte-identical R2 core.

Never opens a hardware device or overwrites an input. Existing inner-FV file
bytes AND offsets are preserved. Outputs are unsigned experimental firmware.
"""
from pathlib import Path
import hashlib, importlib.util, json, lzma, struct, subprocess, uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / 'firmware'
RC2 = ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP'
R2 = ROOT / 'analysis/hero_ipmi_r2'
P5 = ROOT / 'analysis/hero_ipmi_p5'
R2_GUID = '89924765-f984-4ad3-839b-51fdce378d88'
WRAPPER = '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
RC2_SHA = '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
R2_PE_SHA = '1e206aa41b6133c642d724fa1c6aae2f2cd28eb6010a55a66b22a89c3b354845'
R2_FFS_SHA = '8c4b381f533929b8e7281abbf604006319f18ce5893cc4d1a6ce8130edc256da'

def sha(data): return hashlib.sha256(data).hexdigest()

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

base = load('p5_builder', P5 / 'build_candidate.py')

def guided(plain):
    cache = HERE / 'compression'
    cache.mkdir(exist_ok=True)
    source = cache / (sha(plain) + '.bin')
    dest = source.with_suffix('.lzma')
    source.write_bytes(plain)
    subprocess.run([str(P5 / 'host-lzma/encode.exe'), str(source), str(dest)], check=True)
    encoded = dest.read_bytes()
    assert struct.unpack_from('<Q', encoded, 5)[0] == len(plain)
    assert lzma.decompress(encoded, format=lzma.FORMAT_ALONE) == plain
    return base.make_section(2, base.LZMA_GUID + struct.pack('<HH', 24, 1) + encoded)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    source = RC2.read_bytes()
    assert sha(source) == RC2_SHA and len(source) == 33558528
    driver = (R2 / 'HeroIpmiCoreR2.ffs').read_bytes()
    runtime = (R2 / 'USB/EFI/HERO/HeroIpmiR2.efi').read_bytes()
    assert sha(driver) == R2_FFS_SHA and sha(runtime) == R2_PE_SHA
    assert str(uuid.UUID(bytes_le=driver[:16])) == R2_GUID
    assert [s[1] for s in base.sections(driver[24:]) if s[0] == 0x10] == [runtime]
    outer = source[base.BASE:base.BASE + base.LENGTH]
    outer_files, _ = base.files(outer)
    wrapper = next(f['data'] for f in outer_files if f['guid'] == WRAPPER)
    parts = base.sections(wrapper[24:])
    assert len(parts) == 1 and parts[0][0] == 2 and parts[0][1][:16] == base.LZMA_GUID
    inner_parts = base.sections(lzma.decompress(parts[0][1][20:], format=lzma.FORMAT_ALONE))
    assert len(inner_parts) == 2 and inner_parts[1][0] == 0x17
    inner = inner_parts[1][1]
    old, old_end = base.files(inner)
    assert not any(f['guid'] == R2_GUID for f in old)
    assert sum(f['guid'] == base.DRIVER for f in old) == 1
    new_inner, inner_info = base.pack_fv(inner, {}, [driver])
    new_files, _ = base.files(new_inner)
    for a, b in zip(old, new_files):
        assert a == b, 'Existing inner FFS bytes or offset changed'
    assert new_files[-1]['guid'] == R2_GUID and new_files[-1]['offset'] == old_end
    new_wrapper = base.rebuild_file(wrapper, guided(base.pack_sections([
        inner_parts[0][2], base.make_section(0x17, new_inner)])))
    new_outer, outer_info = base.pack_fv(outer, {WRAPPER: new_wrapper})
    candidate = source[:base.BASE] + new_outer + source[base.BASE + base.LENGTH:]
    assert len(candidate) == len(source)
    assert candidate[:base.BASE] == source[:base.BASE]
    assert candidate[base.BASE + base.LENGTH:] == source[base.BASE + base.LENGTH:]
    path = OUT / 'HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
    path.write_bytes(candidate)
    (OUT / 'RC3-inner-fv.bin').write_bytes(new_inner)
    report = dict(version='HERO 3107 IPMI P5 + R2 RC3', date='2026-11-04',
        scope='Offline assembly; no hardware flashing, BMC access, or NVRAM access',
        base=str(RC2.relative_to(ROOT)), base_sha256=RC2_SHA,
        candidate=str(path.relative_to(ROOT)), candidate_sha256=sha(candidate),
        candidate_bytes=len(candidate), r2_pe_sha256=R2_PE_SHA, r2_ffs_sha256=R2_FFS_SHA,
        p5_pe_sha256=sha((P5 / 'USB/EFI/HERO/HeroIpmiP5.efi').read_bytes()),
        existing_inner_ffs_bytes_and_offsets_preserved=True,
        outside_dxe_container_byte_identical=True, capsule_header_unchanged=True,
        r2_only_in_existing_inner_dxe_fv=True, r2_offset=hex(old_end),
        inner=inner_info, outer=outer_info,
        official_asus_release=False, modified_payload_asus_signature_valid=False,
        rc3_hardware_flashing_tested=False, rc3_auto_initialization_tested_on_hardware=False,
        rc2_hardware_status='User reported FlashBack success, native pages populated before ISO, OS boots on .71',
        sensor_target='Eight previously observed motherboard temperature/voltage readings; no promise of 25 Normal Sensors',
        limitations=['R2 automatic initialization runs once at ReadyToBoot, not simply on entering BIOS Setup.',
            'P5 menus retain RC1 resource banner and read-only settings; same bytes as working RC2.',
            'Existing saved disable or failed-attempt lock is honored; no reset, override, or automatic unlock.',
            'Motherboard fan/pump mapping, LED synchronization, in-band driver selection remain unimplemented.',
            'RC3 FlashBack acceptance, automatic startup and recovery require onsite confirmation.'])
    (HERE / 'build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('inner','outer')}, indent=2))

if __name__ == '__main__': main()
