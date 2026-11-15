"""RC2: place the unchanged P5 driver in the original DXE dispatch volume.

All inputs are read from the reviewed P5 build. Outputs are isolated in rc2/.
This script never accesses a device, firmware variables, or a flashing tool.
"""
from pathlib import Path
import hashlib, importlib.util, json, lzma, struct, subprocess, uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
P5 = ROOT / 'analysis/hero_ipmi_p5'
OUT = HERE / 'rc2'
spec = importlib.util.spec_from_file_location('p5_container', P5 / 'build_candidate.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def guided(plain):
    cache = OUT / 'compression'
    cache.mkdir(parents=True, exist_ok=True)
    source = cache / (sha(plain) + '.bin')
    target = source.with_suffix('.lzma')
    source.write_bytes(plain)
    subprocess.run([str(P5/'host-lzma/encode.exe'), str(source), str(target)], check=True)
    z = target.read_bytes()
    assert struct.unpack_from('<Q', z, 5)[0] == len(plain)
    assert lzma.decompress(z, format=lzma.FORMAT_ALONE) == plain
    return base.make_section(2, base.LZMA_GUID + struct.pack('<HH', 24, 1) + z)

def main():
    OUT.mkdir(exist_ok=True)
    original = base.ORIGINAL.read_bytes()
    assert sha(original) == 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
    assert json.loads((P5/'native-verification.json').read_text())['passed']
    inventory = next(iter(json.loads((base.OFFICIAL/'inventory.json').read_text()).values()))
    setup_dir = ROOT / next(x['path'] for x in inventory if x['guid'].lower() == base.SETUP)
    fv_dir = setup_dir.parent
    inner = (fv_dir/'header.bin').read_bytes() + (fv_dir/'body.bin').read_bytes()
    old, _ = base.files(inner)
    by_guid = {x['guid']: x['data'] for x in old}
    assert len(by_guid) == len(old) and base.DRIVER not in by_guid

    setup_parts = base.sections(by_guid[base.SETUP][24:])
    assert [s[0] for s in setup_parts] == [0x13, 0x10, 0x14]
    setup_pe = (P5/'Setup-P5-RESOURCE-REVIEW.efi').read_bytes()
    new_setup = base.rebuild_file(by_guid[base.SETUP], base.pack_sections([
        setup_parts[0][2], guided(base.make_section(0x10, setup_pe)), setup_parts[2][2]]))
    old_spf = base.sections(by_guid[base.SPF][24:])
    assert len(old_spf) == 1 and old_spf[0][0] == 2 and old_spf[0][1][:16] == base.LZMA_GUID
    spf_parts = base.sections(lzma.decompress(old_spf[0][1][20:], format=lzma.FORMAT_ALONE))
    assert [s[0] for s in spf_parts] == [0x18, 0x15]
    assert spf_parts[0][1][:16] == uuid.UUID(base.SPF).bytes_le
    spf = (P5/'AMITSESetupData-P5.bin').read_bytes()
    new_spf = base.rebuild_file(by_guid[base.SPF], guided(base.pack_sections([
        base.make_section(0x18, spf_parts[0][1][:16] + spf), spf_parts[1][2]])))

    driver = (P5/'HeroIpmiNativeP5.ffs').read_bytes()
    runtime = (P5/'USB/EFI/HERO/HeroIpmiP5.efi').read_bytes()
    assert sha(runtime) == 'bfdf3ae73fee0492ae664f0925ae86a26607aafa00c0c41d3fd32a1257383a71'
    assert str(uuid.UUID(bytes_le=driver[:16])) == base.DRIVER
    driver_parts = base.sections(driver[24:])
    assert [s[1] for s in driver_parts if s[0] == 0x10] == [runtime]
    rebuilt_inner, inner_info = base.pack_fv(inner, {base.SETUP:new_setup, base.SPF:new_spf}, [driver])

    outer = original[base.BASE:base.BASE+base.LENGTH]
    outer_files, _ = base.files(outer)
    wrapper_guid = '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
    wrapper = next(x['data'] for x in outer_files if x['guid'] == wrapper_guid)
    wrapper_sections = base.sections(wrapper[24:])
    assert len(wrapper_sections) == 1 and wrapper_sections[0][0] == 2
    parts = base.sections(lzma.decompress(wrapper_sections[0][1][20:], format=lzma.FORMAT_ALONE))
    assert len(parts) == 2 and parts[1][0] == 0x17 and parts[1][1] == inner
    new_wrapper = base.rebuild_file(wrapper, guided(base.pack_sections([
        parts[0][2], base.make_section(0x17, rebuilt_inner)])))
    rebuilt_outer, outer_info = base.pack_fv(outer, {wrapper_guid:new_wrapper})
    candidate = original[:base.BASE] + rebuilt_outer + original[base.BASE+base.LENGTH:]
    assert len(candidate) == len(original)
    assert candidate[:base.BASE] == original[:base.BASE]
    assert candidate[base.BASE+base.LENGTH:] == original[base.BASE+base.LENGTH:]
    new_inner_files, _ = base.files(rebuilt_inner)
    new_outer_files, _ = base.files(rebuilt_outer)
    assert sum(x['guid'] == base.DRIVER for x in new_inner_files) == 1
    assert not any(x['guid'] == base.DRIVER for x in new_outer_files)
    (OUT/'HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP').write_bytes(candidate)
    (OUT/'P5-RC2-inner-fv.bin').write_bytes(rebuilt_inner)
    report = dict(version='P5 RC2 TEST CANDIDATE', original_sha256=sha(original),
        candidate_sha256=sha(candidate), bytes=len(candidate),
        revision='Move byte-identical P5 runtime from outer to existing inner DXE FV',
        runtime_sha256=sha(runtime), setup_sha256=sha(setup_pe), spf_sha256=sha(spf),
        driver_in_inner_fv=True, driver_in_outer_fv=False,
        outside_dxe_container_unchanged=True, capsule_header_unchanged=True,
        inner=inner_info, outer=outer_info,
        hardware_flashback_accepted=False, hardware_native_menu_verified=False,
        firmware_configuration_writes_implemented=False,
        note='The driver preflight applies to unchanged runtime bytes only, not to flashed dispatch or native UI.')
    (OUT/'build.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('inner','outer')}, indent=2))

if __name__ == '__main__':
    main()
