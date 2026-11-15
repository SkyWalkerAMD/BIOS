"""Independent parser and whole UEFIExtract inventory comparison for RC3."""
from pathlib import Path
from collections import Counter
import hashlib, json, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103'))
from container_review import read_image, sections, depex_tokens, BASE, SIZE, WRAPPER, DRIVER, SETUP, SPF
from container_review_rc2 import extracted_files

R2_GUID = '89924765-f984-4ad3-839b-51fdce378d88'
RC2 = ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP'
CAP = HERE / 'firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
OFFICIAL = ROOT / 'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
def sha(b): return hashlib.sha256(b).hexdigest()

def main():
    old = read_image(RC2)
    new = read_image(CAP)
    original = OFFICIAL.read_bytes()
    assert sha(old['cap']) == '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
    assert len(new['cap']) == len(original) == len(old['cap']) == 33558528
    for baseline in (old['cap'], original):
        assert new['cap'][:BASE] == baseline[:BASE]
        assert new['cap'][BASE+SIZE:] == baseline[BASE+SIZE:]
    assert set(old['outer_files']) == set(new['outer_files'])
    assert set(new['inner_files']) == set(old['inner_files']) | {R2_GUID}
    assert R2_GUID not in new['outer_files'] and DRIVER not in new['outer_files']
    for layer, allowed in [('outer', {WRAPPER}), ('inner', set())]:
        assert old[layer+'_info']['header_sha256'] == new[layer+'_info']['header_sha256']
        for guid, entry in old[layer+'_files'].items():
            if guid not in allowed:
                assert entry['data'] == new[layer+'_files'][guid]['data']
                if layer == 'inner': assert entry['offset'] == new[layer+'_files'][guid]['offset']
    assert new['inner_files'][R2_GUID]['offset'] == int(old['inner_info']['used_end'], 16)
    assert new['inner_files'][R2_GUID]['data'] == (ROOT/'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs').read_bytes()
    before = extracted_files(RC2)
    after = extracted_files(CAP)
    assert set(after) == set(before) | {R2_GUID}
    changed = []
    identical = 0
    for guid, entries in before.items():
        assert len(entries) == len(after[guid])
        if Counter(sha(e['data']) for e in entries) != Counter(sha(e['data']) for e in after[guid]):
            changed.append(guid)
        else: identical += len(entries)
    assert changed == [WRAPPER]
    assert sum(map(len, before.values())) == 718
    assert sum(map(len, after.values())) == 719 and identical == 717
    payloads = []
    for guid, reference in [
        (R2_GUID, ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi'),
        (DRIVER, ROOT/'analysis/hero_ipmi_p5/USB/EFI/HERO/HeroIpmiP5.efi'),
        (SETUP, ROOT/'analysis/hero_ipmi_p5/Setup-P5-RESOURCE-REVIEW.efi')]:
        assert len(after[guid]) == 1
        images = [p for p in after[guid][0]['path'].rglob('body.bin') if p.parent.name.endswith('PE32 image section')]
        assert len(images) == 1 and images[0].read_bytes() == reference.read_bytes()
        payloads.append(dict(guid=guid, extracted=str(images[0].relative_to(ROOT)),
            reference=str(reference.relative_to(ROOT)), sha256=sha(reference.read_bytes()), bytes=reference.stat().st_size))
    deps = {}
    for guid in (R2_GUID, DRIVER):
        parts = sections(new['inner_files'][guid]['data'][24:])
        assert [s['type'] for s in parts] == [0x13, 0x10, 0x15]
        deps[guid] = depex_tokens(parts[0]['body'])
    assert [t[1] for t in deps[R2_GUID] if t[0]=='PUSH'] == [
        '30cfe3e7-3de1-4586-be20-deaba1b3b793', '6441f818-6362-4e44-b570-7dba31dd2453']
    # Entire official reset/FIT/microcode/ME/authentication regions outside this
    # already modified DXE container are byte-identical. This is not a fuse test.
    pointer = int.from_bytes(original[-0x40:-0x38], 'little')
    fit_offset = pointer - (0x100000000-(len(original)-0x1000)) + 0x1000
    assert original[fit_offset:fit_offset+8] == b'_FIT_   '
    count = int.from_bytes(original[fit_offset+8:fit_offset+11], 'little')
    assert original[fit_offset:fit_offset+16*count] == new['cap'][fit_offset:fit_offset+16*count]
    report = dict(passed=True, scope='Independent FV parser plus full UEFIExtract byte inventory; not hardware validation',
        candidate_sha256=sha(new['cap']), base_sha256=sha(old['cap']), official_sha256=sha(original),
        bytes=len(new['cap']), original_rc2_ffs_count=718, rc3_ffs_count=719,
        rc2_byte_identical_existing_ffs=identical, changed_existing_ffs=changed, added_ffs=R2_GUID,
        both_drivers_inside_original_inner_dxe_fv=True, existing_inner_offsets_preserved=True,
        setup_spf_p5_byte_identical_to_hardware_working_rc2=True,
        r2_byte_identical_to_previously_hardware_tested_manual_core=True,
        outside_dxe_container_and_capsule_header_byte_identical_to_official=True,
        fit_and_reset_bytes_unchanged=True, checksums_alignment_and_lzma_declared_sizes_valid=True,
        dependencies=deps, extracted_payloads=payloads,
        inner=new['inner_info'], outer=new['outer_info'],
        limitations=['No new capsule signing; FlashBack acceptance must be tested on target.',
                    'No live Boot Guard policy or automatic OEM initialization demonstrated by structural checks.'])
    (HERE/'container-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('extracted_payloads','inner','outer','dependencies')},indent=2))

if __name__ == '__main__': main()
