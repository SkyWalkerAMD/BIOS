"""Independent RC3 integration review. Writes only beside this script.

Reuses the earlier independent FV parser, not the RC3 builder/verifier.
Source review conclusions are in integration-review.txt. No target execution.
"""
from pathlib import Path
from collections import Counter
import hashlib
import io
import json
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103'))
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
sys.path.insert(0, str(ROOT / 'tools/kvm-pydeps'))
from container_review import read_image, sections, depex_tokens, BASE, SIZE, WRAPPER, DRIVER, SETUP, SPF
from container_review_rc2 import extracted_files
import pefile
import pycdlib

RC2 = ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP'
RC3 = HERE.parent / 'firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP'
R2 = '89924765-f984-4ad3-839b-51fdce378d88'
COLLECTOR = HERE.parent / 'collector'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def binding(path):
    data = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': sha(data)}


def main():
    old, new = read_image(RC2), read_image(RC3)
    assert sha(old['cap']) == '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
    assert sha(new['cap']) == '8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'
    assert len(old['cap']) == len(new['cap']) == 33558528
    assert old['cap'][:BASE] == new['cap'][:BASE]
    assert old['cap'][BASE+SIZE:] == new['cap'][BASE+SIZE:]
    assert set(old['outer_files']) == set(new['outer_files'])
    assert set(new['inner_files']) == set(old['inner_files']) | {R2}
    assert R2 not in new['outer_files'] and DRIVER not in new['outer_files']
    for layer, exception in [('outer', {WRAPPER}), ('inner', set())]:
        assert old[layer+'_info']['header_sha256'] == new[layer+'_info']['header_sha256']
        for guid, ffs in old[layer+'_files'].items():
            if guid not in exception:
                assert ffs['data'] == new[layer+'_files'][guid]['data']
                if layer == 'inner':
                    assert ffs['offset'] == new[layer+'_files'][guid]['offset']
    inserted = new['inner_files'][R2]
    assert inserted['offset'] == int(old['inner_info']['used_end'], 16)
    assert inserted['data'] == (ROOT/'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs').read_bytes()
    dependencies = {}
    for guid, reference in [
        (R2, ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi'),
        (DRIVER, ROOT/'analysis/hero_ipmi_p5/USB/EFI/HERO/HeroIpmiP5.efi')]:
        parts = sections(new['inner_files'][guid]['data'][24:])
        assert [p['type'] for p in parts] == [0x13, 0x10, 0x15]
        assert parts[1]['body'] == reference.read_bytes()
        dependencies[guid] = depex_tokens(parts[0]['body'])
    before, after = extracted_files(RC2), extracted_files(RC3)
    assert set(after) == set(before) | {R2}
    changed, same = [], 0
    for guid, files in before.items():
        if Counter(sha(f['data']) for f in files) == Counter(sha(f['data']) for f in after[guid]):
            same += len(files)
        else:
            changed.append(guid)
    assert changed == [WRAPPER] and same == 717
    assert sum(map(len, before.values())) == 718
    assert sum(map(len, after.values())) == 719
    for guid in (R2, DRIVER, SETUP, SPF):
        assert len(after[guid]) == 1
        if guid != R2:
            assert before[guid][0]['data'] == after[guid][0]['data']
    collector_build = json.loads((COLLECTOR/'build.json').read_text(encoding='utf-8'))
    for relative, expected in collector_build['source_hashes'].items():
        assert sha((COLLECTOR/'source'/relative).read_bytes()) == expected
    app = COLLECTOR/'USB/EFI/BOOT/BOOTX64.EFI'
    iso_path = COLLECTOR/'HERO-RC3-AUTO-LOG.iso'
    assert sha(app.read_bytes()) == collector_build['app_sha256']
    assert sha(iso_path.read_bytes()) == collector_build['iso_sha256']
    assert sha((COLLECTOR/'efi-boot.img').read_bytes()) == collector_build['boot_image_sha256']
    launcher = (COLLECTOR/'source/launcher.c').read_text(encoding='utf-8')
    calls = sorted(set(re.findall(r'service->([A-Za-z_][A-Za-z_0-9]*)\s*\(', launcher)))
    assert calls == ['config', 'log', 'status']
    all_c = '\n'.join(p.read_text(encoding='utf-8') for p in (COLLECTOR/'source').rglob('*.c'))
    forbidden_calls = re.findall(r'->(?:load_image|start_image|unload_image|set_variable)\s*\(', all_c)
    assert not forbidden_calls
    assert 'LAST_RUN_REPORT (lock may be unqueried)' in launcher
    assert 'if(service->manual_only)' in launcher
    pe = pefile.PE(str(app))
    assert pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Subsystem == 10 and pe.verify_checksum()
    assert not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')
    usb_files = {p.relative_to(COLLECTOR/'USB').as_posix(): p.read_bytes()
                 for p in (COLLECTOR/'USB').rglob('*') if p.is_file()}
    assert set(usb_files) == {'EFI/BOOT/BOOTX64.EFI', 'HERO_RC3.TAG'}
    iso = pycdlib.PyCdlib()
    iso.open(str(iso_path))
    assert iso.eltorito_boot_catalog.validation_entry.platform_id == 0xef
    for name, data in usb_files.items():
        retrieved = io.BytesIO()
        iso.get_file_from_iso_fp(retrieved, iso_path='/'+name+';1')
        assert retrieved.getvalue() == data
    embedded = io.BytesIO()
    iso.get_file_from_iso_fp(embedded, iso_path='/EFIBOOT.IMG;1')
    assert embedded.getvalue() == (COLLECTOR/'efi-boot.img').read_bytes()
    iso.close()
    prior_tests = []
    for relative in ['analysis/hero_ipmi_r2/verification.json', 'analysis/hero_ipmi_r2/entry-verification.json']:
        previous = json.loads((ROOT/relative).read_text(encoding='utf-8'))
        assert previous['driver_sha256'] == sha((ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi').read_bytes())
        prior_tests.append({'path': relative, 'count': previous['count'], 'all_passed': previous['all_passed'],
                            'reexecuted_by_this_review': False, 'coverage': 'Separate R2 synthetic fixtures, not combined P5/R2 hardware execution'})
    source_paths = [ROOT/f'analysis/hero_ipmi_{module}/source/{name}'
                    for module, names in [('r2', ['driver.c', 'common.c', 'engine.c', 'probe_core.c']),
                                           ('p5', ['driver.c', 'transport.c'])] for name in names]
    source_paths += [ROOT/'analysis/hero_ipmi_r2/verify.py', ROOT/'analysis/hero_ipmi_r2/verify_entry.py']
    source_paths += [COLLECTOR/'source/launcher.c', COLLECTOR/'source/kvm.c', COLLECTOR/'source/common.c',
                     COLLECTOR/'prepare_source.py', COLLECTOR/'build.py']
    additional_tests = []
    for relative, identity_field, expected_identity in [
        ('runtime-verification.json', 'candidate_sha256', sha(new['cap'])),
        ('collector/app-verification.json', 'app_sha256', sha(app.read_bytes()))]:
        path = HERE.parent/relative
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data[identity_field] == expected_identity
        assert data.get('passed', data.get('all_passed'))
        additional_tests.append({'path': str(path.relative_to(ROOT)), 'sha256': sha(path.read_bytes()),
                                 'count': data['count'], 'all_passed': True,
                                 'reexecuted_by_this_review': False, 'scope': data['scope']})
    vm_report = COLLECTOR/'vm-verification.json'
    vm_data = json.loads(vm_report.read_text(encoding='utf-8'))
    assert vm_data['all_passed'] and len(vm_data['cases']) == 2
    for case in vm_data['cases']:
        assert case['app_sha256'] == sha(app.read_bytes()) and case['iso_sha256'] == sha(iso_path.read_bytes())
    additional_tests.append({'path': str(vm_report.relative_to(ROOT)), 'sha256': sha(vm_report.read_bytes()),
                             'count': len(vm_data['cases']), 'all_passed': True,
                             'reexecuted_by_this_review': False, 'scope': vm_data['limitations']})
    report = {
        'date': '2026-11-04', 'reviewer': '/root/p5_container_review',
        'scope': 'Independent static integration and capture-tool review. No BMC access, flashing, source edits, or hardware execution.',
        'passed_static_checks': True,
        'disposition': 'No static blocker to the unchanged automatic P5/R2 integration with the capture-only tool. New RC3 hardware acceptance is not established by this report.',
        'bindings': [binding(p) for p in [RC2, RC3, ROOT/'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs',
                     ROOT/'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi',
                     ROOT/'analysis/hero_ipmi_p5/USB/EFI/HERO/HeroIpmiP5.efi', app, iso_path]],
        'sources': [binding(p) for p in source_paths],
        'container': {
            'same_rc2_existing_ffs': same, 'rc2_total_ffs': 718, 'rc3_total_ffs': 719,
            'changed_existing_ffs': changed, 'added_ffs': R2,
            'outer_driver_absent': True, 'both_drivers_in_existing_inner_dxe_fv': True,
            'existing_inner_offsets_preserved': True, 'inserted_offset_inner': hex(inserted['offset']),
            'inserted_bytes': inserted['size'], 'remaining_inner_free': new['inner_info']['free_bytes'],
            'remaining_outer_free': new['outer_info']['free_bytes'], 'depex': dependencies,
            'setup_spf_and_p5_exact_to_rc2': True, 'r2_ffs_exact_to_prior_r2': True,
            'outside_dxe_range_exact_to_rc2': True,
            'fv_ffs_checksums_alignment_state_and_erase_fill': 'passed independent parser assertions',
            'paths': {guid: str(after[guid][0]['path'].relative_to(ROOT)) for guid in (R2, DRIVER, SETUP, SPF)}},
        'collector': {
            'source_bound_to_build': True, 'service_calls': calls,
            'old_operation_hotkeys_absent': True, 'no_driver_load_start_unload_or_variable_write_call_in_collector_c_sources': True,
            'usb_payload': sorted(usb_files), 'iso_uefi_boot_catalog_and_embedded_image_verified': True,
            'explicit_l_writes_only_marked_boot_volume': True,
            'captures': 'R2 resident audit/config/last-run status only; P5 log is not exported.',
            'lock_field_caveat_displayed': True,
            'not_equivalent_to_hardware_read_only': 'The collector itself initiates no BMC query; booting it can trigger the already-resident ReadyToBoot automatic initializer before its entry point.',
            'other_effects': 'Disables UEFI application watchdog; renders console/GOP; explicit L writes TXT on marked writable boot volume.'},
        'scheduling': {
            'r2_ready_tpl': 8, 'p5_setup_and_timer_tpl': 8,
            'normal_automatic_callbacks': 'Same-TPL notifications do not preempt one another; no automatic cross-driver transaction overlap identified.',
            'manual_apis': 'No shared mutex or TPL promotion. Private busy/running guards are not cross-driver synchronization. Do not mix old manual diagnostic tools with this release.',
            'specification': 'https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html'},
        'prior_test_reports_inspected_not_rerun': prior_tests,
        'additional_reports_inspected_and_artifact_hashes_checked': additional_tests,
        'remaining_hardware_items': [
            'RC3 FlashBack acceptance and cold/warm boot on intended HERO.',
            'R2 firmware dispatch and ReadyToBoot run, including actual card BDF, BMC identity, and saved configuration/lock state.',
            'Successful 4/4 sequence when required, stable 16-record postcheck, PCI memory-bit restoration, and cleared attempt lock.',
            'Already-initialized no-replay branch on subsequent boot; failed/disabled branches without extra commands.',
            'Motherboard values versus native BIOS values; all 16 readable sensors and fan RPM are not guaranteed by the success gate.',
            'Native P5 pages and OS boot after co-resident R2 initialization.',
            'Passive collector QR/text/file paths on actual KVM/USB; static checks do not establish display compatibility.',
            'Actual recovery from RC3; earlier RC2 FlashBack success is separate evidence.'],
        'out_of_scope_capabilities': ['Editable Creator LAN/OS-watchdog settings', 'LED synchronization', 'Fan/pump mapping/control', 'Creator-equivalent full feature completion']}
    (HERE/'integration-review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'passed_static_checks': True, 'rc3_sha256': sha(new['cap']),
                      'same_rc2_existing_ffs': same, 'added_offset_inner': hex(inserted['offset']),
                      'remaining_inner_free': new['inner_info']['free_bytes'], 'collector_service_calls': calls,
                      'report': str(HERE/'integration-review.json')}, indent=2))


if __name__ == '__main__':
    main()
