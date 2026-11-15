"""Freeze reviewed candidate identity and evidence; no firmware modification."""
from pathlib import Path
import hashlib
import json

if not __debug__:
    raise RuntimeError('This freeze requires assertions enabled')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = 'RC5-IPMI-ONLY-R4-S21S-CANDIDATE03'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(path):
    data = path.read_bytes()
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=len(data), sha256=sha(data))


def main():
    candidate = HERE / BUILD / ('HERO-3107-IPMI-' + BUILD + '-UNSIGNED.CAP')
    assert candidate.stat().st_size == 33558528
    assert sha(candidate.read_bytes()) == '7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624'
    guards = json.loads((HERE / 'builder-guard-tests-ipmi-only-s21s.json').read_text())
    local = json.loads((HERE / BUILD / 'independent-container-verification.json').read_text())
    excluded = json.loads((HERE / 'inventory-exclusion.json').read_text())
    review = ROOT / 'analysis/hero_rc5_r4_s21s_independent_review_20261108'
    independent = json.loads((review / 'independent-byte-audit.json').read_text())
    regressions = json.loads((review / 'verification-regressions.json').read_text())
    native_report = ROOT / 'analysis/hero_p6_s21s_independent_review_20261108/hardware-verification.json'
    live = json.loads(native_report.read_text())
    assert guards['passed'] and guards['tests'] == 31
    assert local['passed'] and excluded['passed']
    assert independent['passed'] and independent['unchanged_ffs_count'] == 543
    assert independent['candidate_sha256'] == sha(candidate.read_bytes())
    assert regressions['passed'] and regressions['cases'] == 18 and regressions['root_guards'] == 31
    assert live['passed_first_real_afterboot_cycle'] and live['passed_repeated_real_afterboot_no_replay']
    assert live['core_sha256'] == '401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66'
    assert not live['native_first_setupenter_verified'] and not live['F10_configuration_writes_verified']
    for capture in live['captures']:
        assert record(ROOT / capture['path'])['sha256'] == capture['sha256']
    provenance = json.loads((HERE / 'builder-source-provenance.json').read_text())
    for name, pin in provenance['original_sha256'].items():
        assert sha((ROOT / provenance['source'] / name).read_bytes()) == pin
    old = ROOT / 'analysis/hero_ipmi_rc5_20261108/RC5-IPMI-ONLY-R4-S21R-CANDIDATE02/HERO-3107-IPMI-RC5-IPMI-ONLY-R4-S21R-CANDIDATE02-UNSIGNED.CAP'
    assert sha(old.read_bytes()) == 'a10c22412e0f1388915b14c3c297121cc9d9b976ce10143652b4b15b9cc4f5c1'

    own_names = ['build_candidate.py', 'verify_candidate.py', 'test_builder_guards.py',
                 'integration-manifest.json', 'builder-source-provenance.json',
                 'builder-guard-tests-ipmi-only-s21s.json', 'audit_inventory_exclusion.py',
                 'inventory-exclusion.json', '本轮核心验证摘要-供现场手册引用.txt',
                 'freeze_candidate.py', BUILD + '/build-report.json',
                 BUILD + '/integration-manifest.json',
                 BUILD + '/independent-container-verification.json']
    evidence = [native_report,
                ROOT / 'analysis/hero_ipmi_complete_live_20261108/r4-fresh-hardware-verification.json',
                ROOT / 'analysis/hero_ipmi_complete_live_20261108/r4-warm-hardware-verification.json',
                review / 'independent-byte-audit.json', review / 'verification-regressions.json',
                review / 'unchanged-ffs.json',
                ROOT / 'analysis/hero_p6_settings21s_20261108/FROZEN-CORE-UTF8.json',
                ROOT / 'analysis/hero_p6_s21s_independent_review_20261108/review-manifest.json',
                ROOT / 'analysis/hero_sensor_r4_20261108/HeroIpmiCoreR4.ffs',
                ROOT / 'analysis/hero_p6_settings21s_20261108/HeroIpmiNativeP6.ffs']
    result = dict(status='FROZEN_FIELD_RC_CANDIDATE03_NOT_OFFICIAL_OR_FULLY_FLASH_VALIDATED',
                  candidate=record(candidate), flashback_name='MZ790H.CAP',
                  exactly_two_existing_ipmi_cores_replaced=True,
                  unchanged_ffs_count_vs_sectionfix=543,
                  no_i3_i5_inventory_publisher=True,
                  inventory_exclusion_verified_against_official_and_baseline=True,
                  inventory_ffs_guid_note=excluded['guid_note'],
                  test_counts=dict(builder_guards=31, independent_container_cases=18),
                  real_afterboot_first_and_repeat_verified=True,
                  fresh_and_initialized_bmc_r4_real_bds_verified=True,
                  native_first_setupenter_timer_verified=False,
                  native_post_flash_dispatch_verified=False,
                  real_F10_BMC_configuration_write_verified=False,
                  final_CAP_flashback_acceptance_verified=False,
                  official_restore_verified=False,
                  modified_CAP_ASUS_signature_valid=False,
                  old_candidate02_still_withheld=True,
                  old_candidate02_and_build_sources_unchanged=True,
                  own_files=[record(HERE / name) for name in own_names],
                  external_evidence=[record(path) for path in evidence],
                  hardware_operations_by_this_builder=False)
    destination = HERE / 'FROZEN-CANDIDATE03.json'
    assert not destination.exists(), 'Preserve frozen manifest; do not overwrite'
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(candidate=result['candidate'], frozen_manifest=record(destination)), indent=2))


if __name__ == '__main__':
    main()
