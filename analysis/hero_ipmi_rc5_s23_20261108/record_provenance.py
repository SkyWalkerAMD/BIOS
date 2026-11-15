"""Record C05 derivation and pinned read-back without changing any firmware."""
from pathlib import Path
import difflib
import hashlib
import json

if not __debug__:
    raise RuntimeError('Run with assertions enabled')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / 'analysis/hero_ipmi_rc5_s22_20261108'
BUILD = 'RC5-IPMI-ONLY-R5-S23-CANDIDATE05'
CAP = HERE / BUILD / ('HERO-3107-IPMI-' + BUILD + '-UNSIGNED.CAP')
CAP_SHA = '68cfc48a76d41f23edf093984818b64a6b13a686956666339733fe0a84e287f9'
OLD_CAP = OLD / 'RC5-IPMI-ONLY-R5-S22-CANDIDATE04/HERO-3107-IPMI-RC5-IPMI-ONLY-R5-S22-CANDIDATE04-UNSIGNED.CAP'
OLD_CAP_SHA = '8adf138c82c71d8d599b625fa5776bcd201096f59d6f357fd2ef75251efdf70f'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def record(path):
    data = path.read_bytes()
    return dict(path=path.relative_to(ROOT).as_posix(), bytes=len(data), sha256=sha(data))


def write_new(name, obj):
    out = HERE / name
    assert not out.exists(), 'Never overwrite recorded release evidence'
    out.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n', encoding='utf8')


def main():
    assert sha(CAP.read_bytes()) == CAP_SHA and CAP.stat().st_size == 33558528
    assert sha(OLD_CAP.read_bytes()) == OLD_CAP_SHA
    initial = json.loads((HERE / 'builder-source-provenance-initial.json').read_text(encoding='utf8'))
    rows = []
    for item in initial['files']:
        source, output = ROOT / item['source'], ROOT / item['output']
        assert sha(source.read_bytes()) == item['source_sha256'], 'C04 source changed'
        rows.append(dict(source=record(source), output=record(output),
                         unified_diff=''.join(difflib.unified_diff(
                             source.read_text(encoding='utf8').splitlines(keepends=True),
                             output.read_text(encoding='utf8').splitlines(keepends=True),
                             fromfile=item['source'], tofile=item['output']))))
    dependencies = [record(ROOT / path) for path in (
        'analysis/hero_ipmi_p5/build_candidate.py',
        'analysis/hero_ipmi_p5/host-lzma/encode.exe',
        'analysis/hero_ipmi_p5_rea_review_20261103/container_review.py')]
    provenance = dict(
        scope='C04 source -> independently pinned C05 builder/checker/audit; no old artifacts edited',
        old_C04_CAP=record(OLD_CAP), files=rows, dependencies=dependencies,
        permitted_changes=[
            'S22 native P6 fixed PE/FFS pins and source paths replaced by frozen S23 pins/paths',
            'Build name and report names updated to CANDIDATE05 / S23',
            'Inherited R4 variable labels corrected to R5 without changing sensor pins',
            'Verifier independently pins official3107 comparison SHA',
            'Six new guard cases reject old R4, S21S, S22, old C04 manifest/container and check official pin',
            'Inventory exclusion independently pins C05 CAP and additionally checks known I5 trigger GUID'],
        not_changed=['SECTIONFIX baseline', 'R5 core', 'S23 core', 'Setup/SPF resources',
                     'All old C04 builder/checker/test/audit sources and CAP'],
        hardware_actions_performed=False, final_zip_created=False)
    write_new('builder-source-provenance-final.json', provenance)

    guard = json.loads((HERE / 'builder-guard-tests-ipmi-only-s23.json').read_text())
    verify = json.loads((HERE / BUILD / 'independent-container-verification.json').read_text())
    audit = json.loads((HERE / 'inventory-exclusion.json').read_text())
    assert guard['passed'] and guard['tests'] == 37 and not guard['failures'] and not guard['errors']
    assert verify['passed'] and verify['candidate_sha256'] == CAP_SHA
    assert audit['passed'] and audit['no_project_inventory_publisher']
    assert audit['images']['candidate05']['cap_sha256'] == CAP_SHA
    unchanged = verify['inner']['files'] - 2 + verify['outer']['files'] - 1
    assert unchanged == 543
    assert sha((HERE / 'build_candidate.py').read_bytes()) == guard['builder_sha256']
    assert sha((HERE / 'verify_candidate.py').read_bytes()) == guard['checker_sha256']

    frozen = dict(
        status='FROZEN_OFFLINE_CANDIDATE05_PARENT_HANDLES_RUNTIME_AND_FIELD_RELEASE',
        candidate=record(CAP), flashback_filename='MZ790H.CAP',
        exactly_two_existing_ipmi_cores_replaced=True, unchanged_ffs_count_vs_SECTIONFIX=unchanged,
        no_new_ffs_GUID=True, no_I3_I5_inventory_publisher=True,
        inventory_exclusion_covers_official_baseline_and_candidate=True,
        inventory_project_PE_count=len(audit['known_project_pe_artifacts']),
        builder_guards_passed=37, independent_parser_readback_passed=True,
        parent_hardware_evidence_separate=True, independent_reviewer_evidence_separate=True,
        no_hardware_actions_by_container_builder=True, final_CAP_flashing_verified=False,
        native_cold_first_SetupEnter_timer_verified=False, F10_configuration_writes_verified=False,
        final_CAP_FlashBack_acceptance_verified=False, official_restore_verified=False,
        ASUS_signature_for_modified_payload_valid=False, official_ASUS_release=False,
        full_Z790_Creator_feature_parity_claimed=False, final_ZIP_created=False,
        fixed_core_sources=[record(ROOT / path) for path in (
            'analysis/hero_sensor_r5_20261108/USB/EFI/HERO/HeroIpmiR5.efi',
            'analysis/hero_sensor_r5_20261108/HeroIpmiCoreR5.ffs',
            'analysis/hero_sensor_r5_20261108/FROZEN-R5.json',
            'analysis/hero_p6_s23_20261108/HeroIpmiP6.efi',
            'analysis/hero_p6_s23_20261108/HeroIpmiNativeP6.ffs',
            'analysis/hero_p6_s23_20261108/FROZEN-CORE-UTF8.json')],
        own_files=[record(p) for p in sorted(HERE.rglob('*')) if p.is_file() and '__pycache__' not in p.parts],
        notes=[
            'S23 accepts byte-equal known P5 readonly40-value and P6 41-value resources; unknown/mixed/duplicate resources are rejected.',
            'C05 keeps the baseline P6 Setup/SPF resources unchanged; the P5 compatibility branch supports older installed menus during exact-core RAM validation.',
            'C05 is not marked hardware-tested merely because a core passed RAM validation. Flash, native cold dispatch and first SetupEnter still need field evidence.',
            'The inventory protocol GUIDs are API/trigger fingerprints, not assigned I3/I5 FFS GUIDs.',
            'No final field package or user-facing instructions are generated here.'])
    write_new('FROZEN-CANDIDATE05.json', frozen)
    print(json.dumps(dict(candidate=record(CAP), frozen=record(HERE / 'FROZEN-CANDIDATE05.json'),
                          provenance=record(HERE / 'builder-source-provenance-final.json')), indent=2))


if __name__ == '__main__':
    main()
