"""Offline, read-only binding of the actual engineering CAP to existing evidence.

Only writes this directory. No BMC, network, firmware, signing, or source changes.
Does not rerun the completed REA/EFI suites or infer live security fuses.
"""
from pathlib import Path
import ast
import datetime
import hashlib
import json
import lzma
import re
import struct
import uuid

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
CASE = HERE.parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ref(path):
    data = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(data), 'bytes': len(data)}


def pinned(path, digest):
    data = path.read_bytes()
    assert sha(data) == digest, str(path)
    return data


def extract(path, names, namespace):
    nodes = [n for n in ast.parse(path.read_bytes()).body
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes} == set(names)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def write(name, data):
    path = HERE / name
    assert path.parent == HERE
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    return ref(path)


def main():
    official_path = ROOT / 'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
    old_path = CASE / 'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin'
    engineering_path = CASE / 'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
    driver_path = CASE / 'lock_1904_candidate05/driver/build/AiTweakerLock1904.efi'
    official = pinned(official_path, '03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29')
    old = pinned(old_path, '9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455')
    engineering = pinned(engineering_path, 'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08')
    driver = pinned(driver_path, '71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98')
    assert len(official) == len(old) == len(engineering) == 0x4001000
    assert old[:4096] == official[:4096]
    assert old[4096:] == engineering[4096:]
    assert sha(engineering[4096:]) == '2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809'
    allowed = [(0x48, 0x148), (0x148, 0x248), (0x258, 0x358), (0x358, 0x458)]
    header_changes = [i for i in range(4096) if old[i] != engineering[i]]
    assert header_changes and all(any(a <= i < b for a, b in allowed) for i in header_changes)
    assert engineering[0x458:4096] == official[0x458:4096]

    layout_path = CASE / 'layout_recovery/analyze_layout.py'
    layout = extract(layout_path, {'sha', 'span', 'capsule', 'parse_fit', 'scan_signatures', 'decompress_slot', 'files_in_fv'},
                     {'hashlib': hashlib, 'struct': struct, 'uuid': uuid, 're': re, 'lzma': lzma, 'SLOT': 0x3181078})
    old_raw, raw = official[4096:], engineering[4096:]
    fit0, fit1 = layout['parse_fit'](old_raw), layout['parse_fit'](raw)
    assert fit0 == fit1
    slot_start, slot_size = 0x3180078, 0x36bba0
    assert old_raw[:slot_start] == raw[:slot_start]
    assert old_raw[slot_start + slot_size:] == raw[slot_start + slot_size:]
    delta = [i for i, (a, b) in enumerate(zip(old_raw[slot_start:slot_start + slot_size], raw[slot_start:slot_start + slot_size])) if a != b]
    changed_blocks = [p for p in range(0, len(raw), 4096) if old_raw[p:p + 4096] != raw[p:p + 4096]]

    inner0, compression0 = layout['decompress_slot'](official)
    inner1, compression1 = layout['decompress_slot'](engineering)
    files0, size0, _ = layout['files_in_fv'](inner0, 16)
    files1, size1, _ = layout['files_in_fv'](inner1, 16)
    assert len(files0) == 423 and len(files1) == 424 and files1[:-1] == files0
    added = files1[-1]
    assert added['guid'] == '97f9cf3d-1209-4c68-a827-e547d0531904'
    start = int(added['offset'], 16)
    assert inner1[start:start + added['bytes']].count(driver) == 1

    signature_helper = ROOT / 'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/verify_capsule_static.py'
    pinned(signature_helper, 'fc7348a36ba77cf100095db89de12e6f45963ed456b962c876839160fbe693c2')
    signature = extract(signature_helper, {'require', 'guid', 'parse_capsule', 'firmware_digest'},
                        {'struct': struct, 'uuid': uuid, 'hashlib': hashlib,
                         'CAPSULE_GUID': '4a3ca68b-7723-48fb-803d-578cc1fec44d',
                         'RSA_CERT_GUID': 'a7717414-c616-4977-9420-844712a735bf'})
    header0, header1 = signature['parse_capsule'](official), signature['parse_capsule'](engineering)
    assert header0 == header1
    changed_areas = []
    for area in header1['regions']:
        p, n = area['body_offset'], area['size']
        if old_raw[p:p + n] != raw[p:p + n]:
            changed_areas.append(area)
    assert len(changed_areas) == 1
    assert changed_areas[0]['body_offset'] == 0x3180000
    assert changed_areas[0]['included_by_observed_signature_rule']

    raw_ranges = [(0, 0x1000, 'public descriptor'),
                  (0x1000, 0x692000, 'public ME'),
                  (0x693000, 0x296d000, 'public region9'),
                  (0x3010000, 0x80000, 'factory NVAR, not target current variables'),
                  (0x384f000, 0x1000, 'FIT containing volume'),
                  (0x3e78000, 0x8000, 'original high BIOS volume'),
                  (0x3e80000, 0x180000, 'original high BIOS tail volume'),
                  (0x3ffffc0, 8, 'referenced FIT pointer'),
                  (0x3fffff0, 16, 'top16 bytes including reset-vector location')]
    preserved = []
    for p, n, label in raw_ranges:
        a, b = old_raw[p:p + n], raw[p:p + n]
        assert len(a) == len(b) == n and a == b
        preserved.append({'label': label, 'raw_offset': hex(p), 'bytes': n,
                          'end_exclusive': hex(p + n), 'sha256': sha(b), 'byte_identical': True})
    fv_report_path = official_path.with_suffix('.CAP.report.txt')
    volumes = []
    for line in fv_report_path.read_text(encoding='utf8').splitlines():
        fields = [s.strip() for s in line.split('|')]
        if len(fields) < 6 or fields[0] != 'Volume' or fields[2] == 'N/A':
            continue
        p, n = int(fields[2], 16), int(fields[3], 16)
        assert official[p + 40:p + 44] == b'_FVH'
        assert struct.unpack_from('<Q', official, p + 32)[0] == n
        a, b = official[p:p + n], engineering[p:p + n]
        volumes.append({'raw_offset': hex(p - 4096), 'bytes': n, 'official_sha256': sha(a),
                        'engineering_sha256': sha(b), 'byte_identical': a == b})
    assert len([v for v in volumes if not v['byte_identical']]) == 1

    cold_path = CASE / 'rea_cold_entry/cold_entry_review_summary.json'
    cold = json.loads(pinned(cold_path, 'b168b8e0460430bc18b48535523174acbef39ee1895b3efd427cd193c27767d5'))
    assert cold['recommendation'] == 'RETAIN_CURRENT_05_NO_ADDITIONAL_NATIVE_READINESS_PATCH'
    assert cold['rea_counts']['sessions_closed_successfully'] == cold['rea_counts']['sessions'] == 5
    reused_results = []
    for item in cold['bounded_execution_results']:
        target = ROOT / item['report']['path']
        pinned(target, item['report']['sha256'])
        reused_results.append(item)
    live_path = CASE / 'update_path_reference/api_auth_review/live_staging_review.json'
    live = json.loads(pinned(live_path, '9914e11a4c88674f24844e1ef1decb931c32a161ef148cb88207fdd9e4e98f75'))
    engineering_verification_path = CASE / 'engineering_signature/verification.json'
    engineering_verification = json.loads(engineering_verification_path.read_bytes())
    assert engineering_verification['engineering_artifact']['sha256'] == sha(engineering)
    assert engineering_verification['preservation']['payload_byte_identical']

    data = {
        'schema': 'ace1904_flash_preflight_offline_v1',
        'status': 'PASS_EXACT_ARTIFACT_LAYOUT_AND_CONDITIONAL_NATIVE_ORDER_REVIEW_WITH_LIVE_GATES_OPEN',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Offline local file review only; existing completed REA/EFI evidence reused without rerunning; no flash readiness approval is fabricated.',
        'bmc_access': False, 'hardware_write': False, 'frozen_file_modified': False,
        'artifacts': {'official': ref(official_path), 'candidate_old_signature': ref(old_path),
                      'actual_engineering_cap': ref(engineering_path), 'production_driver05': ref(driver_path)},
        'capsules': {'official': layout['capsule'](official), 'engineering': layout['capsule'](engineering)},
        'engineering_header': {
            'changes_from_old_signature_candidate_only_in_four_RSA_fields': True,
            'changed_header_bytes': len(header_changes),
            'allowed_ranges': [{'start': hex(a), 'end_exclusive': hex(b)} for a, b in allowed],
            'ROM_map_flags_offsets_and_nonprogram_table_unchanged': True,
            'payload_byte_identical_to_verified_candidate05': True,
            'scope': 'Embedded engineering public keys/signatures, not OEM signing authority or changed resident trust anchors.'},
        'actual_payload_delta_from_official': {
            'container_allocation_raw_offset': hex(slot_start), 'container_allocation_bytes': slot_size,
            'all_payload_bytes_outside_container_unchanged': True,
            'first_changed_raw_offset': hex(slot_start + delta[0]),
            'last_changed_raw_offset_inclusive': hex(slot_start + delta[-1]),
            'changed_bytes': len(delta), 'changed_4k_blocks': len(changed_blocks),
            'changed_4k_raw_offsets': [hex(p) for p in changed_blocks],
            'inner_original_FFS_preserved_byte_exact_at_original_offsets': 423,
            'added_driver_FFS': added, 'added_PE_exact_71b05e': True,
            'original_inner_FV_bytes': size0, 'candidate_inner_FV_bytes': size1,
            'original_compression': compression0, 'candidate_compression': compression1},
        'fit': fit1,
        'flat_signature_scan': {'official': layout['scan_signatures'](old_raw), 'engineering': layout['scan_signatures'](raw)},
        'expanded_DXE_signature_scan': {'official': layout['scan_signatures'](inner0), 'engineering': layout['scan_signatures'](inner1)},
        'preserved_reference_ranges': preserved,
        'all_original_outer_FV_ranges': volumes,
        'authentication_distinctions': {
            'AMI_CAP_signature': {
                'changed_ROM_map_entries': changed_areas,
                'official_firmware_digest': signature['firmware_digest'](official, header0).hex(),
                'candidate_firmware_digest': signature['firmware_digest'](engineering, header1).hex(),
                'conclusion': 'The changed DXE container IS inside an AMI capsule signed range. The old OEM firmware signature no longer authenticates it. The current CAP has valid engineering signatures under different embedded public keys; normal BMC standalone verification has accepted those exact bytes.',
                'existing_crypto_verification': ref(engineering_verification_path),
                'existing_live_staging_review': ref(live_path),
                'existing_live_staging_conclusion': live['conclusion']},
            'Intel_Boot_Guard_IBB': {
                'referenced_public_FIT_unchanged': True,
                'known_manifest_defined_IBB_ranges': None,
                'changed_range_outside_all_IBB_proven': False,
                'reason': 'The referenced public FIT contains only its header and two microcode entries, with no startup ACM/KM/BPM. There is no BPM-defined IBB interval to intersect with the DXE change. Preserved boot-tail/FIT bytes and absent manifest signatures are observations, not proof of live disabled Boot Guard or exemption of the changed DXE.',
                'live_fuses_measured': False, 'live_boot_policy_known': False,
                'live_boot_guard_state': 'UNKNOWN',
                'hardware_probe06_scope': 'Only fixed SPI/PCI status and protection registers were read; no full live flash/FIT/manifest or Boot Guard policy/MSR/fuse was acquired.'},
            'BMC_start_update': {
                'standalone_engineering_CAP_verification_passed': True,
                'complete_start_or_programming_acceptance_proven_here': False,
                'separate_resident_root_tail_signature_branch': 'Runtime enablement remains unobserved; no disable, key replacement or bypass is proposed. Treat normal update rejection as rejection.'}},
        'native_cold_entry': {
            'existing_review': ref(cold_path), 'recommendation': cold['recommendation'],
            'REA_session_and_response_counts': cold['rea_counts'], 'new_REA_sessions_this_review': 0,
            'static_observations_with_existing_Evidence_IDs': cold['static_observations'],
            'existing_bounded_execution_results_rebound_not_rerun': reused_results,
            'physical_permanent_DXE_Del_F2_passed': False,
            'scope_limit': 'Ordinary successful DXE discovery/auth/load/provider and Core-to-BDS order is supported. Absent/failed driver, unavailable prerequisites and unusual OEM reentry are not claimed covered. RAM external SendForm and console-owner NVRAM tests are separate evidence.'},
        'remaining_preflight_conditions': [
            {'id': 'exact_current_artifact', 'type': 'CHECKABLE_BEFORE_UPDATE', 'condition': 'The normal updater must use the exact e330039e CAP / 2dd240c1 payload, 64MiB geometry, unchanged map/NPB flags and normal non-force flow. Revalidate actual staging identity; the stale9b038 CAP is not interchangeable.'},
            {'id': 'normal_update_acceptance', 'type': 'SEPARATE_LIVE_GATE', 'condition': 'Complete normal update entry/init/prepare/size/signature/start acceptance and flash-completion verification remain live gates owned by the parent. Do not call destructive/state-changing prepare or start a read-only dry run, and do not turn off any rejected policy branch.'},
            {'id': 'write_extent_and_device_data', 'type': 'KNOWN_OPERATIONAL_CONSEQUENCE', 'condition': 'Normal update compares all64MiB. Only four native NonProgramBlock intervals conditionally copy current MTD bytes. Factory NVAR raw3010000..3090000 is outside these; settings/boot/password variables and custom modules/logo may reset or be replaced. Public-source equality is not live-device preservation.'},
            {'id': 'partial_compressed_NPB', 'type': 'PREEXISTING_COMPATIBILITY_UNCERTAINTY', 'condition': 'NPB raw3131000..3132000 lies inside an original compressed Freeform file. Current/live bytes were not dumped; copied differences could mix objects. No live mismatch or inevitable corruption is asserted.'},
            {'id': 'BootGuard_runtime', 'type': 'UNMEASURED_HARDWARE_POLICY', 'condition': 'No local evidence can certify live fuse/IBB coverage. Do not claim this condition passed based on absent public FIT manifests, unchanged boot tail or PR0..4=0. Additional evidence must come from a documented supported live read/interface or actual acceptance/boot; no blind hardware probe is proposed.'},
            {'id': 'recovery', 'type': 'SEPARATE_RESIDUAL_RISK', 'condition': 'No current full SPI backup or target no-POST recovery was proven. Successful staging, unchanged source bytes, or theoretical local FlashBack do not supply that proof. The parent must retain this explicit boundary under the user-authorized flash scope.'},
            {'id': 'native_postflash', 'type': 'MUST_BE_MEASURED_AFTER_FLASH', 'condition': 'After successful ordinary programming and completion, first cold native Del/F2 entry, HII management, session relock, actual credential persistence and normal boot/EBS must be observed without loading a RAM driver or calling external SendForm.'}],
        'evidence': {
            'layout_parser': ref(layout_path), 'capsule_map_parser': ref(signature_helper),
            'official_extractor_report': ref(fv_report_path),
            'current_structure_validation': ref(CASE / 'lock_1904_candidate05/lab/asus_review/verification.json'),
            'current_BMC_write_preservation': ref(CASE / 'update_path_reference/update_preservation/update_preservation_review.json'),
            'current_BMC_tail_signature_flag': ref(CASE / 'update_path_reference/runtime_signature_flag_review.json'),
            'normal_backup_recovery_limits': ref(CASE / 'update_path_reference/recovery_extension/recovery_extension_summary.json'),
            'physical_SPI06_decode': ref(CASE / 'spi_register_probe06/hardware_review/hardware06_interpretation.json'),
            'console_shim_NV_hardware_review': ref(CASE / 'nv_persistence_review/independent_review/hardware_nv_summary.json'),
            'production_status_header': ref(CASE / 'lock_1904_candidate05/driver/status.h'),
            'script': ref(Path(__file__))},
        'conclusion': 'Exact current artifact bytes preserve the referenced FIT, both microcodes, original high boot volumes/reset tail and every original expanded DXE FFS; only the existing compressed DXE container payload changes. That container belongs to the capsule signature coverage and has been re-signed with engineering keys accepted by the standalone BMC verifier. This does not establish live Boot Guard/IBB exclusion, full updater acceptance, device-data preservation or recovery. Existing actual REA and compiled-code replay justify retaining05 native readiness design; final permanent-DXE acceptance requires the real postflash native path.'
    }
    report = write('flash_preflight_review.json', data)
    print(json.dumps({'report': report, 'changed_bytes': len(delta), 'changed_blocks': len(changed_blocks),
                      'first': hex(slot_start + delta[0]), 'last_inclusive': hex(slot_start + delta[-1]),
                      'original_FFS_byte_preserved': len(files0), 'referenced_FIT_equal': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
