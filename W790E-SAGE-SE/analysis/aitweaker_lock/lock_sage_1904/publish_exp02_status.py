"""Publish the local EXP02 index without changing historical release bytes."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

HERE = Path(__file__).resolve().parent
BASE = HERE.parent

def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

def save(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    delivery = read(HERE / 'bios_delivery_exp02.json')
    source = read(HERE / 'review_delivery_exp02.json')
    manifest = read(Path(delivery['directory']) / 'manifest.json')
    assert manifest['release'] == 'EXP02'
    assert sha(Path(delivery['capsule'])) == delivery['capsule_sha256']
    assert sha(Path(delivery['zip'])) == delivery['zip_sha256']
    assert sha(Path(delivery['directory']) / 'manifest.json') == delivery['manifest_sha256']
    assert sha(Path(source['archive'])) == source['sha256']
    assert source['release'] == 'EXP02'
    assert source['driver_sha256'] == delivery['driver_sha256']
    assert source['capsule_sha256'] == delivery['capsule_sha256']
    assert sha(HERE / 'driver/build/AiTweakerLock1904.efi') == delivery['driver_sha256']
    assert delivery['driver_sha256'] == 'da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
    hw = read(HERE / 'remote_172_20_2_162/history01_hardware_notes.json')
    cleanup = read(HERE / 'remote_172_20_2_162/cleanup.json')
    assert hw['conclusions']['automatic_failures'] == 0 and cleanup['final_power_state'] == 'Off'
    now = datetime.now(timezone.utc).isoformat()
    scope = 'SAGE SE1904: native FormBrowser2 RAM credential/entry tests completed on 2026-11-03. HISTORY01 platform and production driver bytes match EXP02. Permanent NVRAM and flashed direct Del/F2 integration remain untested.'
    limits = [
        'Modified payload has not been re-signed; updater acceptance and recoverable deployment are not established.',
        'ASUS full modified-firmware boot, automatic dispatch and direct Del/F2 graphical integration remain unverified.',
        'Physical NVRAM persistence, defaults/training and all proprietary search/EZ/raw-write paths remain unverified.',
        'Ordinary boot and authorized saves with the global variable guard, plus the visible BIOS visit boundary, require full ASUS firmware acceptance testing.',
        'Some initial alternate forms exit the current browser invocation when password input is cancelled.',
        'One-shot attach and fail-closed rollback behavior under resource/write-permission failure remain firmware integration recovery limitations.'
    ]
    hardware = {
        'board': 'ASUS Pro WS W790E-SAGE SE', 'bios_version': '1904', 'date': '2026-11-03',
        'collection': 'P4 inventory and P5 RAM-only native FormBrowser2 tests via BMC/KVM',
        'build': 'HISTORY01', 'candidate_driver_sha256': delivery['driver_sha256'],
        'runtime_fingerprints_match_official_1904': ['Setup', 'AMITSE'],
        'final_log': str(HERE / 'remote_172_20_2_162/hardware-p4-1793666523615/hardware-log.txt'),
        'final_log_sha256': '041df80c8a06a8d00885db5427df0b5bf9d5a0fb8839ec22aa4b2d7111411b75',
        'automatic_checks': 50, 'automatic_failures': 0,
        'password_lock_hardware_verified': True, 'password_lock_hardware_verified_scope': scope,
        'persistent_hardware_password_lock_verified': False,
        'firmware_flashing_performed': False, 'last_power_state': 'Off',
        'media_detached': True, 'bmc_session_closed': True,
        'boot_note': cleanup['boot_note'], 'limits': limits
    }
    candidate = {
        'target': manifest['target'], 'release': 'EXP02', 'status': delivery['status'], 'priority': 'highest',
        'driver_sha256': delivery['driver_sha256'], 'candidate_sha256': delivery['capsule_sha256'],
        'password_lock_code_implemented': True, 'firmware_review_image_created': True,
        'history01_fix_integrated': True, 'persistent_credential_storage_implemented': True,
        'hardware_password_lock_validated': True, 'hardware_password_lock_validation_scope': scope,
        'persistent_hardware_password_lock_validated': False, 'signed_flash_package_created': False,
        'physical_firmware_writes_performed': False,
        'validation': manifest['test_counts'], 'hardware_evidence': hardware,
        'report': str(Path(delivery['directory']) / '验证报告.html'),
        'source_directory': str(HERE), 'limits': limits
    }
    req = read(HERE / 'requirements.json')
    req.setdefault('release_history', {}).setdefault('EXP01', req.get('experimental_bios_release'))
    req.update({
        'status': delivery['status'], 'updated_utc': now,
        'hardware_password_tested': True, 'hardware_password_test_scope': scope,
        'firmware_flashing_authorized': False, 'firmware_flashing_performed': False,
        'experimental_bios_release': delivery, 'source_evidence_release': source,
        'current_password_lock_candidate': candidate, 'hardware_evidence': hardware,
        'persistent_hardware_deployment_complete': False
    })
    save(HERE / 'requirements.json', req)
    root = read(BASE / 'requirements.json')
    history = root.setdefault('target_history', {})
    sage_history = history.setdefault('W790E_SAGE_SE_1904', {})
    sage_history.setdefault('EXP01', root.get('experimental_bios_release'))
    old_hw = root.get('hardware_evidence', {})
    if old_hw and old_hw.get('board') != hardware['board']:
        history.setdefault('W790_ACE_1904', {}).setdefault('read_only_inventory', old_hw)
    root.update({
        'active_target': 'W790E_SAGE_SE_1904', 'priority_updated_utc': now,
        'implementation_status': delivery['status'], 'modified_cap_created': True,
        'hardware_validation_performed': True, 'hardware_validation_scope': scope,
        'hardware_evidence': hardware, 'password_lock_hardware_validated': True,
        'password_lock_baseline_hardware_validated': False,
        'password_lock_baseline_hardware_status': 'EXP01 navigation defect reproduced; fixed in HISTORY01/EXP02',
        'password_lock_hardware_validation_scope': scope,
        'password_lock_fully_delivered': False,
        'persistent_password_lock_hardware_validated': False,
        'experimental_bios_release': delivery, 'source_evidence_release': source,
        'current_password_lock_candidate': candidate,
        'next_required_external_evidence': 'Verified recovery/update path and physical acceptance testing of the modified firmware: automatic direct Del/F2 entry, persistent credential and platform boot. No flashing has been authorized or performed.',
        'latest_hardware_analysis': {'date': '2026-11-03', 'build': 'W790E_SAGE_SE_1904',
                                     'password_lock_implemented': True, 'scope': scope,
                                     'report': str(HERE / 'remote_172_20_2_162/hardware_review_package.json')}
    })
    root['outstanding_deployment_validation'] = limits
    if 'proposed_details_not_yet_implemented' in root:
        sage_history.setdefault('pre_EXP02_outstanding_validation', root.pop('proposed_details_not_yet_implemented'))
    root['confirmed_by_user']['maintenance_authorization_scope'] = 'ACE and SAGE: maintenance reboot and no-flash RAM tests authorized. SAGE test completed and host returned Off. Firmware image creation authorized; firmware flashing is not authorized.'
    observed = root.setdefault('observed_hardware_builds', [])
    if 'W790E_SAGE_SE_1904' not in observed:
        observed.append('W790E_SAGE_SE_1904')
    save(BASE / 'requirements.json', root)
    save(BASE / 'priority.json', {'active_target': root['active_target'],
         'priority_order': root['priority_order'], 'current_release': delivery,
         'source_evidence_release': source, 'original_scope_preserved': True,
         'hardware_ram_validation_completed': True, 'persistent_hardware_deployment_complete': False,
         'flashing_performed': False})
    print(json.dumps({'active_target': root['active_target'], 'release': 'EXP02',
                      'history_preserved': True, 'hardware_scope_updated': True}))

if __name__ == '__main__':
    main()
