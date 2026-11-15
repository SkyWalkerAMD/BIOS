"""Round 06 additive state, preserving frozen component and historical reports."""
from pathlib import Path
import datetime
import json
import sys

HERE = Path(__file__).resolve().parent
path = HERE / 'work_status.json'
status = json.loads(path.read_text(encoding='utf-8'))
phase = sys.argv[1] if len(sys.argv) > 1 else 'collecting'
status['current_stage'] = 'round06_read_only_hardware_fingerprints_and_true_close_lifecycle_validation'
status['release_ready'] = False
status['flashing_performed'] = False
status['deployment_preference'] = {
    'route': 'USB BIOS FlashBack',
    'user_statement': '我可以接受只用flashback更新BIOS的',
    'bmc_updater_acceptance_required': False,
    'modified_cap_flashback_acceptance_proven': False,
    'onsite_usb_availability_confirmed': False,
    'hardware_flash_performed': False,
}
status['current_remote_session'].update(
    active=phase != 'closed', virtual_cd_attached=phase in ('collecting', 'delta_collecting'),
    last_observed_stage='HII06 captured and exited normally to original Setup. Media detached and BootOverride Disabled at 05:25 UTC; session retained for next reviewed read-only carrier.' if phase == 'awaiting_delta' else 'Round06 authorized read-only collector maintenance session; see current hardware evidence below.',
    host_password_write_count=0,
)
status['active_work06'] = {
    'updated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'state': 'IN_PROGRESS_NOT_FLASHABLE',
    'remote_phase': phase,
    'collector': 'diagnostic_hii06/component_manifest.json',
    'collector_independent_review': 'collector_review06/hii06_review.json',
    'efi_sha256': 'c48d89a78c17aba5a975b939bc71ed8d67de2f200abc22f60212fb6b198fc983',
    'iso_sha256': '47dd173f3feaa7c4fa3124b8f0751e0531623fda0704283304432dbe3e337976',
    'foreign_callback_original_review': 'foreign_callbacks06/first_layer_review.json',
    'true_close_review': 'navigation06_actions/',
    'independent_parser_review': 'parser_review06/',
    'fixed_spf_sampler': {
        'manifest': 'spf_sampler06/component_manifest.json',
        'sha256': '9ad2fe6aa51566aa24f02e7d2fdce99104dbe19b423707770fad8e8c985395e4',
        'compiled_cases': 35,
        'independent_review': 'spf_sampler06_review/component_review.json',
        'independent_decoder_negative_cases': 14,
        'carrier_qualification_separate': True,
    },
    'original_exit_control': {
        'manifest': 'exit_control07/component_manifest.json',
        'actual_tail_cases': 10,
        'finding': 'Both normal and reset tails perform protocol teardown before cleanup748C. The reset branch ignores its error return. No late-refusal return-to-GUI claim is valid.',
        'production_early_guard_implemented': False,
    },
    'dynamic_forms_original_replay': {
        'manifest': 'dynamic_forms06/manifest.json',
        'sha256': 'aadeb51126d829a8d49e8a29b34d7e0c69027979dc7000bfc51270c4a4f92561',
        'rea_queries': 34, 'original_instruction_cases': 6,
        'hardware_full_bytes_replay_pending': True,
    },
    'next_read_only_carrier': {
        'folder': 'diagnostic_delta07',
        'selection': 'diagnostic_delta07/selection_hardware02.json',
        'status': 'Frozen and independently reviewed. Mounted for authorized hardware maintenance collection.' if phase == 'delta_collecting' else 'Frozen and independently reviewed; see hardware event records for deployment phase.',
        'manifest': 'diagnostic_delta07/component_manifest.json',
        'manifest_sha256': '5ba5d6f150d405e0096c2f72c853b56e353153ea96b0845ab1ecc31ce5c9fab8',
        'efi_sha256': '3918cbaea2559429a30bf8e78208b9df02c3a4a79ce4f1ea143e537a630dfcff',
        'iso_sha256': '8f99b7e0b04779000c9cc4763bacb8cd33316096c8ef79d9a2da428ed72d5e13',
        'independent_review': 'spf_sampler06_review/final_review.json',
        'planned_instances': 5, 'max_qr_pages': 20,
    },
    'hardware_events': [
        'New owned headless BMC/KVM session; initial original BIOS Main0603 observed.',
        'Mounted exact independently reviewed HII06 read-only ISO.',
        'One-time CD boot request first rejected HTTP428 for missing ETag. Fresh read confirmed unchanged state; corrected exact If-Match request accepted HTTP204. No wildcard used.',
        'Authorized ForceRestart from visually confirmed original Setup accepted HTTP202 as Task3 at 05:05:32 UTC.',
        'One-time CD override did not produce a captured collector screen; original Rocky Linux 9.6 booted. Override restored to original Disabled/None/Legacy HTTP204.',
        'Advertised GracefulShutdown requested and power Off confirmed, then On requested as Tasks4/5. No hard reset was used against the running OS.',
        'KVM Delete returned to original Setup; visible Boot Override UEFI AMI Virtual CDROM selected without saving configuration.',
        'HII06 displayed 15 pages. All captured and CRC restored: 11190 bytes, CRC258FA03E, SHA932c0a5e1f051b6160982d5fe95ab17bac3211239b0d59ba2ed84839bf618331.',
        'Collector exited normally to original Exit; navigation returned to Main, virtual CD detached. Original boot order and Disabled override confirmed.',
    ],
    'hardware_hii06': {
        'capture': 'hardware_hii06/capture01.json',
        'reconciled': 'hardware_hii06/reconciled01.json',
        'raw_log': 'remote_172_20_2_245/hardware-inventory01-1794115320552-227fa99e/hardware-log.txt',
        'matching_original_modules': 10, 'unknown_external_modules': 2,
        'hii_instances': 13, 'reported_hii_forms': 391,
        'exact_static_forms_packages': 8,
        'requires_bytes_or_delta': ['NvmeDynamicSetup +7 bytes', 'GetCpuInfo +1344 bytes', 'SocketSetup +28 bytes', 'two distinct 25FD instances, each 2400 bytes'],
        'range_service_errors': 0, 'budget_overflow': False,
        'null_driver_original_saved_handle_match': True,
        'runtime_authority_proven': False,
    },
    'password_writes': 0, 'firmware_write_requests': 0,
    'no_modified_cap_rom_or_private_test_keys_persisted': True,
    'release_limit': 'No flashable release claimed. Local aggregate load, decoder and bootstrap checks are not full native startup or hardware lock qualification.',
}
path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'phase': phase, 'release_ready': False, 'file': str(path)}))
