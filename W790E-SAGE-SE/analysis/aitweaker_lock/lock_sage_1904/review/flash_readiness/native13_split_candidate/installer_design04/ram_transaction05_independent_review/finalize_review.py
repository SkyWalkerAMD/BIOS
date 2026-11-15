"""Bind the independently reviewed RAM candidate, without executing firmware.

Run only after the author and OVMF reviewer have frozen all named inputs.
This does not grant a firmware-flash approval or claim a hardware result.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
D04 = HERE.parent
TX = D04 / 'ram_transaction05'
DELIVERY = D04 / 'ram_test05_delivery'
READY = HERE.parents[2]
CASE = READY.parents[1]
EFI_SHA = '9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'
P13_SHA = 'caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text(encoding='utf-8'))
def bound(p): return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}

def main():
    extra_index_path = HERE / 'final_additional_reports.json'
    extra = read(extra_index_path)
    assert extra['efi_sha256'] == EFI_SHA
    ISO_SHA = extra['iso_sha256']
    author_manifest_path = TX / 'ram_candidate_manifest.json'
    author_manifest = read(author_manifest_path)
    assert sha(author_manifest_path) == '1b9f3b1979855cf3a20b2101c84983854500f3f57f8fefbcdab6c3bf8cd20925'
    assert author_manifest['efi_sha256'] == EFI_SHA and author_manifest['iso_sha256'] == ISO_SHA
    for row in author_manifest['artifacts']:
        p = D04 / row['path']
        assert sha(p) == row['sha256'] and p.stat().st_size == row['bytes'], row['path']
    assert author_manifest['review_sha256'] == sha(TX / 'ram_candidate_review.json')
    efi = TX / 'app_build/SageNative13RamTest05.efi'
    build_path = TX / 'app_build/app_build.json'
    build = read(build_path)
    assert sha(efi) == build['efi_sha256'] == EFI_SHA
    source_files = []
    for row in build['sources']:
        p = TX / row['path']
        assert sha(p) == row['sha256'], p
        source_files.append(p)
    object_files = []
    for name, digest in build['objects'].items():
        p = TX / 'app_build' / name
        assert sha(p) == digest, name
        object_files.append(p)
    assets_path = TX / 'platform_assets.json'
    assets = read(assets_path)
    assert sha(assets_path) == build['assets_sha256']
    for name, digest in assets['generated'].items():
        assert sha(TX / 'source' / name) == digest
    assert assets['provider_declared_bytes'] == 51341 and assets['provider_relocations'] == 17
    p13_manifest_path = D04 / 'provider13/local_candidate_manifest.json'
    p13_manifest = read(p13_manifest_path)
    assert sha(p13_manifest_path) == build['p13_manifest_sha256'] == assets['dependencies']['p13_manifest']
    for row in p13_manifest['artifacts']:
        assert sha(D04 / row['path']) == row['sha256'], row['path']
    p13 = D04 / 'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi'
    assert sha(p13) == assets['dependencies']['p13_efi'] == P13_SHA

    package_path = DELIVERY / 'packages' / EFI_SHA[:16] / 'package.json'
    package = read(package_path)
    assert package['efi_sha256'] == package['source_efi_sha256'] == EFI_SHA
    assert package['iso_sha256'] == ISO_SHA
    assert sha(Path(package['efi'])) == sha(Path(package['source_efi'])) == EFI_SHA
    assert sha(Path(package['iso'])) == ISO_SHA
    assert sha(Path(package['boot_image'])) == package['boot_image_sha256']
    assert Path(package['iso']).stat().st_size == package['iso_bytes'] == 16842752
    assert package['fat_file_equals_compiled_efi'] and package['iso_fat_roundtrip_exact']
    iso_run = Path(extra['iso_ovmf_report'])
    iso_report = read(iso_run)
    assert iso_report['status'] == 'PASS_EXACT_ISO_OVMF_REFUSAL_AND_QR_TRANSPORT'
    assert iso_report['efi_sha256'] == EFI_SHA and iso_report['iso_sha256'] == ISO_SHA
    assert iso_report['package_sha256'] == sha(package_path)
    assert iso_report['input_images_unchanged'] and iso_report['qemu_exit_code'] == 0

    entry_path = HERE / ('final_app_edges_' + EFI_SHA[:16]) / 'result.json'
    entry = read(entry_path)
    assert entry['efi_sha256'] == EFI_SHA and entry['build_sha256'] == sha(build_path) and entry['cases'] == 20
    assert entry['test_source_sha256'] == sha(HERE / 'verify_final_app_entry.py')
    assert entry['fixture_source_sha256'] == sha(HERE / 'verify_app_entry_edges.py')
    platform_path = TX / 'app_build/platform_verification.json'
    platform = read(platform_path)
    assert platform['efi_sha256'] == EFI_SHA and platform['build_sha256'] == sha(build_path)
    assert platform['p13_efi_sha256'] == P13_SHA
    assert platform['test_source_sha256'] == sha(TX / 'verify_platform.py')
    assert platform['checks'] == len(platform['check_names'])
    assert any('unreadable destroyed LoadedImage' in name for name in platform['check_names'])
    assert any('runtime AMITSE guard equals' in name for name in platform['check_names'])
    assert any('runtime Setup guard equals' in name for name in platform['check_names'])
    edges_path = TX / 'app_build/platform_edges.json'
    edges = read(edges_path)
    assert edges['efi_sha256'] == EFI_SHA and edges['build_sha256'] == sha(build_path)
    assert edges['checks'] == len(edges['check_names']) == 37
    assert edges['test_sha256'] == sha(TX / 'verify_platform_edges.py')
    assert edges['base_fixture_sha256'] == sha(TX / 'verify_platform.py')
    assert all(any(f'query returning at unexpected TPL {tpl}' in label for label in edges['check_names']) for tpl in (8,16,31))
    integrated_core_path = TX / 'app_build/integrated_core_verification.json'
    integrated_core = read(integrated_core_path)
    assert integrated_core['transaction_efi_sha256'] == EFI_SHA and integrated_core['build_sha256'] == sha(build_path)
    assert integrated_core['checks'] == len(integrated_core['check_names']) == 75
    assert integrated_core['test_source_sha256'] == sha(TX / 'verify_integrated_core.py')
    assert integrated_core['suite_source_sha256'] == sha(TX / 'verify_transaction.py')

    validator_path = Path(extra['actual_validator_ovmf_report'])
    validator = read(validator_path)
    assert validator['actual_app_sha256'] == EFI_SHA and validator['provider_sha256'] == P13_SHA
    assert validator['status'] == 'PASS_ACTUAL_LOADED_APP_VALIDATOR_IN_OVMF'
    assert validator['checks'] == 85 and validator['readonly_boot_unchanged'] and not validator['imports_started']
    for row in validator['source_bindings']:
        assert sha(Path(row['path'])) == row['sha256'], row['path']

    ui_path = D04 / 'ram_test05_delivery_review/full_app_ui_9115f1afbab01b62/ui_test_result.json'
    ui = read(ui_path)
    assert ui['cases'] == len(ui['results']) == 122
    assert ui['actual_app_sha256'] == ui['fixture_sha256'] == EFI_SHA
    assert sha(ui_path.parent / 'inputs/SageNative13RamTest05.efi') == EFI_SHA
    ui_derivation_path = ui_path.parent / 'derivation.json'
    ui_derivation = read(ui_derivation_path)
    assert ui_derivation['actual_app_sha256'] == EFI_SHA
    assert ui_derivation['generated_test_sha256'] == sha(ui_path.parent / 'test_full_app_ui.py')
    assert ui_derivation['template_sha256'] == sha(ui_path.parent / 'suite_template.py')
    assert all(row['status'] == 'PASS' for row in ui['results'])
    for row in ui['source_bindings']:
        assert sha(Path(row['path'])) == row['sha256'], row['path']
    transport_path = DELIVERY / 'transport_boundary_result.json'
    transport = read(transport_path)
    assert transport['source_sha256'] == sha(TX / 'source/transport/kvm.c')
    assert transport['checks'] == 99

    # Additional final reports are explicitly named by the author below; no
    # wildcard transfer of old candidate, hardware, or release status occurs.
    extra_reports = []
    for row in extra['reports']:
        p = Path(row['path'])
        assert sha(p) == row['sha256'], p
        extra_reports.append(p)
    assert extra['author_frozen'] is True
    assert extra['efi_sha256'] == EFI_SHA and extra['iso_sha256'] == ISO_SHA
    assert extra['successful_provider_start_and_query_reviewed'] is True
    assert extra['delivery_independent_reviewed'] is True

    inputs = [efi, TX / 'app_build/app.map', build_path, assets_path, p13, p13_manifest_path,
              author_manifest_path, TX / 'ram_candidate_review.json',
              TX / 'verify_platform.py', TX / 'generate_platform_assets.py',
              package_path, iso_run, entry_path, platform_path, edges_path, integrated_core_path,
              TX / 'verify_platform_edges.py', TX / 'verify_integrated_core.py', TX / 'verify_transaction.py',
              validator_path, ui_path, ui_derivation_path,
              ui_path.parent / 'test_full_app_ui.py', ui_path.parent / 'suite_template.py', transport_path,
              HERE / 'core_review.json', HERE / 'core_edges_result.json',
              HERE / 'original_startimage_error_cleanup.json', HERE / 'original_startimage_cleanup.asm.txt',
              HERE / 'original_startimage_tpl_restore.json', HERE / 'original_startimage_tpl_restore.asm.txt',
              HERE / 'operations09_review.json', HERE / 'transport_and_keys_increment_review.json',
              HERE / 'poweroff_increment_review.json', extra_index_path] + extra_reports
    sources_snapshot = HERE / 'final_source_snapshot'
    sources_snapshot.mkdir(exist_ok=True)
    for p in source_files:
        dest = sources_snapshot / p.relative_to(TX)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(p.read_bytes())
    report = {
        'status': 'PASS_INDEPENDENT_LOCAL_REVIEW_FOR_BOUNDED_MANUAL_RAM_TEST',
        'utc': datetime.now(timezone.utc).isoformat(),
        'hardware_executed_by_this_review': False, 'device_calls': 0,
        'flash_approval': False, 'firmware_release_ready': False,
        'efi_sha256': EFI_SHA, 'iso_sha256': ISO_SHA, 'p13_efi_sha256': P13_SHA,
        'confirmed_source_blockers_remaining_in_reviewed_scope': [],
        'scope': 'Temporary resident RAM installer test only. Exact original ASUS module identity, launch frame, memory permissions and supported BIOS services still must satisfy the application runtime gates on the maintained host.',
        'closed_findings': [
            {'id': 'APP_EVENT_ERROR_LIFETIME', 'finding': 'First CreateEvent error-after-ending could return and unload callback state in the early source.',
             'resolution': 'Immediate services guard plus nonzero-handle error hold. Actual final linked app entry matrix covers success/error ending and watchdog failure.'},
            {'id': 'TRANSPORT_ENDING', 'finding': 'Original copied QR transport lacked per-service ending checks.',
             'resolution': 'Every console/GOP/input/memory service is guarded before and after; root actual-PE 99-case boundary report reviewed. Exact ISO smoke separately exercises the real codec and viewer.'},
            {'id': 'GUARD_NOP_GAP', 'finding': 'Twelve bytes between the immutable template and the first trampoline were zero-filled instead of the frozen P13 NOP bytes.',
             'resolution': 'Explicit NOP fill; actual adapter outputs equal both independently frozen guard blobs; actual P13 owner accepts the runtime-produced bytes.'},
            {'id': 'LOADER_DEFINED_RANGES', 'finding': 'Whole-loaded-image hashing rejected ordinary standard loader ImageBase relocation and undefined alignment/raw-tail bytes.',
             'resolution': 'Only the exact 51341 declared header/VirtualSize bytes are compared, including BSS and all17 DIR64 targets; only allowed ImageBase rewrite is normalized. Final exact app validator passes85 real OVMF assertions.'},
            {'id': 'STARTIMAGE_ERROR_LOADEDIMAGE', 'finding': 'Original Core frees the provider LoadedImage interface after entry EFI_ERROR; a later exclusion check could dereference it.',
             'resolution': 'Cache validated image span in app-owned memory, null the old interface after error; actual adapter rollback with unreadable old interface passes. Four original Core native tail/cleanup replays independently prove the lifetime rule.'},
            {'id': 'WRAPPER_AND_CALLBACK_TPL', 'finding': 'Wrapper pre-map operations and OEM/browser callback returns needed explicit application-TPL boundaries.',
             'resolution': 'Prepare/install/start/remove verify TPL before map/loader calls. Provider query and SendForm return verify TPL before variable observation or returning to the menu; anomalous TPL holds without RestoreTPL. The exact original Core StartImage already restores saved TPL, independently supported by three original instruction-excerpt cases.'},
        ],
        'review_conclusions': [
            'Only the twelve compiled exact original-module sites are writable targets. Unsupported identity, original text/site mismatch, unexpected page mapping or permission refuses before the transaction.',
            'AllocatePages owns all detached guard/state pages. Attribute changes target only the allocated inner pages; foreign target-page permissions and owned boundary pages are checked. Original image size and RT service tables are not changed.',
            'The TPL31 validator uses cached metadata, bounded page-table reads and local hashes with no BootServices call. Unknown original-site bytes are not overwritten during rollback; ambiguous transaction state holds the CPU.',
            'Both provider start and publication are single attempt. Validated provider object and all five methods bind to frozen RVAs. Published buffers, context, events and images remain resident until power-off, including after rollback.',
            'Only mode2 permits a temporary private password record. Session UI refuses a preexisting unknown record, compares owned record bytes before exact deletion, and observes protected OC variables without repair writes.',
            'Native-key and password operations require manual screen observations and bound local evidence. The power-off operation is one supported ForceOff request and makes no claim that it restores the private credential.',
        ],
        'test_evidence': [
            {'name': 'Independent exact final app entry/EBS', 'checks': 20, 'report': bound(entry_path), 'execution_by_this_reviewer': True},
            {'name': 'Independent original Core error cleanup', 'checks': 4, 'report': bound(HERE / 'original_startimage_error_cleanup.json'), 'execution_by_this_reviewer': True},
            {'name': 'Independent original Core caller-TPL save/restore excerpts', 'checks': 3, 'report': bound(HERE / 'original_startimage_tpl_restore.json'), 'execution_by_this_reviewer': True},
            {'name': 'Independent transaction edge cases on pinned core carrier', 'checks': 16, 'report': bound(HERE / 'core_edges_result.json'), 'execution_by_this_reviewer': True, 'scope': 'Separate carrier; not misidentified as complete final app.'},
            {'name': 'Author actual final platform/transaction matrix', 'checks': platform['checks'], 'report': bound(platform_path), 'execution_by_this_reviewer': False},
            {'name': 'Author exact final app provider-publication and terminal edges', 'checks': 37, 'report': bound(edges_path), 'execution_by_this_reviewer': False, 'scope': 'Successful StartImage/provider query modeled; actual final adapter executes.'},
            {'name': 'Author original transaction assertions on exact final app', 'checks': 75, 'report': bound(integrated_core_path), 'execution_by_this_reviewer': False, 'scope': 'Read-only path rebinding preserves all assertions; TPL and validator are explicit models.'},
            {'name': 'Independent OVMF exact final validator', 'checks': 85, 'report': bound(validator_path), 'execution_by_this_reviewer': False},
            {'name': 'Exact final app UI/service-model matrix', 'checks': 122, 'report': bound(ui_path), 'execution_by_this_reviewer': False, 'scope': 'Unchanged full-app UI functions/actual services gate execute; UEFI/provider endpoints and pure log sink modeled. No app entry/installer execution in this matrix.'},
            {'name': 'Transport PE boundary matrix', 'checks': 99, 'report': bound(transport_path), 'execution_by_this_reviewer': False},
            {'name': 'Exact final ISO refusal/QR smoke', 'checks': len(iso_report['checks']), 'report': bound(iso_run), 'execution_by_this_reviewer': False},
        ],
        'limits_and_test_sequence': [
            'No ASUS native GUI, physical installation, successful cold-boot permanent lock, or flash trust/recovery acceptance follows from this local review.',
            'Runtime firmware identity and inventory still must pass. The platform matrix seeds exact fixture inventory and models firmware allocation/attributes/TPL/image services. The real OVMF validator initializes only its documented BSS preconditions, and does not StartImage the app or provider.',
            'TPL and the exact caller-frame observation are not proof that APs/SMM or arbitrary other firmware cannot touch code. Standard BSP execution, allocator/service correctness and identity-map assumptions remain explicit.',
            'An actual CPU write fault is not caught as a graceful rollback. In terminal hold there is no console/QR/ResetSystem/RestoreTPL path; use the separately reviewed BMC power-off operation and observe Off independently.',
            'A forced power-off does not clean a private password record. Mode2 cleanup must be observed and logged; if interrupted, persistent private-record state remains unresolved and must not be reported restored.',
            'Run mode1 and verify exact restoration before opening mode2. Mode1 success does not certify password UI. Browse-only original Setup testing must avoid Save/boot overrides; complete final QR and exact restoration logs are separate physical acceptance evidence.',
            'Local check counts are not summed into a success percentage. Matrices use distinct or overlapping scopes and explicit service models.',
        ],
        'verified_source_count': len(source_files), 'verified_link_object_count': len(object_files),
        'verified_frozen_p13_manifest_entries': len(p13_manifest['artifacts']),
        'verified_author_manifest_entries': len(author_manifest['artifacts']),
        'sources': [bound(p) for p in source_files], 'objects': [bound(p) for p in object_files],
        'inputs': [bound(p) for p in inputs], 'review_script_sha256': sha(Path(__file__)),
    }
    out = HERE / 'independent_review.json'
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'sha256': sha(out), 'efi': EFI_SHA, 'iso': ISO_SHA}))

if __name__ == '__main__': main()
