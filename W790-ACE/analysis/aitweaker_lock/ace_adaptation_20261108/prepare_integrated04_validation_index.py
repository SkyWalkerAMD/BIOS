"""Prepare exact local evidence inputs only. Never freezes, rebuilds or packages."""
from pathlib import Path
import argparse
import importlib.util
import json
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ace04_delivery', HERE/'assemble_integrated04_delivery.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
ROOT, CASE, BUILD = p.ROOT, p.CASE, p.BUILD
H02 = HERE/'lock_1904_history02'
I03 = HERE/'lock_1904_integrated03'
NATIVE = ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules'
SAVE = HERE/'integration03_rea_review/save_wrapper_experiment'
CAP = ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
PIN = '463b94139cb64207e1b756965ebb9ca3513250c8712bbbcd20798fd317dec904'
BIN_PIN = '1e5e7db497949016855afd0575a6d4dfedf633ec52b644ed8fa3c60d3bc54c4e'


def ref(path):
    path = p.workspace_path(path)
    return {'path': p.relative(path), 'sha256': p.digest(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-driver-sha', required=True)
    parser.add_argument('--replace-pending', action='store_true')
    args = parser.parse_args()
    p.require(args.expected_driver_sha == PIN, 'this reviewed input specification is pinned to 463b; update the specification explicitly for another revision')
    target = CASE/'final_validation_index.json'
    if target.exists():
        old = json.loads(target.read_text(encoding='utf8'))
        p.require(args.replace_pending and old.get('frozen') is False, 'refusing to replace an existing or frozen validation index')
    specifications = [
        ('core', CASE/'core/source_core_binding.json', 'source', 'driver_sha256', [CASE/'core/verify_core.py']),
        ('adapter', BUILD/'adapter_emulation.json', 'candidate', 'driver_sha256', [CASE/'driver/verify_adapter.py']),
        ('history', BUILD/'history_regression.json', 'candidate', 'driver_sha256', [CASE/'driver/verify_history.py', CASE/'driver/verify_adapter.py']),
        ('policy', BUILD/'policy_test.json', 'candidate', 'driver_efi_sha256', [CASE/'driver/verify_policy.py', CASE/'driver/policy.json', NATIVE/'Setup_IFR.json', BUILD/'policy_test.dll', BUILD/'setup_hii_policy_fixture.bin']),
        ('entropy', BUILD/'entropy_test.json', 'candidate', 'driver_sha256', [CASE/'driver/verify_entropy.py']),
        ('hii_abi', BUILD/'hii_abi_test.json', 'candidate', 'driver_sha256', [CASE/'driver/verify_hii_abi.py']),
        ('owner', CASE/'owner_review/integrated_owner_regression.json', 'candidate', 'candidate_driver_sha256', [H02/'driver/build/AiTweakerLock1904.efi', H02/'driver/build/driver.map', H02/'driver/policy.json']),
        ('publication', CASE/'owner_review/integrated_publication_retirement_regression.json', 'candidate', 'driver_sha256', [I03/'driver/build/AiTweakerLock1904.efi', I03/'driver/build/driver.map', I03/'owner_review/publication_retirement_review.json']),
        ('discovery', BUILD/'discovery_regression.json', 'candidate', 'driver_sha256', [CASE/'driver/verify_discovery.py', CASE/'driver/verify_adapter.py']),
        ('ebs', CASE/'ebs_review/integrated_ebs_regression.json', 'candidate', 'driver_sha256', [CASE/'ebs_review/verify_ebs.py', CASE/'ebs_review/build_fixture.py', CASE/'ebs_review/fixture.c', CASE/'ebs_review/build/build.json', CASE/'ebs_review/build/EBS-SERVICES-ONLY.EFI', CASE/'ebs_review/build/fixture.map', CASE/'ebs_review/build/services.obj', BUILD/'services.obj', H02/'driver/build/AiTweakerLock1904.efi', H02/'driver/build/driver.map']),
        ('entry', CASE/'entry_review/integrated_retirement_regression.json', 'candidate', 'driver_sha256', [CASE/'entry_review/verify_retirement.py', I03/'driver/build/AiTweakerLock1904.efi']),
        ('save', SAVE/'unified_efi_verification.json', 'candidate', 'unified_efi.sha256', [SAVE/'verify_unified_efi.py', SAVE/'verify_retry_state.py', SAVE/'build_and_verify.py', SAVE/'save_scope.c', SAVE/'build/save_scope.dll', SAVE/'build/save_scope.map']),
        ('notice_ui', SAVE/'notice_ui_verification.json', 'candidate', 'efi_sha256', [SAVE/'verify_notice_ui.py', SAVE/'verify_unified_efi.py', SAVE/'verify_retry_state.py', SAVE/'build_and_verify.py', SAVE/'save_scope.c', SAVE/'build/save_scope.dll', SAVE/'build/save_scope.map']),
        ('ovmf', BUILD/'vm_integration.json', 'candidate', 'driver_sha256', [CASE/'driver/run_vm.py', CASE/'driver/build_vm.py', CASE/'driver/vm_fixture.c', CASE/'lab/inject_ovmf.py', BUILD/'VM-INTEGRATION-ONLY.EFI', BUILD/'vm_fixture.map', BUILD/'vm_hii_data.h', CASE/'lab/build/OVMF-ACTUAL-1904.fd', CASE/'lab/build/OVMF-ACTUAL-1904.json', ROOT/'tools/qemu-11.1.0/share/edk2-x86_64-code.fd', ROOT/'tools/qemu-11.1.0/share/edk2-i386-vars.fd', ROOT/'analysis/aitweaker_lock/uefi_vm_20261015/disk_images.py', ROOT/'analysis/aitweaker_lock/inspect_setup.py', NATIVE/'Setup_IFR.json']),
        ('compression', CASE/'compression_review/compression_summary.json', 'candidate', 'driver_sha256', [CASE/'compression_review/builder.snapshot.py', CASE/'compression_review/experiment.py', CASE/'compression_review/finalize.py', CASE/'compression_review/input.json', CASE/'compression_review/modified_inner.bin', CASE/'lab/build_asus_review.py', CASE/'lab/verify_asus_review.py', CAP]),
    ]
    reports = []
    supporting = set()
    for role, path, binding, identity, inputs in specifications:
        evidence = p.Evidence()
        p.verify_final_build(evidence, PIN)
        evidence.bind(path)
        data = json.loads(path.read_text(encoding='utf8'))
        p.require(p.passed(data) and p.dotted(data, identity) == PIN, 'report status/candidate mismatch: '+role)
        if role != 'core':
            inputs += [NATIVE/'AMITSE.efi', NATIVE/'Setup.efi']
        if role in {'policy', 'ovmf'}:
            inputs += sorted(BUILD.glob('*.obj'))
        if role == 'compression':
            inputs += [Path(data['independent_decoded_file']), Path(data['selected_verification_report']), CASE/'lab/asus_review/W790-ACE-1904-lock.review.bin']
        for source in inputs:
            evidence.bind(source)
        p.embedded_bindings(evidence, data, [path.parent, CASE, CASE/'driver', CASE/'core', ROOT, HERE])
        item = {'role': role, **ref(path), 'binding': binding, 'driver_hash_field': identity}
        if role == 'policy':
            ifr = json.loads((NATIVE/'Setup_IFR.json').read_text(encoding='utf8'))[0]
            item['derived_inputs'] = [{'report_field': 'source_ifr_sha256', 'source_path': p.relative(NATIVE/'Setup.efi'),
                                      'source_sha256': p.digest(NATIVE/'Setup.efi'), 'offset': ifr['offset'], 'length': ifr['length'],
                                      'sha256': data['source_ifr_sha256'], 'description': 'Original official Setup IFR package bytes; not the complete Setup PE or JSON.'}]
            evidence.derived_hashes.add(data['source_ifr_sha256'])
        p.scalar_input_bindings(evidence, data)
        item['input_files'] = {p.relative(file): value for file, value in sorted(evidence.inputs.items()) if file != path}
        reports.append(item)
        for file in evidence.inputs:
            if file == path or file.suffix.lower() in {'.obj', '.fd', '.cap'} or file.name in {'modified_inner.bin', 'unc_data.bin'}:
                continue
            if file.is_relative_to(ROOT/'tools'):
                continue
            p.package_safe(file)
            supporting.add(file)
    supporting.update([CASE/'lab/asus_review/W790-ACE-1904-lock.review.json', CASE/'test_harness_adaptations.json', Path(__file__).resolve()])
    # Capture actual OVMF log/result pairs; never include its writable NVRAM,
    # generated disks, or launch commands. Hashes must match the final summary.
    vm = json.loads((BUILD/'vm_integration.json').read_text(encoding='utf8'))
    vm_matches = [x for x in (CASE/'driver/vm_runs').glob('*/result.json') if p.digest(x) == p.digest(BUILD/'vm_integration.json')]
    p.require(len(vm_matches) == 1, 'expected exactly one run matching final six-boot report')
    run = vm_matches[0].parent
    supporting.add(vm_matches[0])
    for group in vm['groups']:
        folder = run/('readonly_iso' if group['readonly_iso'] else 'fat')
        for boot in group['boots']:
            directory = folder/('boot'+str(boot['phase']))
            p.require(p.digest(directory/'debug.log') == boot['debug_sha256'], 'OVMF debug log identity mismatch')
            supporting.update([directory/'debug.log', directory/'result.json'])
    index = {'schema': 1, 'frozen': False, 'driver_sha256': PIN,
             'status': 'LOCAL_VALIDATION_COMPLETE_PENDING_PARENT_HARDWARE_REVIEW_AND_FREEZE',
             'review_image': ref(CASE/'lab/asus_review/W790-ACE-1904-lock.review.bin'),
             'structural_verification': ref(CASE/'lab/asus_review/verification.json'),
             'ram_delivery_summary': ref(CASE/'ram_validation/delivery_summary.json'),
             'rea_summaries': [ref(HERE/'integration03_rea_review/integration03_review_summary.json'), ref(HERE/'integration03_rea_review/save_feedback_final_summary.json')],
             'reports': reports,
             'supporting_evidence': [ref(file) for file in sorted(supporting)],
             'pending_items': ['Parent review and final closure of version-separated hardware evidence and cleanup.', 'Parent explicitly freezes this validation index; no automatic freezing or packaging.'],
             'limits': ['Core 1844 historical assertions are reused by exact source equivalence; not rerun for this revision.', 'Every other reported candidate role binds actual complete 463b EFI. Explicit test doubles and per-report limits still apply.', 'HISTORY02 and INTEGRATED03 physical observations never constitute INTEGRATED04 physical acceptance.', 'Cold-start Del/F2, physical persistence, actual Save/Reset, OEM signing, flashing and recovery remain outside the demonstrated scope.'],
             'generator': ref(Path(__file__).resolve())}
    p.require(index['review_image']['sha256'] == BIN_PIN, 'review image changed from root-fixed candidate')
    # Exercise the same role validator as final publication without changing
    # either persisted freeze gate. Hardware is intentionally not consulted.
    evidence = p.Evidence()
    p.verify_final_build(evidence, PIN)
    p.verify_regressions(evidence, index, PIN, require_frozen=False)
    p.verify_structure(evidence, index, PIN, BIN_PIN)
    evidence.unchanged()
    target.write_text(json.dumps(index, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
    print(json.dumps({'status': 'PENDING_INDEX_WRITTEN', **ref(target), 'driver_sha256': PIN,
                      'roles': len(reports), 'supporting_files': len(supporting), 'frozen': False,
                      'hardware_index_modified': False, 'production_modified': False, 'candidate_packaged': False}, indent=2))


if __name__ == '__main__':
    main()
