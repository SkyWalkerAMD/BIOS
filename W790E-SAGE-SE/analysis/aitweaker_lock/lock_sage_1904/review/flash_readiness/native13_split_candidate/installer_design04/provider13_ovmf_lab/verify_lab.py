"""Read-only verification of retained P13 OVMF evidence; --freeze writes this lab only."""
from pathlib import Path
import argparse, hashlib, json, re, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
D04 = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
READY = D04.parent.parent
C08 = READY / 'remote_only/continuation08'
sys.path[:0] = [str(ROOT / 'tools/vm-pydeps'), str(ROOT / 'tools/kvm-pydeps')]
from pyfatfs.PyFatFS import PyFatFS
from PIL import Image

RUNS = ['20261103_203355', '20261103_203502', '20261103_203721', '20261103_203804']
GOOD = {'20261103_203502': [185, 191], '20261103_203804': [173, 192]}
PROVIDER = 'caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'
PIN = '2f7738e0cdfdb75a9557cf8c7bba233d512c17ac63063fea23d8e77975566e8a'
REVIEW = HERE / 'provider13_ovmf_review.json'
MANIFEST = HERE / 'provider13_ovmf_manifest.json'

def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def read(p):
    return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def artifact(p, base=None):
    p = Path(p).resolve()
    return {'path': str(p.relative_to(base)) if base else str(p),
            'bytes': p.stat().st_size, 'sha256': sha(p)}

def matched(p, record):
    p = Path(p)
    assert p.is_file() and p.stat().st_size == record['bytes'], str(p)
    assert sha(p) == record['sha256'], str(p)

def collect():
    external = set()
    candidate_path = D04 / 'provider13/local_candidate_manifest.json'
    assert sha(candidate_path) == PIN
    candidate = read(candidate_path)
    assert Path(candidate['path_base']).resolve() == D04.resolve()
    assert len(candidate['artifacts']) == 60
    for a in candidate['artifacts']:
        p = D04 / a['path']; matched(p, a); external.add(p.resolve())
    external.add(candidate_path.resolve())
    candidate_review = D04 / 'provider13/local_candidate_review.json'
    assert sha(candidate_review) == 'a76955fb4d869878355bb72f2617cac225ac772a5e4cf408a3a0c973163b62ce'
    external.add(candidate_review.resolve())
    assert sha(D04 / 'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi') == PROVIDER
    reference_results = []
    provenance_paths = [HERE / 'reference/browser_provenance.json',
                        C08 / 'edk2_reference/provenance.json',
                        C08 / 'edk2_debug_reference/provenance.json']
    for provenance_path in provenance_paths:
        doc = read(provenance_path)
        records = doc.get('files', doc.get('artifacts', [doc]))
        for record in records:
            p = Path(record['path'])
            if p.name not in {'FormBrowser2.h', 'HiiConfigAccess.h', 'Cpu.h', 'DebugSupport.h'}:
                continue
            matched(p, record)
            raw = p.read_bytes()
            git_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            assert git_blob == record['git_blob_sha'], str(p)
            reference_results.append({**record, 'independent_sha256_and_git_blob_match': True})
            if not p.is_relative_to(HERE): external.add(p.resolve())
        if not provenance_path.is_relative_to(HERE): external.add(provenance_path.resolve())
    assert len(reference_results) == 4
    origins = read(HERE / 'reference_origins.json')
    assert sha(origins['reference_path']) == origins['reference_sha256']
    external.add(Path(origins['reference_path']).resolve())
    modules = {'/TSE.EFI': D04.parent / 'boot_context/AMITSE.original.efi',
               '/SETUP.EFI': D04.parent / 'boot_context/Setup.original.efi',
               '/PROVIDER.EFI': D04 / 'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi'}
    external.update(p.resolve() for p in modules.values())
    tools = [ROOT / 'tools/qemu-11.1.0/qemu-system-x86_64.exe',
             ROOT / 'tools/qemu-11.1.0/share/edk2-x86_64-code.fd',
             ROOT / 'tools/qemu-11.1.0/share/edk2-i386-vars.fd',
             ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe',
             ROOT / 'analysis/aitweaker_lock/uefi_vm_20261015/disk_images.py']
    external.update(p.resolve() for p in tools)
    run_results = []
    total_screens = 0
    common_labels = [
        'actual provider entry starts', 'actual provider published',
        'cold provider starts locked without owner',
        'actual NewPackageList and ExportPackageLists preserve exact P13 package',
        'exactly one independent P13 management package',
        'management callback rejects no-owner invocation',
        'GetVariable and SetVariable were never replaced',
        'remove owned debug callback before EBS',
        'real ExitBootServices succeeds', 'real EBS permanently revokes provider',
        'actual EBS retires split state to ENDED']
    for run_name in RUNS:
        run = HERE / 'runs' / run_name
        result = read(run / 'result.json')
        snap = run / 'fixture-snapshot'
        assert result['provider_sha256'] == PROVIDER
        assert result['frozen_candidate_60_bindings_unchanged'] is True
        assert result['readonly_boot_disk_unchanged'] is True
        assert sha(snap / 'P13-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI') == result['fixture_sha256']
        assert sha(snap / 'persist_ui.c') == result['fixture_source_sha256']
        assert sha(snap / 'run_persist_ui.py') == result['runner_sha256']
        build = read(snap / 'build.json')
        assert build['fixture_sha256'] == result['fixture_sha256']
        assert build['source_sha256'] == result['fixture_source_sha256']
        assert build['extra_source_sha256'] == sha(snap / 'fixture_extra.inc')
        assert result['initial_vars_sha256'] == sha(tools[2])
        assert result['ovmf_code_sha256'] == sha(tools[1])
        assert result['final_vars_sha256'] == sha(run / 'shared-vars.fd')
        disk = run / 'readonly-boot.img'
        expected_files = {**modules, '/EFI/BOOT/BOOTX64.EFI': snap / 'P13-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI'}
        with PyFatFS(str(disk), read_only=True, utc=True) as fs:
            names = set(fs.walk.files())
            assert names == set(expected_files), (run_name, names)
            for name, source in expected_files.items():
                assert fs.readbytes(name) == source.read_bytes(), (run_name, name)
        summaries = []
        previous = result['initial_vars_sha256']
        for boot in result['boot_reports']:
            phase = boot['phase']; bd = run / f'boot{phase}'
            assert read(bd / 'result.json') == boot
            raw = (bd / 'debug.log').read_text(encoding='ascii', errors='replace')
            assert sha(bd / 'debug.log') == boot['debug_sha256']
            assert len(re.findall(r'^PASS ', raw, re.M)) == boot['checks']
            assert boot['vars_before_sha256'] == previous
            previous = boot['vars_after_sha256']
            command = read(bd / 'command.json')
            assert command[command.index('-nic') + 1] == 'none'
            assert command[command.index('-accel') + 1] == 'tcg,thread=single'
            assert command[command.index('-smp') + 1] == '1'
            drives = [command[i + 1] for i, word in enumerate(command) if word == '-drive']
            assert len(drives) == 3
            assert drives == [
                'if=pflash,format=raw,unit=0,readonly=on,file=' + str(tools[1]),
                'if=pflash,format=raw,unit=1,file=' + str(run / 'shared-vars.fd'),
                'if=none,id=boot,format=raw,readonly=on,file=' + str(disk)]
            for shot in boot['screenshots']:
                p = Path(shot['path']); assert p.parent == bd
                assert sha(p) == shot['sha256']
                with Image.open(p) as png, Image.open(p.with_suffix('.ppm')) as ppm:
                    assert png.size == ppm.size == (1280, 800)
                    assert png.convert('RGB').tobytes() == ppm.convert('RGB').tobytes()
                total_screens += 1
            labels = re.findall(r'^(?:PASS|FAIL) .*$', raw, re.M)
            if run_name in GOOD:
                assert result['status'].startswith('PASS') and boot['status'] == 'PASS'
                assert boot['exit_code'] == 33 and boot['error'] is None
                assert boot['checks'] == GOOD[run_name][phase - 1]
                assert not re.search(r'^FAIL ', raw, re.M)
                assert 'P13_UI_OVMF_PASS\n' in raw
                assert int(re.search(r'^CHECKS=([a-f0-9]+)$', raw, re.M)[1], 16) == boot['checks']
                for label in common_labels: assert 'PASS ' + label + '\n' in raw, label
                session_count = 4 if phase == 1 else 5
                for label in ['exactly one TCG debug redirection per owned session',
                              'real split guard popped both detached chains',
                              'outer end revokes owned session and grant']:
                    assert raw.count('PASS ' + label + '\n') == session_count, label
                if phase == 2:
                    assert 'PASS credential bytes persist identically across separate QEMU boots\n' in raw
                    for step in ['old_a_rejected', 'unlock_b', 'cancel_b', 'clear_b', 'disabled_next_session']:
                        assert 'STEP_DONE ' + step + '\n' in raw
                    assert raw.count('PASS wrong password or cancel leaves session locked\n') == 2
                    assert 'PASS full real GOP framebuffer restored byte-for-byte\n' in raw
                if run_name == '20261103_203804' and phase == 1:
                    assert 'FORM_BROWSER_RETURN 0000000000000000 ACTION 0000000000000000\n' in raw
                    assert 'PASS real HII management form exits successfully\n' in raw
            else:
                assert result['status'].startswith('FAILED') and boot['status'] == 'FAIL'
                assert boot['exit_code'] == 35 and 'P13_UI_OVMF_FAIL\n' in raw
                failure = ('real OVMF x64 DebugSupport located' if run_name.endswith('203355')
                           else 'real NVRAM record length and NV-BS attributes')
                assert 'FAIL ' + failure + '\n' in raw
                if run_name.endswith('203355'): assert 'PASS actual provider entry starts\n' not in raw
            summaries.append({'phase': phase, 'status': boot['status'], 'runtime_assertions': boot['checks'],
                              'debug_sha256': boot['debug_sha256'], 'screens': len(boot['screenshots']),
                              'assertion_labels': labels})
        assert previous == result['final_vars_sha256']
        assert len(summaries) == (2 if run_name in GOOD else 1)
        run_results.append({'run': run_name, 'status': result['status'], 'fixture_sha256': result['fixture_sha256'],
                            'readonly_boot_image_sha256': sha(disk), 'boot_reports': summaries})
    latest = HERE / 'runs/20261103_203804'
    assert read(HERE / 'latest_result.json') == read(latest / 'result.json')
    for name in ['persist_ui.c', 'fixture_extra.inc', 'run_persist_ui.py']:
        assert sha(HERE / name) == sha(latest / 'fixture-snapshot' / name)
    assert sha(HERE / 'build/P13-OVMF-FIXTURE-NOT-FOR-HARDWARE.EFI') == read(latest / 'result.json')['fixture_sha256']
    return {'status': 'PASS_LOCAL_OVMF_ONLY_NOT_HARDWARE_OR_INSTALLER_ACCEPTANCE',
            'candidate_manifest_sha256': PIN, 'candidate_bindings_verified': 60,
            'provider_sha256': PROVIDER, 'official_header_references_verified': reference_results,
            'raw_png_ppm_pairs_verified': total_screens, 'retained_runs': run_results,
            'external_inputs': [artifact(p) for p in sorted(external)],
            'runtime_assertion_count_note': 'Counts repeat setup, HII iteration and session assertions; do not sum into unique cases or combine with prior P04/Unicorn counts.',
            'tested': [
                'Actual frozen P13 EFI entry through OVMF LoadImage/StartImage; exact frozen split guards and 12 reviewed detours in owned VM copies.',
                'Actual HII package creation/export byte identity and ConfigAccess ownership; latest enrollment traverses real OVMF FormBrowser2 SendForm and keyboard selection.',
                'Real console input/GOP, actual credential logic and unmodified OVMF RuntimeServices GetVariable/SetVariable.',
                'Enroll A, wrong-password rejection, unlock A, change A to B; separate second process with same owned vars verifies byte-identical generation-2 record, old A refusal, B unlock, Escape cancellation, explicit clear and disabled next session.',
                'Each wrapper session creates and pops detached frame chains, grants only its owner and revokes at End; actual ExitBootServices permanently ends provider/state.',
                'Direct callback UI checkpoints compare console mode/cursor state and full GOP pixel hashes; latest selected unlock B checkpoint passed.'
            ],
            'declared_substitutions': [
                'The original ASUS DXE entrypoints and native browser body do not execute. Fixture supplies matching FV-file LoadedImage paths and the two BootServices globals.',
                'TCG-only hardware execution breakpoint at original E1CA continuation changes saved exception context, restores eight original pushes and redirects to declared body stub; no OEM body-byte patch.',
                'Twelve detours and real CPU Arch RX/RW-NX assignments are prepared by the local fixture, not the production transaction installer.',
                'Only enrollment in run 203804 is selected through SendForm. Later change/verify/clear use the actual installed ConfigAccess callback directly.',
                'Dummy test strings and a lab completion marker are stored only in owned writable OVMF vars; no real credentials, BMC or physical disks.'
            ],
            'retained_failures': [
                {'run': RUNS[0], 'reason': 'Fixture required x64 DebugSupport, but this OVMF exposed EBC DebugSupport only; rejected before starting P13.', 'resolution': 'Use official CPU Arch exception registration with verified x64 context layout in a revised local fixture.'},
                {'run': RUNS[2], 'reason': 'Initial FormBrowser highlight was explanatory text; Enter did not select Set/change. Record-presence check correctly failed.', 'resolution': 'Add Down before Enter in the standard keyboard fixture; production provider unchanged.'}
            ],
            'visual_review': ['203804 boot1/enroll_a-prompt: distinct Ai Tweaker Password form with Set/change, Clear, Verify.',
                              '203804 boot1/enroll_a-password-via-form: real management New password prompt.',
                              '203804 boot2/unlock_b-restored: original OVMF frame restored; backed by runtime full-pixel equality.',
                              '203804 boot2/clear_b-prompt: current password prompt before explicit clear.'],
            'limits': [
                'Does not validate native ASUS browser rendering, all 12 navigation paths, direct Del entry, BMC/KVM input, or hardware password/NVRAM behavior.',
                'Does not validate the new allocation/publication/rollback transaction, AP/TLB synchronization, real platform attribute enforcement faults, or production ReadyToBoot scheduling.',
                'Does not validate Secure Boot, capsule signature/Boot Guard, flashing, SPI backup or recovery. No release acceptance.',
                'Single-vCPU QEMU TCG observations cannot establish multicore hardware or hostile-ring0 security.',
                'Immutable package equality and full .text observation refer to their recorded checkpoints; separate source review supplies their broader intent.'
            ]}

def owned_artifacts():
    return [artifact(p, HERE) for p in sorted(HERE.rglob('*'))
            if p.is_file() and p != MANIFEST
            and not any(part in {'zig-local', 'zig-global', '__pycache__'} for part in p.relative_to(HERE).parts)]

def main():
    parser = argparse.ArgumentParser(); group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--freeze', action='store_true'); group.add_argument('--verify-only', action='store_true')
    args = parser.parse_args(); review = collect()
    if args.freeze:
        assert not REVIEW.exists() and not MANIFEST.exists(), 'Already frozen; use --verify-only'
        REVIEW.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
        manifest = {'status': review['status'], 'path_base': str(HERE),
                    'external_inputs': review['external_inputs'], 'artifacts': owned_artifacts(),
                    'excluded': ['this manifest self-reference', 'build/zig-local/**', 'build/zig-global/**', '**/__pycache__/**']}
        MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    else:
        assert read(REVIEW) == review, 'Review differs from verified evidence'
        manifest = read(MANIFEST)
        assert manifest['external_inputs'] == review['external_inputs']
        assert manifest['artifacts'] == owned_artifacts(), 'Owned artifact binding or membership changed'
    print(json.dumps({'status': 'PASS', 'review_sha256': sha(REVIEW), 'manifest_sha256': sha(MANIFEST),
                      'external_bindings': len(manifest['external_inputs']), 'local_artifacts': len(manifest['artifacts']),
                      'raw_png_ppm_pairs': review['raw_png_ppm_pairs_verified'], 'candidate_bindings': 60}))

if __name__ == '__main__': main()
