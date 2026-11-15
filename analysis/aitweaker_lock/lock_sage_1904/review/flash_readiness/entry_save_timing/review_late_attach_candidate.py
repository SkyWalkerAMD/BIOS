"""Independent, offline review binder for the isolated late-attach candidate.

Reads candidate artifacts; writes only this review directory. It does not run
firmware, repeat the author's tests, modify candidates, or access any device.
Pass the final ownership-test JSON as the sole positional argument.
"""
from pathlib import Path
import datetime
import difflib
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FLASH = HERE.parent
CASE = FLASH.parents[1]
ROOT = CASE.parents[2]
CANDIDATE = FLASH / 'late_attach_candidate'
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import capstone
import pefile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf8'))


def rel(path):
    return path.relative_to(CASE).as_posix()


manifest = read(CANDIDATE / 'source_manifest.json')
build = read(CANDIDATE / 'build/build.json')
frozen_summary_path = CANDIDATE / 'candidate_summary.json'
frozen_summary = read(frozen_summary_path)
for path, digest in frozen_summary['files'].items():
    assert sha(CANDIDATE / path) == digest, path
efi = CANDIDATE / 'build/AiTweakerLock1904.efi'
assert sha(efi) == build['candidate_driver_sha256']
assert sha(efi) == frozen_summary['candidate_driver_sha256']
assert sha(CASE / 'driver/build/AiTweakerLock1904.efi') == build['baseline_driver_sha256']
assert sha(FLASH / 'ebs_candidate/build/AiTweakerLock1904.efi') == build['ebs_candidate_driver_sha256']
for path, digest in manifest['baseline_sources'].items():
    assert sha(CASE / path) == digest, path
for path, digest in manifest['candidate_sources'].items():
    assert sha(CANDIDATE / path) == digest, path
for path, digest in build['object_sha256'].items():
    assert sha(CASE / path) == digest, path
assert build['candidate_sources'] == manifest['candidate_sources']

sources = {name: (CANDIDATE / name).read_text(encoding='utf8')
           for name in manifest['candidate_sources']}
ebs_source = (FLASH / 'ebs_candidate/services.c').read_text(encoding='utf8')
ebs_anchor = 'static int update_runtime_set(SETVAR fn) {'
assert sources['services.c'].split(ebs_anchor, 1)[1] == ebs_source.split(ebs_anchor, 1)[1]
base_platform = (CASE / 'driver/platform.c').read_text(encoding='utf8')
for start, end in [('static int reset_history_root(', 'static int gate('),
                   ('static uint64_t EA browser_loop(', 'static void absolute_jump('),
                   ('int attach_platform(', 'void end_platform(')]:
    assert sources['platform.c'].split(start, 1)[1].split(end, 1)[0] == base_platform.split(start, 1)[1].split(end, 1)[0], start


def excerpt(name, start, end=None):
    lines = sources[name].splitlines()
    index = next(i for i, line in enumerate(lines) if start in line)
    finish = next((i for i in range(index + 1, len(lines)) if end and end in lines[i]), len(lines))
    return {'path': rel(CANDIDATE / name), 'sha256': manifest['candidate_sources'][name],
            'first_line': index + 1, 'last_line': finish,
            'lines': [{'line': i + 1, 'text': lines[i]} for i in range(index, finish)]}


evidence = {
    'ownership': excerpt('platform.c', 'int platform_session_owned(', 'typedef uint64_t'),
    'ui_hooks': excerpt('platform.c', 'static int gate(', 'static uint64_t EA browser_loop('),
    'wrapper': excerpt('platform.c', 'static uint64_t EA browser_loop(', 'static void absolute_jump('),
    'ensure': excerpt('ui.c', 'int ensure_unlocked(', 'int manage_password('),
    'management': excerpt('ui.c', 'int manage_password('),
    'hii_callback': excerpt('hii.c', 'static ES EA config_callback(', 'static int nibble('),
    'hii_route': excerpt('hii.c', 'static ES EA config_route(', 'static uint16_t add_string('),
    'credential_persistence': excerpt('services.c', 'static int persist_record(', 'static int entropy('),
    'variable_guard': excerpt('services.c', 'static ES EA guarded_set(', '/* Check actual page-table'),
}

pe = pefile.PE(str(efi))
base = pe.OPTIONAL_HEADER.ImageBase
image = pe.get_memory_mapped_image()
symbols = {}
for line in (CANDIDATE / 'build/driver.map').read_text(encoding='utf8').splitlines():
    match = re.match(r'\s*0001:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s', line)
    if match:
        symbols[match[1]] = int(match[2], 16)
by_address = {address: name for name, address in symbols.items()}
addresses = sorted(by_address)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
native = {}
for name in ['platform_session_owned', 'platform_can_enter', 'gate', 'render',
             'page_input', 'app_input', 'frame_input', 'navigation', 'poll',
             'browser_loop', 'ensure_unlocked', 'manage_password',
             'config_callback', 'config_route', 'persist_record', 'guarded_set']:
    begin = symbols[name]
    finish = next(x for x in addresses if x > begin)
    raw = image[begin-base:finish-base]
    instructions = list(md.disasm(raw, begin))
    calls = []
    for insn in instructions:
        if insn.mnemonic not in ('call', 'jmp') or not insn.operands:
            continue
        op = insn.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            calls.append({'at_rva': hex(insn.address-base), 'op': insn.mnemonic,
                          'target_rva': hex(op.imm-base), 'symbol': by_address.get(op.imm)})
    native[name] = {'rva': hex(begin-base), 'extent_to_next_link_symbol': len(raw),
                    'extent_sha256': hashlib.sha256(raw).hexdigest(), 'calls_and_tailcalls': calls,
                    'instructions': [{'rva': hex(i.address-base), 'bytes': i.bytes.hex(),
                                      'instruction': f'{i.mnemonic} {i.op_str}'} for i in instructions]}

tests = []
summary_path = CANDIDATE / 'full_regression/summary.json'
summary = read(summary_path)
assert summary['candidate_driver_sha256'] == build['candidate_driver_sha256']
for item in summary['tests']:
    path = Path(item['report'])
    assert sha(path) == item['report_sha256']
    result = read(path)
    assert result.get('driver_sha256', result.get('driver_efi_sha256')) == build['candidate_driver_sha256']
    tests.append({'report': rel(path), 'sha256': sha(path),
                  'status': result.get('status', result.get('passed')),
                  'checks_or_cases': item['checks_or_cases'],
                  'test_source': rel(CANDIDATE / 'full_regression' / item['test']),
                  'test_source_sha256': sha(CANDIDATE / 'full_regression' / item['test']),
                  'limits': result.get('limits', result.get('scope'))})
ebs_report = CANDIDATE / 'ebs_regression.json'
ebs_result = read(ebs_report)
assert ebs_result['candidate_driver_sha256'] == build['candidate_driver_sha256']
tests.append({'report': rel(ebs_report), 'sha256': sha(ebs_report),
              'status': ebs_result['status'], 'checks_or_cases': ebs_result['checks'],
              'limits': ebs_result['limits']})
ownership_report = Path(sys.argv[1]).resolve()
ownership_result = read(ownership_report)
assert str(ownership_report).startswith(str(CANDIDATE.resolve()))
assert ownership_result.get('candidate_driver_sha256', ownership_result.get('driver_sha256')) == build['candidate_driver_sha256']
assert ownership_result['status'] == 'PASS_ISOLATED_LATE_ATTACH_OWNER_CANDIDATE'
assert ownership_result['test_sha256'] == sha(CANDIDATE / 'verify_late_attach.py')
assert ownership_result['checks'] == len(ownership_result['check_names'])
assert ownership_result['source_sha256'] == manifest['candidate_sources']
for required in [
    'enabled stale unlocked: Ai render denied silently',
    'enabled stale unlocked: direct actual UI unlock returns denied',
    'enabled stale unlocked: private credential persistence denies before service read',
    'explicit disabled without active session is allowed',
    'disabled ordinary boot changed OC write remains allowed',
    'disabled management still requires owned session',
    'same owned session second navigation reuses grant without prompt',
    'same owned session protected HII callback reuses grant without prompt',
    'nested return retains outer grant without another prompt',
    'outer return ends owner and clears grant',
    'credential pre-read losing owner blocks original SetVariable',
    'legitimate owned core-busy persistence remains possible',
    'first discovery in stage5 remains unhooked (documented gap)',
    'first attach failure is still not retried (documented gap)',
]:
    assert required in ownership_result['check_names'], required
tests.append({'report': rel(ownership_report), 'sha256': sha(ownership_report),
              'status': ownership_result.get('status'),
              'checks_or_cases': ownership_result.get('checks', ownership_result.get('cases')),
              'limits': ownership_result.get('limits')})

report = {
    'schema': 1,
    'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'reviewer': '/root/sage_remote_identity',
    'status': 'INDEPENDENT_STATIC_REVIEW_WITH_REVIEWED_LOCAL_EMULATION_EVIDENCE',
    'candidate_driver': {'path': rel(efi), 'sha256': sha(efi)},
    'production_driver': {'path': 'driver/build/AiTweakerLock1904.efi', 'sha256': build['baseline_driver_sha256']},
    'ebs_base_driver_sha256': build['ebs_candidate_driver_sha256'],
    'candidate_sources': manifest['candidate_sources'],
    'frozen_candidate_summary': {'path': rel(frozen_summary_path), 'sha256': sha(frozen_summary_path)},
    'review_builder_sha256': sha(Path(__file__)),
    'build_manifest': {'path': rel(CANDIDATE / 'build/build.json'), 'sha256': sha(CANDIDATE / 'build/build.json')},
    'entry_save_timing_report': {'path': rel(HERE / 'entry_save_timing_review.json'), 'sha256': sha(HERE / 'entry_save_timing_review.json')},
    'method': [
        'Read full source and diff for all five isolated candidate files.',
        'Independently checked all baseline/candidate source and selected link-object digests against the build/source manifests.',
        'Bound decoded actual candidate x64 function bytes and direct calls to its linker map.',
        'Reviewed test source retargeting and reported results; this audit does not represent another independent execution of those suites.',
        'No BMC/network/device access, no firmware execution on host hardware, no candidate/production/package mutation.'
    ],
    'review_conclusion': {
        'normal_input_blocker_introduced_found': False,
        'observed_physical_stage4_bypass': False,
        'stage4_window_closed_conditionally_after_hooks_installed': True,
        'first_discovery_at_stage5_without_hooks_fixed': False,
        'physical_or_full_firmware_acceptance': False,
        'approved_for_flash_by_this_review': False,
        'note': 'The reviewed change coherently denies protected callbacks when an installed wrapper does not own an active session. This supports the narrow late-stage4 fix, not guaranteed cold-boot first-Del protection.'
    },
    'findings': [
        {
            'id': 'LA-OWNER', 'classification': 'OBSERVED_SOURCE_AND_COMPILED_BYTES',
            'finding': 'platform_session_owned requires 1 <= loop_depth <= 16, active and pre-EBS. A stale active/unlocked pair at loop_depth zero cannot grant protected access. platform_can_enter explicitly handles a validated DISABLED mode before the owner/core gate, while busy/EBS always deny that helper.',
            'evidence': ['ownership', 'platform_session_owned', 'platform_can_enter'],
            'boundary': 'This is local code state, not a hardware-attested session identity; the core serial-callback contract remains required.'
        },
        {
            'id': 'LA-UI', 'classification': 'OBSERVED_SOURCE_AND_COMPILED_BYTES',
            'finding': 'Installed render, page_input, app_input and frame_input enforce protection even at loop_depth zero. Unowned protected/unknown pages redirect through the unchanged HISTORY01 validation or end the browser. Input deny returns zero to consume it. Poll checks stage5 independently of depth, and can prompt only with owner. Navigation rejects an unauthorized protected destination without prompting.',
            'evidence': ['ui_hooks'],
            'boundary': 'navigation still calls the original verified OEM navigation stub to obtain its result before its checks. Safe pages may still chain normally. A frame deny consumes that frame input without mandatory page redirection.'
        },
        {
            'id': 'LA-HII-AND-WRITES', 'classification': 'OBSERVED_SOURCE_AND_COMPILED_BYTES',
            'finding': 'HII policy callbacks, protected RouteConfig, and changed protected SetVariable writes use the shared grant predicate. Credential management requires owner even when disabled. ensure/manage recheck ownership before core calls and ownership plus token before reporting success. persist_record verifies owner both before and after its preliminary GetVariable, and does not incorrectly require !busy during the core commit.',
            'evidence': ['hii_callback', 'hii_route', 'ensure', 'management', 'credential_persistence', 'variable_guard'],
            'boundary': 'DISABLED retains existing external RouteConfig/SetVariable pass behavior; the new helper is not evaluated on those existing disabled fast paths. This does not authorize credential-variable writes, which remain denied through guarded_set.'
        },
        {
            'id': 'LA-NORMAL-SESSIONS', 'classification': 'OBSERVED_SOURCE_AND_LOCAL_EMULATION',
            'finding': 'browser_loop, HISTORY01 redirect/history normalization and attach/rollback source remain byte-for-byte unchanged in C. The wrapper still begins/relocks one outer session, retains its grant across nested calls, and ends/relocks on outer return. Owned+unlocked helpers avoid further prompts. Existing adapter/history regressions are rebound to this new EFI, with their authentication/full-browser stubs explicitly retained.',
            'evidence': ['wrapper', 'ui_hooks', 'ensure'],
            'boundary': 'These results do not execute the complete OEM browser or establish persistence after a real F10/save/reboot.'
        },
        {
            'id': 'LA-EBS', 'classification': 'OBSERVED_SOURCE_AND_LOCAL_EMULATION',
            'finding': 'services.c from update_runtime_set through end of file is exactly the preserved EBS candidate source. The existing 83 local handoff checks report pass against the new candidate hash.',
            'boundary': 'The EFI is newly linked; prior OVMF or physical acceptance of an older hash cannot be inherited. Final callback and terminal safety behavior are emulated only in the cited suite.'
        },
        {
            'id': 'LA-FIRST-ENTRY', 'classification': 'CONFIRMED_UNCHANGED_CODE_LIMIT_AND_UNVERIFIED_PLATFORM_TIMING',
            'finding': 'entry.obj remains the original one-shot discover implementation: a first eligible scan at stage5 refuses attach and attempted is latched before attach. The candidate does not repair a complete absence of hooks for that current invocation or safe recovery after partial attach failure.',
            'required_next_evidence': 'Measure that original Setup and AMITSE, board/BIOS identity and FormBrowser2 prerequisites are available before the first native browser prologue, or implement and independently validate a pre-entry installation path. EndOfDxe-before-normal-BDS-Setup is statically supported but does not itself prove all prerequisites or exclude earlier OEM entries.',
            'evidence': ['entry_save_timing_report']
        }
    ],
    'test_review': {
        'reports': tests,
        'owner_test_source': {'path': rel(CANDIDATE / 'verify_late_attach.py'), 'sha256': sha(CANDIDATE / 'verify_late_attach.py')},
        'owned_session_prompt_reuse': 'The final new suite directly asserts one prompt across a second native navigation, protected HII callback and nested-browser return; outer return then clears authorization.',
        'retargeting_note': 'The ABI positive fixture deliberately seeds loop_depth=1 and active=1 for managed callbacks; its prior ABI assertions are unchanged. Absence/stale-owner behavior is assessed by the separate ownership suite, not inferred from these seeded ABI cases.',
        'test_counts_are_not_hardware_coverage_percentages': True
    },
    'preservation_checks': {
        'all_manifest_digests_match_files': True,
        'original_production_efi_unchanged': True,
        'original_ebs_candidate_efi_unchanged': True,
        'ebs_cleanup_source_tail_exact': True,
        'browser_wrapper_source_exact': True,
        'history_redirect_source_exact': True,
        'attach_and_rollback_source_exact': True
    },
    'source_evidence': evidence,
    'native_evidence': native,
    'outstanding_limits': [
        'The stage4 attach condition is demonstrated from native control flow, not observed as a physical bypass on SAGE.',
        'Without any installed hook, a stage5-discovered browser remains outside this repair.',
        'One-shot attempted and incomplete rollback recovery remain unchanged; do not clear attempted blindly.',
        'With protection enabled or unconfigured, the global guard still denies changed protected variables outside a browser session, including a missing OC variable. Whether a normal original OEM boot needs such writes after driver installation is not established by these synthetic storage cases.',
        'No cold-boot Del/F2 physical test, persistent NVRAM readback/reboot test, full OEM Save chain emulation, or firmware update acceptance is supplied by this audit.',
        'Source matches plus partial native execution are narrower than a complete ASUS DXE boot.'
    ]
}
output = HERE / 'late_attach_candidate_review.json'
output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps({'report': str(output), 'sha256': sha(output),
                  'candidate_driver_sha256': sha(efi),
                  'native_functions': len(native), 'test_reports': len(tests)}, indent=2))
