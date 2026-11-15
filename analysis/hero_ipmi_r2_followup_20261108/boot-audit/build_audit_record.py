"""Hash-bind the local boot audit; no network or firmware mutation."""
from pathlib import Path
import hashlib
import json
import sys

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]


def record(relative):
    p = ROOT / relative
    return {'path': relative, 'bytes': p.stat().st_size,
            'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}


paths = [
    'analysis/hero_ipmi_rc3_20261104/firmware/HERO-3107-IPMI-P5-R2-RC3-UNSIGNED.CAP',
    'analysis/hero_ipmi_r2/USB/EFI/HERO/HeroIpmiR2.efi',
    'analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs',
    'analysis/hero_ipmi_r2/driver.map',
    'analysis/hero_ipmi_r2/build.json',
    'analysis/hero_ipmi_r2/source/driver.c',
    'analysis/hero_ipmi_r2/source/common.c',
    'analysis/hero_ipmi_r2/source/engine.c',
    'analysis/hero_ipmi_r2/source/r2.h',
    'analysis/hero_ipmi_r2/source/efi_min.h',
    'analysis/hero_ipmi_p5/source/driver.c',
    'analysis/hero_ipmi_p5/source/transport.c',
    'analysis/hero_ipmi_rc3_20261104/container-verification.json',
    'analysis/hero_ipmi_rc3_20261104/runtime-verification.json',
    'analysis/hero_ipmi_rc3_20261104/review/integration-review.json',
    'analysis/hero_ipmi_rc3_20261104/FIELD-PACKAGE/04-EVIDENCE/REUSED-REA/P5-RC2-review-index.json',
    'analysis/hero_ipmi_r2/reference/rea/seeded/rea-evidence.json',
    'analysis/hero_ipmi_r2/适配与REA解析记录.txt',
    'analysis/hero_ipmi_r2_live_20261102/live-verification.json',
    'analysis/hero_ipmi_r2_live_20261102/R2-before-summary.TXT',
    'analysis/hero_ipmi_r2_live_20261102/R2-final-summary.TXT',
    'analysis/hero_ipmi_rc3_live_20261108/live-verification.json',
    'analysis/hero_ipmi_rc3_live_20261108/r2-baseline-replay.json',
    'analysis/hero_ipmi_p6_20261104/collector/source/launcher.c',
    'analysis/hero_ipmi_p6_20261104/collector/HERO-P6-RC4-READONLY-LOG.iso',
    'analysis/hero_ipmi_rc3_20261104/collector/HERO-RC3-AUTO-LOG.iso',
    'analysis/hero_ipmi_continued_live_20261108/screens/initial-kvm.png',
]
bindings = [record(p) for p in paths]
assert bindings[0]['sha256'] == '8ffc4b33f6d0e2bb7180c724de01a805f556ad126d08830e7f052b37ce771951'
assert bindings[1]['sha256'] == '1e206aa41b6133c642d724fa1c6aae2f2cd28eb6010a55a66b22a89c3b354845'
build = json.loads((ROOT / 'analysis/hero_ipmi_r2/build.json').read_text(encoding='utf-8'))
for item in bindings:
    marker = 'analysis/hero_ipmi_r2/source/'
    if item['path'].startswith(marker):
        assert item['sha256'] == build['sources'][item['path'][len(marker):]], item['path']
replay = json.loads((OUT / 'machine-code-readiness-replay.json').read_text(encoding='utf-8'))
assert replay['all_passed'] and replay['count'] == 2
outputs = [record(str(p.relative_to(ROOT)).replace('\\', '/')) for p in OUT.iterdir()
           if p.is_file() and p.name != 'boot-path-audit.json']
result = {
    'date': '2026-11-08',
    'reviewer': '/root/r2_boot_path_audit',
    'scope': 'Local R2/RC3 automatic dispatch, one-shot readiness, locks, P5 interaction, and current-boot log availability.',
    'network_or_physical_device_accessed_by_this_review': False,
    'published_firmware_changed': False,
    'source_bindings_match_published_build': True,
    'bindings': bindings,
    'outputs': outputs,
    'reused_not_reexecuted': [
        'RC3 container validation and independent integration review',
        'RC3 9-case shared P5/R2 machine-code execution report',
        'Existing REA donor event/publisher evidence and P5/inner-DXE review',
        '.182 2026-11-02 hardware E0 then C0 record',
        '.71 2026-11-08 captured baseline replay supplied by parent',
    ],
    'new_executed_cases': [c['case'] for c in replay['cases']],
    'confirmed': [
        'Entry has no BMC query and waits for ReadyToBoot in firmware mode.',
        'SMBIOS missing at entry is not a hard dispatch rejection; it is re-read for operation.',
        'An E0 pre-OEM baseline failure consumes the automatic one-shot latch; later Ready signals do not rescan after C0 becomes available.',
        'No evidence of a source/byte mismatch, incorrect inner DXE placement, LoadedImage ABI bug, or normal automatic P5/R2 collision.',
        'Any previous attempt variable blocks OEM; no automatic stale-lock clearing exists.',
        'Current log is a boot-service RAM object with no implemented BMC, ACPI, or OS runtime export.',
    ],
    'latest_hardware_context_from_parent': {
        'evidence': 'analysis/hero_ipmi_continued_live_20261108/screens/initial-kvm.png',
        'independently_viewed_by_this_reviewer': True,
        'observation': 'AMI POST CPU Fan speed detection error / press F1; HERO BIOS3107; not an observed OS session.',
        'interpretation': 'ReadyToBoot might not have occurred. No automatic initialization failure is established by the 10-sensor snapshot.',
    },
    'unresolved_on_actual_71': [
        'Current flashed RC3 SPI bytes and resident R2 API/LoadOptions mode',
        'Whether first ReadyToBoot has run, including actual initial KCS and VERSION_ERR state',
        'Actual HeroIpmiCfg and HeroIpmiAttempt state',
        'Real OEM sequence and stable postcheck outcome',
    ],
    'minimum_next_evidence': 'Resident R2 summary and full cached audit from the same firmware session before any manual engine run or lock change.',
    'limit': 'The synthetic compatibility failure is not established as .71 root cause; actual POST pause is separate evidence.',
}
(OUT / 'boot-path-audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'bindings': len(bindings), 'outputs': len(outputs), 'machine_code_cases': 2, 'passed': True}))
