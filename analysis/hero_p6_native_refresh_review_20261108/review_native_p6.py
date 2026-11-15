"""Offline identity/resource comparison only; no firmware/device writes."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import zlib

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
spec = importlib.util.spec_from_file_location(
    'prior_independent_parser', ROOT / 'analysis/hero_rc5_independent_review_20261108/audit_rc5.py')
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)

def sha(data):
    return hashlib.sha256(data).hexdigest()

paths = {
    'observed': ROOT / 'analysis/hero_ipmi_p6_20261104/review-20261108/container-441b61136974/P6-RC4.CAP',
    'latest': ROOT / 'analysis/hero_ipmi_p6_20261104/firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP',
    'sectionfix_latest': ROOT / 'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/HERO-3107-IPMI-SECTIONFIX-LATEST-UNSIGNED.CAP',
}
images = {k: parser.image(p) for k, p in paths.items()}
forms = (ROOT / 'analysis/hero_ipmi_p6_20261104/native/Setup-forms-P6.bin').read_bytes()
result = {'scope': 'Offline comparison and source review; no new device test or firmware build.',
          'forms': {'bytes': len(forms), 'sha256': sha(forms)}, 'images': {}, 'comparisons': []}
for label, image in images.items():
    ffs = image['inner']['files'][parser.P6]['data']
    body = ffs[24:]
    if label != 'sectionfix_latest':
        if body[-2:] != b'\0\0':
            raise ValueError('Unexpected original tail')
        body = body[:-2]
    parts = parser.sections(body)
    pe = parts[1]['body']
    if pe.count(forms) != 1:
        raise ValueError('Expected forms identity mismatch')
    result['images'][label] = {
        'path': str(paths[label].relative_to(ROOT)), 'sha256': sha(image['cap']),
        'inner_ffs_count': len(image['inner']['files']), 'p6_ffs_sha256': sha(ffs),
        'p6_ffs_bytes': len(ffs), 'p6_pe_bytes': len(pe), 'p6_pe_sha256': sha(pe),
        'p6_pe_crc32': f'{zlib.crc32(pe):08X}', 'forms_occurrences': 1,
        'forms_file_offset': pe.find(forms), 'p6_depex_hex': parts[0]['body'].hex(),
    }
for before, after, expected in [
    ('observed', 'latest', {parser.P6}),
    ('latest', 'sectionfix_latest', {parser.P6, parser.R2}),
]:
    a, b = images[before]['inner'], images[after]['inner']
    if set(a['files']) != set(b['files']):
        raise ValueError('Unexpected file-set change')
    changed = [g for g in a['files'] if a['files'][g]['data'] != b['files'][g]['data']]
    if set(changed) != expected:
        raise ValueError('Unexpected file changes: ' + repr(changed))
    result['comparisons'].append({'before': before, 'after': after,
                                  'changed_inner_guids': changed,
                                  'all_other_inner_ffs_exact': True,
                                  'original_file_order_preserved': a['order'] == b['order']})
for label in ['observed', 'latest']:
    p = images[label]['inner']['files'][parser.P6]['data'][24:]
    result['images'][label]['target_dxecore_accepts_original_stream'] = parser.run_native_validator(p)
    result['images'][label]['target_dxecore_accepts_trimmed_stream'] = parser.run_native_validator(p[:-2])
    if result['images'][label]['target_dxecore_accepts_original_stream'] or not result['images'][label]['target_dxecore_accepts_trimmed_stream']:
        raise ValueError('Target DxeCore comparison differs from prior evidence')

log = ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-fv-sections-i2c.TXT'
data = log.read_bytes()
result['i2c_hardware_evidence'] = {'path': str(log.relative_to(ROOT)), 'bytes': len(data),
    'sha256': sha(data), 'crc32': f'{zlib.crc32(data):08X}',
    'scope': 'Actual original ReadSection failures; trimmed stream success above is local exact-target machine-code execution, not a flashed result.'}
sources = [
    'analysis/hero_ipmi_p6_20261104/source/driver.c',
    'analysis/hero_ipmi_p6_20261104/source/settings.c',
    'analysis/hero_ipmi_p6_20261104/source/settings.h',
    'analysis/hero_ipmi_p6_20261104/source/publisher.c',
    'analysis/hero_ipmi_p6_20261104/source/transport.c',
    'analysis/hero_ipmi_p6_20261104/runtime-verification.json',
    'analysis/hero_ipmi_p6_20261104/publisher-tests.json',
    'analysis/hero_ipmi_p6_20261104/review-20261108/setupenter-lifecycle.json',
    'analysis/hero_ipmi_p6_20261104/collector/source/launcher.c',
    'analysis/hero_ipmi_p6_20261104/collector/HERO-P6-RC4-READONLY-LOG.iso',
    'analysis/hero_ipmi_p6_20261104/HeroIpmiP6.efi',
    'analysis/hero_ipmi_complete_live_20261108/screens/current-native-ipmi-info.png',
]
result['reviewed_artifacts'] = {p: {'bytes': (ROOT / p).stat().st_size,
                                  'sha256': sha((ROOT / p).read_bytes())} for p in sources}
result['passed'] = True
(OUT / 'identity-and-resource-comparison.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'passed': True, 'report': str(OUT / 'identity-and-resource-comparison.json'),
                  'observed_vs_latest_only_p6_changed': True,
                  'same_forms_all_three': True, 'target_core_original_rejects_trimmed_accepts': True}))
