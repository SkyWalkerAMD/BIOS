"""Independent binding review of the frozen read-only collector candidate."""
from pathlib import Path
import hashlib
import json
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[2]
COLLECTOR = BASE / 'diagnostic_hii06'

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

manifest = COLLECTOR / 'component_manifest.json'
assert sha(manifest) == '0af72ade1c3e0b8dfa1350216cf5db37dbd4935e86f1aa005e85558657dcfe97'
data = json.loads(manifest.read_text())
checks = []
for item in data['files']:
    p = ROOT / item['path']
    assert p.is_relative_to(ROOT)
    assert p.stat().st_size == item['bytes'] and sha(p) == item['sha256'], str(p)
    checks.append(item)
assert len(checks) == 70
for name, count in [('core_tests', 139), ('efi_tests', 13), ('decoder_tests', 22)]:
    result = json.loads((COLLECTOR / 'build' / (name + '.json')).read_text())
    assert result['passed'] and result['count'] == count
    assert result['efi_sha256'] == data['efi_sha256']
artifact = json.loads((COLLECTOR / 'build/artifact_tests.json').read_text())
assert artifact['passed'] and artifact['old_sources_and_artifacts_unchanged'] == 71
assert artifact['iso_and_el_torito_fat_embedded_efi_equal']
vm = json.loads((COLLECTOR / 'build/ovmf_tests.json').read_text())
assert vm['passed'] and len(vm['results']) == 2
for r in vm['results']:
    assert r['passed'] and r['matches_console_byte_for_byte']
    assert r['efi_sha256'] == data['efi_sha256']
    assert r['iso_sha256_before'] == r['iso_sha256_after'] == data['iso_sha256']
    raw = COLLECTOR / 'build' / r['folder'] / 'RESTORED-LOG.TXT'
    assert sha(raw) == r['qr_restoration']['sha256']

result = {
    'utc': datetime.now(timezone.utc).isoformat(),
    'status': 'FROZEN_BINDINGS_MATCH_AND_REVIEWED_FOR_AUTHORIZED_READ_ONLY_COLLECTION',
    'manifest_sha256': sha(manifest),
    'efi_sha256': data['efi_sha256'],
    'iso_sha256': data['iso_sha256'],
    'bindings_checked': len(checks),
    'source_review': {
        'files': ['source/probe.c', 'runtime.c', 'core.c', 'source/memory.c', 'build.py'],
        'read_only_data': 'Loaded-image code/relocations, HII structural export and opaque owner handles; no question/password values.',
        'services': 'Allocation, memory-map and protocol inventory, HII list/export/get-driver, screen/keyboard and temporary watchdog disable.',
        'no_calls_to': ['GetVariable', 'SetVariable', 'ConfigAccess.Callback', 'ConfigAccess.RouteConfig', 'SendForm', 'LoadImage', 'SPI or update APIs', 'filesystem output'],
        'bounds': 'Exact known relocation profiles; mapping/page-table checked reads; 8000-byte atomic-line extension output with explicit PARTIAL state.',
    },
    'limits': [
        'Test counts are reviewed existing evidence, not new independently rerun tests.',
        'Not a firmware image or password lock and not a hardware qualification.',
        'Unknown module and dynamic form fingerprints remain diagnostic, never authority.',
        'UEFI services can allocate and run firmware-internal notifications; not a global no-side-effect or atomic snapshot claim.',
        'New fingerprints are QR-only. Existing P2 filesystem collector is preserved unchanged.',
    ],
    'file_bindings': checks,
}
(HERE / 'hii06_review.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: result[k] for k in ['status', 'bindings_checked', 'efi_sha256', 'iso_sha256']}, indent=2))
