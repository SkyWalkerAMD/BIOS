"""Bind reviewed runtime artifacts; do not package or activate firmware."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
OLD = HERE.parent/'password'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding='utf8'))
base = read(OLD/'component_manifest.json')
for relative, entry in base['bindings'].items():
    assert sha(OLD/relative) == entry['sha256'], 'frozen password component changed: '+relative
build = read(HERE/'build/build.json')
component = HERE/'build'/build['component_file']
assert sha(component) == build['component']['sha256']
for relative, expected in build['sources'].items():
    assert sha(ROOT/relative) == expected, relative
pe = read(HERE/'build/runtime_pe_test.json')
assert pe['efi_sha256'] == build['component']['sha256'] and pe['case_count'] == 115
assert sha(HERE/'verify_runtime_pe.py') == pe['source_sha256']
labdir = HERE/'lab/runs/20261108_012702'
lab = read(labdir/'result.json')
assert lab['status'] == 'PASS_THREE_COLD_BOOTS_COMMIT_INTERRUPTION_RECOVERY'
assert lab['component_sha256'] == build['component']['sha256']
assert lab['lab_sha256'] == build['lab']['sha256'] == sha(HERE/'build'/build['lab_file'])
assert lab['build_sha256'] == sha(HERE/'build/build.json')
assert all(b['passed'] for b in lab['boots']) and sum(b['checks'] for b in lab['boots']) == 94
for b in lab['boots']:
    assert sha(labdir/f"boot{b['phase']}/debug.log") == b['debug_sha256']
journal = HERE/'journal/runs/20261108_011504/result.json'
j = read(journal)
assert j['case_count'] == 15 and j['source_sha256'] == sha(HERE/'journal/durable_fixture.py')
paths = [HERE/'README.txt', HERE/'prepare.py', HERE/'derivation.json', HERE/'build.py', Path(__file__), HERE/'verify_runtime_pe.py',
         HERE/'build/build.json', component, component.with_suffix('.map'), HERE/'build/runtime_pe_test.json',
         HERE/'build'/build['lab_file'], (HERE/'build'/build['lab_file']).with_suffix('.map'),
         HERE/'lab/run_ovmf.py', HERE/'lab/lab_fixture.c', HERE/'lab/profile_fixture.h',
         HERE/'journal/durable_fixture.py', HERE/'journal/verify_journal.py', journal]
paths += list((HERE/'source').glob('*.[ch]'))
paths += list((HERE/'lab/runs').glob('*/result.json'))
paths += list(labdir.glob('boot*/*.json')) + list(labdir.glob('boot*/*.log'))
paths += [labdir/'vars.fd', labdir/'runtime02-lab.iso']
paths += [p for p in (labdir/'inputs').rglob('*') if p.is_file()]
paths = sorted(set(paths))
manifest = {'status': 'FROZEN_RUNTIME_COMPONENT_FOR_REVIEW_ENTRY_CLOSED',
            'target': 'ASUS Pro WS W890E-SAGE SE BIOS0603', 'release_ready': False,
            'native_owner_bound': False, 'hardware_password_or_flash_writes': 0,
            'component': build['component'],
            'frozen_base': {'path': '../password/component_manifest.json', 'sha256': sha(OLD/'component_manifest.json'),
                            'verified_binding_count': len(base['bindings'])},
            'validation': {'real_OVMF_checks': 94, 'OVMF_cold_boots': 3, 'compiled_PE_checks': 115,
                           'current_user_DPAPI_journal_checks': 15,
                           'OVMF_native_owner_and_input_are_modeled': True,
                           'PE_UEFI_services_and_PBKDF2_are_modeled': True},
            'not_complete': ['native owner and all entry/save hooks', 'persistent per-BIOS-entry dispatch',
                            'management HII publication', 'original-boot physical recovery carrier/controller',
                            'disabled-record recovery ownership', 'flash integration and update-signature acceptance'],
            'bindings': {str(p.relative_to(HERE)): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in paths},
            'created_utc': datetime.now(timezone.utc).isoformat()}
output = HERE/'component_manifest.json'
output.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf8')
print(json.dumps({'status': manifest['status'], 'bindings': len(paths), 'sha256': sha(output),
                  'component_sha256': build['component']['sha256'], 'frozen_base_verified': len(base['bindings'])}))
