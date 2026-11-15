"""Bind the diagnostic component and its precise validation inputs."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = HERE.parent

def bind(path):
    data = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}

build = json.loads((HERE / 'build/build.json').read_text())
tests = json.loads((HERE / 'build/tests.json').read_text())
assert tests['passed'] and tests['count'] == 35
assert tests['dll_sha256'] == bind(HERE / 'build/spf_sampler_test.dll')['sha256'] == build['dll_sha256']
for name, digest in build['sources'].items():
    assert bind(HERE / 'source' / name)['sha256'] == digest
for name in ('sampler.c', 'sampler.h'):
    assert (HERE / name).read_bytes() == (HERE / 'source' / name).read_bytes()
for item in build['inputs']:
    assert bind(Path(item['path']))['sha256'] == item['sha256']

local = [HERE / x for x in ('README.md', 'freeze.py', 'build.py', 'verify.py', 'decode.py',
                           'sampler.c', 'sampler.h', 'build/build.json', 'build/tests.json',
                           'build/spf_sampler_test.dll')]
local += sorted((HERE / 'source').glob('*'))
external = [BASE / x for x in (
    'diagnostic_hii06/component_manifest.json', 'diagnostic_hii06/build/profiles.json',
    'parser_review06/original_inventory.json',
    'spf_sampler06_review/independent_tests.json',
    'spf_sampler06_review/verify_independent.py',
    'spf_sampler06_review/design_static_review.json')]
external += [Path(x['path']) for x in build['inputs']]
profiles = json.loads((BASE / 'diagnostic_hii06/build/profiles.json').read_text())
external += [Path(next(x for x in profiles if x['name'] == 'AMITSE')['path'])]
spf = json.loads((BASE / 'parser_review06/original_inventory.json').read_text())
external += [Path(spf['original_source'])]
manifest = {
    'status': 'FROZEN_LOCAL_DIAGNOSTIC_COMPONENT_NOT_FLASHABLE',
    'target': 'ASUS Pro WS W890E-SAGE SE 0603', 'abi_snapshot_bytes': 70, 'abi_pair_bytes': 140,
    'authorization': False, 'compiled_c_cases': 35,
    'files': [bind(p) for p in local if p.is_file()],
    'external_bindings': [bind(p) for p in sorted(set(external))],
    'limits': ['Carrier adapter, final EFI and transport binding require separate review.',
               'Post-Setup values do not prove initial-parser values or allocation ownership.',
               'No password, firmware write or flashability qualification.'],
}
out = HERE / 'component_manifest.json'
out.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'manifest': bind(out), 'files': len(manifest['files']),
                  'external_bindings': len(manifest['external_bindings'])}, indent=2))
