from pathlib import Path
import hashlib
import json

here = Path(__file__).resolve().parent
base = here.parent
files = ['inventory_legacy71.c', 'inventory_legacy71.h', 'catalog71.h', 'legacy71_json.h']
frozen = {'inventory_legacy71.c': '41af4c7705a99cdb9b59f3f6bc193bfa0f5eca0603d22b3cda1a68121aa6065c',
          'inventory_legacy71.h': '072822914db7a723fcbb396e98103de23f75560bad8e8a0f549b92a1d87aff7d',
          'catalog71.h': '578cb00bd06f3601e93e6aad732e02e7c85de7568e4bae76f67e9107948879dd',
          'legacy71_json.h': 'f9ba47674881a8e0a36cf1f106e49b13d2198d3b5af024057f41ddaa8abcf1ad'}
for name, digest in frozen.items():
    assert hashlib.sha256((base / 'native' / name).read_bytes()).hexdigest() == digest
result = {'kind': 'I3d-continuation-native-local-only', 'native_mock_tests_passed': 29,
          'frozen_i3b_unchanged': True,
          'sources': {name: {'bytes': len((here / name).read_bytes()),
                            'sha256': hashlib.sha256((here / name).read_bytes()).hexdigest()} for name in files},
          'summary': {'bytes': len((here/'processor-summary.patch.json').read_bytes()),
                      'sha256': hashlib.sha256((here/'processor-summary.patch.json').read_bytes()).hexdigest()},
          'live_execution_by_this_agent': False,
          'frozen_note': 'Do not alter handed-off files without notifying the integrating agent.'}
(here / 'handoff.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
