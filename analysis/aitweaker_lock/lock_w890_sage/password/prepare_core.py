"""Copy the reviewed board-independent core, never its W790 platform adapter."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SAGE = ROOT / 'analysis/aitweaker_lock/lock_sage_1904'
LATEST = SAGE / 'review/flash_readiness/native13_split_candidate/installer_design04/provider15_diagnostic09/source'
OUT = HERE / 'core'
OUT.mkdir(exist_ok=True)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

bindings = []
for name in ['password_core.h', 'password_core.c', 'password_crypto.c']:
    prior, latest = SAGE / 'core' / name, LATEST / name
    # The later snapshot contains doubled CRs. Confirm the change is line
    # endings only before choosing the clean, already-tested source spelling.
    normalize = lambda p: p.read_text().replace('\n', '')
    assert normalize(prior) == normalize(latest), name
    target = OUT / name
    target.write_bytes(prior.read_bytes())
    bindings.append({'file': name, 'source': str(prior.relative_to(ROOT)),
                     'source_sha256': sha(prior), 'latest_source': str(latest.relative_to(ROOT)),
                     'latest_sha256': sha(latest), 'identical_except_line_breaks': True,
                     'output_sha256': sha(target)})
for name in ['build_core.py', 'verify_core.py']:
    source, target = SAGE / 'core' / name, OUT / name
    text = source.read_text(encoding='utf8')
    if name == 'build_core.py':
        assert 'ROOT = HERE.parents[3]' in text
        text = text.replace('ROOT = HERE.parents[3]', 'ROOT = HERE.parents[4]')
    target.write_text(text, encoding='utf8', newline='\n')
    bindings.append({'file': name, 'source': str(source.relative_to(ROOT)),
                     'source_sha256': sha(source), 'output_sha256': sha(target),
                     'change': 'workspace root depth only' if name == 'build_core.py' else 'none except newline normalization'})
(HERE / 'core_derivation.json').write_text(json.dumps({
    'scope': 'Only pure password state/cryptography and its existing host test; no W790 address, UI, variable name, native adapter or hook copied.',
    'bindings': bindings,
    'script_sha256': sha(Path(__file__)),
}, indent=2) + '\n', encoding='utf8')
print(json.dumps({'copied_core_sources': 3, 'copied_core_test_files': 2}))
