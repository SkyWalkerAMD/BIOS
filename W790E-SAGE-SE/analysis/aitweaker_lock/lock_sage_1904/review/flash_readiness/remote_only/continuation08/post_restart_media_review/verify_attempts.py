"""Recheck the frozen bounded-attempt review without changing its evidence."""
from pathlib import Path
import hashlib, json

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/kvm-pydeps').is_dir())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
manifest_path = HERE / 'attempts_manifest.json'
assert sha(manifest_path) == '84cbe9e3418d080794f13f02d5a367610a1bddc4e2b192b12491cf2ea5210c8d'
manifest = json.loads(manifest_path.read_text(encoding='utf8'))
rows = manifest['inputs'] + manifest['artifacts']
for row in rows:
    path = Path(row['path']).resolve()
    assert path.is_relative_to(ROOT.resolve())
    assert path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], path
report = json.loads((HERE / 'attempts_review.json').read_text(encoding='utf8'))
assert report['inputs']['p04_candidate_manifest']['sha256'] == '1c70adb50d8e17c2672b091c4bc0ab8fa201a5035b3bfda1a67e017fb3033ba9'
assert report['inputs']['p04_independent_manifest']['sha256'] == '771dc8792b501a9431e866b7da0e313ab34f3379dceeb42c474ba11522585f39'
assert report['inputs']['linux2_pinned_loader_manifest']['sha256'] == '03749d2e36d203e6af459b93621579721443ac0aca5aaa90b849460cc2ff2247'
assert manifest['review_sha256'] == sha(HERE / 'attempts_review.json')
result = {'status': 'PASS_BOUNDED_ATTEMPT_REVIEW_RECHECK', 'input_bindings': len(manifest['inputs']),
          'review_artifact_bindings': len(manifest['artifacts']), 'manifest_sha256': sha(manifest_path),
          'scope': 'A binding recheck of the two attempt records; final C08 cleanup and publication remain separate.'}
(HERE / 'attempts_verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
print(json.dumps(result))
