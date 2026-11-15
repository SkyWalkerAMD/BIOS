"""Reuse established independent EBS/discovery tests with explicit new paths."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
CASE = HERE / 'lock_1904_candidate05'
ORIGINAL = HERE.parent / 'lock_1904_integrated04'
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
BASE = "ROOT/'analysis/aitweaker_lock/ace_adaptation_20261108/"
jobs = [
    ('entry_review/verify_retirement.py', {"OLD = CASE.parent/'lock_1904_integrated03'": "OLD = " + BASE + "lock_1904_integrated03'",
        "HERE/'build_entry_review.py'": "CASE/'driver/build.py'", "Complete integrated04 driver executes.": "Complete candidate05 driver executes.",
        "Complete actual integrated04 EFI;": "Complete actual candidate05 EFI;"}),
    ('ebs_review/build_fixture.py', {"BASELINE=CASE.parent/'lock_1904_history02'": "BASELINE=" + BASE + "lock_1904_history02'", "tofile='INTEGRATED04/": "tofile='CANDIDATE05/"}),
    ('ebs_review/verify_ebs.py', {"BASELINE=CASE.parent/'lock_1904_history02/driver/build'": "BASELINE=" + BASE + "lock_1904_history02/driver/build'"}),
    ('ebs_review/fixture.c', {}),
]
entries = []
for relative, replacements in jobs:
    original, dest = ORIGINAL / relative, CASE / relative
    text = original.read_text(encoding='utf8')
    for old, new in replacements.items():
        assert text.count(old) == (2 if old == "tofile='INTEGRATED04/" else 1), (relative, old)
        text = text.replace(old, new)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        assert dest.read_text(encoding='utf8') == text, 'Preserve existing regression edits'
    else:
        dest.write_text(text, encoding='utf8')
    entries.append({'path': relative, 'original_sha256': hashlib.sha256(original.read_bytes()).hexdigest(),
                    'adapted_sha256': hashlib.sha256(dest.read_bytes()).hexdigest(), 'replacements': replacements})
(CASE / 'regression-source-binding.json').write_text(json.dumps(entries, indent=2) + '\n', encoding='utf8')
print(json.dumps({'prepared': len(entries)}))
