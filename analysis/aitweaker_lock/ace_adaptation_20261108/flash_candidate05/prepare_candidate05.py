"""Seed a separate source tree; preserve all frozen INTEGRATED04 evidence."""
from pathlib import Path
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'lock_1904_integrated04'
DEST = HERE / 'lock_1904_candidate05'
EXPECTED = '463b94139cb64207e1b756965ebb9ca3513250c8712bbbcd20798fd317dec904'
assert hashlib.sha256((SOURCE / 'driver/build/AiTweakerLock1904.efi').read_bytes()).hexdigest() == EXPECTED
assert not DEST.exists(), 'Keep existing candidate edits and evidence'
entries = []
for section in ('driver', 'core', 'lab'):
    (DEST / section).mkdir(parents=True, exist_ok=True)
    for source in sorted((SOURCE / section).iterdir()):
        if not source.is_file() or source.suffix not in ('.c', '.h', '.py'):
            continue
        target = DEST / section / source.name
        shutil.copyfile(source, target)
        entries.append({'path': str(target.relative_to(DEST)), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
result = {'purpose': 'Editable successor source seed; no flash-ready claim', 'baseline_driver_sha256': EXPECTED,
          'baseline': str(SOURCE), 'candidate': str(DEST), 'files': entries}
(DEST / 'source-seed.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
print(json.dumps({'files': len(entries), 'candidate': str(DEST)}))
