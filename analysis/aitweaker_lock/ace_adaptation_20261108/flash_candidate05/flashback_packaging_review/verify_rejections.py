"""Small offline negative checks for the actual file validator; never copy CAPs."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
SPEC = importlib.util.spec_from_file_location('file_validator', HERE / 'verify_flashback_package.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
ROWS = []


def rejected(name, action, fragment):
    try:
        action()
    except ValueError as error:
        assert fragment in str(error), (name, str(error))
        ROWS.append({'case': name, 'result': 'PASS_REJECTED', 'reason': str(error)})
    else:
        raise AssertionError(name + ': wrongly accepted')


candidate = (ROOT / V.PATHS['candidate']).read_bytes()
engineering = (ROOT / V.PATHS['engineering']).read_bytes()
official = (ROOT / V.PATHS['official']).read_bytes()
V.package_names('candidate05/PWW790A.CAP', 'official1904-recovery/PWW790A.CAP')
ROWS.append({'case': 'distinct exact official names', 'result': 'PASS'})
rejected('raw 64 MiB is not a CAP', lambda: V.cap_info(candidate[4096:], 'candidate', 'memory'), 'full 64 MiB')
rejected('truncated CAP', lambda: V.cap_info(candidate[:-1], 'candidate', 'memory'), 'full 64 MiB')
rejected('engineering key CAP cannot replace selected original-header candidate', lambda: V.cap_info(engineering, 'candidate', 'memory'), 'whole-file SHA256')
rejected('official CAP cannot replace adaptation', lambda: V.cap_info(official, 'candidate', 'memory'), 'whole-file SHA256')
rejected('adaptation cannot replace official recovery', lambda: V.cap_info(candidate, 'official', 'memory'), 'whole-file SHA256')
damaged = bytearray(candidate)
damaged[-1] ^= 1
rejected('one changed payload byte', lambda: V.cap_info(damaged, 'candidate', 'memory'), 'whole-file SHA256')
for name, path, reason in [
    ('wrong case', 'candidate05/pww790a.cap', 'exact PWW790A.CAP'),
    ('hidden second extension', 'candidate05/PWW790A.CAP.bin', 'exact PWW790A.CAP'),
    ('candidate at common root', 'PWW790A.CAP', 'separate directories'),
    ('path traversal', '../PWW790A.CAP', 'unsafe package member'),
    ('Windows absolute path', 'C:/PWW790A.CAP', 'ambiguous package member'),
    ('backslash ambiguity', 'candidate05\\PWW790A.CAP', 'unsafe package member'),
]:
    rejected(name, lambda path=path: V.package_names(path, 'official1904-recovery/PWW790A.CAP'), reason)
rejected('case-insensitive same path', lambda: V.package_names('candidate05/PWW790A.CAP', 'CANDIDATE05/PWW790A.CAP'), 'paths must differ')

with tempfile.TemporaryDirectory(prefix='file-validator-', dir=HERE) as temporary:
    base = Path(temporary)
    archive = base / 'negative-fixture.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('candidate05/PWW790A.CAP', b'x')
        z.writestr('official1904-recovery/PWW790A.CAP', b'x')
    rejected('ZIP rejects declared wrong CAP size before loading', lambda: V.verify_package(archive, 'candidate05/PWW790A.CAP', 'official1904-recovery/PWW790A.CAP'), 'CAP length differs')
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('candidate05/PWW790A.CAP', b'x')
        z.writestr('official1904-recovery/PWW790A.CAP', b'x')
        z.writestr('engineering/PWW790A.CAP', b'x')
    rejected('ZIP rejects additional engineering CAP', lambda: V.verify_package(archive, 'candidate05/PWW790A.CAP', 'official1904-recovery/PWW790A.CAP'), 'exactly the selected')
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('candidate05/PWW790A.CAP', b'x')
        z.writestr('CANDIDATE05/PWW790A.CAP', b'x')
        z.writestr('official1904-recovery/PWW790A.CAP', b'x')
    rejected('ZIP rejects case collision', lambda: V.verify_package(archive, 'candidate05/PWW790A.CAP', 'official1904-recovery/PWW790A.CAP'), 'duplicate or case-colliding')
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('../PWW790A.CAP', b'x')
    rejected('ZIP traversal refused without extraction', lambda: V.verify_package(archive, 'candidate05/PWW790A.CAP', 'official1904-recovery/PWW790A.CAP'), 'unsafe package member')

report = {'status': 'PASS', 'checks': len(ROWS), 'cases': ROWS, 'validator': V.file_record(HERE / 'verify_flashback_package.py', ROOT),
          'fixture': V.file_record(Path(__file__), ROOT), 'source_review': V.file_record(HERE / 'source_review.json', ROOT),
          'no_candidate_or_official_input_modified': True, 'no_final_package_created': True, 'hardware_access': False}
output = HERE / 'rejection_validation.json'
output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'checks': len(ROWS), 'sha256': V.sha(output.read_bytes())}))
