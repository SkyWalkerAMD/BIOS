"""Freeze the completed independent review; no parent artifacts are written."""
from pathlib import Path
import hashlib
import json
import zlib

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]


def sha(b):
    return hashlib.sha256(b).hexdigest()


result = json.loads((OUT / 'final-regressions.json').read_text())
if not result['passed'] or not result['source_unchanged']:
    raise RuntimeError('Final verifier regression is not complete')
live_dir = ROOT / 'analysis/hero_ipmi_complete_live_20261108'
live = json.loads((live_dir / 'r3-auto-hardware-verification.json').read_text())
checked = []
for field in ('first', 'second'):
    item = live[field]
    data = (live_dir / item['path']).read_bytes()
    if len(data) != item['bytes'] or sha(data) != item['sha256'] or f'{zlib.crc32(data):08X}' != item['crc32']:
        raise RuntimeError('Runtime record hash/CRC mismatch')
    checked.append(dict(pass_name=field, bytes=len(data), sha256=sha(data), crc32=f'{zlib.crc32(data):08X}'))
evidence = dict(driver_sha256=live['driver_sha256'], files=checked,
                scope='Read-only verification of parent-supplied complete TXT hashes/CRCs; no new hardware operation or new QR reconstruction.',
                hardware_operator='parent agent', reviewer_hardware_access=False)
(OUT / 'runtime-record-check.json').write_text(json.dumps(evidence, indent=2) + '\n')
warning = 'NEGATIVE TEST FIXTURE. NEVER FLASH THIS CAP. See parent review report.\n'
for directory in OUT.glob('NEGATIVE-*'):
    if directory.is_dir():
        (directory / 'DO-NOT-FLASH.txt').write_text(warning)
files = []
destination = OUT / 'frozen-review-manifest.json'
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path != destination:
        data = path.read_bytes()
        files.append(dict(path=str(path.relative_to(OUT)), bytes=len(data), sha256=sha(data)))
manifest = dict(schema='hero-rc5-independent-review-1', status='complete',
                tested_source_hashes=result['source_hashes'], verifier_cases=len(result['cases']),
                builder_guard_tests=result['root_guards'], all_tests_passed=True,
                hardware_access=False, parent_files_modified=False, background_processes_left=False,
                release_cap_produced=False, contains_negative_caps_not_for_flashing=True,
                files=files)
destination.write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(dict(report=str(OUT / 'RC5-独立审查结果.txt'), report_sha256=sha((OUT / 'RC5-独立审查结果.txt').read_bytes()),
                      files=len(files), manifest_sha256=sha(destination.read_bytes()), runtime_record_hashes_verified=True)))
