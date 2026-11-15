"""Synthetic child-process contract for the local bridge. No file writes/network."""
import hashlib
import json
import os
import sys

mode = sys.argv[1]
values = json.load(sys.stdin)
assert isinstance(values, list) and len(values) == 4 and all(isinstance(x, str) for x in values)
assert len(set(values[:3])) == 3 and all(len(x) == 16 for x in values[:3])
assert all(x not in ' '.join(sys.argv) and all(x not in v for v in os.environ.values()) for x in values)
archive = b'SYNTHETIC_ARCHIVE_NOT_A_DELIVERY_ZIP'
result = {
    'status': 'ENGINEERING_ARCHIVE_CREATED_NOT_FLASHED',
    'path': 'analysis/aitweaker_lock/ace_adaptation_20261108/flash_candidate05/delivery_review/archives/W790-ACE-1904-AI-TWEAKER-CANDIDATE05-ENGINEERING.zip',
    'sha256': hashlib.sha256(archive).hexdigest(), 'bytes': len(archive), 'files': 275,
    'engineering_cap_sha256': 'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08', 'flash_ready': False,
}
if mode == 'failure':
    print(values[0])
    print(values[3], file=sys.stderr)
    raise SystemExit(2)
if mode == 'stderr_secret':
    print(values[3], file=sys.stderr)
if mode == 'extra_secret':
    result['untrusted_extra'] = values[0]
if mode == 'prefix_secret':
    print(values[1])
if mode == 'wrong_path':
    result['path'] = values[2]
if mode == 'wrong_hash':
    result['sha256'] = '0' * 64
if mode == 'overflow':
    print(values[0] * 10000)
    raise SystemExit(0)
if mode == 'empty':
    raise SystemExit(0)
if mode == 'malformed':
    print('not JSON')
    raise SystemExit(0)
print(json.dumps(result))
