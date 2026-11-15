"""Bounded HTTPS fetch of individually pinned public netboot members."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sys
import time
import urllib.request

BASE = 'https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot-3.22.7/'
LIMITS = {'vmlinuz-lts': 20 * 1024**2, 'initramfs-lts': 35 * 1024**2, 'modloop-lts': 240 * 1024**2}
DEST = Path(__file__).resolve().parent / 'official'
name = sys.argv[1]
assert name in LIMITS
target = DEST / name
partial = DEST / (name + '.partial')
assert not target.exists() and not partial.exists(), 'Preserve existing download files'
start = time.monotonic()
req = urllib.request.Request(BASE + name, headers={'User-Agent': 'firmware-diagnostic-local-lab/1'})
count = 0
digest = hashlib.sha256()
with urllib.request.urlopen(req, timeout=15) as response:
    assert response.geturl() == BASE + name and response.status == 200
    length = int(response.headers['Content-Length'])
    assert 0 < length <= LIMITS[name]
    print(json.dumps({'file': name, 'expected_bytes': length, 'status': response.status}), flush=True)
    with partial.open('xb') as out:
        next_report = 1024**2
        while chunk := response.read1(65536):
            count += len(chunk)
            assert count <= length and time.monotonic() - start < 180, 'Bounded download exceeded'
            out.write(chunk)
            digest.update(chunk)
            if count >= next_report:
                out.flush()
                print(json.dumps({'file': name, 'bytes': count}), flush=True)
                next_report += 4 * 1024**2
assert count == length
partial.rename(target)
report = {'url': BASE + name, 'utc': datetime.now(timezone.utc).isoformat(), 'bytes': count,
          'sha256': digest.hexdigest(), 'https_verified': True, 'archive_checksum_verified': False,
          'pgp_signature_verified': False, 'scope': 'Download only; no code executed.'}
(DEST / (name + '.acquisition.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report), flush=True)
