"""Acquire one pinned official netboot archive for isolated local inspection."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
DEST = HERE / 'official'
BASE = 'https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/'
NAME = 'alpine-netboot-3.22.7-x86_64.tar.gz'


def fetch(name, limit):
    target = DEST / name
    if target.exists():
        return target
    req = urllib.request.Request(BASE + name, headers={'User-Agent': 'firmware-diagnostic-local-lab/1'})
    with urllib.request.urlopen(req, timeout=30) as response:
        if response.geturl() != BASE + name:
            raise RuntimeError('Unexpected download redirect')
        count = 0
        with target.with_suffix(target.suffix + '.partial').open('xb') as out:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > limit:
                    raise RuntimeError('Download exceeds size limit')
                out.write(chunk)
        target.with_suffix(target.suffix + '.partial').rename(target)
    return target


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    sums = fetch(NAME + '.sha256', 4096)
    line = sums.read_text(encoding='ascii').strip().split()
    assert len(line) == 2 and line[1].lstrip('*') == NAME and len(line[0]) == 64
    print('Official checksum acquired; downloading version-pinned archive.', flush=True)
    archive = fetch(NAME, 360 * 1024 * 1024)
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert actual == line[0], 'Official archive checksum mismatch'
    # No archive paths are used for output: extract only these exact regular-file basenames.
    wanted = {'vmlinuz-lts', 'initramfs-lts', 'modloop-lts', 'config-6.12.114-0-lts'}
    records = []
    with tarfile.open(archive, 'r:gz') as tf:
        for member in tf:
            leaf = Path(member.name).name
            if leaf not in wanted:
                continue
            assert member.isfile() and member.size <= 250 * 1024 * 1024
            assert not any(r['name'] == leaf for r in records), 'Duplicate selected member'
            data = tf.extractfile(member).read()
            target = DEST / leaf
            if target.exists():
                assert target.read_bytes() == data
            else:
                target.write_bytes(data)
            records.append({'name': leaf, 'member': member.name, 'bytes': len(data),
                            'sha256': hashlib.sha256(data).hexdigest()})
            print('Inspected and extracted ' + leaf, flush=True)
    assert {r['name'] for r in records} == wanted
    report = {'utc': datetime.now(timezone.utc).isoformat(), 'source': BASE + NAME,
              'checksum_source': BASE + NAME + '.sha256', 'sha256': actual,
              'checksum_matched': True, 'pgp_signature_verified': False,
              'scope': 'Official HTTPS archive and checksum, local selective extraction only; no stock init or kernel executed.',
              'selected_regular_files': records}
    (DEST / 'acquisition.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
