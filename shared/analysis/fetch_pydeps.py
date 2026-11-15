"""Download pinned public analysis libraries into this workspace only."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

target = Path(__file__).resolve().parent.parent / 'tools/pydeps'
for package, version in [('pefile', '2024.8.26'), ('capstone', '5.0.6'), ('unicorn', '2.1.4')]:
    meta = json.load(urllib.request.urlopen(f'https://pypi.org/pypi/{package}/{version}/json', timeout=20))
    files = [f for f in meta['urls'] if f['filename'].endswith('.whl') and
             ('none-any' in f['filename'] or 'win_amd64' in f['filename'])]
    f = files[0]
    data = urllib.request.urlopen(f['url'], timeout=30).read()
    assert hashlib.sha256(data).hexdigest() == f['digests']['sha256']
    zipfile.ZipFile(io.BytesIO(data)).extractall(target)
    print(f['filename'], f['digests']['sha256'])
