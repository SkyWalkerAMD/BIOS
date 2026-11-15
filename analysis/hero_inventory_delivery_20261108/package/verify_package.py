"""Local hash verification only. Does not execute packaged binaries or contact a host."""
from pathlib import Path, PurePosixPath
import hashlib, json, sys, zipfile

def safe(name):
    p=PurePosixPath(name)
    return bool(name) and not p.is_absolute() and '..' not in p.parts and ':' not in name and '\\' not in name

def check(read):
    m=json.loads(read('校验/内容清单.json'))
    for row in m['files']:
        assert safe(row['path']), row['path']
        data=read(row['path'])
        assert len(data)==row['bytes'], row['path']
        assert hashlib.sha256(data).hexdigest()==row['sha256'], row['path']
    print('PASS:',len(m['files']),'content files; no binaries executed.')

if len(sys.argv)==2:
    with zipfile.ZipFile(sys.argv[1]) as z:
        names=z.namelist()
        assert len(names)==len(set(names)) and all(safe(n) for n in names)
        assert z.testzip() is None
        check(z.read)
elif len(sys.argv)==1:
    root=Path(__file__).resolve().parent
    def read(name):
        path=(root/name).resolve(strict=True)
        assert path.is_relative_to(root),name
        return path.read_bytes()
    check(read)
else:
    raise SystemExit('Usage: python verify_package.py [package.zip]')
