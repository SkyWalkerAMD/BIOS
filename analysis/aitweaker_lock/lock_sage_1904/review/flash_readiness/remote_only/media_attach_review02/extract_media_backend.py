"""Offline extraction of selected original BMC files; never executes firmware."""
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
REMOTE = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/PySquashfsImage-0.9.0').is_dir())
sys.path.insert(0, str(ROOT / 'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage

SOURCE = REMOTE / 'official_bmc/W7901157.ima'
EXPECTED = '0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'
WANTED = {
    '/usr/local/bin/hdserverapp', '/usr/local/bin/cdserverapp',
    '/usr/local/lib/libmediaredir.so.13.9.5',
    '/usr/local/lib/libmediaredir_https.so.13.2.0',
    '/usr/local/lib/libusbgadget.so.13.31.13',
    '/usr/local/lib/libvmedia.so.13.11.9',
    '/usr/local/lib/libnbd.so.13.4.3', '/usr/local/bin/adviserd',
    '/etc/init.d/hdserver', '/etc/init.d/cdserver',
}

def main():
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED
    rows = []
    with SquashFsImage.from_file(str(SOURCE), offset=5308416) as fs:
        for item in fs:
            if not item.is_file or item.path not in WANTED:
                continue
            data = item.read_bytes()
            target = (HERE / 'backend' / item.path.lstrip('/')).resolve()
            assert target.is_relative_to(HERE.resolve())
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                assert target.read_bytes() == data
            else:
                target.write_bytes(data)
            rows.append({'source_path':item.path,'offset':5308416,'output':str(target.relative_to(HERE)),
                         'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    assert set(x['source_path'] for x in rows) == WANTED
    report = {'source':str(SOURCE),'sha256':EXPECTED,'scope':'offline static extraction only','files':rows}
    (HERE/'backend_manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(rows,indent=2))

if __name__ == '__main__':main()
