"""Inventory and statically extract selected public BMC implementation files.

Does not execute any firmware member or access a device. Source image is pinned.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/PySquashfsImage-0.9.0').is_dir())
sys.path.insert(0, str(ROOT / 'tools/PySquashfsImage-0.9.0'))
from PySquashfsImage import SquashFsImage

SOURCE = HERE / 'official_bmc/W7901157.ima'
EXPECTED = '0eea0a707e9bcaa6da157db0c8c637b889c456889e0e550a7fb1756a528e565a'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--extract', action='store_true')
    parser.add_argument('--path-list', type=Path)
    args = parser.parse_args()
    raw = SOURCE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    positions = [m.start() for m in re.finditer(b'hsqs', raw)]
    rows, errors, extracted = [], [], []
    wanted = set(args.path_list.read_text(encoding='utf-8').splitlines()) if args.path_list else set()
    out = HERE / 'bmc_backend'
    for offset in positions:
        try:
            fs = SquashFsImage.from_file(str(SOURCE), offset=offset)
            with fs:
                for item in fs:
                    path = item.path
                    if not item.is_file:
                        continue
                    rows.append({'path': path, 'filesystem_offset': offset})
                    selected = path in wanted or (
                        args.extract and (
                            path.endswith('/source.min.js')
                            or ('bios' in path.lower() and path.endswith(('.lua', '.rcmd', '.conf', '.sh', '.json')))
                            or (path.startswith('/etc/') and any(word in path.lower() for word in ('flash', 'update', 'mtd', 'lighttpd')))
                        )
                    )
                    if not selected:
                        continue
                    target = (out / str(offset) / path.lstrip('/')).resolve()
                    assert target.is_relative_to(out.resolve())
                    data = item.read_bytes()
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists():
                        assert target.read_bytes() == data
                    else:
                        target.write_bytes(data)
                    extracted.append({'path': path, 'filesystem_offset': offset, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'output': str(target.relative_to(HERE))})
        except Exception as exc:
            errors.append({'offset': offset, 'error': type(exc).__name__ + ': ' + str(exc)})
    report = {'source': str(SOURCE), 'source_sha256': EXPECTED, 'files': rows, 'errors': errors, 'extracted': extracted}
    name = ('bmc_backend_' + args.path_list.stem + '.json') if wanted else 'bmc_backend_inventory.json'
    (HERE / name).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'filesystems': sorted(set(r['filesystem_offset'] for r in rows)), 'file_count': len(rows), 'extracted_count': len(extracted), 'errors': errors, 'manifest': name}, indent=2))


if __name__ == '__main__':
    main()
