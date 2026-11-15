"""Restore published sources to their original relative layout."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
repo = Path(__file__).resolve().parent
output = args.output.resolve()
if output == repo or output.is_relative_to(repo):
    parser.error('Choose an output folder outside this repository.')
records = json.loads((repo / 'SOURCE-MANIFEST.json').read_text('utf-8'))
for record in records:
    source = (repo / record['path']).resolve()
    target = (output / record['original_path']).resolve()
    if not source.is_relative_to(repo) or not target.is_relative_to(output):
        raise ValueError('Manifest path escapes its root.')
    if hashlib.sha256(source.read_bytes()).hexdigest() != record['sha256']:
        raise ValueError('Source checksum mismatch: ' + record['path'])
    if target.exists():
        if hashlib.sha256(target.read_bytes()).hexdigest() == record['sha256']:
            continue
        raise FileExistsError('Refusing to overwrite different content: ' + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
print(f'Restored {len(records)} source files to {output}')
