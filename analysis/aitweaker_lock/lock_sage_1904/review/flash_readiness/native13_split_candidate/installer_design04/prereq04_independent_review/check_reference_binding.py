"""Recheck the four parent-acquired official EDK II reference blobs locally."""
from pathlib import Path
import hashlib, json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[2]
REFERENCE = READY / 'remote_only/continuation08/edk2_reference/provenance.json'

def main():
    source = json.loads(REFERENCE.read_text(encoding='utf8'))
    rows = []
    for entry in source['artifacts']:
        path = Path(entry['path']); raw = path.read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        git_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        assert len(raw) == entry['bytes'] and sha256 == entry['sha256'] and git_blob == entry['git_blob_sha'], path
        rows.append({'path': str(path), 'bytes': len(raw), 'sha256': sha256, 'git_blob_sha': git_blob, 'url': entry['url']})
    result = {'status': 'PASS_FOUR_OFFICIAL_REFERENCE_BLOB_BINDINGS', 'reference_count': len(rows),
              'provenance_sha256': hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), 'references': rows,
              'scope': 'Independent local length, SHA-256 and Git object SHA-1 recheck of parent-acquired official sources; this does not identify the ASUS protocol implementation.'}
    assert len(rows) == 4
    (HERE / 'reference_binding_result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'status': result['status'], 'reference_count': len(rows)}))

if __name__ == '__main__':
    main()
