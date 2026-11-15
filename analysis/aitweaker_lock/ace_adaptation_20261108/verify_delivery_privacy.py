"""Scan the finished ZIP for caller-supplied sensitive strings without echoing them."""
from pathlib import Path
import base64
import datetime
import getpass
import hashlib
import json
import zipfile

HERE = Path(__file__).resolve().parent
OUT = HERE / 'delivery_integrated04_463b94139cb6'
delivery = json.loads((OUT / 'delivery.json').read_text(encoding='utf8'))
archive_path = HERE.parents[2] / delivery['archive']
assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == delivery['archive_sha256']
supplied = json.loads(getpass.getpass('Sensitive scan input (not echoed): '))
patterns = set()
for phrase in supplied['phrases'] + supplied.get('basic_pairs', []):
    assert isinstance(phrase, str) and len(phrase) >= 6
    patterns.update([phrase.encode('utf8'), phrase.encode('utf-16-le'),
                     base64.b64encode(phrase.encode('utf8'))])
del supplied
matches = []
forbidden_members = []
member_count = 0
total_bytes = 0
with zipfile.ZipFile(archive_path) as archive:
    for member in archive.infolist():
        member_count += 1
        name = member.filename
        parts = {p.lower() for p in Path(name).parts}
        if parts & {'operations', 'sessions', 'credentials', 'node_modules', '.git'} or name.lower().endswith('.mjs'):
            forbidden_members.append(name)
        raw = archive.read(member)
        total_bytes += len(raw)
        if any(pattern in raw for pattern in patterns):
            matches.append(name)
del patterns
result = {'status': 'PASS_FINAL_ARCHIVE_SENSITIVE_PATTERN_SCAN' if not matches and not forbidden_members else 'FAIL',
          'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'archive': delivery['archive'], 'archive_sha256': delivery['archive_sha256'],
          'members_scanned': member_count, 'decoded_member_bytes_scanned': total_bytes,
          'sensitive_matches': len(matches), 'forbidden_member_count': len(forbidden_members),
          'matching_member_names': matches, 'forbidden_member_names': forbidden_members,
          'scan_methods': ['exact UTF-8 bytes', 'exact UTF-16LE bytes', 'base64 encoded values', 'forbidden path/member checks'],
          'patterns_written_or_echoed': False,
          'scope': 'Caller supplied BMC credential material and all actual temporary interactive RAM passwords. Selected hardware screenshots were separately reviewed visually; this byte scan is not OCR.'}
(OUT / 'delivery-privacy-audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
print(json.dumps(result, ensure_ascii=True))
raise SystemExit(0 if result['status'].startswith('PASS') else 1)
