"""Pure read-only exact dependency check for TX09 builders."""
from pathlib import Path
import hashlib,json
_tx09_here=Path(__file__).resolve().parent;_tx09_d04=_tx09_here.parent
_tx09_pins={
 'diagnostic_guard09/candidate_manifest.json':'16b8ece77f0569cf477b4126bde86586a5b8414ef0d06ac1a98915e634564675',
 'provider15_diagnostic09/local_candidate_manifest.json':'3ae77997b6855fe57d2e670bcb119b108a2a717b9586e1c852133aa4d1e29976',
 'ram_transaction08/ram_candidate_manifest.json':'7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96'}
for _tx09_name,_tx09_digest in _tx09_pins.items():
 _tx09_path=_tx09_d04/_tx09_name
 assert hashlib.sha256(_tx09_path.read_bytes()).hexdigest()==_tx09_digest,_tx09_name
 for _tx09_row in json.loads(_tx09_path.read_text())['artifacts']:
  assert hashlib.sha256((_tx09_d04/_tx09_row['path']).read_bytes()).hexdigest()==_tx09_row['sha256'],_tx09_row['path']
