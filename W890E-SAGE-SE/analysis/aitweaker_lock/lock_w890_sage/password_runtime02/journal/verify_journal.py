from pathlib import Path
from datetime import datetime, timezone
import hashlib, json, subprocess, sys
sys.dont_write_bytecode = True
import durable_fixture as j
HERE = Path(__file__).resolve().parent
TARGET = 'QEMU-W890-0603-OWNED-FIXTURE'

if len(sys.argv) == 3 and sys.argv[1] == '--fresh-process':
    data = j.open_fixture(sys.argv[2], TARGET)
    assert data['binding'] == j.binding(TARGET)
    assert len(data['before']) == 48 and len(data['after']) == 48
    print('FRESH_PROCESS_RECOVERY_CANDIDATES_PRESENT')
    raise SystemExit

folder = HERE / 'runs' / datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
folder.mkdir(parents=True)
path = folder / 'owned-fixture.dpapi'
checks = []
def check(name, condition):
    assert condition, name
    checks.append(name)
def rejects(name, fn):
    try:
        fn()
    except (j.JournalError, FileNotFoundError):
        checks.append(name)
        return
    raise AssertionError(name)

metadata = j.prepare(path, TARGET)
data = j.open_fixture(path, TARGET)
check('encrypted durable publication before typing', metadata['status'] == 'DURABLE_BEFORE_TYPING')
check('metadata contains no password fields', set(metadata) == {'id', 'binding', 'path', 'ciphertext_sha256', 'status'})
raw = path.read_bytes()
check('neither candidate plaintext stored', all(data[x].encode() not in raw for x in ['before', 'after']))
check('all candidate lengths accepted by runtime UI', all(8 <= len(data[x]) <= 128 for x in ['before', 'after']))
check('distinct before and after commit candidates', data['before'] != data['after'])
proc = subprocess.run([sys.executable, '-X', 'utf8', str(Path(__file__).resolve()), '--fresh-process', str(path)], capture_output=True, text=True)
check('fresh process recovers both candidates without secret output', proc.returncode == 0 and proc.stdout.strip() == 'FRESH_PROCESS_RECOVERY_CANDIDATES_PRESENT' and not proc.stderr)
rejects('existing durable journal never overwritten', lambda: j.prepare(path, TARGET))
check('overwrite refusal preserves exact ciphertext', path.read_bytes() == raw)
rejects('wrong target binding rejected', lambda: j.open_fixture(path, TARGET + '-OTHER'))
tampered = folder / 'tampered.dpapi'
damage = bytearray(raw); damage[len(damage)//2] ^= 1; tampered.write_bytes(damage)
rejects('ciphertext tamper rejected', lambda: j.open_fixture(tampered, TARGET))
truncated = folder / 'truncated.dpapi'; truncated.write_bytes(raw[:64])
rejects('truncated journal rejected', lambda: j.open_fixture(truncated, TARGET))
missing = folder / 'not-published.dpapi'; missing.with_suffix('.partial').write_bytes(raw)
rejects('pre-publication interruption cannot be treated as durable', lambda: j.open_fixture(missing, TARGET))
check('post-publication interruption retains recovery candidates', j.open_fixture(path, TARGET) == data)
check('exact W890 namespace pinned', data['binding']['name'] == j.NAME and data['binding']['guid'] == j.GUID)
check('journal and cleanup operations contain no firmware controller', not hasattr(j, 'delete_fixture') and not hasattr(j, 'send_keys'))
report = {'status': 'PASS_DURABLE_JOURNAL_CURRENT_WINDOWS_USER', 'case_count': len(checks), 'cases': checks,
          'journal_sha256': hashlib.sha256(raw).hexdigest(), 'source_sha256': hashlib.sha256((HERE/'durable_fixture.py').read_bytes()).hexdigest(),
          'physical_firmware_or_kvm_operations': 0,
          'scope': 'Actual current-user DPAPI, exclusive flushed encrypted publication, readback and a fresh Python process. No automatic KVM typing or firmware cleanup. Two passwords retained for unknown commit outcome; disabled records remain outside password-based recovery.'}
(folder/'result.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({'status': report['status'], 'case_count': len(checks), 'report': str(folder/'result.json')}))
