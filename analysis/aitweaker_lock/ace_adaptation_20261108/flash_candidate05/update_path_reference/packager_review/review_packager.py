"""Independent, isolated archive-helper review. Synthetic secrets only; no network."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import json
import sys

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
BASE = OUT.parent.parent
ROOT = BASE.parents[3]
SOURCE = BASE / 'assemble_candidate05_delivery.py'
raw = SOURCE.read_bytes()
source_sha = hashlib.sha256(raw).hexdigest()
snapshot = OUT / ('builder-' + source_sha[:8] + '.snapshot.py')
if not snapshot.exists():
    snapshot.write_bytes(raw)
spec = importlib.util.spec_from_file_location('archive_under_review', SOURCE)
m = importlib.util.module_from_spec(spec)
exec(compile(raw, str(SOURCE), 'exec'), m.__dict__)
fixture = OUT / ('fixture-' + source_sha[:8])
fixture.mkdir(exist_ok=True)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def ident(p):
    return {'path': p.relative_to(ROOT).as_posix(), 'sha256': sha(p), 'bytes': p.stat().st_size}

def write(p, value):
    p.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')

def file_ref(p):
    return {'path': p.relative_to(ROOT).as_posix(), 'sha256': sha(p)}

inventory_path = BASE / 'delivery_review/review_inventory.json'
inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
inventory_matches = []
for row in inventory['entries']:
    p = ROOT / row['source_path']
    assert sha(p) == row['sha256'], p
    assert p.stat().st_size == row['bytes'], p
    m.scan(p, p.read_bytes())
    inventory_matches.append(row['source_path'])
for row in inventory['checked_inputs_not_packaged']:
    assert sha(ROOT / row['path']) == row['sha256'], row['path']

build = json.loads((BASE / 'lock_1904_candidate05/driver/build/build.json').read_text(encoding='utf-8'))
assert build['efi_sha256'] == m.DRIVER
assert sha(BASE / 'lock_1904_candidate05/driver/build/AiTweakerLock1904.efi') == m.DRIVER
for name, digest in build['sources'].items():
    assert sha(BASE / 'lock_1904_candidate05' / name) == digest
cap = m.CAP_PATH.read_bytes()
review = (BASE / 'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin').read_bytes()
assert hashlib.sha256(cap).hexdigest() == m.CAP and hashlib.sha256(review).hexdigest() == m.REVIEW
assert cap[4096:] == review[4096:]

pending_control = json.loads((BASE / 'delivery_review/archive_control.json').read_text(encoding='utf-8'))
assert pending_control['root_collection_closed'] is False
try:
    m.validate_final(m.Selection(), pending_control)
except ValueError as e:
    pending_refused = 'Root collection is not closed' in str(e)
else:
    pending_refused = False
assert pending_refused

# Deliberately feed a known marker present in a selected synthetic binary file.
# Never use actual user passwords or BMC credentials.
marker = 'SyntheticReviewMarker_9'
sample = fixture / 'fixture_artifact.bin'
sample.write_bytes(b'public-prefix:' + marker.encode() + b':public-suffix')
small_inventory = {'engineering_cap_sha256': m.CAP, 'driver_sha256': m.DRIVER,
    'entries': [{'source_path': sample.relative_to(ROOT).as_posix(), 'sha256': sha(sample), 'bytes': sample.stat().st_size,
                 'role': 'synthetic_review_fixture', 'version_binding': 'not_hardware', 'archive_path': 'fixture_artifact.bin'}],
    'checked_inputs_not_packaged': []}
write(fixture / 'review_inventory.json', small_inventory)
write(fixture / 'archive_control.json', {'root_collection_closed': False})
original_out, original_argv, original_stdin = m.OUT, sys.argv, sys.stdin
capture = io.StringIO()
try:
    m.OUT = fixture
    sys.argv = [str(SOURCE), '--check-pending', '--private-patterns-stdin']
    sys.stdin = io.StringIO(json.dumps([marker]))
    with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
        m.main()
    mode_ignored = 'PINNED_LOCAL_INPUTS_VALID_FINAL_NV_COLLECTION_PENDING' in capture.getvalue()
finally:
    m.OUT, sys.argv, sys.stdin = original_out, original_argv, original_stdin
assert marker not in capture.getvalue()

# The same selected bytes are detected if the extra patterns reach scan().
try:
    m.scan(sample, sample.read_bytes(), [marker.encode()])
except ValueError:
    explicit_scan_detected = True
else:
    explicit_scan_detected = False
assert explicit_scan_detected

# Check that error rendering itself is safe even if an artifact basename contains
# the pattern. Save only a boolean, never the marker-containing error text.
try:
    m.scan(marker + '.txt', marker.encode(), [marker.encode()])
except ValueError as e:
    marker_in_failure_message = marker in str(e)
else:
    marker_in_failure_message = False

# Construct only the required exact log fields, with explicit FAILED metadata.
# This proves acceptance criteria, not genuine hardware success or a ZIP publish.
stage2 = json.loads((BASE / 'nv_persistence_review/stage2/build/build.json').read_text(encoding='utf-8'))
common = {'DriverSHA256': m.DRIVER, 'RequestedStage': '0x0000000000000002', 'Stage': '0x0000000000000002',
          'Phase1ReceiptLogSHA256': stage2['stage1_receipt_binding']['log_sha256'], 'Fault': '0x0000000000000000', 'Failures': '0x0000000000000000'}
initial = dict(common, CredentialSHA256=stage2['stage1_receipt_binding']['record_sha256'], CredentialMode='0x0000000000000001', CoreUnlocked='0x0000000000000000')
for k, v in {'CredentialAttributes':3, 'CredentialBytes':128, 'CredentialGeneration':1, 'AcceptedWrites':0, 'NativeSetAttempts':0}.items():
    initial[k] = '0x' + format(v, '016x')
final = dict(common, CredentialSHA256='0' * 64)
for k, v in {'CleanupRestoredAbsence':1, 'CleanupDeleteAttempts':1, 'CredentialBytes':0, 'CredentialAttributes':0, 'CoreActive':0, 'CoreUnlocked':0, 'ConsoleOwnerActive':0, 'CredentialMode':2, 'CredentialGeneration':3, 'AcceptedWrites':2, 'NativeSetAttempts':2}.items():
    final[k] = '0x' + format(v, '016x')
lp, fp = fixture / 'fixture_load.txt', fixture / 'fixture_final.txt'
lp.write_text('\n'.join(k+'='+v for k,v in initial.items())+'\n', encoding='ascii')
fp.write_text('\n'.join(k+'='+v for k,v in final.items())+'\nUnlockResult=0x0000000000000000\nUnlockResult=0x0000000000000001\nPASS explicit new console session relocks\nPASS OC/memory variable metadata and SHA256 unchanged\n', encoding='ascii')
failed = fixture / 'fixture_failed_evidence.json'
write(failed, {'synthetic_fixture': True, 'status': 'FAILED', 'power': 'On', 'boot_unchanged': False, 'media_inserted': True, 'logout_confirmed': False, 'cold_power_cycle_occurred': False})
fake_control = {'root_collection_closed': True, 'engineering_cap_sha256': m.CAP, 'driver_sha256': m.DRIVER,
    'nv': {'stage2_load_log': file_ref(lp), 'final_log': file_ref(fp), 'hardware_summary': file_ref(failed), 'cold_power_evidence': [file_ref(failed)]},
    'cleanup_report': file_ref(failed), 'additional_public_evidence': []}
result = m.validate_final(m.Selection(), fake_control)
failed_metadata_accepted = result['status'] == 'PHYSICAL_ISOLATED_CONSOLE_NV_COMPLETED_WITH_EXACT_ABSENCE_LOG'

selected = {x['source_path'] for x in inventory['entries']}
missing_generated = []
for stage in [1, 2]:
    folder = BASE / f'nv_persistence_review/stage{stage}/build'
    b = json.loads((folder / 'build.json').read_text(encoding='utf-8'))
    for name, digest in b['generated_sources'].items():
        p = folder / 'source' / name
        assert sha(p) == digest
        if p.relative_to(ROOT).as_posix() not in selected:
            missing_generated.append(ident(p))

assert not (fixture / 'archives').exists()
report = {
    'status': 'INDEPENDENT_REVIEW_FINDINGS_BEFORE_FINAL_ARCHIVE', 'source': ident(SOURCE), 'snapshot': ident(snapshot),
    'inventory': ident(inventory_path), 'current_root_control': ident(BASE / 'delivery_review/archive_control.json'),
    'actual_secrets_read': False, 'BMC_accessed': False, 'production_or_helper_modified': False,
    'archive_created': False, 'firmware_tests_rerun': False,
    'positive_checks': {'all_selected_hash_size_and_generic_scans': len(inventory_matches), 'all_reference_hashes_checked': len(inventory['checked_inputs_not_packaged']), 'production_sources_checked': len(build['sources']), 'pinned_CAP_EFI_and_payload_equality': True, 'pending_collection_refused': pending_refused, 'stdin_pattern_not_echoed_in_check_pending': marker not in capture.getvalue()},
    'findings': [
        {'id': 'PRIVATE_PATTERNS_IGNORED_IN_READONLY_MODES', 'reproduced': mode_ignored and explicit_scan_detected, 'impact': '--check-pending returns success with a supplied synthetic pattern actually present in the selected artifact; only --package uses extra patterns. The existing stdin local test checks non-echo, not successful scanning.', 'recommendation': 'Scan every selected artifact with supplied patterns before returning from check-pending/prepare, or explicitly reject that flag in those modes. A scan-only mode fits the secret-retaining runner.'},
        {'id': 'FINAL_METADATA_STATUS_UNCHECKED', 'reproduced': failed_metadata_accepted, 'impact': 'Exact required synthetic NV log fields plus root_collection_closed=true pass validate_final even when hardware_summary/cold-power/cleanup JSON explicitly says FAILED, power On, media attached, logout false and no cold cycle. File hashes alone validate identity, not result semantics.', 'recommendation': 'Bind the final root-defined schemas/status and required Off/Boot/media/logout/cold-cycle facts, or have an explicit recorded final review gate; do not imply validate_final independently verifies these properties.'},
        {'id': 'NV_GENERATED_SOURCE_OMITTED', 'count': len(missing_generated), 'files': missing_generated, 'impact': 'Both test EFIs are included, but their manifest-bound build_identity.h, generated kvm.c and target_detect.h are absent from the current inventory; local_sources are not compared to their build manifests either.', 'recommendation': 'Bind local_sources/generated_sources and include the six small generated source files, or identify them as deliberate external dependencies. Check production object hashes using the existing NV build manifest without relinking.'},
        {'id': 'SENSITIVE_BASENAME_IN_SCAN_ERROR', 'reproduced_with_synthetic_only': marker_in_failure_message, 'impact': 'If a sensitive pattern appears in an artifact basename, scan failure includes that basename and main prints it. Current fixed inventory basenames are not known to contain secrets; this is an avoidable diagnostic path, not a claim of an actual leak.', 'recommendation': 'Use an opaque artifact index or constant redacted diagnostic for private-pattern failures; scan archive names/manifests before creating a pending ZIP.'},
    ],
    'scope_assessment': 'README and manifest keep engineering/non-OEM/not-flash-ready status. Historical04 and fresh05 component evidence are explicitly separated. Existing preserved-byte, NVRAM reset, custom splash replacement, missing whole-SPI backup, cabling and recovery limits are retained. The pending control currently rejects sealing as required.',
    'limits': ['Only local actual-source packaging/control fixtures were run; no firmware regression, network request, real credential input or final archive production.', 'The optional pattern scan detects literal encodings supplied to it; it is not OCR or a general detector for encoded/compressed secrets. Selected screenshots should remain explicitly reviewed QR evidence.', 'Fixtures are intentionally synthetic failed inputs and must never be included as real hardware evidence.'],
}
target = OUT / ('review-' + source_sha[:8] + '.json')
write(target, report)
print(json.dumps({'report': ident(target), 'source_sha256': source_sha, 'findings': [x['id'] for x in report['findings']], 'selected_files_checked': len(inventory_matches), 'archive_created': False}))
