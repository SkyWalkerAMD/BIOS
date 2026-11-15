"""Snapshot a scoped operation review; does not execute the operation."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[2]
CASE = READY.parents[1]
C09 = READY / 'remote_only/continuation09'
OP = CASE / 'remote_172_20_2_162/operations/power_off_ram_test09.mjs'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    expected = '6e76322f7fb081f9cb602da042785209aaa1640f4a5a2ccacb9fdfcd1b871f8f'
    assert sha(OP) == expected
    report_path = C09 / 'poweroff_ram09_tests.json'
    report = json.loads(report_path.read_text())
    assert report['source_sha256'] == expected and len(report['checks']) == 4
    test = C09 / 'test_power_off_ram09.mjs'
    assert "import op from '../../../../remote_172_20_2_162/operations/power_off_ram_test09.mjs'" in test.read_text()
    snapshot = HERE / 'poweroff_increment_snapshot'
    snapshot.mkdir(exist_ok=True)
    records = []
    for p in (OP, report_path, test):
        copy = snapshot / p.name
        copy.write_bytes(p.read_bytes())
        records.append({'path': str(p), 'sha256': sha(p), 'snapshot': str(copy)})
    result = {
        'status': 'PASS_SCOPED_SOURCE_AND_MOCK_BINDING_REVIEW',
        'utc': datetime.now(timezone.utc).isoformat(),
        'review_source_sha256': sha(Path(__file__)),
        'confirmed_blockers': [],
        'device_calls': 0,
        'reviewed_existing_mock_checks': 4,
        'new_test_execution_count': 0,
        'findings': [
            'Arguments are limited to the fixed observed resident-app stage and a bounded basename PNG plus exact SHA256; age and size are checked before any power action.',
            'Both Redfish and native chassis inventory must report On, BIOS1904 must match, and the standard action info must advertise ForceOff.',
            'A fresh screenshot is captured and an exclusive-create intent is persisted before the one standard ComputerSystem.Reset POST. Automatic transport retry is disabled.',
            'HTTP acceptance is explicitly not an Off readback and does not establish private credential restoration.',
            'The source changes no firmware image, manager configuration, BootOrder or override settings.',
        ],
        'limits': [
            'The screenshot stage is a human observation; this is not image recognition or automatic proof of which application currently runs.',
            'The authorized target identity depends on the already-owned fixed-target controller context; this helper does not independently pin its client transport.',
            'Fresh inventories and the POST are separate operations, not an atomic hardware transaction. The controller must serialize maintenance actions.',
            'An ambiguous POST response must be followed by read-only power-state observation, never blind retry. Power loss can leave a temporary private NVRAM credential if application cleanup did not finish.',
            'Existing mocks were inspected and bound but were not reexecuted by this review.',
        ],
        'bindings': records,
    }
    out = HERE / 'poweroff_increment_review.json'
    out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'sha256': sha(out)}))

if __name__ == '__main__': main()
