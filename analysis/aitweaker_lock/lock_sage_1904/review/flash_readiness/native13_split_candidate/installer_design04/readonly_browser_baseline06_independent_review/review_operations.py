"""Read-only review of the new baseline06 operation family; no device calls."""
from pathlib import Path
from datetime import datetime, timezone
import difflib
import hashlib
import json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[2]
CASE = READY.parents[1]
HW = CASE / 'remote_172_20_2_162'
C09 = READY / 'remote_only/continuation09'
EXPECTED = {
    'read_native13_browser_baseline06_qr.py': 'abdcad40b3fc79443ab6b0933a488c850cfeefb31645ef6081a3b39169d7c240',
    'operations/capture_native13_browser_baseline06.mjs': '858ca368a64d6e8d1c22cef22a8b31861f8be76265e838780e7ca44eea944836',
    'operations/browser_baseline06_keys.mjs': 'b12f6aa415bb23ce2626ed2cd362e39121fdb12d64600a7a0e74c6c6921dc872',
    'operations/power_off_browser_baseline06.mjs': 'ac5f360c4202ce46fba1a9fd86fa9c1027e6a8020aabfe10590e39bfdec19bc0',
}
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text())
def bound(p): return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p)}

def main():
    for name, digest in EXPECTED.items(): assert sha(HW / name) == digest
    derivation_path = C09 / 'browser06_operations_derivation.json'
    derivation = read(derivation_path)
    for row in derivation['bindings']:
        assert sha(Path(row['input'])) == row['input_sha256']
        assert sha(Path(row['output'])) == row['output_sha256']
    decoder = read(C09 / 'decoder06_tests.json')
    capture = read(C09 / 'capture06_tests.json')
    keys = read(C09 / 'browser06_key_tests.json')
    power = read(C09 / 'poweroff_browser06_tests.json')
    assert decoder['source_sha256'] == EXPECTED['read_native13_browser_baseline06_qr.py'] and len(decoder['checks']) == 14
    assert capture['decoder_sha256'] == decoder['source_sha256']
    assert capture['capture_sha256'] == EXPECTED['operations/capture_native13_browser_baseline06.mjs'] and len(capture['checks']) == 4
    assert keys['source_sha256'] == EXPECTED['operations/browser_baseline06_keys.mjs'] and len(keys['cases']) == 6
    assert power['source_sha256'] == EXPECTED['operations/power_off_browser_baseline06.mjs'] and len(power['checks']) == 4
    comparisons = [
        ('read_native13_ram_test05_qr.py','read_native13_browser_baseline06_qr.py'),
        ('operations/capture_native13_ram_test05.mjs','operations/capture_native13_browser_baseline06.mjs'),
        ('operations/native_test_keys09.mjs','operations/browser_baseline06_keys.mjs'),
        ('operations/power_off_ram_test09.mjs','operations/power_off_browser_baseline06.mjs'),
    ]
    delta = HERE / 'operations05_to06.diff.txt'
    delta.write_text(''.join(''.join(difflib.unified_diff((HW/old).read_text().splitlines(True), (HW/new).read_text().splitlines(True),
                                                      fromfile=old, tofile=new)) for old,new in comparisons),encoding='utf-8')
    files = [HW/name for name in EXPECTED] + [C09/name for name in [
        'prepare_browser06_operations.py','browser06_operations_derivation.json',
        'decoder06_tests.json','capture06_tests.json','browser06_key_tests.json','poweroff_browser06_tests.json',
        'test_browser06_decoder.py','make_capture06_fixtures.py','test_capture06.mjs','test_browser06_keys.mjs','test_power_off_browser06.mjs']]
    snap = HERE / 'operations_snapshot'
    snap.mkdir(exist_ok=True)
    for p in files:
        out = snap/p.name
        if out.exists(): assert out.read_bytes() == p.read_bytes()
        else: out.write_bytes(p.read_bytes())
    result = {
        'status': 'PASS_LOCAL_BASELINE06_OPERATION_SOURCE_AND_TEST_BINDING_REVIEW',
        'utc': datetime.now(timezone.utc).isoformat(), 'device_calls': 0,
        'confirmed_source_blockers': [], 'new_test_execution_by_reviewer': 0,
        'reviewed_existing_tests': {'decoder':14,'actual_capture_with_synthetic_pngs':4,'keys':6,'poweroff':4},
        'findings': [
            'The new decoder accepts only the baseline06 prefix/end pair and retains the pinned P3 page CRC/whole CRC/length/bounds/snapshot completeness checks. QR content is data, never instructions.',
            'Capture differs only by frozen decoder path/folder/event identity. It preserves attempts and accepted frames, advances only n after a verified page, and leaves semantic interpretation pending.',
            'The only menu stage is SAGE_NATIVE13_BROWSER_BASELINE06_MAIN, and only b/q are allowed. Password text, modes1/2, M/R, arbitrary key names and unknown fields are excluded.',
            'The one-key operation retains bounded recent local screenshot SHA verification, owned viewer focus, intent-before-key and no automatic retry. It is a manual observation gate, not screen recognition.',
            'The new ForceOff operation retains fixed standard ComputerSystem.Reset/ForceOff, On+BIOS1904+nativeOn and advertised-action checks, prewritten intent, exactly one POST and no retry. HTTP acceptance is not an Off readback.',
            'Wording explicitly allows an unresponsive native browser without falsely diagnosing CPU hold. Power-off is not represented as reversal of possible OEM internal state changes.',
            'Original05 operations and frozen evidence remain unchanged; the derivation checks each pinned original tool identity and refuses conflicting output overwrite.',
        ],
        'pending_candidate_integration': [
            'The baseline app must display the same family and b/q menu, enforce at most one browse call, and emit matching complete snapshot markers.',
            'This operation review does not accept a baseline EFI/ISO, original SendForm outcome, or password/firmware deployment.',
            'Actual no-detour/no-provider/no-credential-setter code paths and callback lifecycle remain to be reviewed against the frozen app binary.',
        ],
        'limits': [
            'Existing local tests were inspected/bound and not reexecuted here. They use fake API/viewer endpoints or synthetic screenshots, not the physical device.',
            'The caller owns target pinning and serializes operations. Screenshot freshness and queried state are not an atomic hardware lock.',
            'Ambiguous ForceOff transport must be resolved with read-only power-state observation. No blind resend is authorized by this helper.',
            'An application without a direct variable writer does not prove absence of OEM internal writes during standard SendForm.',
        ],
        'bindings': [bound(p) for p in files] + [bound(delta),bound(Path(__file__))],
    }
    out = HERE / 'operations_review.json'
    assert not out.exists()
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':result['status'],'sha256':sha(out)}))

if __name__ == '__main__': main()
