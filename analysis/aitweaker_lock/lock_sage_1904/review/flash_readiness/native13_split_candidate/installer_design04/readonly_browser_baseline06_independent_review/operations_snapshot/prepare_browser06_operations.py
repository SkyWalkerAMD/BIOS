"""Derive narrowly scoped browser-baseline capture/control operations.

Original RAM_TEST05 operations and evidence remain immutable. No device calls.
"""
from pathlib import Path
import hashlib, json

HERE = Path(__file__).resolve().parent
HW = HERE.parents[3] / 'remote_172_20_2_162'
bindings = []

def derive(source, target, substitutions, expected=None):
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected and digest != expected:
        raise ValueError(f'Frozen input mismatch: {source.name}')
    text = raw.decode('utf-8')
    for old, new in substitutions:
        if old not in text:
            raise ValueError(f'Missing replacement in {source.name}: {old!r}')
        text = text.replace(old, new)
    result = text.encode('utf-8')
    if target.exists():
        if target.read_bytes() != result:
            raise FileExistsError(f'Refusing overwrite: {target}')
    else:
        with target.open('xb') as out:
            out.write(result)
    bindings.append({'input': str(source), 'input_sha256': digest,
                     'output': str(target), 'output_sha256': hashlib.sha256(result).hexdigest()})

derive(HW/'read_native13_ram_test05_qr.py', HW/'read_native13_browser_baseline06_qr.py', [
    ('RAM_TEST05', 'BROWSER_BASELINE06'), ('ram_test05', 'browser_baseline06'),
    ('Snapshot transport, identity and completeness only; original RAM detours and private test credential writes may occur. No flash acceptance inferred.',
     'Snapshot transport, identity and completeness only. Does not establish native browser success or absence of OEM internal variable writes. No password or flash acceptance inferred.')
], 'a1cc79c0fc172f38990e8467acd96bcab801ca579322df1f7fbac2d027c395d0')
derive(HW/'operations/capture_native13_ram_test05.mjs', HW/'operations/capture_native13_browser_baseline06.mjs', [
    ('RAM_TEST05', 'BROWSER_BASELINE06'), ('ram_test05', 'browser_baseline06'),
    ('ram-test05', 'browser-baseline06')
], '502f924f25d542292aeec9cf8bb0f7d0c8da2b07852c100906aaedd069fe76be')
derive(HW/'operations/native_test_keys09.mjs', HW/'operations/browser_baseline06_keys.mjs', [
    (" SAGE_NATIVE13_RAM_TEST05_MAIN:['1','2','q'],\n SAGE_NATIVE13_RAM_TEST05_SESSION:['m','b','r','q'],",
     " SAGE_NATIVE13_BROWSER_BASELINE06_MAIN:['b','q'],"),
    ('RAM_TEST05', 'BROWSER_BASELINE06'), ('native-test09', 'browser-baseline06')
], '49f08fa7b86f4fb565e7bec3832987fcba993cf9cce2524e48de462712f39a6e')
derive(HW/'operations/power_off_ram_test09.mjs', HW/'operations/power_off_browser_baseline06.mjs', [
    ('RAM_TEST05', 'BROWSER_BASELINE06'), ('ram-test09', 'browser-baseline06'),
    ('This also covers its preannounced CPU-only hold, where QR output is unavailable.',
     'This also covers an unresponsive native browser reached by this resident diagnostic.'),
    ('Resident RAM test app or its observed CPU hold; stops RAM execution. Does not itself restore any private credential left in NVRAM.',
     'Resident browser-baseline diagnostic or its unresponsive native browser; stops RAM execution. Does not reverse any OEM internal state changes.')
], '6e76322f7fb081f9cb602da042785209aaa1640f4a5a2ccacb9fdfcd1b871f8f')

derive(HERE/'test_ram_test05_decoder.py', HERE/'test_browser06_decoder.py', [
    ('RAM_TEST05', 'BROWSER_BASELINE06'), ('ram_test05', 'browser_baseline06'),
    ('test05_decoder', 'browser06_decoder'), ('decoder05', 'decoder06')
])
derive(HERE/'make_capture05_fixtures.py', HERE/'make_capture06_fixtures.py', [
    ('RAM_TEST05', 'BROWSER_BASELINE06'), ('capture05', 'capture06')
])
derive(HERE/'test_capture05.mjs', HERE/'test_capture06.mjs', [
    ('ram_test05', 'browser_baseline06'), ('capture05', 'capture06')
])
derive(HERE/'test_native_keys.mjs', HERE/'test_browser06_keys.mjs', [
    ('native_test_keys09.mjs', 'browser_baseline06_keys.mjs'),
    ('native-key-mock-', 'browser06-key-mock-'), ('native_key_tests.json', 'browser06_key_tests.json'),
    ('SAGE_NATIVE13_RAM_TEST05_MAIN', 'SAGE_NATIVE13_BROWSER_BASELINE06_MAIN'),
    ('SAGE_NATIVE13_RAM_TEST05_SESSION', 'SAGE_NATIVE13_BROWSER_BASELINE06_MAIN'),
    ("key:'1'", "key:'b'"), ("key:'r'", "key:'q'"),
    ("[{key:'F10'}", "[{key:'1'},{key:'2'},{key:'r'},{key:'F10'}"),
    ("['1']", "['b']"), ("['1','r']", "['b','q']"), ("['1','r','1']", "['b','q','b']"),
    ('restore key restricted to owned session menu', 'log key permitted only in baseline menu')
])
derive(HERE/'test_power_off_ram09.mjs', HERE/'test_power_off_browser06.mjs', [
    ('power_off_ram_test09.mjs', 'power_off_browser_baseline06.mjs'),
    ('ram-poweroff-mock-', 'browser06-poweroff-mock-'),
    ('SAGE_NATIVE13_RAM_TEST05_RESIDENT', 'SAGE_NATIVE13_BROWSER_BASELINE06_RESIDENT'),
    ('poweroff_ram09_tests.json', 'poweroff_browser06_tests.json')
])
report = {'status': 'DERIVED_OPERATIONS_LOCAL_ONLY', 'bindings': bindings,
          'device_calls': False, 'scope': 'New immutable identities and baseline-only menu scope; tests remain to be run.'}
(HERE/'browser06_operations_derivation.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
print(json.dumps(report, indent=2))
