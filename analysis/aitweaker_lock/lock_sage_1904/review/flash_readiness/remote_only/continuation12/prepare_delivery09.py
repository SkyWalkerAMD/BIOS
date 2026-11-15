"""Derive isolated diagnostic09 delivery tools; no device operation or EFI build."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
C11 = HERE.parent / 'continuation11'
HW = HERE.parents[3] / 'remote_172_20_2_162'
D04 = HERE.parents[1] / 'native13_split_candidate/installer_design04'
OUT = D04 / 'ram_test09_delivery'
OUT.mkdir(exist_ok=True)
bindings = []


def derive(source, target, replacements):
    before = source.read_bytes()
    body = before.decode('utf-8-sig')
    for old, new in replacements:
        assert old in body, (source, old)
        body = body.replace(old, new)
    data = body.encode('utf-8')
    if target.exists():
        assert target.read_bytes() == data, target
    else:
        target.write_bytes(data)
    assert source.read_bytes() == before
    bindings.append({'source':str(source),'source_sha256':hashlib.sha256(before).hexdigest(),
                     'output':str(target),'output_sha256':hashlib.sha256(data).hexdigest()})


derive(D04/'ram_test08_delivery/package_app.py', OUT/'package_app.py', [
    ('RAM_TEST08','RAM_TEST09'), ('ram_transaction08','ram_transaction09'),
    ('RamTest08','RamTest09'), ('RAMTEST08','RAMTEST09'), ('SAGERAM08','SAGERAM09'), ('SAGE_N13_RAM08','SAGE_N13_RAM09')])
derive(D04/'ram_test08_delivery/smoke_iso.py', OUT/'smoke_iso.py', [
    ('RAM_TEST08','RAM_TEST09'), ('ram_test08','ram_test09'), ('ram08_actual','ram09_actual')])
for name in ['build_transport_boundary.py','transport_boundary_support.c','verify_transport_boundary.py']:
    body = (D04/'ram_test08_delivery'/name).read_text()
    replacements = [(a,b) for a,b in [('ram_transaction08','ram_transaction09'),('SAGE_NATIVE13_RAM_TEST08','SAGE_NATIVE13_RAM_TEST09')] if a in body]
    derive(D04/'ram_test08_delivery'/name, OUT/name, replacements)
derive(HW/'read_native13_ram_test08_qr.py', HW/'read_native13_ram_test09_qr.py', [
    ('RAM_TEST08','RAM_TEST09'), ('ram_test08','ram_test09')])
derive(HW/'operations/capture_native13_ram_test08.mjs', HW/'operations/capture_native13_ram_test09.mjs', [
    ('RAM_TEST08','RAM_TEST09'), ('ram_test08','ram_test09'), ('ram-test08','ram-test09')])
derive(HW/'operations/native_test_keys11.mjs', HW/'operations/native_test_keys12.mjs', [
    ('RAM_TEST08','RAM_TEST09'), ('native-test11','native-test12')])
derive(HW/'operations/power_off_ram_test11.mjs', HW/'operations/power_off_ram_test12.mjs', [
    ('RAM_TEST08','RAM_TEST09'), ('ram-test11','ram-test12')])
spec = {
    'test_ram_test08_decoder.py': ('test_ram_test09_decoder.py', [('RAM_TEST08','RAM_TEST09'),('ram_test08','ram_test09'),('test08_decoder','test09_decoder'),('decoder08','decoder09')]),
    'make_capture08_fixtures.py': ('make_capture09_fixtures.py', [('RAM_TEST08','RAM_TEST09'),('capture08','capture09')]),
    'test_capture08.mjs': ('test_capture09.mjs', [('ram_test08','ram_test09'),('capture08','capture09')]),
    'test_capture08_stale.mjs': ('test_capture09_stale.mjs', [('ram_test08','ram_test09'),('capture08','capture09')]),
    'test_native_keys11.mjs': ('test_native_keys12.mjs', [('native_test_keys11','native_test_keys12'),('native11','native12'),('RAM_TEST08','RAM_TEST09')]),
    'test_power_off_ram11.mjs': ('test_power_off_ram12.mjs', [('power_off_ram_test11','power_off_ram_test12'),('ram11','ram12'),('RAM_TEST08','RAM_TEST09')]),
}
for source,(dest,replacements) in spec.items():
    derive(C11/source, HERE/dest, replacements)
report = {'status':'LOCAL_DELIVERY_TOOLS_DERIVED_TESTS_PENDING','device_calls':0,
          'new_efi_built':False,'hardware_approval':False,'bindings':bindings,
          'delta':'Only names/markers/paths changed from tested08 tools; prior-page same-snapshot retry logic retained. Password fixture intentionally not part of this diagnostic scope.'}
(HERE/'delivery09_derivation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'files':len(bindings)}))
