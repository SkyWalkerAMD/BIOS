"""Derive isolated TX08 delivery/control files. No device calls or frozen-input edits."""
from pathlib import Path
import hashlib,json

HERE=Path(__file__).resolve().parent
C09=HERE.parent/'continuation09'
HW=HERE.parents[3]/'remote_172_20_2_162'
D04=HERE.parents[1]/'native13_split_candidate/installer_design04'
OUT=D04/'ram_test08_delivery'
OUT.mkdir(exist_ok=True)
bindings=[]

def derive(source,target,replacements,expected=None):
    raw=source.read_bytes(); digest=hashlib.sha256(raw).hexdigest()
    if expected: assert digest==expected,source
    s=raw.decode('utf-8')
    for old,new in replacements:
        assert old in s,(source.name,old)
        s=s.replace(old,new)
    data=s.encode('utf-8')
    if target.exists():assert target.read_bytes()==data,target
    else:target.write_bytes(data)
    bindings.append({'source':str(source),'source_sha256':digest,'output':str(target),'output_sha256':hashlib.sha256(data).hexdigest()})

derive(D04/'ram_test05_delivery/package_app.py',OUT/'package_app.py',[
    ('RAM_TEST05','RAM_TEST08'),('ram_transaction05','ram_transaction08'),
    ('RamTest05','RamTest08'),('RAMTEST05','RAMTEST08'),('SAGERAM05','SAGERAM08'),('SAGE_N13_RAM05','SAGE_N13_RAM08')],
    '7cbce850c3c85fdf996508f3748b9a60fe7367e16efa7651596aa894f5c58ddd')
derive(D04/'ram_test05_delivery/smoke_iso.py',OUT/'smoke_iso.py',[
    ('RAM_TEST05','RAM_TEST08'),('ram_test05','ram_test08'),('ram05_actual','ram08_actual')])
for name in ['build_transport_boundary.py','transport_boundary_support.c','verify_transport_boundary.py']:
    replacements=[]
    s=(D04/'browser_baseline06_delivery'/name).read_text()
    for old,new in [('readonly_browser_baseline06/source/transport','ram_transaction08/source/transport'),('SAGE_NATIVE13_BROWSER_BASELINE06','SAGE_NATIVE13_RAM_TEST08')]:
        if old in s:replacements.append((old,new))
    derive(D04/'browser_baseline06_delivery'/name,OUT/name,replacements)

derive(HW/'read_native13_ram_test05_qr.py',HW/'read_native13_ram_test08_qr.py',[
    ('RAM_TEST05','RAM_TEST08'),('ram_test05','ram_test08')],
    'a1cc79c0fc172f38990e8467acd96bcab801ca579322df1f7fbac2d027c395d0')
derive(HW/'operations/capture_native13_ram_test05.mjs',HW/'operations/capture_native13_ram_test08.mjs',[
    ('RAM_TEST05','RAM_TEST08'),('ram_test05','ram_test08'),('ram-test05','ram-test08'),
    ('attempt<=4','attempt<=8'),('waitForTimeout(1000)','waitForTimeout(1500)'),
    ("if(info.page!==expected)throw Error(`Expected QR page ${expected}; no automatic navigation attempted`);",
     "if(info.page!==expected){\n    // A delayed KVM frame may still show the preceding page. Wait without another key.\n    if(first && info.page===expected-1 && info.crc===first.crc && info.total===first.total && info.pages===first.pages){info=null;continue;}\n    throw Error(`Expected QR page ${expected}; no automatic navigation attempted`);\n   }")],
    '502f924f25d542292aeec9cf8bb0f7d0c8da2b07852c100906aaedd069fe76be')
derive(HW/'operations/native_test_keys09.mjs',HW/'operations/native_test_keys11.mjs',[
    ('RAM_TEST05','RAM_TEST08'),('native-test09','native-test11')],
    '49f08fa7b86f4fb565e7bec3832987fcba993cf9cce2524e48de462712f39a6e')
derive(HW/'operations/power_off_ram_test09.mjs',HW/'operations/power_off_ram_test11.mjs',[
    ('RAM_TEST05','RAM_TEST08'),('ram-test09','ram-test11'),
    ('This also covers its preannounced CPU-only hold, where QR output is unavailable.',
     'This also covers an unresponsive native browser reached by this resident diagnostic; pixels alone do not prove CPU hold.'),
    ('Resident RAM test app or its observed CPU hold; stops RAM execution. Does not itself restore any private credential left in NVRAM.',
     'Resident RAM test app or its unresponsive native browser; pixels alone do not prove CPU hold. Stops RAM execution but does not itself restore any private credential left in NVRAM.')],
    '6e76322f7fb081f9cb602da042785209aaa1640f4a5a2ccacb9fdfcd1b871f8f')
derive(HW/'operations/kvm_password_fixture09.mjs',HW/'operations/kvm_password_fixture11.mjs',[
    ('aiTweakerPasswordFixture09','aiTweakerPasswordFixture11')],
    'bb9e34721f46078915e094d001b4585391c7ff25e98a760564942ebd3a482866')
testspec={
    'test_ram_test05_decoder.py':('test_ram_test08_decoder.py',[('RAM_TEST05','RAM_TEST08'),('ram_test05','ram_test08'),('test05_decoder','test08_decoder'),('decoder05','decoder08')]),
    'make_capture05_fixtures.py':('make_capture08_fixtures.py',[('RAM_TEST05','RAM_TEST08'),('capture05','capture08')]),
    'test_capture05.mjs':('test_capture08.mjs',[('ram_test05','ram_test08'),('capture05','capture08')]),
    'test_native_keys.mjs':('test_native_keys11.mjs',[('native_test_keys09','native_test_keys11'),('native-key-mock-','native11-key-mock-'),('native_key_tests.json','native11_key_tests.json'),('RAM_TEST05','RAM_TEST08')]),
    'test_power_off_ram09.mjs':('test_power_off_ram11.mjs',[('power_off_ram_test09','power_off_ram_test11'),('ram-poweroff-mock-','ram11-poweroff-mock-'),('RAM_TEST05','RAM_TEST08'),('poweroff_ram09','poweroff_ram11')]),
    'test_kvm_password_fixture.mjs':('test_kvm_password_fixture11.mjs',[('kvm_password_fixture09','kvm_password_fixture11'),('aiTweakerPasswordFixture09','aiTweakerPasswordFixture11'),('kvm_password_fixture_tests.json','kvm_password_fixture11_tests.json')]),
}
for source,(dest,replacements) in testspec.items():derive(C09/source,HERE/dest,replacements)
report={'status':'DERIVED_LOCAL_ONLY_TESTS_PENDING','device_calls':False,'bindings':bindings,
        'capture_change':'Same snapshot immediately preceding page may be retried without extra key; 8 attempts at1.5s, all other order/identity/completeness rules retained'}
(HERE/'ram08_delivery_derivation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'files':len(bindings)}))
