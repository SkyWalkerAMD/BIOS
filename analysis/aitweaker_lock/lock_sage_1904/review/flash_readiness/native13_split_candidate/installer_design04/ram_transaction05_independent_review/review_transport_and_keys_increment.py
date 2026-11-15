"""Incremental read-only review; preserve preceding operation snapshots."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent
D04=HERE.parent
READY=HERE.parents[2]
CASE=READY.parents[1]
DELIVERY=D04/'ram_test05_delivery'
KVM=D04/'ram_transaction05/source/transport/kvm.c'
KEY=CASE/'remote_172_20_2_162/operations/native_test_keys09.mjs'
C09=READY/'remote_only/continuation09'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
def bound(p):return {'path':str(p),'sha256':sha(p)}
def main():
    assert sha(KVM)=='209e27f9780841e30ab9423a4db1a5f8d5a50c4306753c8be76070b202b24405'
    assert sha(KEY)=='49f08fa7b86f4fb565e7bec3832987fcba993cf9cce2524e48de462712f39a6e'
    report=read(DELIVERY/'transport_boundary_result.json')
    assert report['source_sha256']==sha(KVM) and report['checks']==len(report['labels'])==99
    buildpath=DELIVERY/'transport_boundary_build/build.json';build=read(buildpath)
    assert report['build_sha256']==sha(buildpath)
    pe=DELIVERY/'transport_boundary_build/TransportBoundary.TESTONLY.efi'
    assert report['test_efi_sha256']==sha(pe)==build['efi_sha256']
    assert report['test_source_sha256']==sha(DELIVERY/'verify_transport_boundary.py')
    for name,digest in build['sources'].items():assert sha(Path(name))==digest
    keys=read(C09/'native_key_tests.json');assert keys['source_sha256']==sha(KEY) and len(keys['cases'])==6
    assert "{key:'t'}" in (C09/'test_native_keys.mjs').read_text()
    old=HERE/'operations09_snapshot/native_test_keys09.mjs'
    assert sha(old)=='9eaa0c71ade3429780cc7319aa5681562dcc7c36f3633e247836ae99b2b7c5e4'
    files=[KVM,KEY,C09/'native_key_tests.json',C09/'test_native_keys.mjs',DELIVERY/'transport_boundary_result.json',
           DELIVERY/'verify_transport_boundary.py',DELIVERY/'build_transport_boundary.py',DELIVERY/'transport_boundary_support.c',buildpath,pe]
    snap=HERE/'transport_and_keys_snapshot';snap.mkdir(exist_ok=True)
    for p in files:(snap/p.name).write_bytes(p.read_bytes())
    result={
      'status':'PASS_SOURCE_AND_ACTUAL_PE_TEST_IDENTITY_INCREMENT_NOT_FINAL_APP_ACCEPTANCE',
      'generated_utc':datetime.now(timezone.utc).isoformat(),
      'confirmed_source_blockers':[],
      'transport':bound(KVM),'transport_actual_PE_report':bound(DELIVERY/'transport_boundary_result.json'),
      'key_operation':bound(KEY),'key_tests':bound(C09/'native_key_tests.json'),
      'prior_operation_snapshot_preserved':bound(old),
      'review_source':bound(Path(__file__)),
      'reviewed_matrix_cases':99,'reviewed_key_mock_cases':6,'new_test_execution_count_in_this_increment':0,
      'transport_findings':[
        'SERVICE macro calls app_require_services before and after each firmware method expression, including indirect WaitForEvent, optional stall, GOP Blt and FreePool.',
        'All firmware calls in graphics/query, multi-part text, text/QR display, input waiting and cleanup use SERVICE. No direct reset, NVRAM, filesystem or SPI operation was found.',
        'The 99-case runner executes the linked transport PE; only external service semantics/ending-held latches are modeled. Most cases replace QR encoding, explicitly disclosed; one normal case uses the actual compiled encoder.',
        'Ending is injected at each reached service boundary; the actual guard call reaches modeled terminal hold before the next external service. App gate body is tested separately, so this is not yet full linked app proof.',
        'The current title and viewer-exit text describe RAM_TEST05 and resident application correctly; old no-hooks/no-variables claims are absent.',
      ],
      'key_increment':'Only unsupported menu t was removed. Existing evidence/time/SHA gate, one-key behavior and no-retry semantics are unchanged; T remains the internal QR-viewer command.',
      'remaining_limits':['No real firmware event dispatch, device key delivery or native BIOS GUI is exercised by these local matrices.',
                          'Final app object linking, adapter/credential lifecycle, complete EFI/ISO identity and all dependency hashes remain required.',
                          'No inherited hardware acceptance and no modifications to prior frozen publication/firmware artifacts.'],
      'snapshots':[{**bound(p),'copy':str((snap/p.name).relative_to(HERE))} for p in files],
    }
    out=HERE/'transport_and_keys_increment_review.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'sha256':sha(out)}))
if __name__=='__main__':main()
