"""Read-only binding review of root's small C09 keyboard/capture operations."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib,json
HERE=Path(__file__).resolve().parent
READY=HERE.parents[2]
CASE=READY.parents[1]
HW=CASE/'remote_172_20_2_162'
C09=READY/'remote_only/continuation09'
EXPECTED={
 'operations/native_test_keys09.mjs':'9eaa0c71ade3429780cc7319aa5681562dcc7c36f3633e247836ae99b2b7c5e4',
 'operations/kvm_password_fixture09.mjs':'bb9e34721f46078915e094d001b4585391c7ff25e98a760564942ebd3a482866',
 'operations/capture_native13_ram_test05.mjs':'502f924f25d542292aeec9cf8bb0f7d0c8da2b07852c100906aaedd069fe76be',
 'read_native13_ram_test05_qr.py':'a1cc79c0fc172f38990e8467acd96bcab801ca579322df1f7fbac2d027c395d0',
}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf8'))
def bound(path):return {'path':str(path),'sha256':sha(path)}
def main():
    files=[]
    for name,digest in EXPECTED.items():
        path=HW/name;assert sha(path)==digest;files.append(path)
    mappings=[('native_key_tests.json','cases',6,'source_sha256','operations/native_test_keys09.mjs'),
              ('kvm_password_fixture_tests.json','cases',5,'source_sha256','operations/kvm_password_fixture09.mjs'),
              ('decoder05_tests.json','checks',14,'source_sha256','read_native13_ram_test05_qr.py'),
              ('capture05_tests.json','checks',4,'capture_sha256','operations/capture_native13_ram_test05.mjs')]
    tests=[]
    for name,key,count,hashkey,source in mappings:
        path=C09/name;data=read(path)
        assert data['status'].startswith('PASS') and len(data[key])==count and data[hashkey]==EXPECTED[source]
        tests.append({**bound(path),'cases':count,'scope':'Author-executed local tests inspected and identity-bound; not repeated as new independent execution.'})
        files.append(path)
    assert read(C09/'capture05_tests.json')['decoder_sha256']==EXPECTED['read_native13_ram_test05_qr.py']
    for name in ['test_native_keys.mjs','test_kvm_password_fixture.mjs','test_ram_test05_decoder.py','test_capture05.mjs']:
        files.append(C09/name)
    p3=CASE.parent/'probe_p3_kvm/decode_captures.py'
    assert sha(p3)=='f1ad8dc74f62136ce06a1b1cdb18df24de3bcaae0acdd1d388a769d31c128283'
    files.append(p3)
    snapshot=HERE/'operations09_snapshot';snapshot.mkdir(exist_ok=True)
    for path in files:(snapshot/path.name).write_bytes(path.read_bytes())
    result={
      'status':'PASS_SCOPED_SOURCE_AND_LOCAL_TEST_BINDINGS_NOT_HARDWARE_EXECUTION',
      'generated_utc':datetime.now(timezone.utc).isoformat(),
      'confirmed_blockers':[], 'hardware_or_network_execution_by_reviewer':False,
      'author_local_cases_bound':29, 'new_test_execution_count_in_this_review':0,
      'review_source':bound(Path(__file__)),
      'sources':[bound(HW/name) for name in EXPECTED], 'author_tests':tests,
      'findings':[
        {'source':'native_test_keys09.mjs','lines':[6,26],
         'finding':'Menu/stage pair and single exact key are allowlisted. Basename-only screenshot is size/mtime/SHA-bound, keyboard focus checked, intent saved before one keypress, and an uncertain send is never retried.'},
        {'source':'kvm_password_fixture09.mjs','lines':[9,28],
         'finding':'Creates three independent 32-character hexadecimal buffers; caller cannot inject arbitrary text. Type requires the asserted masked prompt, one existing choice and KVM focus; no Enter is sent, errors hide underlying secret-bearing text.'},
        {'source':'capture_native13_ram_test05.mjs','lines':[9,42],
         'finding':'Decoder bytes are pinned. Screenshots and failed attempts remain local evidence. Only an accepted current page can trigger one n advance; wrong page/mixed CRC/size/page count aborts. Final assembly determines transport completeness, not application success.'},
        {'source':'read_native13_ram_test05_qr.py','lines':[5,53],
         'finding':'Pins original decoder; verifies exact family, one 16-hex snapshot ID within first chunk, full length/CRC, one end marker, completeness and no-overflow markers. Existing differing evidence cannot be overwritten; output marks semantic parsing pending.'},
      ],
      'operating_boundaries':[
        'Screenshot stage and masked password prompt are operator observations, not OCR or automatic application recognition.',
        'The menu allowlist must remain synchronized with the final RAM_TEST05 application; this review predates final adapter/EFI/ISO binding.',
        'Controller must serialize key/capture/password operations. No concurrent create/type/clear sequence is accepted by this review.',
        'Fixture clear proves its held Buffers are zeroed and removed. It cannot prove erasure of prior JS strings, Playwright transport copies, browser memory or firmware password state.',
        'CRC32 and snapshot identity detect ordinary corruption/mixed captures, not adversarial authenticated log forgery.',
        'Tool source review and existing local mocks do not establish actual key arrival, native installer success, password acceptance or hardware cleanup.',
      ],
      'snapshots':[{**bound(path),'frozen_copy':str((snapshot/path.name).relative_to(HERE))} for path in files],
    }
    out=HERE/'operations09_review.json';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'source_files':4,'bound_author_cases':29,'report_sha256':sha(out)}))
if __name__=='__main__':main()
