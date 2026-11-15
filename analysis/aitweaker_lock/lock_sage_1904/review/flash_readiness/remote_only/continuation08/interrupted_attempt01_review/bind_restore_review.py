"""Bind source review and existing mocked tests; no network/device actions."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
C08=HERE.parent
HW=HERE.parents[4]/'remote_172_20_2_162'
PIN='d6456057bfea8a9c1c4f060a1e1b8065327bf1c596e25a10f57fa40a27b948bc'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def main():
    source=HW/'operations/restore_media_overrides08.mjs';assert sha(source)==PIN
    text=source.read_text(encoding='utf8')
    assert text.count('rf.client.patch(')==1
    assert "d.Id!==id||d.BootOptionReference!=='Boot'+id" in text
    assert "headers:{...rf.auth,'If-Match':etag},data:{Boot:requested},timeout:15000,maxRetries:0" in text
    tests=C08/'restore_overrides_tests.json';t=json.loads(tests.read_text())
    assert t['source']['sha256']==PIN and t['status']=='PASS' and len(t['cases'])==10
    assert all(x['status']=='PASS' for x in t['cases'])
    duplicate=next(x for x in t['cases'] if x['name']=='duplicate_option_response')
    assert duplicate['accepted'] is False and duplicate['patches']==0
    history=HW/'boot-options-1793666634014.json'
    assert sha(history)=='1d0b3d5f35385aabea214a5b412a3c4ec19aa3df1f6c93d7b79c4ee6bb03e11c'
    assert sha(HERE/'interruption_review.json')=='2ded91978e9f5651069226dae0bcdea74afff4ddcbcb75c8adcc459aaf6f8c2b'
    (HERE/'reviewed_restore_operation.mjs').write_bytes(source.read_bytes())
    report={
        'status':'NO_BLOCKING_DEFECT_IDENTIFIED_AFTER_URI_IDENTITY_HARDENING',
        'scope':'Independent source review plus hash/schema verification of parent10-case actual-operation mocks; reviewer made no device request and did not rerun the mocks.',
        'source':ref(source),'parent_tests':ref(tests),'parent_test_source':ref(C08/'test_restore_overrides.mjs'),
        'historical_option_input':ref(history),
        'physical_option_comparison':ref(HERE/'interruption_review.json'),
        'parent_mock_cases':t['cases'],
        'issue_found_and_resolved':{
            'initial_source_sha256':'5e4a168a8fbaee58faa4861c7421ca2175c1bcf94c7226834be491459706a0fe',
            'issue':'Initial version compared each returned BootOption to any historical reference, but did not require its Id/Reference to match the requested URI. Duplicate responses could falsely appear to cover the inventory.',
            'fix':'Final version requires Id==URI suffix and BootOptionReference==Boot+suffix before historical field comparison.',
            'test':'duplicate_option_response: refused, zero PATCH calls'},
        'verified_properties':[
            'Baseline filename restricted and digest verified; original overrides must be exactly Disabled/None/Legacy, BootNext null, and one of two fixed six/seven orders.',
            'Historical boot-option artifact pinned by hash; removed/added Boot0007 is the known AMI Virtual CDROM0 entry.',
            'Current order must equal the fixed six or seven sequence, preserving all non-CD relative order; BootNext must be null.',
            'BootOptions member URI set and count must equal the current order.',
            'Every fetched option is bound to its requested URI, then compared on Id/Reference/DisplayName/Enabled/DevicePath to the historical entry.',
            'Fresh native host power must be Off before mutation.',
            'Exclusive local intent written before PATCH; PATCH uses captured ETag and maxRetries0.',
            'Request body contains only three original override properties. No BootOrder/BootNext write, no option creation/deletion, no power/firmware/reset call.',
            'Already-restored override values avoid PATCH; otherwise at most one PATCH per invocation.',
            'Readback must match three requested overrides, preserve exact pre-PATCH current BootOrder, and keep BootNext null before verified=true.'],
        'limits':[
            'This is a supported settings restoration for a physically verified dynamic virtual-CD exception, not permission to accept arbitrary boot-option loss.',
            'No absolute cross-operator atomicity: If-Match covers the settings resource, not all individual BootOptions. Fresh checks and final readback bound the observed state.',
            'Live application and cleanup outcome must be bound separately; mocked success alone does not prove hardware restoration.',
            'HTTP or transport failure after PATCH is not auto-retried; parent should read state before any further action.',
            'Correct owned Redfish client target/TLS/authentication is inherited from the reviewed parent session.']}
    write(HERE/'restore_operation_review.json',report)
    write(HERE/'restore_operation_manifest.json',{'files':[ref(HERE/'bind_restore_review.py'),ref(HERE/'reviewed_restore_operation.mjs'),ref(HERE/'restore_operation_review.json')],
          'external_inputs':[ref(source),ref(tests),ref(C08/'test_restore_overrides.mjs'),ref(history)]})
    print(json.dumps({'report':ref(HERE/'restore_operation_review.json'),'manifest':ref(HERE/'restore_operation_manifest.json')},indent=2))
if __name__=='__main__':main()
