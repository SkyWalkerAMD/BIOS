"""Bind completed independent review; no firmware or network operations."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent
F05=HERE.parent.parent
ROOT=F05.parents[3]
RUN=F05/'bmc_flash05'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
def ident(p):return {'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'bytes':p.stat().st_size}
assert len(sys.argv)==3, 'Require final core and API digests'
core_pin,api_pin=sys.argv[1:]
assert sha(RUN/'flash_core.mjs')==core_pin and sha(RUN/'flash_api.mjs')==api_pin
manifest=read(RUN/'source_manifest.json')
assert manifest['core_sha256']==core_pin and manifest['api_sha256']==api_pin
assert manifest['contract_sha256']==sha(HERE/'contract-v2.json')
assert manifest['policy_sha256']==sha(RUN/'preflight-policy.json')
fixtures=read(HERE/'orchestration-safety-fixtures.json')
assert fixtures['core_sha256']==core_pin and fixtures['case_count']==12
assert all(c['pass'] for c in fixtures['cases']) and not fixtures['network_used']
assert fixtures['fixture_sha256']==sha(HERE/'verify_safety_edges.mjs')
report={
 'status':'PASS_FINAL_OFFLINE_ORCHESTRATION_REVIEW',
 'core':ident(RUN/'flash_core.mjs'),'api':ident(RUN/'flash_api.mjs'),
 'manifest':ident(RUN/'source_manifest.json'),'policy':ident(RUN/'preflight-policy.json'),
 'native_contract':ident(HERE/'contract-v2.json'),
 'review_script':ident(Path(__file__).resolve()),
 'independent_fixtures':ident(HERE/'orchestration-safety-fixtures.json'),
 'fixture_script':ident(HERE/'verify_safety_edges.mjs'),
 'native_IPC_failure_evidence':ident(HERE/'manager_ipc_late_failure_evidence.json'),
 'implementation_fixture_report_inspected_not_rerun':ident(F05/'flash_orchestration_review/local_validation.json'),
 'necessary_findings_resolved':[
  {'finding':'HTTP500/code1373 does not prove start failure before dispatch. Manager IPC can time out after sending a command.',
   'resolution':'Entry, Prepare, flash, verify_image and Exit non-exact successes remain UNKNOWN; flash/verify starts cannot repeat or unlock Exit based on the generic HTTP error. Unknown start remains unknown even if a component-only poll later returns100.'},
  {'finding':'A successful Entry response must not lose its uid if writing the response log fails.',
   'resolution':'onSuccess stores uid before phase/logging; actual valid uid0 remains distinguishable from null. Independent injected post-response log failure retains uid0 and ENTERED.'}
 ],
 'static_source_observations':[
  'Fixed e330 engineering CAP and payload2dd SHA/size checks, same checked private buffer for CAP upload and [4096:] payload upload; no path reread between stages.',
  'Normal cookie/CSRF administrator authentication; Redfish before login/after confirmed logout uses separate request context; no concurrent SPA/browser calls.',
  'Fixed API allowlist, HTTP methods and phase checks; redirect/retry disabled. State machine uses explicit commands and never automatically performs Exit, logout, power or another flash request.',
  'Prepare/flash echo validation, exact ten native ACE1904/A5336/HW0 metadata fields, actual receipt SHA and root review binding before flash. No ForceMode or SECTION_FLASH255.',
  'Write progress100 leads only to WRITE_COMPLETE; verifyimage start response is exactly COMPONENT_ID2; only separate readback progress100 reaches VERIFIED. Confirmed-start progress-1 is an explicit failure eligible for owned normal Exit.',
  'Recursive logging redaction covers password/token/cookie/Authorization/session IDs/unique_id/FWUPDATEID; raw credentials enter through non-echoing TTY and remain in memory. No actual credentials were accessed in this review.',
  'Source manifest binds API/core/policy/native-contract/CAP/archive identities; checked core bytes are imported directly from memory. Default --check-local exits before creating a network context.'
 ],
 'preflash_only_explicit_abort_scope':{
  'request_from_parent':'Preserve safe defaults, but do not turn an unmeasured Prepare failure into an impossible new recovery requirement.',
  'conditions':['Current Entry returned a known owned uid','No flash start request has been sent','No verify_image start request has been sent','Operator explicitly records the exceptional best-effort abort'],
  'interpretation':'Prepare has no inspected erase/program or flash-thread creation. An explicit normal Exit under these preflash-only conditions cannot start the unissued flash operation. It may restore normal driver/GPIO ownership even after an uncertain Prepare result.',
  'limit':'It is not atomic cancellation of a potentially still-finishing Prepare nor exact electrical rollback. Preserve prior state and Exit result, then independently observe host recovery. This is distinct from an unknown flash/verify worker and does not authorize Exit while such a worker may run.',
  'implementation_scope':'The final runner provides explicit abort_preflash requiring root confirmation, exact policy hash, an owned uid, no flash/verify request, and a preflash unknown operation. It sends the same normal Exit exactly once, retains original unknown history, and requires independent host-restoration observation. Generic automatic Exit remains blocked. Four additional independent checks cover this final interface.'
 },
 'verification':{'independent_cases':12,'actual_core_source_imported':True,'candidate_bytes_used':True,
  'HTTP_responses_and_evidence_failures':'synthetic in-memory callbacks','API_adapter_review':'static actual source; no network execution by reviewer',
  'full_prior_tests_repeated':False,'actual_credentials_read':False,'BMC_accessed':False,'hardware_write_performed':False},
 'limits':[
  'This is a local source and fault-state review, not evidence that live Prepare, flash, verify or restoration succeeded.',
  'Normal preflight offers no fresh JEDEC/capacity measurement or atomic exclusion. The policy states the available official specification/host FD/layout cross-check and requires real MTD identity.',
  'An unknown started operation remains a matter for explicit reconciliation; it is never silently normalized to success.',
  'No assurance of factory signed trust, preserved custom logo/native NVRAM, full current SPI backup, or independent physical recovery is added by this review.'
 ]
}
p=HERE/'orchestration-review.json';p.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
print(json.dumps({'review':ident(p),'core_sha256':core_pin,'api_sha256':api_pin,'independent_cases':12,'BMC_accessed':False}))
