"""Bind a read-only credential recovery gap audit. No recovery tool is built."""
from pathlib import Path
import hashlib,json,sys,datetime
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
TX=D04/'ram_transaction08';P14=D04/'provider14_chrome07'
checked=[]
for path in [TX/'ram_candidate_manifest.json',P14/'local_candidate_manifest.json']:
    m=json.loads(path.read_text());rows=m['artifacts']
    for row in rows:assert sha(D04/row['path'])==row['sha256'],row
    checked.append({'path':str(path.relative_to(ROOT)),'sha256':sha(path),'items_verified':len(rows)})
actual=json.loads((HERE/'actual_app_recovery_gap.json').read_text())
controller=json.loads((HERE/'controller_lifetime_result.json').read_text())
assert actual['cases']==11 and controller['cases']==6
assert sha(TX/'app_build/SageNative13RamTest08.efi')=='e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'
def source(p,needle):
    text=p.read_text();assert needle in text
    return {'path':str(p.relative_to(ROOT)),'sha256':sha(p),'line':text[:text.index(needle)].count('\n')+1,'anchor':needle}
ui=TX/'source/session_ui.c';app=TX/'source/app.c';svc=P14/'source/services.c';core=P14/'source/password_core.c'
fixture=HW/'operations/kvm_password_fixture11.mjs';browser=HW/'bmc_browser.mjs'
facts=[
 {'id':'RECOVERY-01','severity':'blocks_future_physical_password_writes_until_recovery_exists',
  'finding':'The test owns no credential bytes until native SendForm returns and the post-return owned-chain/TPL checks succeed. Persistence may already have completed inside that call.',
  'sequence':['P14 persist_record writes the fixed private128B record with attributes3 and validates exact readback.',
              'The native SendForm call can still be outstanding after that storage transaction.',
              'TX08 observe_private_after copies the record only after SendForm return, quiescent_state and application_tpl.',
              'A non-returning browser cannot reach the application R menu. A hold after return also prevents observation/services.',
              'BMC ForceOff discards application RAM; it is not a private-variable deletion transaction.'],
  'anchors':[source(svc,'ES s=persist_variable(credential_name,&credential_guid,3,n,(void *)record);'),
             source(ui,'ES status=initial_send(initial_browser,&hii,1,formset,form_id,0,&request);boundary();'),
             source(ui,'if(!quiescent_state(s,0))app_hold(0x55350001u);'),source(ui,'int observed=observe_private_after();'),
             source(ui,'if(ok){memcpy(private_owned,now,sizeof(now));private_state=PRIVATE_OWNED;}')],
  'evidence_limit':'Conditional counterexample using actual frozen application code and explicitly modeled external persistence/non-return. No real password enrollment or hardware cause is asserted.'},
 {'id':'RECOVERY-02','severity':'blocks_fresh_boot_cleanup_with_current_app',
  'finding':'Fresh app state does not adopt an existing valid enabled or disabled record. The size-only initial query requires NOT_FOUND; capture_ready remains false and both native management and cleanup are refused.',
  'anchors':[source(ui,'/* A size-only query never reads or adopts a pre-existing credential. */'),
             source(ui,'if(status!=ERR(14)){unknown_private("initial private credential must be absent; existing or unknown preserved");return 0;}'),
             source(ui,'boundary();if(!capture_ready||!quiescent_state(s,1)||!application_tpl())return 0;'),
             source(app,"if(ch=='2'&&inventory_ok&&credential_ready&&!ui_active&&!(used_modes&2))")],
  'additional_case':'Even normal successful observation followed by power loss before R loses the only private_owned copy.'},
 {'id':'RECOVERY-03','severity':'existing_route_has_strict_preconditions',
  'finding':'Existing R is the simplest legitimate current cleanup route only while the original app remains alive, control has returned, ownership is quiescent, the last observed valid128B record exactly matches current bytes/attributes, and the one deletion attempt has not been consumed.',
  'anchors':[source(ui,'int exact=private_state==PRIVATE_OWNED&&status==0&&n==sizeof(now)&&attributes==3&&'),
             source(ui,'boundary();ES deleted=initial_set(credential_name,&credential_guid,0,0,0);boundary();'),
             source(app,'int restored=ui_restore_credential(s);app_result("temporary private credential restored",restored);')],
  'limit':'This route does not survive a host reboot or controller-induced ForceOff; app R cannot be invoked safely from an arbitrary outstanding native call.'},
 {'id':'RECOVERY-04','severity':'clear_is_not_absence_restoration',
  'finding':'Provider Clear authenticates then commits a DISABLED128B record with a new generation. It never deletes this variable, so it does not restore the test baseline of absence; a fresh TX08 still refuses it.',
  'anchors':[source(core,'header(next,gen,0);ap_sha256(next,96,next+96);'),
             source(core,'if(c->env.persist(c->env.opaque,next,128)!=0)return AP_STORAGE_FAILED;'),
             source(P14/'source/password_core.h','* until explicit enrollment. Clear writes DISABLED; it never deletes storage.')],
  'limit':'The disabled record has no password verifier. A future recovery design cannot authenticate it with the last password and must not silently accept every structurally valid disabled record.'},
 {'id':'RECOVERY-05','severity':'controller_process_lifetime_is_not_durable_recovery',
  'finding':'The fixture is held in globalThis in the Node controller realm. Login/reopened viewer in the same live process does not recreate that realm or clear the slot. A new process has no fixture; there is no import/export route. Explicit clear wipes its buffers but not firmware storage.',
  'anchors':[source(fixture,"const slot='aiTweakerPasswordFixture11';"),
             source(fixture,'globalThis[slot]={values,typed:0};'),source(fixture,"if(args.action==='clear'){clear();"),
             source(browser,"if(c.action==='login'){"),source(browser,'const result=await op.default({page,viewer,context,api,base,here,capture,emit},c.args||{});'),
             source(browser,'}finally{await context.close();await browser.close();input.close();process.stdin.setRawMode(false);}')],
  'limits':['Reauthentication survival is contingent on the same controller process; restarting it, process death, logout/exit or explicit clear loses this application-level recovery channel.',
            'Process exit is not proof of cryptographic erasure from operating-system RAM, pagefile or crash dumps.',
            'Fixture clear/log out must not be mistaken for the later, separately verified firmware cleanup.']},
 {'id':'RECOVERY-06','severity':'no_alternate_supported_route_established',
  'finding':'No audited existing original-boot tool accepts or deletes an orphan private record. The frozen public provider ABI has begin/end/query/request/manage only; it exposes neither a record receipt nor a recovery deletion method.',
  'anchors':[source(P14/'source/provider.h','struct GATE_PROVIDER {'),source(P14/'source/provider.h','_Static_assert(sizeof(GATE_PROVIDER)==56,"Frozen provider ABI v1");')],
  'excluded_assumptions':['Original ASUS administrator-password screens do not constitute evidence of support for this project-specific variable.',
                          'Do not count CMOS/default reset, firmware flashing, generic variable deletion, or undocumented BMC operations as a scoped recovery procedure.',
                          'The persisted attributes are exactly3 and omit the runtime-access bit4; no audited OS runtime variable tool is provided here. No OS recovery access is claimed.']}
]
design={
 'status':'DESIGN_ONLY_NOT_IMPLEMENTED_OR_EXECUTED',
 'authorization_scope':'A future explicitly bounded test may create and then remove its own temporary fixed credential. This design does not authorize generic variable deletion, firmware flashing or ownership of an unrelated record.',
 'durable_fixture_before_any_write':[
  'Before even typing the first enrollment secret, persist the generated initial and changed fixture in a Windows current-user DPAPI-encrypted local task journal. Plaintext exists only in memory/required masked keystrokes, never logs, reports, command-line arguments or files.',
  'Use an explicit nonsecret journal version/test-session identifier, exact machine/board/BIOS identity, fixed name/GUID, expected attributes3/record length128, absent-baseline evidence hashes, frozen app/provider identities and operation-stage intent.',
  'Write an atomic complete encrypted record, flush and close it, then start a fresh isolated local process and decrypt/validate the same fixture before permitting enrollment. A roundtrip only in the creating process is insufficient.',
  'Pin the encrypted journal to the Windows user profile and tested DPAPI mechanism; record safe open/decrypt status only. Same-user access is the trust boundary. Do not claim recovery if the Windows profile, journal or decryption key is lost.',
  'Retain all possibly committed enrollment/change secrets until a fresh boot has independently confirmed variable absence. Never overwrite the old value on an ambiguous UI/storage outcome; stage transitions are recorded before typing/submitting.',
  'Preserve the distinction between initial, changed and deliberately wrong test input. Wrong input is never a cleanup authorization candidate. Do not log plaintext, salt/verifier, or an unkeyed password-derived hash usable for guesses.',
  'Reauthentication reuses the current fixture if the process survives; process-death recovery imports only from the verified encrypted journal in a new process. Session teardown alone must not destroy the durable journal.'
 ],
 'minimal_independent_original_boot_recovery_app':[
  'A separate, reviewed boot application runs from the unmodified original BIOS without native hooks/provider/SendForm dependencies. It checks the exact authorized machine/firmware and fixed credential name/GUID, uses a masked console prompt, and has no generic name/address/variable setter.',
  'It bounds the GetVariable operation to the expected128B record with attributes3, validates the existing schema/magic/version/checksum, nonzero generation, enabled state, bounded PBKDF algorithm/iterations, and expected enrollment/change stage. Unknown/malformed/mismatched records remain untouched.',
  'Verify the known recoverable fixture against that record by the actual reviewed PBKDF2-SHA256 core with constant-time verifier comparison. Do not treat format checksum alone, a matching GUID, or presence after a previous absent baseline as proof of ownership.',
  'Immediately before its one allowed fixed deletion, reread the full record and attributes and require an exact in-memory match to the authenticated bytes. Perform only SetVariable(fixed_name,fixed_GUID,0,0,NULL); independently read back NOT_FOUND. Log status and absence only, then retain safe residency/exit semantics until separately reviewed.',
  'A deletion error, ambiguous transport/status, readback failure, changed record, wrong secret, EBS/TPL boundary or identity failure must stop without broad deletion/retry. Exact reread is a cooperative check, not atomic compare-and-swap against malicious parallel firmware writers.',
  'Do not use the old credential for an ambiguous successful password change. Retained initial/changed candidates and staged intent must be handled explicitly and with bounded attempts; never assume which write committed from a success-looking screen.',
  'If current storage is already NOT_FOUND, report confirmed absence without writing. This is distinct from authenticating or deleting a record.'
 ],
 'disabled_or_partial_record_boundary':[
  'Keep the first future physical enrollment/change test free of the provider Clear action until the additional disabled-record receipt design is reviewed.',
  'If Clear is later tested, commit a durable authenticated receipt for the exact expected disabled record (derived from a known owned predecessor/generation and the fixed clear format) before the transition; no password verification exists in the disabled record itself.',
  'Malformed/partial/unknown records must be preserved, even if this prevents automated cleanup. Do not promise unconditional recovery from arbitrary firmware corruption or power loss during the firmware variable transaction.'
 ],
 'required_tests_before_physical_password_input':[
  'Actual DPAPI write/flush/new-process decrypt; missing, corrupt, wrong-user, interrupted journal and stage ambiguity cases; no plaintext or password-derived digest in artifacts/args/logs.',
  'Actual recovery EFI fixed-name setter allowlist plus absent, valid enabled correct/wrong fixture, changed password, wrong identity, wrong attributes/size/schema/checksum, excessive iterations/generation, changed-between-auth-and-delete and all error/readback branches.',
  'Persistence/SendForm-nonreturn/power-loss replay with the same final provider and frozen recovery binary; original browser need not return for recovery to remain usable.',
  'OVMF fresh-process storage recovery with exact code, runtime/TPL/EBS lifetime checks, cleanup output/QR if used, exact packaging and independent source/byte review.',
  'Before any real enrollment, boot the exact recovery application read-only on the authorized board with the absent baseline and verify its identity/input path; then new explicit staged hardware review permits only the bounded test.'
 ]}
report={
 'status':'OPEN_RECOVERY_GAP_PHYSICAL_PASSWORD_WRITES_NOT_YET_ACCEPTED',
 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'scope':{'read_only_source_and_offline_models':True,'BMC_or_device_calls':0,'firmware_writes':0,'production_or_frozen_source_mutations':0,'new_recovery_tool_implemented':False,'TX09_diagnostics_only_no_password_fixture':True},
 'current_artifacts':checked,
 'findings':facts,'minimum_future_design':design,
 'tests':{'actual_app':{'path':'actual_app_recovery_gap.json','sha256':sha(HERE/'actual_app_recovery_gap.json'),'cases':11},
          'actual_fixture_operation':{'path':'controller_lifetime_result.json','sha256':sha(HERE/'controller_lifetime_result.json'),'cases':6}},
 'physical_evidence_limit':'C11 used no password fixture/input and its fresh boot observed the private variable absent. These conditional recovery cases do not imply a credential was actually created or lost in C11.',
 'decision':'Continue TX09 diagnostics without enrollment or a password fixture. Do not type a physical test password until the durable fixture and independent recovery path are implemented, verified and admitted.',
 'bindings':[]}
paths=[HERE/'replay_recovery_gap.py',HERE/'replay_controller_lifetime.mjs',HERE/'write_review.py',
       TX/'app_build/SageNative13RamTest08.efi',TX/'app_build/app.map',ui,app,svc,core,
       P14/'source/password_core.h',P14/'source/password_crypto.c',P14/'source/provider.h',P14/'source/ui.c',
       fixture,browser,HW/'operations/power_off_ram_test11.mjs',
       D04/'ram_transaction09/integration_plan.json',
       HERE/'actual_app_recovery_gap.json',HERE/'controller_lifetime_result.json']
report['bindings']=[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in paths]
(HERE/'recovery_review.json').write_text(json.dumps(report,indent=2)+'\n')
manifest={'status':'FROZEN_LOCAL_READ_ONLY_RECOVERY_REVIEW','report_sha256':sha(HERE/'recovery_review.json'),
          'artifacts':[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in paths+[HERE/'recovery_review.json']]}
(HERE/'review_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'status':report['status'],'bindings':len(paths),'review_sha256':sha(HERE/'recovery_review.json'),'manifest_sha256':sha(HERE/'review_manifest.json')}))
