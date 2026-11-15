"""Record the bounded integration contract and precise comparison evidence."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;CASE=D04.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline=CASE/'remote_172_20_2_162/hardware-native13-browser-baseline06-1793713512938-ce806332/hardware-log.txt'
assert baseline.stat().st_size==4911
r={
 'status':'LOCAL_INTEGRATION_DESIGN_NOT_DEPLOYMENT_OR_RELEASE_ACCEPTANCE',
 'new_directories':['provider14_chrome07','ram_transaction08'],
 'preserved':['provider13','ram_transaction05','static_chrome_candidate07','N12/P12 and earlier frozen probes'],
 'comparison_evidence':{'baseline_log':str(baseline),'bytes':4911,'sha256':sha(baseline),'meaning':'Original ASUS SendForm, exact 991-byte HII package, no guard/provider: visible form and single ESC return; return status0/action0 and recorded original bytes/stores/private absence unchanged. Not a guard/password acceptance or proof of no other OEM writes.'},
 'guard':{'directory':'static_chrome_candidate07','template_sha256':sha(D04/'static_chrome_candidate07/build/guard_template.bin'),'manifest_sha256':sha(D04/'static_chrome_candidate07/candidate_manifest.json'),'changes':'Only the reviewed tri-state native static SUBTITLE chrome classifier. All12 gates, protected stores, session ownership and credential semantics remain unchanged.'},
 'abi':{'provider_guid':'87e3c6fa-11fb-4e77-af2d-ea50b640fa13','provider_bytes':56,'frame_bytes':48,'context_bytes':96,'immutable_binding_bytes':160,'state_page_bytes':4096,'state_used_bytes':32,'changed':False},
 'rebinding':[
  'P14 retains P13 implementation and public ABI. Regenerate full template bytes, module identity segments, exact12 patches, prologue trampolines and actual Begin/End return offsets from frozen07.',
  'P14 pins complete original AMITSE/Setup text with relocation normalization and exact expected installed detours. No generic unknown template or caller exception.',
  'TX08 embeds only exact P14 EFI. Regenerate loaded header/section/BSS identities, DIR64 relocations, provider object/method RVAs and exact transaction plan from P14/07.',
  'Keep independent native HII package byte-identical to991B package. Public GUID stability is not interchangeable candidate identity: preflight refuses existing provider and new/old templates are not cross-accepted.'
 ],
 'ui_changes':[
  'Initialize ActionRequest to EFI_BROWSER_ACTION_REQUEST_NONE (0). Original SendForm may leave this OUT value unchanged on ordinary ESC.',
  'Record original native globals before and after SendForm using fresh bounded MemoryMap/CPU-pagewalk checks; never infer stage7 or a nonzero app pointer means idle.',
  'Check ended state and application TPL before reads/services. Post-SendForm first require empty owned UI/save heads and valid state, then TPL4, then diagnostics/credential/store checks.',
  'No resetflag, application exitflag, RuntimeServices table or original browser state writes. Keep synchronous original SendForm and its native ESC return.'
 ],
 'exit_limitation':{'automatic_unwind_implemented':False,'known_issue':'Unknown page with no verified safe Main remains denied and may suppress native input/poll, preventing ESC. Native exitflag-forcing has unproven reset/save consequences. No permission relaxation is added.','initial_physical_stage_if_reviewed':'First M display -> native ESC -> Q with no password input. Review this return before any password actions or B original Setup test.','blackout_recovery':'BMC power off by root, followed by separate original-identity/private-absence observation. No firmware service from high-TPL HOLD/ended state.'},
 'retained_lifetimes':'One mode1 and one mode2 attempt maximum. All published objects, code/state/context and app remain resident until power off; no unload/free after publication.',
 'credentials':'Initial private variable must be absent; only independently owned exact last observed valid128B record may be deleted at cleanup. Never log record/password or their hashes. OC/MEM remain read-only snapshots.',
 'required_local_evidence':['P14 actual owner/guard binding and rejection of mismatched template/caller/context; unchanged crypto/UI source proof.','Exact TX08 core, platform/rollback/EBS/partial-start and new globals-read failure cases.','Exact UI ActionRequest NONE / unchanged-on-return and TPL/EBS diagnostics boundary tests.','Actual OVMF loaded P14/P14-validator and final app unsupported-platform refusal. GUI models must stay distinct from ASUS execution.'],
 'deferred':'No ISO packaging or hardware action by this agent; root reviews exact app/source/manifests and operates hardware. No signed flashable image or permanent integration claim.'
}
(HERE/'integration_design.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'design_sha256':sha(HERE/'integration_design.json'),'baseline_sha256':sha(baseline)}))
