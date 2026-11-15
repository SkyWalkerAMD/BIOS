"""Read-only causal analysis and proposed diagnostics, not an installer."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;CASE=D04.parents[3]
HW=CASE/'remote_172_20_2_162';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
evidence=[HW/f'screen-{n}-current.png'for n in [376,377,378]]
evidence += [HW/'native-test11-key-1793715715877-68d82412-intent.json',HW/'native-test11-key-1793715715877-68d82412-result.json',HW/'hardware-native13-ram-test08-1793715646283-8c2b8643/hardware-log.txt']
local=[D04/'static_chrome_candidate07/source/gate.c',D04/'provider14_chrome07/source/hii.c',D04/'provider14_chrome07/source/ui.c',D04/'provider14_chrome07/source/provider.c',D04/'provider14_chrome07/source/owner.c',HERE/'repeat_request_counterexample.json']
for name in ['kind4_observation.json','kind4_vtable.json']:
 p=D04/'management_request_review09'/name
 if p.exists():local.append(p)
r={
 'status':'DIAGNOSTIC_DESIGN_ONLY_NO_NEW_EXECUTABLE_OR_POLICY_CHANGE',
 'frozen_candidate':{'app':'e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486','provider':'495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630','guard':'2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'},
 'physical_observation':{'screen376':'Provider-style independent-password unconfigured message visible; original three-action management form not observed.','after_single_ESC':'Screens377/378 show the same message; no post-M Q snapshot. This alone proves neither key consumption, repetition, hold, CPU exception nor native page cause.','not_claimed':['No actual failed frame/page/control was captured.','No inference of zero OEM variable writes from no password input.','Mode1/attach passes are not native GUI acceptance.']},
 'known_request_sources':[
  {'hook':'gate_poll','condition':'Native stage5, readable app, current page classified protected or unknown, not already granted; allow(1).'},
  {'hook':'gate_app_input','condition':'Current page first passes non-prompt gate; nonzero page index plus decoded F5 scan0x0F requests authorization.'},
  {'hook':'gate_defaults','condition':'event0xFFFF001D outside the exact existing external no-UI exception requests authorization.'},
  {'hook':'gate_navigation','condition':'Destination formset is original Setup and formID is protected.'},
  {'hook':'gate_callback','condition':'Original Setup protected question ID and action0/1; FFE0/FFE1 action0 instead opens management title.'},
  {'hook':'P14 independent HII callback','condition':'FFE2/action0 directly requests verification. Lifecycle3/2/4 are UNSUPPORTED and do not request a password.'}
 ],
 'request_loop_counterexample':{'report':'repeat_request_counterexample.json','checks':12,'meaning':'With an explicitly synthetic invalid form index, exact P14 prompt reads modeled ESC, returns denied, then the next actual gate_poll calls request again. Both messages match, two ESC reads and zero modeled SetVariable calls. This is a possible explanation only.','initial_fixture_failures':['Initial script used missing fixture symbol LOCATE; corrected to actual LOC.','Full native SHA repeated verification hit the fixture200M instruction ceiling. Exact-byte hashlib acceleration was then declared; no fixed accepted digest, provider/UI/gate instructions remain unchanged.','Inherited page5 label foreign was not an owner assertion. Final fixture explicitly installs known-foreign HII and executes gate_owner==0; original invalid-form result was reached before ownership and is unchanged.']},
 'new_native_lead':{'scope':'Independent lab original-byte construction evidence, not a physical control dump.','kind':4,'control_type':'0x0E','vtable_rva':'0x6D6F0','IFR_rva':'0x6C360','source_slot':'AMITSE+0x93970','reason_to_instrument':'Not among verified subtitle kinds1/2/3/5; generic owner requires ConfigAccess and AMITSE string package may lack it.','why_no_allow_patch':'Original Input4ECFC/selection4ECB8 can call control+8 and write selected pageID via control+18. This is an actionable menu class, not inert subtitle chrome.'},
 'proposed_diagnostic_storage':{
  'allocation':'Use only otherwise-unused bytes of the already-owned4096B state allocation. Preserve public32B state prefix and all existing provider/frame/context/binding ABI. Reserve diagnostic region beginning offset0x40, bounded below4096.',
  'schema_status':'Proposed, not a frozen executable ABI. A new guard/provider/app generation and exact rebinding are required before any run.',
  'record_scope':'One bounded latest request record plus first-denial record and saturating counters; no unbounded history. Proposed per-record ceiling256B; region ceiling1024B.',
  'writer':'Guard stores only validated scalar metadata and already-computed classification outcomes, plus a short origin/reason enum. No firmware call, allocation, console, timer, variable access or original native-field write is added by logging.',
  'atomicity':'Local per-classification scratch data avoids nested-classifier overwrite. Publish a complete record with version/size and even sequence last; readers check identical even sequence before/after copy. Never spin. Saturation or malformed state marks diagnostics unavailable, never grants access.',
  'lifetime':'Diagnostic memory shares existing owned-state lifetime and is retained through rollback until power off. No token, password, salt, verifier, private variable, OC/MEM payload or their hashes are stored.'
 },
 'minimum_record_fields':[
  'Record schema/version/size, request sequence, completed-acknowledgment count, diagnostic validity/overflow flags.',
  'Exact guard hook enum; allowed origin class and bounded return offset relative to pinned guard/provider/original module, or UNKNOWN. No arbitrary call-stack scan.',
  'Native stage if already readable, current app page index/count; page/form indices and resolved formID with per-field valid bits.',
  'Page HII opaque value/category and gate_owner ternary result; already-observed GetDriver/HandleProtocol/list failure stage/status and canonical Setup count.',
  'First failing frame index, frame kind/count, vtable classification/RVA; native_chrome tri-state plus strict failure reason.',
  'First failing control index, class/vtable RVA, descriptor type if fixed mapped field already validated, HII category and owner tri-state.',
  'IFR opcode/length/store/question metadata only if existing classification actually validated/read them. Unobserved fields stay invalid; diagnostics must not dereference new arbitrary heap pointers just to fill a report.',
  'Redirect attempt/outcome and last denial class when reached; not invented before the synchronous request returns.'
 ],
 'reason_groups':{
  'page_form':['unreadable page/globals','table pointer/length','index outside table','record offset bound','unreadable record'],
  'owner':['missing HII','database/get-driver failure','ConfigAccess unavailable or malformed','matched Setup identity/CRC failure','foreign enumeration failure/duplicate canonical/missing target'],
  'frame':['unreadable frame','bad count/array','unreadable control','generic control owner unknown'],
  'native_chrome':['claim/kind mismatch','frame/control writeability','vtable/method identity','descriptor callback/metadata/expression','IFR exact-location/header','native method CRC/detour identity','source-HII association'],
  'protected':['protected Setup form','protected store/offset question','protected navigation/defaults action'],
  'unobserved':'No synthetic success value for a field not safely read.'
 },
 'export_without_native_return':{
  'where':'A new diagnostic provider, only while the existing UNCONFIGURED request UI is already rendering at verified application TPL, copies the record from its pinned owned-state binding.',
  'presentation':'At most six fixed ASCII lines under the current message: request/ack sequence, hook, page/form/owner, frame/control class, reason/subreason, record CRC. Each line <=72 columns; no extra keyboard command or mode switch is introduced.',
  'reason':'A blocked original browser may never return to app Q. The existing KVM screenshot must suffice to read a small record. If it does return, app Q additionally exports the same bounded record through its existing immutable snapshot/CRC transport.',
  'return_semantics':'Acknowledge remains the existing provider behavior. No native app+5A/resetflag mutation, no forced browser exit, no emergency protocol/UI callback or ResetSystem. A repeated sequence after a key can distinguish repeated requests from a still-pending first request.',
  'ending':'No snapshot service/rendering after EBS/terminal hold. Pure bounded copy only while bound-state valid; print calls retain before/after ended checks.'
 },
 'future_validation_required':[
  'Differential exact-byte tests show all existing policy/classification/credential results unchanged with diagnostics enabled, disabled, full, malformed and unreadable.',
  'Each reason code is driven by an actual original constructor or explicit negative fixture; menus with callbacks remain denied until separately proven safe.',
  'Write tracing confines diagnostic writes to the reserved owned-state region; no native object, variable, RT table, unowned page or existing state-prefix change.',
  'Nested classification/protocol reentry, no-safe-page repeat, sequence overflow/torn records, retired/ended state and per-print EBS boundary cases.',
  'New exact template/provider/loaded-range/detour/callsite hashes and complete transaction rollback regressions; no test transfer across hashes.',
  'Actual OVMF prompt text and standard ESC verify reason/sequence rendering; OEM body remains explicit fixture. Independent review precedes root physical use.'
 ],
 'deliverable_boundary':'This directory contains analysis, a local counterexample and this proposal only. There is no diagnostic EFI, ISO, new installer or release. Frozen TX08/P14/07 remain unchanged.',
 'evidence':[{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}for p in evidence+local]
}
(HERE/'diagnostic_plan.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'plan_sha256':sha(HERE/'diagnostic_plan.json'),'counterexample_sha256':sha(HERE/'repeat_request_counterexample.json'),'evidence_files':len(r['evidence'])}))
