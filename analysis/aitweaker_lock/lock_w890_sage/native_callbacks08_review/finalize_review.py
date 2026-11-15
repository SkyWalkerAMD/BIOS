"""Freeze independent review; do not edit native_callbacks08."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;B=H.parent;R=B.parents[2];N=B/'native_callbacks08'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def load(p):return json.loads(p.read_text())
j=load(H/'replay_review.json');mf=N/'manifest.json';m=load(mf)
assert sha(mf)=='f2cc89f5d9aad2211087eac49e0aa2cea31850705b9ad35d0a28b8f33592ab16'
for key,base in [('files',N),('external_read_only_inputs',R)]:
 for x in m[key]:
  p=base/x['path'];assert sha(p)==x['sha256'] and p.stat().st_size==x['bytes']
assert j['review_script']==bind(H/'review_callbacks.py')
assert len(j['selected_original_replays'])==7 and len(j['synthetic_return_request_matrix'])==48 and len(j['zero_request_hazards'])==3
review={
 'status':'INDEPENDENT_REVIEW_ACCEPTS_STATED_EVIDENCE_BOUNDARIES_NOT_DEPLOYMENT',
 'reviewed_manifest':bind(mf),'bindings':j['verified_input_bindings'],
 'selected_original_instruction_replay':bind(H/'replay_review.json'),
 'actionable_findings':[],
 'scope_assessment':[
  'Preserving untouched original Action3/4 dispatch under its original caller, context, arguments, ordering and consumer is not a new authorization of unknown callbacks.',
  'This architectural recommendation is not an executable permission table. The candidate QID/Action/Type list and its bookkeeping-only fixture results must not be used to route a new foreign, synthetic or caller-forged callback.',
  'UNKNOWN_NOT_AUTHORIZED in these outputs means an offline emulator stopped before an unmodeled boundary; it is not a recommendation to block unchanged stock firmware execution.',
  'A protected UI selection/entry must still be authenticated before it is committed or displayed, including initial landing and alternate UI entry paths. Specifically evidenced unauthenticated OC-changing shortcuts still need precise gates.',
  'The evidence makes no global OC variable ACL claim, does not validate new navigation integration, and does not grant authority merely because a page callback existed before the lock.'
 ],
 'path_separation_assessment':{
  'post_lookup_cases':2396,'post_lookup_success':1385,'post_lookup_original_unsupported':1011,
  'full_original3E700_entries':2396,
  'first_unknown_call_sites':{'0x3E47B':1231,'0x59B6A':1164,'0x3EB7A':1},
  'conditional_saved_frame_returns':1231,
  'conditional_actions':{'3':1187,'4':44},
  'correct_interpretation':'All full entries stop before an unresolved call. The1231 conditional cases explicitly supply exact Setup ConfigAccess after two unexecuted lookups. They establish the later original slice under those inputs, not lookup success, physical interface identity or end-to-end GUI success.',
  'selected_actual_replay':'Original2250 success/Unsupported; full3E700 open3 and REF close4 at two revisions; allocation and CopyMem stop boundaries independently reproduced.'
 },
 'status_and_ActionRequest':[
  'The2396 real2250 post-lookup cases retain Request0 and original native outcomes. Unsupported was not converted to success by a model or wrapper.',
  'All48 synthetic status/request cases were independently rerun as explicit callback-output fixtures; unknown callbacks were not executed.',
  'Negative EFI status exits with that original error before42B78 and request handling. Nonnegative status goes through original42B78, which can itself return Unsupported before request handling.',
  'Original consumer normalization of warnings/status and bookkeeping is preserved as actual original execution. This is distinct from a new lock rewriting callback status.',
  'Request0 is not proof of no activity: original42B78 can process old cache, clear raw HII FFFF sentinels or return Unsupported. All three retained counterexamples reproduce.',
  'Nonzero requests are kept intact. Save/reset/discard/confirm boundaries stop before unmodeled invocation; reconnect, question-apply and otherwise unrecognized nonzero requests retain original refresh/global behavior.',
  'A future lock must pass the callback result and ActionRequest to the original consumer unchanged, not clear them or return success to avoid original behavior.'
 ],
 'ownership_lifecycle_assessment':[
  'The saved native frame in conditional continuation is real emulated caller state, but the ConfigAccess/HII objects and outer caches are explicit models.',
  'The36C00 original code has a ten-entry context bound; a full-depth push can be skipped before a later pop. This supports avoiding extra synthetic/reentrant calls, not declaring a demonstrated hardware defect.',
  'AFF10/AFF18 cleanup, original protocol uninstall, history freeing and exit ordering must remain intact. Intercepting after destructive teardown remains unsuitable for preserving the GUI.',
  'Current physical dynamic-handler topology, cache lifetime, foreign ownership and complete firmware/UI behavior are not established by the listed fixtures.'
 ],
 'REA_assessment':{
  'new_valid_queries':23,'reused_frozen_dossiers':3,'original_byte_windows_independently_compared':4,
  'preserved_contract_errors':2,'export_and_close_records_present':True,
  'original_sources_unmodified':True,
  'interpretation':'Seeded function addresses are disclosed analysis inputs, not automatic discoveries. Read-window bytes agree with exact original AMITSE. No new REA run was invented during this independent review.'},
 'integration_acceptance_conditions':[
  'Do not add an Action3/4 allow-list/router from this evidence.',
  'Do not reenter native callbacks or alter original caller/parameter/return/request semantics to check the lock.',
  'Prove protected entry denial/cancellation before the new page is selected/displayed, retaining the prior native page/state.',
  'Verify normal and error exits after removal of blanket pending/form/tail blockers in the separate integration.',
  'Keep foreign HII publication invalidation separate from credential/native-loop epoch, while invalidating any stale bound effect/management/lease as required by its actual data dependency.'
 ],
 'not_proved':['Complete GUI/startup and all entry paths','Physical callback owner/list lifetime','All variable or hardware service effects','Password operation or firmware integration','FlashBack acceptance or deployability'],
 'no_hardware_operations':True,'no_frozen_inputs_modified':True,'runtime_authorized':False
}
(H/'review.json').write_text(json.dumps(review,indent=2)+'\n')
(H/'README.txt').write_text('''Independent review of native_callbacks08 f2cc89f5…ab16.

92 local /23 external bindings and105+49 parent bindings match. The reported2396 post-lookup shapes,2396 full-entry stops and1231 conditional continuations are accurately separated. Four genuine REA byte windows match original AMITSE. Independent actual-instruction replay covers7 selected original paths, all48 synthetic status/request cases and3 zero-request cleanup counterexamples.

No actionable discrepancy was found in the stated evidence boundaries. This accepts neither deployment nor a callback allow-list. Leaving untouched original Action3/4 execution intact is preservation of the original firmware lifecycle; it does not authorize a new caller, new route, forged arguments or a general unknown handler. The locked UI entry still needs proof before selection/display, plus exact gates for established OC shortcuts.

Unknown emulator stops must not be confused with runtime permission decisions. Conditional continuations explicitly bypass two unexecuted lookups by supplying a model interface and cannot be reported as end-to-end success. Native status and ActionRequest consumption must remain original, including errors, cleanup and nonzero requests. Zero request is not side-effect-free.

See review.json and replay_review.json. No BMC, password operation, firmware patch, CAP generation or frozen input modification occurred.
''',encoding='utf-8')
extra=[mf,B/'callback_shapes07/manifest.json',B/'navigation/modules/AMITSE.efi',B/'navigation/modules/Setup.efi']
out={'status':'FROZEN_INDEPENDENT_EVIDENCE_REVIEW_NOT_RUNTIME_AUTHORITY',
     'local_bindings':[bind(p)for p in sorted(H.iterdir())if p.is_file()and p.name!='component_manifest.json'],
     'external_bindings':[bind(p)for p in extra]}
(H/'component_manifest.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'review':bind(H/'review.json'),'manifest':bind(H/'component_manifest.json')}))
