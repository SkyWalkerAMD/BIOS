"""Bind actual REA observations and original native segments; no permission list."""
from pathlib import Path
import json,hashlib,sys,collections
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def out(name,obj):(H/name).write_text(json.dumps(obj,indent=2)+'\n')
original=B/'navigation/modules/AMITSE.efi';original_sha=sha(original)
assert original_sha=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
pe=pefile.PE(str(original))
prior=B/'callback_shapes07/manifest.json'
assert sha(prior)=='7732770d07cf03ace48d251af29b5215f0b040442a93a2b775f63789daf9b94d'
pm=json.loads(prior.read_text())
for x in pm['files']:assert sha(prior.parent/x['path'])==x['sha256'],x['path']
for x in pm['external_read_only_inputs']:assert sha(R/x['path'])==x['sha256'],x['path']
consumer=json.loads((H/'consumer_results.json').read_text());outer=json.loads((H/'outer_results.json').read_text())
assert consumer['source_sha256']==outer['consumer_sha256']==sha(H/'consumer.py')
assert outer['source_sha256']==sha(H/'outer.py')
assert consumer['base_replay_sha256']==sha(B/'callback_shapes07/replay.py')
assert consumer['original_AMITSE_sha256']==original_sha
assert outer['inputs_sha256']==sha(B/'callback_shapes07/inputs.json')
assert outer['snapshot_sha256']==sha(B/'integration05/parser-snapshot.zip')
new=[];errors=[];windows=[];reused=[];extracts=H/'rea_extracts';extracts.mkdir(exist_ok=True)
for p in sorted((H/'rea05').glob('response-*.json')):
 j=json.loads(p.read_text());cmd=json.loads(p.with_name(p.name.replace('response-','command-')).read_text())
 if j.get('isError'):
  errors.append({'path':p.relative_to(H).as_posix(),'sha256':sha(p),'command':cmd,
    'reason':'Initial analyze_function queries018/019 used address rather than procedure. Schema was inspected; corrected024/025 completed. No target or transport change.'});continue
 s=j.get('structuredContent')
 if not s or not s.get('subject'):continue
 assert s['subject']['digest']['sha256']==original_sha
 nr=s['normalized_result'];item={'path':p.relative_to(H).as_posix(),'sha256':sha(p),'operation':s['operation'],
  'parameters':s['parameters'],'evidence_id':s['evidence_id'],'provider':s['provider'],'original_sha256':original_sha}
 new.append(item)
 if isinstance(nr,dict) and 'pseudocode'in nr:
  (extracts/(s['parameters']['procedure']+'.txt')).write_text('REA '+s['evidence_id']+'\nSHA256 '+original_sha+'\n'+nr['pseudocode'].replace('\r',''))
 if s['operation']=='read_bytes':
  data=bytes.fromhex(nr['bytes_hex']);rva=int(s['parameters']['address'],16)
  assert nr['complete'] and pe.get_data(rva,len(data))==data
  windows.append({'rva':hex(rva),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'REA_equals_original':True,'evidence_id':s['evidence_id']})
for old in json.loads((B/'navigation06_actions/rea_index.json').read_text())['dossiers']:
 if old['module']=='AMITSE.efi' and old['rva']in('0x3e700','0x3e424','0x3f90c'):
  p=B/'navigation06_actions'/old['response'];assert sha(p)==old['response_sha256']
  s=json.loads(p.read_text())['structuredContent'];assert s['evidence_id']==old['evidence_id'] and s['subject']['digest']['sha256']==original_sha
  reused.append({**old,'full_path':p.relative_to(R).as_posix()})
assert len(windows)==4 and len(reused)==3 and len(errors)==2
assert (H/'rea05/final-close.json').exists() and not json.loads((H/'rea05/final-close.json').read_text()).get('isError')
assert (H/'rea05/evidence-export.json').exists() and not json.loads((H/'rea05/evidence-export.json').read_text()).get('isError')
out('rea_index.json',{'new_actual_queries':new,'corrected_contract_errors':errors,'original_byte_windows':windows,
 'reused_frozen_dossiers':reused,'analysis_seeds':'Sixteen exact original function-entry seeds are ephemeral analysis metadata/caller assertions, not automatic discoveries or byte patches.',
 'session_closed':True,'original_source_unmodified':True})

native_premises={
 'purpose':'Conditions of the isolated proof, not conditions that must be globally imposed on the stock firmware lifecycle.',
 'exact_code_and_descriptors':'OriginalAMITSE/Setup identities, exact native descriptor and original IFR; live HII and ConfigAccess identity must not be forged or generalized.',
 'lookup_boundary':'Full3E424 stops at3E47B. Conditional continuation explicitly supplies Setup2FD40 after two unexecuted original lookups3E47B/3E49D; no service-success stub.',
 'Setup_state':'Apply callback_shapes07/runtime_premises.json for the exact shape. No nested context48190 or legacy48180; list topology and code/handler identity have separate runtime premises.',
 'AMITSE_callback_guards':{'AFFf8':'Boolean saved/restored; test values0/1. Original3E4F0 normalizes a previously nonzero flag after callback.',
  'AFD88':'Original entry sets1 and exit clears0; not a nested arbitrary-state-preserving wrapper.',
  'AFEB8':'Original entry stores Action and exit zeroes it; cannot promise restoration of an outer Action.',
  'AFF09_AFF0A':'Original3E700 zeros these before dispatch; nonzero ActionRequest can re-set them.'},
 'context_stack':{'push_pop':'36C00, countAFEA0;10 entriesHiiB8C90/VarIdB8CE0; currentAFE98/AFEB0',
  'bounded_proof':'Depth0 and consistentdepth9 restore. Atdepth10 push is skipped, then pop decrements to9. Do not add recursive/synthetic calls or assert same-state restoration forfullstack.'},
 'zero_request_cleanup':{'42B78':'Called for nonnegative callback status before readingActionRequest. Can releaseAFF40 pendingcache whenAFF22!=0, clear current raw-page HIIFFFF sentinels, or returnUnsupported whenBABC0/AFF68 missing.',
  'slice_fixture':'AFF22=AFF40=0; explicit bounded three-page list, noFFFF; validBABC0/AFF68. Real runtime pages/caches were not sampled here.',
  '3E700_tail':'AFF10/AFF18 empty for no cleanup calls; otherwise originalFreePool/FBE4 invoked. Native variable/string reading and allocation are original lifecycle behavior, not shown side-effect-free.'},
 'unknown_policy':'Unknown functions/services are never executed or replaced with success in these proofs. This evidence gap alone is not grounds to block untouched original lifecycle calls.',
 'protected_management_qids':'271E/271F excluded and never executed;2BF8/2C03 do not enter the candidate set.',
 'not_claimed':['Full originalGUI proof','Current physical handler list','All real variable service results','ProtectedOC values cannot change through any firmware/OS path','Flashability','A native code defect from a model-only boundary']}
out('native_state_premises.json',native_premises)

lifecycle={
 'status':'MINIMUM_INTERVENTION_ARCHITECTURAL_RECOMMENDATION_NOT_IMPLEMENTED',
 'requested_scope':'Independent password for access to the AiTweaker UI in a BIOS session. This is not a newly specified whole-machine OC variable ACL.',
 'can_original_Action3_4_remain_before_authentication':'Yes, as an unchanged original lifecycle dispatch under its original caller/context/Action/QID/Type and native return/ActionRequest handling. This is preservation of existing firmware execution, not admission of a new unknown handler or a claim all callbacks are harmless.',
 'minimum_new_gates':[
  'Gate the positively bound selection/entry of a protectedAiTweaker page before the new selection is committed or displayed, including initial landing page and provenalternateUIentrypaths.',
  'Gate a separately evidenced OC-changing shortcut or business operation that bypasses the protectedpage, with its exact originalQID/action/handler/data binding. Do not infer everyglobalSave/Default/Exit is itself a newUIentry.',
  'On authentication denial/cancellation, retain the pre-transition native page/state and balanced ownership; do not synthesize FormClose/FormOpen or recursively call the firmware callbacks.'],
 'preserve_original_lifecycle':[
  'Leave original initialization, page notifications, legitimate FormClose, cache cleanup, protocoluninstall, history freeing and exit under original native ordering.',
  'Let original callbacks return their exact native status andActionRequest to the original consumer. Never replace unknown withsuccess or clear a nonzeroRequest to avoid a side effect.',
  'Do not use callback flag, a candidateQID table, failure to emulate an allocator, or an unobserved unchanged dynamiclist as a blanket reason to stop allSetup or delay cleanup afterteardown.'],
 'what_new_lock_must_not_add':[
  'New arbitrary/foreign callback routing or caller-forged Action/QID/Type.',
  'Extra nativecontext push/pop on denied transitions, nestedSetup callbackcontexts, or reentryinto3E700 at a fullcontextstack.',
  'Skipped originalpost-callback cleanup, rewritten callbackreturn/status, or exit intercepted after irreversible nativeUIteardown.'],
 'residual_scope':[
  'Unchanged original callbacks may allocate, read variables, update caches, or request normal firmware operations. These existing effects have not all been proved harmless and are not newly authorized by thelock.',
  'A specific observed unauthenticated OC write reachable through a neworunprotectedUIentry requires a precise additionalgate; this report found no such write in the conditionalAction3/4 candidatepaths, but does not rule one out globally.',
  'External firmware/OS variable writes and nativeglobaldefaults/save behavior are outside aUIaccess-onlyclaim unless separately specified and bound.',
  'Navigation08 must verify normal and error exits after narrowing interventions; this report does not validate that integration.'],
 'implementation_changes':0,'runtime_authorized':False}
out('lifecycle_boundary.json',lifecycle)

outcomes=[]
labels={0:'NONE',1:'RESET',2:'SUBMIT',3:'EXIT',4:'FORM_SUBMIT_EXIT',5:'FORM_DISCARD_EXIT',6:'FORM_APPLY',7:'FORM_DISCARD',8:'RECONNECT',9:'QUESTION_APPLY'}
for r in consumer['post_callback_synthetic_outcomes']:
 if r['synthetic_callback_output']['status']!='0x0':continue
 n=r['synthetic_callback_output']['ActionRequest']
 outcomes.append({'request':n,'spec_name':labels.get(n,'UNRECOGNIZED_NONZERO'),
  'status':r['status'],'stop_pc':r.get('pc'),'return_status':r.get('return_status'),'native_global_writes':r['native_global_writes']})
review={'status':'ORIGINAL_LIFECYCLE_BOUNDARIES_VERIFIED_OFFLINE_NO_WHOLE_GUI_OR_FLASHABILITY_CLAIM',
 'original_AMITSE_sha256':original_sha,'original_Setup_sha256':consumer['original_Setup_sha256'],
 'new_actual_REA_queries':len(new),'reused_frozen_REA_dossiers':len(reused),'read_windows':windows,
 'post_lookup_exact_shapes':len(consumer['post_lookup_connected_cases']),
 'post_lookup_zero_ActionRequest':all(r['callback_returns'][0]['request']==0 for r in consumer['post_lookup_connected_cases']),
 'post_lookup_original_return_statuses':dict(collections.Counter(r['return_status']for r in consumer['post_lookup_connected_cases'])),
 'explicit_known_dynamic_nodes':len(consumer['explicit_known_dynamic_node_cases']),
 'synthetic_status_request_cases':len(consumer['post_callback_synthetic_outcomes']),
 'request0_cleanup_hazards':len(consumer['request0_cleanup_hazards']),
 'request_refresh_cases':len(consumer['refresh_state_synthetic_cases']),
 'original3E700_summary':outer['summary'],'ActionRequest_routes':outcomes,
 'spec_source':'https://uefi.org/specs/UEFI/2.11/35_HII_Configuration_Processing_and_Browser_Protocol.html',
 'spec_note':'ActionRequest0..9 labels follow UEFI2.11. Default actions are separate Action0x1000+ values; original1F32C is discard/restore workingdata, not automatically LoadDefaults.',
 'preserved_callback_shapes07_bindings':{'local':len(pm['files']),'external':len(pm['external_read_only_inputs'])},
 'minimum_boundary_recommendation':'Preserve untouched native lifecycle; gate boundprotectedUIselection/entry and separately provenOCbypasses. See lifecycle_boundary.json.',
 'remaining_proof_limits':native_premises['not_claimed'],
 'hardware_actions':0,'firmware_changes':0,'password_operations':0,'runtime_authorized':False}
out('review.json',review)
print(json.dumps({k:v for k,v in review.items()if k in('status','new_actual_REA_queries','reused_frozen_REA_dossiers','post_lookup_exact_shapes','post_lookup_original_return_statuses','synthetic_status_request_cases')}))
