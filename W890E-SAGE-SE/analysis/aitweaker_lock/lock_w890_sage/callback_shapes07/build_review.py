"""Derive exact callback candidates and runtime list premises; no authorization."""
from pathlib import Path
import json,hashlib,struct,sys,collections
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import pefile
sha=lambda b:hashlib.sha256(b).hexdigest()
def dump(name,x):(H/name).write_text(json.dumps(x,indent=2)+'\n')
original=(B/'navigation/modules/Setup.efi').read_bytes();pe=pefile.PE(data=original);im=pe.get_memory_mapped_image()
inputs=json.loads((H/'inputs.json').read_text());actual=json.loads((H/'actual_shapes.json').read_text())
conditional=json.loads((H/'conditional_refinements.json').read_text());dynamic=json.loads((H/'dynamic_shapes.json').read_text())
assert actual['source_sha256']==sha((H/'replay.py').read_bytes())
assert conditional['source_sha256']==actual['source_sha256']==dynamic['source_sha256']
assert actual['inputs_sha256']==sha((H/'inputs.json').read_bytes())
assert sha(original)==inputs['original_setup_sha256']
for p in inputs['inputs']:assert sha((R/p['path']).read_bytes())==p['sha256']
evidence=[];windows=[];negative_resolve=[]
extracts=H/'rea_extracts';extracts.mkdir(exist_ok=True)
for run in ('rea05','rea06','rea07'):
 for path in sorted((H/run).glob('response-*.json')):
  res=json.loads(path.read_text());assert not res.get('isError')
  s=res.get('structuredContent')
  if not s or not s.get('subject'):continue
  assert s['subject']['digest']['sha256']==sha(original)
  nr=s['normalized_result'];item={'path':path.relative_to(H).as_posix(),'response_sha256':sha(path.read_bytes()),
    'operation':s['operation'],'parameters':s['parameters'],'evidence_id':s['evidence_id'],
    'original_setup_sha256':sha(original),'provider':s['provider']}
  evidence.append(item)
  if s['operation']=='resolve_containing_procedure'and not nr['found']:negative_resolve.append(item)
  if isinstance(nr,dict)and 'pseudocode'in nr:
   (extracts/(run+'_'+s['parameters']['procedure']+'.txt')).write_text('REA '+s['evidence_id']+'\nSHA256 '+sha(original)+'\n'+nr['pseudocode'])
  if s['operation']=='read_bytes':
   data=bytes.fromhex(nr['bytes_hex']);rva=int(s['parameters']['address'],16)
   assert nr['complete']and pe.get_data(rva,len(data))==data
   windows.append({'rva':hex(rva),'bytes':len(data),'sha256':sha(data),'REA_equal_original_PE':True,'evidence_id':s['evidence_id']})
reused=[]
for old in json.loads((B/'navigation06_actions/rea_index.json').read_text())['dossiers']:
 if old['module']=='Setup.efi'or old['rva']in ('0x3e700','0x3f414','0x3f90c'):
  path=B/'navigation06_actions'/old['response'];assert sha(path.read_bytes())==old['response_sha256']
  res=json.loads(path.read_text());s=res['structuredContent']
  assert s['evidence_id']==old['evidence_id']
  reused.append({**old,'original_module_sha256':s['subject']['digest']['sha256'],
    'full_response_path':path.relative_to(R).as_posix()})
dump('rea_index.json',{'actual_new_queries':evidence,'original_byte_windows':windows,
 'negative_containment_queries':negative_resolve,'negative_remedy':'Exact original registration starts F7F0,1D250,1D724 were verified from original instruction/CC boundaries and seeded only as ephemeral REA analysis metadata in rea07. Prior unresolved results are preserved.',
 'reused_frozen_actual_REA_dossiers':reused})
registration=[]
for handler,registrar,table,count in [(0xf4b0,0xf7f0,0x2ff10,7),(0x1d44c,0x1d724,0x41180,4)]:
 ranges=[]
 for i in range(count):
  start,end=struct.unpack_from('<HH',im,table+i*0x28);assert start<=end<65535
  ranges.append({'table_rva':hex(table+i*0x28),'first_qid':start,'last_qid':end,'raw_hex':im[table+i*0x28:table+i*0x28+4].hex()})
 registration.append({'handler_rva':hex(handler),'registration_function_rva':hex(registrar),
  'registration_condition':'Legacy initialization second parameter==1; original CreateEvent/RegisterProtocolNotify occur first. This is not proof of callback invocation action==1.',
  'ranges':ranges,'qids':sorted({q for e in ranges for q in range(e['first_qid'],e['last_qid']+1)})})
qids=[struct.unpack_from('<H',im,0x40cfb+i*0x1d)[0]for i in range(38)]
registration.append({'handler_rva':'0x1cf9c','registration_function_rva':'0x1d250',
 'registration_condition':'Legacy initialization second parameter==1 and original LocateProtocol for GUID at2C0F0 returns0. Original variable read and string updates are outside this local execution scope.',
 'table_rva':'0x40cf0','entry_bytes':0x1d,'qid_offset':0xb,'entries':38,'qids':qids})
associations=collections.defaultdict(list)
for e in registration:
 for q in e['qids']:associations[q].append(e['handler_rva'])
dump('dynamic_registration.json',{'original_setup_sha256':sha(original),'registration_groups':registration,
 'unique_potential_dynamic_qids':len(associations),'overlapping_qids':{hex(q):f for q,f in associations.items()if len(f)>1},
 'actual_runtime_registration_order_and_success_unknown':True,'runtime_authorized':False})
byshape={}
for c in actual['cases']:
 if 'action'in c:byshape[(c['qid'],c['action'],c['type'])]=dict(c)
for key,group in __import__('itertools').groupby(sorted(conditional['cases'],key=lambda c:(c['qid'],c['action'],c['type'])),lambda c:(c['qid'],c['action'],c['type'])):
 c=next(group);byshape[key]={**c,'classification':'CONDITIONAL_ONLY','premise':conditional['conditions'][f'{c["qid"]:04X}']}
rows=[]
for q in inputs['qid_inputs']:
 shapes=[byshape[(q['qid'],a,t)]for a in (3,4)for t in q['action%d_types'%a]]if not q['excluded_password_management']else[]
 rows.append({**q,'native_shape_results':[{k:c[k]for k in ('action','type','status','result','reason','read_rva','classification','premise','dispatcher_context_preserved')if k in c}for c in shapes],
  'potential_original_dynamic_handlers':associations.get(q['qid'],[]),
  'all_observed_types_only_bookkeeping_under_list_and_state_premises':bool(shapes)and all(c['status']=='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING'for c in shapes),
  'runtime_authorized':False})
dump('qid_action_type_candidates.json',{'scope':'Exact original Setup callback QIDs; no live execution permission. Apply all common and per-QID premises.',
 'rows':rows,'runtime_authorized':False})
runtime={
 'module':{'original_pe_sha256':sha(original),'loaded_image_size':pe.OPTIONAL_HEADER.SizeOfImage,
   'setup_callback_rva':'0x2250','static_dispatch_table_rva':'0x2c600','static_table_bytes':0x3740,
   'static_table_sha256':sha(im[0x2c600:0x2fd40])},
 'globals':{'legacy_flag':{'rva':'0x48180','bytes':1,'entry_premise':0},
   'callback_context':{'rva':'0x48190','bytes':8,'entry_premise':0},
   'setup_hii_handle':{'rva':'0x2fd60','bytes':8,'entry_premise':'equals separately bound current Setup HII handle'},
   'dynamic_list_head':{'rva':'0x55180','bytes':16,'Flink_offset':0,'Blink_offset':8},
   '2C1E_cached_protocol':{'rva':'0x48248','bytes':8,'per_qid_premise':'nonzero, for Action3/4 only; no pointer dereference on the verified path'},
   '272B_cached_flag':{'rva':'0x482e0','bytes':8,'per_qid_premise':'zero/nonzero both checked; 3/4 never take action1 helper branch'},
   '2765_literal_read':{'rva':'0x471b0','bytes':114,'sha256':sha(im[0x471b0:0x47222]),'per_qid_premise':'bounded module-local original literal copy only'}},
 'dynamic_list':{
   'node_bytes':32,'Flink_offset':0,'Blink_offset':8,'QID_offset':16,'QID_bytes':2,'Handler_offset':24,'Handler_bytes':8,
   'termination':'original2250 compares each current node pointer with &Setup[55180]; it does not test NULL or enforce a bound',
   'dispatch':'only matching QID invokes CALL2345; return!=EFI_UNSUPPORTED stops the list, otherwise loads nextFlink',
   'empty_diagnostic':'Read only the16 bytes inside verified Setup image. Both links must equal loadedBase+55180. Two stable observations are diagnostic, not proof against later mutation.',
   'nonempty_diagnostic':'Head scalars alone cannot identify handlers. Do not follow arbitrary pool pointers without independent readable allocation bounds. Refuse malformed/cyclic/changed/unowned lists; do not mask with zeros.',
   'candidate_match':'Only a separately bound matching node targeting original Setup+F4B0/+1CF9C/+1D44C has the reviewed3/4 path. Unknown or foreign matching targets remain denied.',
   'lifecycle':'Any later registration may change the list. Snapshot-only evidence cannot authorize a later dispatch; the list/context/code/IFR identity must remain bound through the actual call.'},
 'limits':['No hardware collector or pointer walking implemented here.',
   'Node registration timing/order and actual physical list are unobserved.',
   'Empty model and known-node model are alternative explicit premises, not a default assumption that original hardware list is empty.',
   'No complete3E700/3E424 value extraction/action-request consumer proof; no whole FormOpen/Close or boot claim.'],
 'runtime_authorized':False}
dump('runtime_premises.json',runtime)
review={'status':'EXACT_SHAPE_AND_THREE_DYNAMIC_HANDLER_EVIDENCE_NO_RUNTIME_AUTHORIZATION',
 'original_setup_sha256':sha(original),'callback_qids':len(rows),
 'qids_all_actual_types_bookkeeping_under_explicit_premises':sum(r['all_observed_types_only_bookkeeping_under_list_and_state_premises']for r in rows),
 'qids_remaining':[{ 'qid':r['qid'],'handlers':r['handlers'],'excluded_password_management':r['excluded_password_management'],
   'statuses':r['native_shape_results']}for r in rows if not r['all_observed_types_only_bookkeeping_under_list_and_state_premises']],
 'base_shape_tests':actual['summary'],'conditional_native_cases':len(conditional['cases']),
 'conditional_negative_cases':len(conditional['negative_zero_cache']),
 'dynamic_direct_all_type_byte_cases':len(dynamic['direct_cases']),
 'actual_2250_known_dynamic_node_cases':len(dynamic['actual2250_integration_cases']),
 'dynamic_unknown_target_negative_cases':2,'other_action_negative_cases':len(dynamic['outside_action3_4_negative_cases']),
 'new_actual_REA_queries':len(evidence),'reused_actual_REA_dossiers':len(reused),'exact_original_byte_windows':windows,
 'dynamic_registration_qids':len(associations),'hardware_actions':0,'firmware_changes':0,
 'limitations':['All live list/node, identity, entry/lifecycle and per-QID predicates remain required. These results are not an execution allowlist.',
 'Known password-management callbacks were excluded from new native execution; unknown helper/service calls were never replaced by successful stubs.',
 'Full AMITSE callback effects, current boot parser state, exits, firmware integration and deployment remain separate work.'],
 'runtime_authorized':False}
dump('review.json',review)
print(json.dumps({k:v for k,v in review.items()if k not in ['qids_remaining','exact_original_byte_windows','limitations']}))
print('remaining',[(hex(r['qid']),r['excluded_password_management'])for r in review['qids_remaining']])
print('registered groups',[(e['handler_rva'],len(e['qids']))for e in registration])
