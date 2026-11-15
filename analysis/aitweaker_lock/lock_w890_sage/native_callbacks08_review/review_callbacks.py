"""Independent provenance/count audit and selected original-instruction replay.

No hardware or installed callback is invoked. No frozen producer main() runs.
The replay's explicit fixtures and post-lookup conditional boundary remain.
"""
from pathlib import Path
import sys, json, hashlib, collections, copy, time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;R=B.parents[2];N=B/'native_callbacks08'
sys.path[:0]=[str(R/'tools/pydeps'),str(N)]
import consumer as c
import outer as o
import pefile

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):return {'path':p.relative_to(R).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}
def load(p):return json.loads(p.read_text())
def validate():
    mf=N/'manifest.json';assert sha(mf)=='f2cc89f5d9aad2211087eac49e0aa2cea31850705b9ad35d0a28b8f33592ab16'
    m=load(mf)
    for key,base in [('files',N),('external_read_only_inputs',R)]:
        for x in m[key]:
            p=base/x['path'];assert p.stat().st_size==x['bytes'] and sha(p)==x['sha256'],str(p)
    prior=B/'callback_shapes07/manifest.json';p=load(prior)
    for key,base in [('files',prior.parent),('external_read_only_inputs',R)]:
        for x in p[key]:
            q=base/x['path'];assert q.stat().st_size==x['bytes'] and sha(q)==x['sha256'],str(q)
    return {'manifest':bind(mf),'local':len(m['files']),'external':len(m['external_read_only_inputs']),
            'parent_local':len(p['files']),'parent_external':len(p['external_read_only_inputs'])}

def summarize(r):
    keys=['qid','action','type','status','pc','return_status','setup_calls','callback_returns',
          'modeled_object_writes','final_guard_state','final_context','synthetic_callback_output']
    return {k:r[k] for k in keys if k in r}

def main():
    initial=validate();cr=load(N/'consumer_results.json');out=load(N/'outer_results.json');review=load(N/'review.json')
    assert cr['source_sha256']==out['consumer_sha256']==sha(N/'consumer.py')
    assert cr['base_replay_sha256']==sha(B/'callback_shapes07/replay.py')
    assert out['source_sha256']==sha(N/'outer.py') and out['inputs_sha256']==sha(B/'callback_shapes07/inputs.json')
    assert out['snapshot_sha256']==sha(B/'integration05/parser-snapshot.zip')
    assert cr['original_AMITSE_sha256']==sha(B/'navigation/modules/AMITSE.efi')
    assert cr['original_Setup_sha256']==sha(B/'navigation/modules/Setup.efi')
    shapes=cr['post_lookup_connected_cases'];prefix=out['prefix_cases'];conditional=out['conditional_cases']
    assert len(shapes)==len(prefix)==2396
    assert collections.Counter(x['return_status'] for x in shapes)=={'0x0':1385,'0x8000000000000003':1011}
    for x in shapes:
        assert not x['runtime_authorized'] and x['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE'
        assert len(x['setup_calls'])==len(x['callback_returns'])==1
        assert x['callback_returns'][0]['request']==0 and not x['modeled_object_writes']
        assert x['qid'] not in (0x271e,0x271f,0x2bf8,0x2c03)
    assert collections.Counter(x['pc'] for x in prefix)=={'0x3e47b':1231,'0x59b6a':1164,'0x3eb7a':1}
    for x in prefix:assert x['status']=='UNKNOWN_NOT_AUTHORIZED' and not x['runtime_authorized'] and not x['setup_calls']
    assert len(conditional)==1231 and collections.Counter(x['action'] for x in conditional)=={3:1187,4:44}
    for x in conditional:
        assert x['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE' and not x['runtime_authorized']
        assert not x['supplied_post_lookup_binding']['physical_identity_verified']
        assert x['supplied_post_lookup_binding']['unexecuted_lookup_calls']==['AMITSE3E47B','AMITSE3E49D']
        assert x['callback_returns'][0]['request']==0 and not x['modeled_object_writes']
        assert x['final_context']=={'depth':0,'hii':'0x0','var_id':0}
    # Independently compare genuine REA byte-read payloads with original PE.
    idx=load(N/'rea_index.json');pe=pefile.PE(str(B/'navigation/modules/AMITSE.efi'));windows=[]
    for item in idx['new_actual_queries']:
        p=N/item['path'];assert sha(p)==item['sha256']
        s=load(p)['structuredContent'];assert s['evidence_id']==item['evidence_id']
        assert s['subject']['digest']['sha256']==cr['original_AMITSE_sha256']
        if s['operation']=='read_bytes':
            raw=bytes.fromhex(s['normalized_result']['bytes_hex']);rva=int(s['parameters']['address'],16)
            assert s['normalized_result']['complete'] and pe.get_data(rva,len(raw))==raw
            windows.append({'rva':hex(rva),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    assert len(idx['new_actual_queries'])==23 and len(windows)==4
    assert len(idx['corrected_contract_errors'])==2 and len(idx['reused_frozen_dossiers'])==3
    # Selected actual Setup2250/AMITSE consumer, preserving native statuses.
    selected=[];v=c.VM()
    for expected in ('0x0','0x8000000000000003'):
        row=next(x for x in shapes if x['return_status']==expected)
        v.reset(row['qid'],row['action'],row['type']);r=v.execute(0x3e4af,'INDEPENDENT_CONDITIONAL_POST_LOOKUP')
        assert summarize(r)==summarize(row)
        selected.append({'case':'real original callback return '+expected,'result':summarize(r)})
    # Entire48 synthetic return/request matrix, not calls to unknown callbacks.
    synthetic=[]
    for row in cr['post_callback_synthetic_outcomes']:
        state=row['synthetic_callback_output'];v.reset(row['qid'],row['action'],row['type'])
        r=v.execute(0x3e4f0,'INDEPENDENT_EXPLICIT_SYNTHETIC_OUTPUT',state['ActionRequest'],int(state['status'],16))
        assert summarize(r)==summarize(row)
        if int(state['status'],16)>>63:
            assert r['return_status']==state['status'] and '0x42b78' not in r['native_visits']
        synthetic.append(summarize(r))
    hazards=[]
    for row in cr['request0_cleanup_hazards']:
        label=row['case'];g={0xaff22:(1,1),0xaff40:(8,c.PAD)} if label=='pending_old_cache' else {0xaff68:(8,0)} if label=='missing_refresh_catalog' else {}
        v.reset(row['qid'],row['action'],row['type'],globals_override=g)
        if label=='raw_hii_ffff_sentinel':v.u.mem_write(c.PB+0x40,c.Q(0xffff))
        r=v.execute(0x3e4f0,'INDEPENDENT_ZERO_REQUEST_CLEANUP',0,0)
        assert summarize(r)==summarize(row);hazards.append({'case':label,'result':summarize(r)})
    # Full original entry stops before an unresolved service. Conditional tests
    # explicitly resume past lookups; no unknown service is supplied success.
    ov=o.Outer();selections=[]
    selections.append(next(x for x in conditional if x['action']==3))
    for revision in ('0x2001d','0x20070'):
        selections.append(next(x for x in conditional if x['action']==4 and x['opcode']==15 and x['revision']==revision))
    for pc in ('0x59b6a','0x3eb7a'):selections.append(next(x for x in prefix if x['pc']==pc))
    for row in selections:
        q=next(x for x in o.inputs['questions'] if x['qid']==row['qid'] and x['form']==row['form'])
        ov.prepare(q,row['action'],int(row['revision'],16))
        r=copy.deepcopy(ov.execute(0x3e700,'INDEPENDENT_COMPLETE_ENTRY_FIRST_STOP'))
        assert r['status']=='UNKNOWN_NOT_AUTHORIZED' and not r['setup_calls']
        item={'case':'native3E700 original descriptor','prefix':summarize(r),'revision':row['revision'],'opcode':row['opcode']}
        if row in conditional:
            assert r['pc']=='0x3e47b'
            rr=ov.conditional_continuation('INDEPENDENT_CONDITIONAL_CONTINUATION')
            assert summarize(rr)==summarize(row)
            item['conditional']=summarize(rr)
        else:assert r['pc']==row['pc']
        selected.append(item)
    assert validate()==initial
    result={'status':'INDEPENDENT_SCOPED_REVIEW_REPLAY_MATCHES_NOT_RUNTIME_AUTHORITY','review_script':bind(Path(__file__)),
      'verified_input_bindings':initial,'mechanical_counts':{'post_lookup':2396,'full_entry_unknown':2396,'conditional':1231,'synthetic':48},
      'REA_windows':windows,'selected_original_replays':selected,'synthetic_return_request_matrix':synthetic,'zero_request_hazards':hazards,
      'runtime_authorized':False,'hardware_actions':0,'frozen_inputs_modified':False,
      'boundary':'Untouched factory lifecycle is preserved execution, not a new permit list. Conditional fixtures are not successful original lookups, actual owners or full GUI proof.'}
    (H/'replay_review.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'selected':len(selected),'synthetic':len(synthetic),'hazards':len(hazards),'bindings':initial}))

if __name__=='__main__':main()
