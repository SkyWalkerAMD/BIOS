"""Original3E700 descriptor paths, with unresolved services never substituted.

Full entry stops before unknown services. A separate explicitly conditional
continuation resumes at3E4AF with the saved native caller frame and the exact
original Setup ConfigAccess slot supplied as a model input. It proves neither
protocol lookup success nor physical live handle identity. No unknown call runs.
"""
from pathlib import Path
import json,struct,hashlib,zipfile,collections,time,copy
import consumer as c
from unicorn.x86_const import *
H=c.H;B=c.B;TSE=c.TSE;AUX=c.AUX;Q=c.Q;D=c.D
DESC=AUX+0x4000;IFR=AUX+0x4100;VARTAB=AUX+0x5000
with zipfile.ZipFile(B/'integration05/parser-snapshot.zip') as z:
 sn=json.loads(z.read('state.json'));im=z.read('tse-mapped.bin');pool=z.read('pool.bin')
 vartab=struct.unpack_from('<Q',im,0xbaaf8)[0];varn=sn['live_allocations'][str(vartab)]
 varbytes=pool[vartab-sn['pool_base']:vartab-sn['pool_base']+varn]
assert len(varbytes)==varn==15976 and struct.unpack_from('<I',varbytes)[0]==121
inputs=json.loads((B/'callback_shapes07/inputs.json').read_text())
candidates={x['qid']:x for x in json.loads((B/'callback_shapes07/qid_action_type_candidates.json').read_text())['rows'] if x['all_observed_types_only_bookkeeping_under_list_and_state_premises']}

class Outer(c.VM):
 def prepare(self,q,action,revision=0x20070,globals_override=None):
  self.reset(q['qid'],action,9,globals_override=globals_override)
  assert not q['excluded_password_management'] and len(q['bounded_native_descriptor_bindings'])==1
  binding=q['bounded_native_descriptor_bindings'][0];desc=bytearray.fromhex(binding['descriptor_hex']);ifr=bytes.fromhex(q['ifr_hex'])
  assert len(desc)==64 and struct.unpack_from('<I',desc,12)[0]==q['qid'] and ifr[0]==q['opcode']
  # Retain all native fields. Only relocate two pointer/handle model inputs.
  before=bytes(desc);desc[:8]=Q(0x555100);desc[0x28:0x30]=Q(IFR)
  assert desc[8:0x28]==before[8:0x28] and desc[0x30:]==before[0x30:]
  self.u.mem_write(DESC,bytes(desc));self.u.mem_write(IFR,ifr);self.u.mem_write(VARTAB,varbytes)
  self.gstate[0xbaaf8]=(8,VARTAB);self.u.mem_write(TSE+0xbaaf8,Q(VARTAB))
  self.aux_objects += [(DESC,64),(IFR,len(ifr)),(VARTAB,varn)]
  self.u.mem_write(c.ST+8,D(revision))
  for reg,v in [(UC_X86_REG_RCX,DESC),(UC_X86_REG_RDX,q['qid']),(UC_X86_REG_R8,0),(UC_X86_REG_R9,action)]:self.u.reg_write(reg,v)
  self.current.update(descriptor_sha256=hashlib.sha256(before).hexdigest(),ifr_sha256=hashlib.sha256(ifr).hexdigest(),
    form=q['form'],opcode=q['opcode'],native_kind=binding['native_kind'],revision=hex(revision),
    descriptor_model_changes=['HII handle = explicit model0x555100','IFR pointer relocated to exact original IFR bytes'],
    expected_callback_type=(9 if action==3 else 9 if q['opcode']==15 and revision<0x2001e else 12 if q['opcode']==15 else q['action4_candidate_types'][0]))
 def context(self):
  return {'depth':int.from_bytes(self.u.mem_read(TSE+0xafea0,4),'little'),
          'hii':hex(self.rq(TSE+0xafe98)), 'var_id':int.from_bytes(self.u.mem_read(TSE+0xafeb0,4),'little')}
 def conditional_continuation(self,phase):
  assert self.u.reg_read(UC_X86_REG_RIP)==TSE+0x3e47b
  bp=self.u.reg_read(UC_X86_REG_RBP)
  assert self.rq(bp-0x30)==0
  # This boundary fixture replaces neither call nor machine instruction.
  # It explicitly supplies the outcome needed to analyze the later slice.
  self.u.mem_write(bp-0x20,Q(c.setup.BASE+0x2fd40))
  self.current={k:v for k,v in self.current.items() if k not in ('status','reason','pc','instruction','module')}
  self.current['supplied_post_lookup_binding']={'ConfigAccess':hex(c.setup.BASE+0x2fd40),'Callback':hex(c.setup.BASE+0x2250),
       'unexecuted_lookup_calls':['AMITSE3E47B','AMITSE3E49D'],'physical_identity_verified':False}
  r=self.execute(0x3e4af,phase,preserve_frame=True);r['final_context']=self.context()
  return copy.deepcopy(r)

def main():
 started=time.time();v=Outer();prefix=[];conditional=[]
 for q in inputs['questions']:
  if q['qid'] not in candidates:continue
  for action in (3,4):
   revisions=(0x2001d,0x20070) if action==4 and q['opcode']==15 else(0x20070,)
   for revision in revisions:
    v.prepare(q,action,revision);r=copy.deepcopy(v.execute(0x3e700,'COMPLETE_3E700_ENTRY_FIRST_UNKNOWN_SERVICE'))
    r['boundary_context']=v.context();prefix.append(r)
    assert r['status']=='UNKNOWN_NOT_AUTHORIZED',r
    if r.get('pc')=='0x3e47b':
     s=v.conditional_continuation('CONDITIONAL_POST_LOOKUP_SAVED_3E700_CALLER_AND_REAL_SETUP2250')
     assert s['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE' and len(s['setup_calls'])==1,s
     assert s['setup_calls'][0]['type']==s['expected_callback_type'] and s['setup_calls'][0]['action']==action
     assert s['callback_returns'][0]['request']==0 and s['final_context']=={'depth':0,'hii':'0x0','var_id':0}
     assert not s['modeled_object_writes'] and all(x==0 for x in s['final_guard_state'].values())
     conditional.append(s)
 hazards=[];q=next(x for x in inputs['questions'] if x['qid']in candidates and x['opcode']==28)
 for label,overrides in [('preexisting_AFF10',{0xaff10:(8,c.PAD)}),('preexisting_AFF18',{0xaff18:(8,c.PAD)}),
   ('full_context_stack',{0xafea0:(4,10),0xafe98:(8,0x777100),0xafeb0:(4,17)}),
   ('nonzero_callback_guard',{0xafff8:(1,1)}),('depth9_context_stack',{0xafea0:(4,9),0xafe98:(8,0x777100),0xafeb0:(4,17)})]:
  v.prepare(q,3,globals_override=overrides)
  # Explicit consistent saved context for the depth9/full fixtures.
  for i in range(10):v.u.mem_write(TSE+0xb8c90+i*8,Q(0x777100));v.u.mem_write(TSE+0xb8ce0+i*4,D(17))
  before=v.context();r=v.execute(0x3e700,'CONTEXT_OR_CLEANUP_NEGATIVE_PREFIX')
  assert r.get('pc')=='0x3e47b',r
  s=v.conditional_continuation('CONTEXT_OR_CLEANUP_CONDITIONAL_RETURN');s.update(case=label,initial_context=before);hazards.append(s)
 assert hazards[0]['status']=='UNKNOWN_NOT_AUTHORIZED' and hazards[1]['status']=='UNKNOWN_NOT_AUTHORIZED'
 assert hazards[2]['initial_context']['depth']==10 and hazards[2]['final_context']['depth']==9
 assert hazards[3]['final_guard_state']['0xafff8']==1
 assert hazards[4]['initial_context']==hazards[4]['final_context']
 summary={'full_entries':len(prefix),'full_entry_first_boundaries':dict(collections.Counter(r.get('pc',r['reason'])for r in prefix)),
          'conditional_original_returns':len(conditional),'conditional_by_action':dict(collections.Counter(r['action']for r in conditional)),
          'hazards':[{'case':r['case'],'status':r['status'],'pc':r.get('pc'),'initial_context':r['initial_context'],'final_context':r['final_context']}for r in hazards]}
 result={'status':'BOUNDED_NATIVE_PREFIX_AND_CONDITIONAL_RETURN_ONLY',
 'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'consumer_sha256':hashlib.sha256((H/'consumer.py').read_bytes()).hexdigest(),
 'inputs_sha256':hashlib.sha256((B/'callback_shapes07/inputs.json').read_bytes()).hexdigest(),
 'snapshot_sha256':hashlib.sha256((B/'integration05/parser-snapshot.zip').read_bytes()).hexdigest(),
 'snapshot_var_table_sha256':hashlib.sha256(varbytes).hexdigest(),
 'prefix_cases':prefix,'conditional_cases':conditional,'state_hazards':hazards,'summary':summary,
 'model_inputs':['Original parser snapshot supplies only bounded variable-table bytes and exact descriptors. Snapshot is an offline modeled parser run, not a live hardware table.',
  'The HII handle, protocol objects, global caches, page table, system-table Revision and ConfigAccess binding are explicit in-process fixtures.',
  'No allocator, CopyMem, HII lookup, HandleProtocol, variable service, string service or cleanup helper is replaced with success. Unknown calls stop before invocation.',
  'Conditional return cases resume after two unexecuted protocol calls and cannot authorize end-to-end runtime dispatch.'],
 'runtime_authorized':False,'hardware_actions':0,'firmware_changes':0,'seconds':round(time.time()-started,3)}
 (H/'outer_results.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
