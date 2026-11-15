"""Original3E424 consumer with strict unresolved-call boundaries.

Full entry stops at unresolved HII/BootServices protocol lookup. A separately
labeled post-lookup frame fixture starts at original3E4AF, invokes real original
Setup2250, then executes original42B78 and the consumer. This does not substitute
success for either lookup, nor authorize the complete chain. Post-callback
fixtures explicitly supply synthetic status/ActionRequest values, never call an
unknown callback, and stop before save/reset/discard helpers execute.
"""
from pathlib import Path
import json,sys,struct,hashlib,collections,time
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(B/'callback_shapes07'));sys.path.insert(0,str(R/'tools/pydeps'))
import replay as setup
import pefile,capstone
from unicorn.x86_const import *
from unicorn import UcError
TSE=0x1000000;AUX=0xa000000;DB=AUX+0x100;BS=AUX+0x200;ST=AUX+0x400
APP=AUX+0x800;PT=AUX+0x1000;PB=AUX+0x2000;PAD=AUX+0x3000;VT=AUX+0x3100
Q=setup.Q;D=lambda v:struct.pack('<I',v)
raw=(B/'navigation/modules/AMITSE.efi').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
pe=pefile.PE(data=raw);pe.relocate_image(TSE)
TIMAGE=pe.get_memory_mapped_image();TSIZE=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
TEXT=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
TEXT_BEGIN=TSE+TEXT.VirtualAddress;TEXT_END=TEXT_BEGIN+TEXT.Misc_VirtualSize
TREADONLY=[(TSE+s.VirtualAddress,TSE+s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData))for s in pe.sections if not s.Characteristics&0x80000000]
GLOBALS={0xafc38:(8,DB),0xafbc8:(8,BS),0xafbc0:(8,ST),
 0xafff8:(1,0),0xafd88:(1,0),0xafeb8:(8,0),0xaff22:(1,0),0xaff40:(8,0),
 0xbaaf0:(8,PT),0xbaaf8:(8,VT),0xbabc0:(8,PB),0xaff68:(8,1),0xafe54:(4,0),0xafe78:(8,0),0xbaa88:(8,PAD),
 0xafdd0:(8,APP),0xba9e8:(4,1),0xafdc0:(1,0),0xafdc8:(1,0),0xafdc9:(1,0),
 0xaff09:(1,0),0xaff0a:(1,0),0xafe58:(8,0),0xaff23:(1,0),0xaff10:(8,0),0xaff18:(8,0),
 0xafea0:(4,0),0xafe98:(8,0),0xafeb0:(4,0),0xb8c90:(80,0),0xb8ce0:(40,0)}
ALLOWED_CALLS={0x42b78,0x3682c,0x1600,0x36c00,0x3f90c,0x3e424,0x59b50}
PROTECTED={0x271e,0x271f}

class VM(setup.Replay):
 def __init__(self):
  super().__init__();self.u.mem_map(TSE,TSIZE);self.u.mem_map(AUX,0x10000)
  self.md.detail=True;self.tdecoded={};self.tins={}
 def code(self,u,a,n,_):
  if not TSE<=a<TSE+TSIZE:
   if a==setup.BASE+0x2250:
    self.setup_calls.append({'qid':u.reg_read(UC_X86_REG_R8),'action':u.reg_read(UC_X86_REG_RDX),'type':u.reg_read(UC_X86_REG_R9)&255})
    assert self.setup_calls[-1]['qid']not in PROTECTED
   return super().code(u,a,n,_)
  self.steps+=1;rva=a-TSE
  if not TEXT_BEGIN<=a<TEXT_END:self.halt('outside original AMITSE text',pc=hex(rva));return
  if rva not in self.tdecoded:
   ins=next(self.md.disasm(bytes(u.mem_read(a,n)),a));self.tdecoded[rva]=(ins.mnemonic,ins.op_str);self.tins[rva]=ins
  mnemonic,operand=self.tdecoded[rva]
  if mnemonic in ('out','in','rdmsr','wrmsr','syscall','sysenter','vmcall','int','cpuid'):
   self.halt('hardware/system instruction',module='AMITSE',pc=hex(rva));return
  if rva in (0x3e4af,0x3e4ed,0x3e4f0,0x3e515,0x3e51d,0x42b78,0x36c00,0x3682c):
   self.native_visits.append(hex(rva))
  if rva==0x3e4f0 and self.setup_calls:
   request=self.rq(u.reg_read(UC_X86_REG_RBP)-0x30)
   self.callback_returns.append({'status':hex(u.reg_read(UC_X86_REG_RAX)),'request':request})
   assert request==0,'known Setup candidate changed ActionRequest'
  if mnemonic=='call':
   ins=self.tins[rva]
   if rva==0x3e4ed:
    target=self.rq(u.reg_read(UC_X86_REG_RAX)+0x10)
    assert target==setup.BASE+0x2250 and u.reg_read(UC_X86_REG_RCX)==setup.BASE+0x2fd40
    return
   if ins.operands[0].type==capstone.x86.X86_OP_IMM:
    target=ins.operands[0].imm-TSE
    if target in ALLOWED_CALLS:return
   self.halt('unresolved native/helper/protocol call',module='AMITSE',pc=hex(rva),instruction=operand)
 def read(self,u,access,a,n,value,_):
  if TSE<=a and a+n<=TSE+TSIZE:
   r=a-TSE
   if any(lo<=r and r+n<=lo+width for lo,(width,_)in self.gstate.items()):self.treads.add((r,n));return
   if any(lo<=a and a+n<=hi for lo,hi in TREADONLY):return
   self.halt('unproven AMITSE global read',pc=hex(u.reg_read(UC_X86_REG_RIP)-TSE),read_rva=hex(r),bytes=n);return
  if AUX<=a and a+n<=AUX+0x10000:
   if any(lo<=a and a+n<=lo+width for lo,width in self.aux_objects):return
   self.halt('outside modeled AMITSE object',address=hex(a),bytes=n);return
  return super().read(u,access,a,n,value,_)
 def write(self,u,access,a,n,value,_):
  if TSE<=a and a+n<=TSE+TSIZE:
   r=a-TSE
   if any(lo<=r and r+n<=lo+width for lo,(width,_)in self.gstate.items()):
    self.twrites.append({'rva':hex(r),'bytes':n,'value':hex(value)});return
   self.halt('unproven AMITSE write',pc=hex(u.reg_read(UC_X86_REG_RIP)-TSE),write_rva=hex(r),bytes=n);return
  if AUX<=a and a+n<=AUX+0x10000:
   if any(lo<=a and a+n<=lo+width for lo,width in [(PB,0xc0),(APP,0x100),(PAD,32)]):
    self.object_writes.append({'object':'raw_pages'if PB<=a<PB+0xc0 else'app_or_refresh_state','address':hex(a),'bytes':n,'value':hex(value)});return
   self.halt('unproven modeled object write',address=hex(a),bytes=n);return
  return super().write(u,access,a,n,value,_)
 def reset(self,qid,action,typ,list_nodes=(),globals_override=None):
  assert qid not in PROTECTED
  u=self.u;u.mem_write(setup.BASE,setup.IMAGE);u.mem_write(TSE,TIMAGE)
  u.mem_write(setup.STACK,bytes(0x20000));u.mem_write(setup.DATA,bytes(0x4000));u.mem_write(AUX,bytes(0x10000))
  self.gstate=dict(GLOBALS);self.gstate.update(globals_override or{})
  for r,(n,v)in self.gstate.items():u.mem_write(TSE+r,v.to_bytes(n,'little'))
  u.mem_write(PT,D(3)+D(0)+D(0x40)+D(0x80))
  u.mem_write(PB,Q(0));u.mem_write(PB+0x40,Q(0x555100));u.mem_write(PB+0x80,Q(0))
  u.mem_write(APP+0x28,D(1));u.mem_write(ST+8,D(0x20070));u.mem_write(PAD,b'\x7e'*32)
  u.mem_write(VT,D(1))
  self.aux_objects=[(DB,0x60),(BS,0x180),(ST,0x100),(APP,0x100),(PT,16),(PB,0xc0),(PAD,32),(VT,4)]
  self.nodes=[setup.DATA+0x1000+i*0x30 for i in range(len(list_nodes))]
  for i,(nqid,fn)in enumerate(list_nodes):
   u.mem_write(self.nodes[i],Q(self.nodes[i+1]if i+1<len(self.nodes)else setup.HEAD)+Q(self.nodes[i-1]if i else setup.HEAD)+struct.pack('<H6xQ',nqid,setup.BASE+fn))
  u.mem_write(setup.HEAD,Q(self.nodes[0]if self.nodes else setup.HEAD)+Q(self.nodes[-1]if self.nodes else setup.HEAD))
  u.mem_write(setup.BASE+0x2fd60,Q(0x555100));u.mem_write(setup.BASE+0x48248,Q(1))
  u.mem_write(setup.VALUE,b'\xa5'*32);u.mem_write(setup.REQUEST,b'\x5a'*8)
  # The exact original ConfigAccess.Callback slot, not an arbitrary protocol.
  assert self.rq(setup.BASE+0x2fd50)==setup.BASE+0x2250
  self.read_premises=[(0x2fd50,8),(0x48248,8),(0x482e0,8),(0x471b0,114)];self.premised_reads=set()
  self.direct=False;self.allowed_dynamic=set(setup.KNOWN_DYNAMIC);self.context_reads=set()
  self.static_entered=[];self.dynamic_entered=[];self.bookkeeping=set();self.request_writes=0;self.steps=0
  self.native_visits=[];self.treads=set();self.twrites=[];self.object_writes=[];self.setup_calls=[];self.callback_returns=[]
  self.current={'qid':qid,'action':action,'type':typ,'runtime_authorized':False}
  for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,
              UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):u.reg_write(reg,0)
  s=setup.STACK+0x1f008;u.mem_write(s,Q(setup.STOP));u.mem_write(s+40,Q(action))
  for reg,v in [(UC_X86_REG_RCX,0x555100),(UC_X86_REG_RDX,qid),(UC_X86_REG_R8,typ),(UC_X86_REG_R9,setup.VALUE),(UC_X86_REG_RSP,s)]:u.reg_write(reg,v)
  self.s=s;self.action=action;self.typ=typ;self.qid=qid
 def execute(self,start,phase,request=0,status=0,preserve_frame=False):
  u=self.u;self.current['phase']=phase
  if start in (0x3e4af,0x3e4f0) and not preserve_frame:
   bp=self.s-24;u.reg_write(UC_X86_REG_RBP,bp);u.reg_write(UC_X86_REG_RSP,bp-0x60)
   u.reg_write(UC_X86_REG_R15,self.qid);u.reg_write(UC_X86_REG_R14,self.typ);u.reg_write(UC_X86_REG_RSI,setup.VALUE)
   u.mem_write(bp-0x20,Q(setup.BASE+0x2fd40));u.mem_write(bp-0x30,Q(request))
   if start==0x3e4f0:
    u.reg_write(UC_X86_REG_RAX,status);u.reg_write(UC_X86_REG_RBX,0);u.reg_write(UC_X86_REG_RDI,1)
    for r,n,v in [(0xafff8,1,1),(0xafd88,1,1),(0xafeb8,8,self.action)]:u.mem_write(TSE+r,v.to_bytes(n,'little'))
    self.current['synthetic_callback_output']={'status':hex(status),'ActionRequest':request}
  try:u.emu_start(TSE+start,0,count=40000)
  except UcError as e:
   if 'status'not in self.current:self.halt('CPU boundary',error=str(e))
  if u.reg_read(UC_X86_REG_RIP)==setup.STOP:
   self.current.update(status='RETURNED_ORIGINAL_BOUNDED_SLICE',return_status=hex(u.reg_read(UC_X86_REG_RAX)))
  elif 'status'not in self.current:self.halt('instruction budget')
  self.current.update(instructions=self.steps,native_visits=self.native_visits,setup_calls=self.setup_calls,
    callback_returns=self.callback_returns,static_handlers_entered=self.static_entered,dynamic_handlers_entered=self.dynamic_entered,
    native_global_reads=[{'rva':hex(r),'bytes':n}for r,n in sorted(self.treads)],native_global_writes=self.twrites,
    modeled_object_writes=self.object_writes,modeled_globals={hex(r):{'bytes':n,'value':hex(v)}for r,(n,v)in self.gstate.items()},
    final_guard_state={hex(r):int.from_bytes(u.mem_read(TSE+r,n),'little')for r,n in [(0xafff8,1),(0xafd88,1),(0xafeb8,8)]})
  return dict(self.current)

def main():
 begin=time.time();vm=VM();candidates=json.loads((B/'callback_shapes07/qid_action_type_candidates.json').read_text())['rows']
 rows=[]
 for c in candidates:
  if not c['all_observed_types_only_bookkeeping_under_list_and_state_premises']:continue
  for action in (3,4):
   for typ in c['action%d_types'%action]:
    vm.reset(c['qid'],action,typ);r=vm.execute(0x3e4af,'BOUNDED_POST_LOOKUP_REAL_SETUP2250_AND_ORIGINAL_CONSUMER')
    assert r['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE'and len(r['setup_calls'])==1 and r['callback_returns'][0]['request']==0,r
    assert all(v==0 for v in r['final_guard_state'].values())
    assert not r['modeled_object_writes']
    rows.append(r)
  if len(rows)%400<3:print('post-lookup original chain',len(rows),flush=True)
 prefix=[]
 for action in (3,4):
  vm.reset(0x2c27,action,9);r=vm.execute(0x3e424,'COMPLETE_ENTRY_STOPS_BEFORE_LOOKUP')
  assert r['status']=='UNKNOWN_NOT_AUTHORIZED'and r['pc']=='0x3e47b';prefix.append(r)
 outcomes=[]
 for status in (0,1,0x8000000000000003,0x8000000000000007):
  for request in (*range(11),0xffffffffffffffff):
   vm.reset(0x2c27,4,9);r=vm.execute(0x3e4f0,'EXPLICIT_POST_CALLBACK_STATUS_REQUEST_FIXTURE',request,status)
   if status>>63:
    assert r['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE'and r['return_status']==hex(status)and'0x42b78'not in r['native_visits']
   outcomes.append(r)
 hazards=[]
 for label,g,sentinel in [('pending_old_cache',{0xaff22:(1,1),0xaff40:(8,PAD)},False),
                          ('raw_hii_ffff_sentinel',{},True),('missing_refresh_catalog',{0xaff68:(8,0)},False)]:
  vm.reset(0x2c27,4,9,globals_override=g)
  if sentinel:vm.u.mem_write(PB+0x40,Q(0xffff))
  r=vm.execute(0x3e4f0,'REQUEST0_STATE_DEPENDENT_ORIGINAL_CLEANUP',0,0);r['case']=label;hazards.append(r)
 refresh=[]
 for request in (0,8,9,10,0xffffffffffffffff):
  vm.reset(0x2c27,4,9,globals_override={0xafe54:(4,8),0xafe78:(8,1)})
  r=vm.execute(0x3e4f0,'EXPLICIT_POST_CALLBACK_REFRESH_STATE',request,0)
  assert r['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE'
  assert bool(r['modeled_object_writes'])==(request!=0)
  r['refresh_bytes_after']=bytes(vm.u.mem_read(PAD,32)).hex();refresh.append(r)
 known=[]
 witness=next(c['qid']for c in candidates if c['all_observed_types_only_bookkeeping_under_list_and_state_premises']and not c['handlers'])
 for fn in setup.KNOWN_DYNAMIC:
  for action in (3,4):
   vm.reset(witness,action,9,[(witness,fn)]);r=vm.execute(0x3e4af,'POST_LOOKUP_ORIGINAL2250_WITH_EXPLICIT_KNOWN_NODE')
   assert r['status']=='RETURNED_ORIGINAL_BOUNDED_SLICE'and r['return_status']=='0x0'and r['dynamic_handlers_entered']==[hex(fn)]
   known.append(r)
 result={'status':'BOUNDED_ORIGINAL_CONSUMER_VERIFIED_PROTOCOL_PREFIX_AND_STATE_PREMISES_REMAIN',
  'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'base_replay_sha256':hashlib.sha256((B/'callback_shapes07/replay.py').read_bytes()).hexdigest(),
  'original_AMITSE_sha256':hashlib.sha256(raw).hexdigest(),'original_Setup_sha256':hashlib.sha256(setup.original).hexdigest(),
  'post_lookup_connected_cases':rows,'full_entry_first_unknown_cases':prefix,'post_callback_synthetic_outcomes':outcomes,
  'request0_cleanup_hazards':hazards,'refresh_state_synthetic_cases':refresh,'explicit_known_dynamic_node_cases':known,
  'limits':['The post-lookup slice begins after two unresolved protocol lookup calls. It is not evidence that those services succeed or identify the intended physical ConfigAccess.',
   'Three-page cleanup state and all AMITSE/Setup globals are explicit in-process fixtures, not current physical runtime state.',
   'Zero request only avoids special request dispatch after42B78; that helper can still free pending old cache or clear raw-page HII sentinels.',
   'Synthetic nonzero output fixtures never call an unknown callback. Save/reset/discard helpers stop before invocation.',
   'Original3E700 value extraction/writeback and complete firmware/UI execution are separate, unproven paths.'],
  'seconds':round(time.time()-begin,3),'firmware_changes':0,'hardware_actions':0,'runtime_authorized':False}
 (H/'consumer_results.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'connected_cases':len(rows),'full_entry_unknown':len(prefix),'synthetic_outputs':len(outcomes),'known_nodes':len(known),'hazards':[(r['case'],r['status'])for r in hazards],'seconds':round(time.time()-begin,3)}))
if __name__=='__main__':main()
