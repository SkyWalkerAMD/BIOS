"""Execute only original callback paths, stopping before unknown calls/effects.

No UEFI service returns are substituted. Known password-management handlers are
excluded. Empty/known synthetic lists are explicit model inputs, never physical
attestation. The complete AMITSE callback/value/ActionRequest path is not run.
"""
from pathlib import Path
import json,struct,sys,hashlib,collections,time
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import capstone,pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID,UcError
from unicorn.x86_const import *
BASE=0x4000000;STACK=0x8000000;DATA=0x9000000;STOP=DATA+0x3000
HEAD=BASE+0x55180;VALUE=DATA+0x100;REQUEST=DATA+0x200;CONTEXT=DATA+0x400
Q=lambda n:struct.pack('<Q',n)
KNOWN_DYNAMIC=(0xf4b0,0x1cf9c,0x1d44c)
original=(B/'navigation/modules/Setup.efi').read_bytes()
assert hashlib.sha256(original).hexdigest()=='c1cf9d755c2ea043d44f19fdf4009cf8b12b03f85e8939034de19ee18251b72e'
pe=pefile.PE(data=original);pe.relocate_image(BASE);IMAGE=pe.get_memory_mapped_image();SIZE=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
table=json.loads((B/'navigation06_actions/setup_handler_table.json').read_text())
STATIC_END=table['terminator_rva']+16
STATIC_HANDLERS={int(e['handler'],16)for e in table['entries']}
PROTECTED={0xd604}
READONLY=[(BASE+s.VirtualAddress,BASE+s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData))for s in pe.sections if not s.Characteristics&0x80000000]

class Replay:
 def __init__(self):
  self.u=Uc(UC_ARCH_X86,UC_MODE_64)
  self.u.mem_map(BASE,SIZE);self.u.mem_map(STACK,0x20000);self.u.mem_map(DATA,0x4000)
  self.md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);self.decoded={}
  self.u.hook_add(UC_HOOK_CODE,self.code)
  self.u.hook_add(UC_HOOK_MEM_READ,self.read)
  self.u.hook_add(UC_HOOK_MEM_WRITE,self.write)
  self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
 def halt(self,reason,**kw):
  if 'status'not in self.current:self.current.update(status='UNKNOWN_NOT_AUTHORIZED',reason=reason,**kw)
  self.u.emu_stop()
 def rq(self,a):return int.from_bytes(self.u.mem_read(a,8),'little')
 def code(self,u,a,n,_):
  self.steps+=1
  if a==STOP:u.emu_stop();return
  if not BASE+0x1000<=a<BASE+0x2b7f9:self.halt('outside original Setup text',pc=hex(a));return
  rva=a-BASE
  if rva not in self.decoded:
   ins=next(self.md.disasm(bytes(u.mem_read(a,n)),a));self.decoded[rva]=(ins.mnemonic,ins.op_str)
  name,args=self.decoded[rva]
  if name in ('out','in','rdmsr','wrmsr','syscall','sysenter','vmcall','int','cpuid'):
   self.halt('hardware/system instruction',pc=hex(rva),instruction=name);return
  if name=='call':
   if rva==0x22f6:
    ptr=u.reg_read(UC_X86_REG_R10)+u.reg_read(UC_X86_REG_R14)+8
    target=self.rq(ptr)-BASE
    if target not in STATIC_HANDLERS or target in PROTECTED:
     self.halt('static target excluded or not original table',pc=hex(rva),target=hex(target));return
    self.static_entered.append(hex(target));return
   if rva==0x2345:
    target=self.rq(u.reg_read(UC_X86_REG_RBX)+0x18)-BASE
    if target not in self.allowed_dynamic:
     self.halt('dynamic target not explicitly reviewed original',pc=hex(rva),target=hex(target));return
    self.dynamic_entered.append(hex(target));return
   self.halt('unknown helper/protocol call',pc=hex(rva),instruction=args)
 def read(self,u,access,a,n,value,_):
  if STACK<=a and a+n<=STACK+0x20000:return
  if self.direct and CONTEXT<=a and a+n<=CONTEXT+0x30:
   self.context_reads.add((a-CONTEXT,n));return
  if a==REQUEST and n<=8:return
  if any(p<=a and a+n<=p+32 for p in self.nodes):return
  if BASE<=a and a+n<=BASE+SIZE:
   r=a-BASE
   if any(lo<=r and r+n<=hi for lo,hi in [(0x2c600,STATIC_END),(0x2fd60,0x2fd68),(0x48180,0x48181),(0x48190,0x48198),(0x55180,0x55190)]):return
   if any(lo<=r and r+n<=lo+length for lo,length in self.read_premises):
    self.premised_reads.add((r,n));return
   if any(lo<=a and a+n<=hi for lo,hi in READONLY):return
   self.halt('unproven mutable runtime global read',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE),read_rva=hex(r),bytes=n);return
  self.halt('input value or other unproven data read',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE),address=hex(a),bytes=n)
 def write(self,u,access,a,n,value,_):
  if STACK<=a and a+n<=STACK+0x20000:return
  if a==REQUEST and n==8:
   if value!=0:self.halt('nonzero ActionRequest',value=hex(value));return
   self.request_writes+=1;return
  if a==BASE+0x48180 and n==1:self.bookkeeping.add('legacy_flag');return
  if a==BASE+0x48190 and n==8:self.bookkeeping.add('callback_context');return
  self.halt('non-bookkeeping write',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE),address=hex(a),bytes=n)
 def invalid(self,u,access,a,n,value,_):self.halt('unmapped boundary',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE),address=hex(a));return False
 def run(self,qid,action,typ,list_nodes=(),allowed_dynamic=(),direct_rva=None,budget=18000,read_premises=(),global_values=()):
  u=self.u;u.mem_write(BASE,IMAGE);u.mem_write(STACK,bytes(0x20000));u.mem_write(DATA,bytes(0x4000))
  self.nodes=[DATA+0x1000+i*0x30 for i in range(len(list_nodes))]
  for i,(node_qid,fn)in enumerate(list_nodes):
   nxt=self.nodes[i+1]if i+1<len(self.nodes)else HEAD;prev=self.nodes[i-1]if i else HEAD
   raw=Q(nxt)+Q(prev)+struct.pack('<H6xQ',node_qid,BASE+fn)
   u.mem_write(self.nodes[i],raw)
  u.mem_write(HEAD,Q(self.nodes[0]if self.nodes else HEAD)+Q(self.nodes[-1]if self.nodes else HEAD))
  u.mem_write(BASE+0x2fd60,Q(0x555100))
  self.read_premises=list(read_premises);self.premised_reads=set()
  for rva,width,value in global_values:u.mem_write(BASE+rva,value.to_bytes(width,'little'))
  u.mem_write(VALUE,b'\xa5'*32);u.mem_write(REQUEST,b'\x5a'*8)
  sp=STACK+0x1f008;u.mem_write(sp,Q(STOP));u.mem_write(sp+40,Q(VALUE)+Q(REQUEST))
  for reg in (UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,
              UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15):u.reg_write(reg,0)
  self.direct=direct_rva is not None;self.allowed_dynamic=set(allowed_dynamic);self.context_reads=set()
  self.static_entered=[];self.dynamic_entered=[];self.bookkeeping=set();self.request_writes=0;self.steps=0
  for reg,val in [(UC_X86_REG_RCX,BASE+0x2fd40),(UC_X86_REG_RDX,action),(UC_X86_REG_R8,qid),(UC_X86_REG_R9,typ),(UC_X86_REG_RSP,sp)]:u.reg_write(reg,val)
  self.current={'qid':qid,'action':action,'type':typ,'modeled_list':[{'qid':q,'handler_rva':hex(f)}for q,f in list_nodes],
    'direct_rva':hex(direct_rva)if direct_rva else None,'runtime_authorized':False,
    'read_premises':[{'rva':hex(r),'bytes':n}for r,n in read_premises],
    'modeled_global_values':[{'rva':hex(r),'bytes':n,'value':hex(v)}for r,n,v in global_values]}
  if self.direct:
   context=Q(BASE+0x2fd40)+Q(action)+struct.pack('<HB5x',qid,typ)+Q(VALUE)+Q(REQUEST)+Q(0x555100)
   assert len(context)==0x30;u.mem_write(CONTEXT,context);u.reg_write(UC_X86_REG_RCX,CONTEXT)
  try:u.emu_start(BASE+(direct_rva or 0x2250),0,count=budget)
  except UcError as e:
   if 'status'not in self.current:self.halt('CPU boundary',error=str(e))
  if u.reg_read(UC_X86_REG_RIP)==STOP:
   self.current.update(status='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING',result=hex(u.reg_read(UC_X86_REG_RAX)),action_request=hex(self.rq(REQUEST)))
   if not self.direct:
    assert self.rq(REQUEST)==0 and self.rq(BASE+0x48190)==0
    ctx=bytes(u.mem_read(sp-0x38,0x30))
    expect=Q(BASE+0x2fd40)+Q(action)+struct.pack('<HB5x',qid,typ)+Q(VALUE)+Q(REQUEST)+Q(0x555100)
    assert ctx==expect,'static/dynamic handler changed dispatcher context'
    self.current['dispatcher_context_preserved']=True
  elif 'status'not in self.current:self.halt('instruction budget',pc=hex(u.reg_read(UC_X86_REG_RIP)-BASE))
  self.current.update(instructions=self.steps,static_handlers_entered=self.static_entered,
    dynamic_handlers_entered=self.dynamic_entered,context_fields_read=sorted(self.context_reads),
    bookkeeping=sorted(self.bookkeeping),action_request_writes=self.request_writes,premised_reads=sorted(self.premised_reads))
  return dict(self.current)

def main():
 begin=time.time();inputs=json.loads((H/'inputs.json').read_text());vm=Replay();rows=[]
 for i,q in enumerate(inputs['qid_inputs']):
  if q['excluded_password_management']:
   rows.append({'qid':q['qid'],'status':'EXCLUDED_PASSWORD_MANAGEMENT_NOT_EXECUTED','runtime_authorized':False});continue
  for action in (3,4):
   for typ in q['action%d_types'%action]:rows.append(vm.run(q['qid'],action,typ))
  if i%200==0:print('original input shapes',i,flush=True)
 out={'status':'OBSERVED_EXACT_ORIGINAL_INPUT_SHAPES_NO_AUTHORIZATION','source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'inputs_sha256':hashlib.sha256((H/'inputs.json').read_bytes()).hexdigest(),'original_setup_sha256':hashlib.sha256(original).hexdigest(),
  'cases':rows,'summary':dict(collections.Counter(x['status']for x in rows)),
  'model':'Original Setup2250, original static handlers, dynamic list explicitly empty. No services substituted. Unknown runtime global reads, helpers or writes stop.',
  'seconds':round(time.time()-begin,3),'hardware_actions':0,'runtime_authorized':False}
 (H/'actual_shapes.json').write_text(json.dumps(out,indent=2)+'\n');print(out['summary'],flush=True)
 refinements=[]
 for qid,rva,width,values in [(0x272b,0x482e0,8,(0,1,0xffffffffffffffff)),
                             (0x2765,0x471b0,114,(None,)),
                             (0x2c1e,0x48248,8,(1,0xffffffffffffffff))]:
  inp=next(q for q in inputs['qid_inputs']if q['qid']==qid)
  for action in (3,4):
   for typ in inp['action%d_types'%action]:
    for value in values:
     r=vm.run(qid,action,typ,read_premises=[(rva,width)],global_values=[]if value is None else[(rva,width,value)])
     assert r['status']=='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING',r
     refinements.append(r)
 negative_cache=[]
 for action in (3,4):
  r=vm.run(0x2c1e,action,9 if action==3 else 0,read_premises=[(0x48248,8)],global_values=[(0x48248,8,0)])
  assert r['status']=='UNKNOWN_NOT_AUTHORIZED';negative_cache.append(r)
 (H/'conditional_refinements.json').write_text(json.dumps({'cases':refinements,'negative_zero_cache':negative_cache,
  'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  'conditions':{'272B':'Original191DC tests cached global482E0 only for zero/nonzero, then checks action==1. For3/4 neither predicate class calls a helper.',
    '2765':'Original28ACC copies exactly114 bytes of the module-local static text beginning471B0 onto its stack before action filtering. Allowing that bounded original-constant read returns without other effects.',
    '2C1E':'Requires global48248!=0. For3/4 originalE51C then returns without dereferencing that cached pointer. Zero triggers an unclosed protocol path and remains unknown.'},
  'runtime_authorized':False},indent=2)+'\n')
 direct=[]
 for fn in KNOWN_DYNAMIC:
  for action in (3,4):
   for typ in range(256):
    r=vm.run(0xfffd,action,typ,direct_rva=fn)
    assert r['status']=='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING'and r['result']=='0x0',r
    assert not r['static_handlers_entered']and not r['dynamic_handlers_entered']and not r['bookkeeping']and not r['action_request_writes']
    direct.append(r)
 witness=next(q for q in inputs['qid_inputs']if not q['excluded_password_management']and not q['handlers'])['qid']
 integration=[]
 for fn in KNOWN_DYNAMIC:
  for action in (3,4):
   for typ in (0,1,7,9,10,12):
    r=vm.run(witness,action,typ,[(witness,fn)],KNOWN_DYNAMIC)
    assert r['status']=='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING'and r['result']=='0x0',r
    integration.append(r)
 unknown=vm.run(witness,4,9,[(witness,0x700000)],KNOWN_DYNAMIC)
 assert unknown['status']=='UNKNOWN_NOT_AUTHORIZED'and unknown['reason']=='dynamic target not explicitly reviewed original'
 skipped=vm.run(witness,4,9,[(witness^0xffff,0x700000)],KNOWN_DYNAMIC)
 assert skipped['status']=='RETURNED_WITH_ONLY_DISPATCH_BOOKKEEPING'and not skipped['dynamic_handlers_entered']
 outside=[]
 for fn in KNOWN_DYNAMIC:
  r=vm.run(witness,1,0,direct_rva=fn)
  assert r['status']=='UNKNOWN_NOT_AUTHORIZED';outside.append(r)
 dynamic={'status':'THREE_ORIGINAL_DYNAMIC_HANDLERS_RETURN_FOR_ACTION3_4_ALL_256_TYPE_BYTES_UNDER_EXPLICIT_CONTEXT',
  'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'direct_cases':direct,
  'actual2250_integration_cases':integration,'negative_unknown_matching':unknown,'negative_unknown_nonmatching_skipped':skipped,
  'outside_action3_4_negative_cases':outside,
  'limitations':['Synthetic nodes and contexts are not the runtime linked list. Matching handler pointers must be bound to original live Setup text before any separate authorization review.',
  'Only Action3/4 paths are covered. Other actions can read/write variables and call services.',
  'No foreign or unknown handler executes, including in negative cases. The original dispatcher skips a nonmatching node, which is not a blanket authorization of that node.',
  'Full AMITSE3E700 value extraction and3E424 ActionRequest consumers remain outside this program.'],
  'runtime_authorized':False,'hardware_actions':0}
 (H/'dynamic_shapes.json').write_text(json.dumps(dynamic,indent=2)+'\n')
 print(json.dumps({'dynamic_direct_cases':len(direct),'native2250_known_node_cases':len(integration),'unknown_target_called':False,'seconds':round(time.time()-begin,3)}))
if __name__=='__main__':main()
