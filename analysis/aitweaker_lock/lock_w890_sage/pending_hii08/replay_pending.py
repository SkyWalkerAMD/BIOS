"""Original queue processing with explicit fixtures and first-unknown stops.

The single EFI FreePool model owns only synthetic queue-node allocations.
No business callback/parse helper is replaced by success. No firmware changes.
"""
from pathlib import Path
import hashlib,json,struct,sys
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
P=B/'navigation/modules/AMITSE.efi'
SHA='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
assert hashlib.sha256(P.read_bytes()).hexdigest()==SHA
T,D,S=0x28000000,0x50000000,0x60000000
HEAD,BS,FREE,FILTER,RET=D,D+0x1000,D+0x2000,D+0x3000,D+0x4000
pe=pefile.PE(str(P));pe.relocate_image(T)
mapped=pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0')
ERR=lambda n:(1<<63)|n

def run(name,nodes,selected=None,head_present=True,free_status=0):
 u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(T,len(mapped));u.mem_write(T,mapped)
 u.mem_map(D,0x20000);u.mem_map(S,0x10000)
 def wq(a,x):u.mem_write(a,struct.pack('<Q',x))
 def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
 def ret(v):
  sp=u.reg_read(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RAX,v)
  u.reg_write(UC_X86_REG_RIP,rq(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 ptrs=[D+0x5000+i*0x100 for i in range(len(nodes))]
 for i,((handle,kind),p) in enumerate(zip(nodes,ptrs)):
  for off,val in ((0,handle),(8,kind),(16,D+0x10000+i*0x100),(32,ptrs[i-1] if i else 0),(40,ptrs[i+1] if i+1<len(ptrs) else 0)):
   wq(p+off,val)
 wq(HEAD,len(nodes));wq(HEAD+8,ptrs[0] if ptrs else 0);wq(HEAD+16,ptrs[-1] if ptrs else 0)
 wq(T+0xaff30,HEAD if head_present else 0);wq(T+0xafbc8,BS);wq(BS+0x48,FREE)
 # Native producer catalog deliberately empty. The selection list is independent.
 wq(T+0xaff80,0);wq(T+0xaff68,0)
 if selected is not None:
  for i,h in enumerate(selected):wq(FILTER+i*8,h)
 wq(T+0xbaa68,FILTER if selected is not None else 0);wq(T+0xbaa70,len(selected or []))
 u.mem_write(T+0xaff20,b'\x01\x00\x00\x00')
 wq(T+0xaff40,0);u.mem_write(T+0xaff38,b'\0')
 sp=S+0x8008;wq(sp,RET);u.reg_write(UC_X86_REG_RSP,sp)
 trace=[];writes=[];freed=[];stop=None
 boundaries={0x3fab4:'queue_normalization',0x4244c:'add_or_parse_package',0x426cc:'remove_package',0x429c4:'replace_package',0x42b78:'refresh_cached_package'}
 def code(uc,address,size,opaque):
  nonlocal stop
  if address==RET:stop={'kind':'RETURN','status':hex(uc.reg_read(UC_X86_REG_RAX))};uc.emu_stop();return
  if address==FREE:
   p=uc.reg_read(UC_X86_REG_RCX)
   assert p in ptrs and p not in freed
   freed.append(p);trace.append({'service':'FreePool','node_index':ptrs.index(p),'model_status':hex(free_status)})
   ret(free_status);return
  off=address-T
  if off in boundaries:
   stop={'kind':'UNPROVED_CALLEE','rva':hex(off),'name':boundaries[off],
    'return_rva':hex(rq(uc.reg_read(UC_X86_REG_RSP))-T),
    'arguments':[uc.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]}
   uc.emu_stop();return
  if not 0x3fed4<=off<0x4037a:raise AssertionError(('unexpected instruction',hex(address)))
 def write(uc,access,address,size,value,opaque):
  if T<=address<T+len(mapped):writes.append({'rva':hex(address-T),'bytes':size,'value':value})
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_WRITE,write)
 u.emu_start(T+0x40094,RET+1,count=20000)
 assert stop is not None,'Instruction budget exhausted'
 remaining=[];p=rq(HEAD+8);visited=set()
 while p:
  assert p in ptrs and p not in visited and p not in freed
  visited.add(p);remaining.append(ptrs.index(p));p=rq(p+40)
 assert len(remaining)==rq(HEAD)
 assert (rq(HEAD+16)==ptrs[remaining[-1]]) if remaining else rq(HEAD+16)==0
 if stop['kind']=='RETURN':assert bytes(u.mem_read(T+0xaff20,4))==b'\0\0\0\x01'
 return {'name':name,'passed':True,'input_nodes':nodes,'selection':selected,'stop':stop,
  'freed_node_indices':[ptrs.index(p) for p in freed],'remaining_node_indices':remaining,
  'native_writes':writes,'service_models':trace}

def main():
 cases=[run('Null pending pointer',[],head_present=False),run('Empty real head',[]),
  run('Unknown kind drains one node',[(0x100,0)]),
  run('Unknown kind drains three linked nodes',[(0x100,0),(0x200,4),(0x300,16)]),
  run('Selection leaves unmatched linked nodes',[(0x100,0),(0x200,4),(0x300,16)],[0x200]),
  run('Selection with no match preserves all nodes',[(0x100,0),(0x200,4)],[0x999]),
  run('Native ignores failed FreePool status',[(0x100,0)],free_status=ERR(7)),
  run('Add notification stops before original parser',[(0x100,1)]),
  run('Remove notification stops at original normalization',[(0x100,2)]),
  run('Replacement notification stops at original normalization',[(0x100,8)])]
 assert [c['stop']['status'] for c in cases[:2]]==[hex(ERR(14))]*2
 assert cases[2]['freed_node_indices']==[0] and cases[3]['freed_node_indices']==[0,1,2]
 assert cases[4]['freed_node_indices']==[1] and cases[4]['remaining_node_indices']==[0,2]
 assert cases[5]['freed_node_indices']==[] and cases[5]['remaining_node_indices']==[0,1]
 assert cases[6]['stop']=={'kind':'RETURN','status':'0x0'}
 assert cases[7]['stop']['rva']=='0x4244c' and not cases[7]['freed_node_indices']
 assert cases[8]['stop']['rva']==cases[9]['stop']['rva']=='0x3fab4'
 report={'status':'ORIGINAL_PENDING_CONTROL_FLOW_NOT_AN_INSTALLED_GUARD','count':len(cases),'passed':True,
  'original_sha256':SHA,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':cases,
  'limitations':['Queue/catalog/selection are declared synthetic fixtures, not physical allocations.',
   'EFI FreePool alone is a return-value model; its failure is deliberately tested and native status handling retained.',
   'Original 3FED4 and 40094 instructions execute; unknown business helpers stop before body execution.',
   'No fabricated callback success, no complete live rebuild, and no claim of an integrated password lock.']}
 (H/'pending_cases.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'passed':True,'cases':len(cases),'completed_native_returns':7,'first_unknown_stops':3}))
if __name__=='__main__':main()
