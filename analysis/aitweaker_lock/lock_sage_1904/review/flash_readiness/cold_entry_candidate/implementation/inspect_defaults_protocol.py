"""Bounded native references to the known AMITSE direct-defaults protocol.

This is instruction-reference evidence, not proof that every indirect call in
all firmware was recovered. No claim of closed-world absence of UI callers.
"""
from pathlib import Path
import hashlib,json,sys,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,capstone as C
CAP=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
GUID=uuid.UUID('451175cf-377b-4bbc-b0c3-f592c4920871').bytes_le
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True;cs.skipdata=True
def rip(o,i):return i.address+i.size+o.mem.disp if o.type==C.x86_const.X86_OP_MEM and o.mem.base==C.x86_const.X86_REG_RIP else None
def text(i):return {'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
rows=[];all_method_candidates=[]
for path in Path(str(CAP)+'.dump').rglob('*PE32 image section/body.bin'):
 data=path.read_bytes()
 if GUID not in data:continue
 p=pefile.PE(data=data);guid_rvas=[];at=0
 while True:
  at=data.find(GUID,at)
  if at<0:break
  guid_rvas.append(p.get_rva_from_offset(at));at+=16
 instructions=[i for s in p.sections if s.Characteristics&0x20000000 for i in cs.disasm(s.get_data(),s.VirtualAddress)if i.id]
 references=[];result_globals=set()
 for n,i in enumerate(instructions):
  if any(rip(o,i)in guid_rvas for o in i.operands):
   block=instructions[max(0,n-5):n+8];references.append({'instruction':text(i),'context':[text(x)for x in block]})
   # Only record directly visible R8=global output slots, not inferred stack
   # aliasing or method pointers copied elsewhere.
   for x in block:
    if x.mnemonic=='lea'and len(x.operands)==2 and x.operands[0].type==C.x86_const.X86_OP_REG and x.operands[0].reg==C.x86_const.X86_REG_R8:
     target=rip(x.operands[1],x)
     if target is not None:result_globals.add(target)
 calls=[]
 for n,i in enumerate(instructions):
  if i.mnemonic not in ['call','jmp']or len(i.operands)!=1:continue
  o=i.operands[0]
  if o.type!=C.x86_const.X86_OP_MEM or o.mem.disp!=0x48:continue
  base=o.mem.base;origin=None
  for x in reversed(instructions[max(0,n-20):n]):
   if x.mnemonic=='mov'and len(x.operands)==2 and x.operands[0].type==C.x86_const.X86_OP_REG and x.operands[0].reg==base:
    origin=rip(x.operands[1],x);break
  if origin in result_globals:
   calls.append({'instruction':text(i),'base_global':hex(origin),'context':[text(x)for x in instructions[max(0,n-7):n+2]]})
 module={'path':str(path),'sha256':sha(path),'guid_rvas':[hex(x)for x in guid_rvas],'guid_instruction_references':references,'potential_protocol_result_globals':[hex(x)for x in sorted(result_globals)],'direct_slot48_candidate_calls':calls}
 rows.append(module);all_method_candidates.extend({'module_sha256':module['sha256'],**x}for x in calls)
# Exact original AMITSE proof of registration and direct method body.
amitse=CASE/'analysis/modules/AMITSE.efi';ap=pefile.PE(str(amitse))
assert ap.get_data(0x6b470,16)==GUID
assert int.from_bytes(ap.get_data(0x7b568,8),'little')==0x6286c
native={name:[text(i)for i in cs.disasm(ap.get_data(r,n),r)]for name,r,n in [('registration',0x625d0,0x29),('direct_defaults_method',0x6286c,0xe)]}
setup=next(x for x in rows if x['sha256']=='719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d')
r={'status':'BOUNDED_NATIVE_PROTOCOL_CALLER_INVENTORY_NOT_CLOSED_WORLD_PROOF','source_CAP_sha256':sha(CAP),'original_AMITSE_sha256':sha(amitse),'protocol_GUID':str(uuid.UUID(bytes_le=GUID)),'native_registration':native,'interface_RVA':'0x7b520','direct_defaults_slot':'0x48','direct_defaults_method_RVA':'0x6286c','native_target':'0x13b9c','modules_containing_GUID':len(rows),'modules':rows,'candidate_calls':all_method_candidates,'Setup_direct_slot48_candidates':len(setup['direct_slot48_candidate_calls']),'script_sha256':sha(Path(__file__)),
 'limits':['The known published slot reaches13B9C without the5ABC gate. This remains an explicit unaccepted path in the frozen11-point prototype.','Linear x64 decoding with skipdata and local instruction lookback is a bounded reference search, not a complete callgraph or absence proof.','Global output pointers are candidate LocateProtocol results; stack-result pointers, copied methods and computed calls need manual proof if a relevant UI path emerges.','No normal interactive UI caller is established merely from the presence of this protocol GUID in a module.','No module source/binary was edited; no device access occurred.']}
(HERE/'build/defaults_protocol_inventory.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':r['status'],'modules_with_GUID':len(rows),'candidate_calls':[(x['module_sha256'][:12],x['instruction']['rva'])for x in all_method_candidates],'Setup_direct_slot48_candidates':r['Setup_direct_slot48_candidates']},indent=2))
