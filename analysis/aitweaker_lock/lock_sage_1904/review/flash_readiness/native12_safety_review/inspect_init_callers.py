"""Bounded references to OEM defaults/save protocol; not complete CFG proof."""
from pathlib import Path
import sys,hashlib,json,uuid
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone as C
guid=uuid.UUID('57e61629-63a2-4241-b2e9-b74c5c23f8cf').bytes_le
CAP=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True;cs.skipdata=True
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def text(i):return {'rva':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}
rows=[]
for p in Path(str(CAP)+'.dump').rglob('*PE32 image section/body.bin'):
 data=p.read_bytes()
 if guid not in data:continue
 pe=pefile.PE(data=data);loc=[];at=0
 while (at:=data.find(guid,at))>=0:loc.append(pe.get_rva_from_offset(at));at+=16
 ins=[i for s in pe.sections if s.Characteristics&0x20000000 for i in cs.disasm(s.get_data(),s.VirtualAddress)if i.id]
 refs=[];callers=[]
 for k,i in enumerate(ins):
  if any(o.type==C.x86_const.X86_OP_MEM and o.mem.base==C.x86_const.X86_REG_RIP and i.address+i.size+o.mem.disp in loc for o in i.operands):
   refs.append({'instruction':text(i),'context':[text(x)for x in ins[max(0,k-6):k+19]]})
  if i.mnemonic in ['call','jmp'] and i.operands and i.operands[0].type==C.x86_const.X86_OP_MEM and i.operands[0].mem.disp==16:
   callers.append({'instruction':text(i),'context':[text(x)for x in ins[max(0,k-8):k+4]]})
 rows.append({'file':str(p),'sha256':sha(p),'guid_RVAs':list(map(hex,loc)),'references':refs,'all_indirect_slot10_candidates_unclassified':callers})
r={'status':'BOUNDED_CALLER_SEARCH_NOT_TRIGGER_OR_STAGE_PROOF','CAP_sha256':sha(CAP),'protocol_guid':str(uuid.UUID(bytes_le=guid)),
 'interface_RVA':'0x79050','method_slot':'0x10','method_RVA':'0x5F688','modules':rows,'script_sha256':sha(Path(__file__)),
 'limits':['Slot10 calls listed here are unclassified candidates; their receiver must be traced before assigning this protocol identity.','A GUID reference plus nearby call does not prove CMOS recovery or source authorization.','No normal-UI exception should be authorized solely by empty UI head or coarse vendor stage variable.']}
(HERE/'initializer_callers.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'module_count':len(rows),'modules':[{'sha':x['sha256'][:12],'guidrefs':[r['instruction']['rva']for r in x['references']],'slot10_candidates':[r['instruction']['rva']for r in x['all_indirect_slot10_candidates_unclassified']]}for x in rows]},indent=2))
