"""Static ownership and code mapping for the SAGE FormBrowser2.SendForm entry."""
from map_native import *
from verify_full_routines import reachable,normalized
import struct,uuid

def hits(data,raw):return [m.start() for m in re.finditer(re.escape(raw),data)]
def main():
 a=image(OLD/'AMITSE.efi');b=image(NEW/'AMITSE.efi')
 old,new=0x20f34,0x20ee4
 pat,ins=pattern(a,old,64);found=[m.start() for m in re.finditer(pat,b,re.S)]
 assert found==[new]
 ai,au=reachable(a,old);bi,bu=reachable(b,new)
 same=b''.join(normalized(x) for x in ai)==b''.join(normalized(x) for x in bi)
 offsets=[x.address-old for x in ai]==[x.address-new for x in bi]
 branches=all([o.imm-old for o in x.operands if o.type==C.CS_OP_IMM]==[o.imm-new for o in y.operands if o.type==C.CS_OP_IMM] for x,y in zip(ai,bi) if x.group(C.CS_GRP_JUMP))
 assert same and offsets and branches and not au and not bu
 guid=uuid.UUID('b9d4c360-bcfb-4f9b-9298-53c136982258').bytes_le
 oldrefs=hits(a,struct.pack('<Q',old));newrefs=hits(b,struct.pack('<Q',new))
 assert newrefs==[0x6bed8] and b[0x6b270:0x6b280]==guid
 registration=list(cs.disasm(b[0x2671:0x2694],0x2671))
 assert [x.address for x in registration]==[0x2671,0x2678,0x267f,0x2682,0x2689,0x268e]
 assert registration[1].mnemonic=='lea' and registration[1].op_str.startswith('r8, ')
 assert registration[1].address+registration[1].size+registration[1].operands[1].mem.disp==0x6bed8
 assert registration[3].mnemonic=='lea' and registration[3].op_str.startswith('rdx, ')
 assert registration[3].address+registration[3].size+registration[3].operands[1].mem.disp==0x6b270
 assert registration[-1].bytes==bytes.fromhex('ff9048010000')
 report={'status':'PASS','module_sha256':hashlib.sha256((NEW/'AMITSE.efi').read_bytes()).hexdigest(),'ace_entry':hex(old),'sage_entry':hex(new),'sage_prologue_32_bytes':b[new:new+32].hex(),'reachable_instructions':len(bi),'sage_end':hex(bi[-1].address+bi[-1].size),'same_masked_opcodes_and_relative_offsets':True,'same_direct_branch_edges':True,'unresolved_direct_branches':bu,'ace_sendform_pointer_locations':[hex(x) for x in oldrefs],'sage_sendform_pointer_locations':[hex(x) for x in newrefs],'ace_formbrowser_guid_locations':[hex(x) for x in hits(a,guid)],'sage_formbrowser_guid_locations':[hex(x) for x in hits(b,guid)],'old_refs':refs(ai),'new_refs':refs(bi),'scope':'Static mapping from earlier ACE FormBrowser2 ownership evidence; requires live FormBrowser2 interface pointer equal to AMITSE base plus 0x20ee4 before invocation.'}
 report['static_protocol_registration']={'instruction':'0x268e','operation':'gBS.InstallMultipleProtocolInterfaces','guid_rva':'0x6b270','interface_rva':'0x6bed8','first_method_rva':'0x20ee4','instructions':[{'rva':hex(x.address),'bytes':x.bytes.hex(),'text':x.mnemonic+' '+x.op_str} for x in registration]}
 report['scope']='Static exact-SHA full reachable function mapping plus independent actual FormBrowser2 protocol registration evidence. Live FormBrowser2.send must still equal AMITSE base + 0x20ee4 before invocation.'
 (HERE/'sendform_mapping.json').write_text(json.dumps(report,indent=2),encoding='utf8')
 print(json.dumps({k:v for k,v in report.items() if k not in ['old_refs','new_refs']},indent=2))
if __name__=='__main__':main()
