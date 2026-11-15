"""Read-only original instruction evidence for bounded NATIVE12 safety review."""
from pathlib import Path
import sys,json,hashlib
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];ROOT=CASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone as C
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=CASE/'analysis/modules/AMITSE.efi';pe=pefile.PE(str(p))
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True
def text(i):return {'rva':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}
regions={name:[text(i)for i in cs.disasm(pe.get_data(start,end-start),start)]for name,start,end in [
 ('vendor_defaults_save',0x5f688,0x5f6ed),('direct_protocol_defaults',0x6286c,0x6287a),
 ('defaults_effect',0x13b9c,0x1425c),('save_iterator',0x1425c,0x148d0),
 ('generic_commit',0x11164,0x11260),('vendor_initialize',0x5d4cc,0x5d61c)]}
targets={0x5f688,0x6286c,0x13b9c,0x1425c,0x11164,0x5d4cc};refs=[]
for section in pe.sections:
 if not section.Characteristics&0x20000000:continue
 for i in cs.disasm(section.get_data(),section.VirtualAddress):
  if i.mnemonic in ['call','jmp']and i.operands and i.operands[0].type==C.x86_const.X86_OP_IMM and i.operands[0].imm in targets:refs.append(text(i))
r={'original_AMITSE_sha256':sha(p),'regions':regions,'direct_references':refs,'script_sha256':sha(Path(__file__))}
(HERE/'original_paths.json').write_text(json.dumps(r,indent=2)+'\n')
(HERE/'original_paths.txt').write_text('\n\n'.join(name+'\n'+'\n'.join(x['rva']+' '+x['asm']for x in instructions)for name,instructions in regions.items())+'\n')
print(json.dumps({'regions':{n:len(x)for n,x in regions.items()},'references':refs},indent=2))
