from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path[:0]=[str(ROOT/'tools/pydeps')]
import pefile,capstone
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP
raw=(HERE/'inputs/AMITSE.efi').read_bytes();pe=pefile.PE(data=raw)
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
targets={0xbaaf8,0xafcd8,0xaff30,0xaff68,0xaff80,0xbaa68,0xbaa70}
refs=[]
for section in pe.sections:
 if not section.Characteristics&0x20000000:continue
 for i in md.disasm(section.get_data()[:section.Misc_VirtualSize],section.VirtualAddress):
  for j,o in enumerate(i.operands):
   if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP:
    a=i.address+i.size+o.mem.disp
    if a in targets:
     refs.append(dict(rva=hex(i.address),target=hex(a),instruction=i.mnemonic+' '+i.op_str,bytes=i.bytes.hex(),operand=j,write=bool(o.access&capstone.CS_AC_WRITE)))
(HERE/'native_global_refs.json').write_text(json.dumps(dict(module_sha256=hashlib.sha256(raw).hexdigest(),references=refs),indent=2)+'\n')
print(json.dumps([r for r in refs if r['write']],indent=2))
