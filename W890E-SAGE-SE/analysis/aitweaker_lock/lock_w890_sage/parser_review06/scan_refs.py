from pathlib import Path
import json,sys,collections,hashlib,struct
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
pe=pefile.PE(str(B/'navigation/modules/AMITSE.efi')); sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
targets={0xbabc0,0xbab10,0xbab18,0xbab20,0xbaaf0,0xbafc0}; refs={hex(k):[] for k in targets}
for i in md.disasm(sec.get_data()[:sec.Misc_VirtualSize],sec.VirtualAddress):
    for idx,op in enumerate(i.operands):
        if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
            target=i.address+i.size+op.mem.disp
            if target in targets:refs[hex(target)].append({'rva':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str,'operand':idx,'access':op.access})
(H/'global_refs.json').write_text(json.dumps(refs,indent=2)+'\n');print(json.dumps(refs,indent=2))
