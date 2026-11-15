from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
pe=pefile.PE(str(HERE.parent.parent/'boot_context/AMITSE.original.efi'))
start,end=int(sys.argv[1],16),int(sys.argv[2],16)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
lines=[]
section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
for i in cs.disasm(pe.get_data(section.VirtualAddress,section.Misc_VirtualSize),section.VirtualAddress):
 if i.address<start:continue
 if i.address>=end:break
 suffix=''
 rip=[i.address+i.size+o.mem.disp for o in i.operands if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP] if i.id else []
 if rip:suffix=' ; RIP -> '+','.join(hex(x)for x in rip)
 lines.append(f'{i.address:08X} {i.bytes.hex():32s} {i.mnemonic} {i.op_str}{suffix}')
text='\n'.join(lines)+'\n';(HERE/(sys.argv[3]+'.asm.txt')).write_text(text)
print(text)
