from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
MODULE=HERE.parent.parent/'boot_context/AMITSE.original.efi'
assert hashlib.sha256(MODULE.read_bytes()).hexdigest()=='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
pe=pefile.PE(str(MODULE));sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
start,end=int(sys.argv[1],16),int(sys.argv[2],16);lines=[]
for i in cs.disasm(pe.get_data(sec.VirtualAddress,sec.Misc_VirtualSize),sec.VirtualAddress):
 if i.address<start:continue
 if i.address>=end:break
 suffix=''
 refs=[i.address+i.size+o.mem.disp for o in i.operands if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP]if i.id else[]
 if refs:suffix=' ; RIP -> '+','.join(hex(x)for x in refs)
 lines.append(f'{i.address:08X} {i.bytes.hex():32s} {i.mnemonic} {i.op_str}{suffix}')
out='\n'.join(lines)+'\n';(HERE/(sys.argv[3]+'.asm.txt')).write_text(out);print(out)
