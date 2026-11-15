from pathlib import Path
import hashlib,json,sys,struct
HERE=Path(__file__).resolve().parent;D04=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
p=D04.parent/'boot_context/AMITSE.original.efi'
assert hashlib.sha256(p.read_bytes()).hexdigest()=='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
pe=pefile.PE(str(p));cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
table=[struct.unpack('<Q',pe.get_data(0x6d6f0+8*i,8))[0] for i in range(12)]
(HERE/'kind4_vtable.json').write_text(json.dumps({'module_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'table_rva':'0x6d6f0','entries':[hex(x)for x in table],'raw_6c360_32bytes':pe.get_data(0x6c360,32).hex()},indent=2)+'\n')
print(json.dumps({'table':[hex(x)for x in table]}))
if len(sys.argv)==4:
 start,end=int(sys.argv[1],16),int(sys.argv[2],16);lines=[]
 sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
 for i in cs.disasm(pe.get_data(sec.VirtualAddress,sec.Misc_VirtualSize),sec.VirtualAddress):
  if i.address<start:continue
  if i.address>=end:break
  refs=[i.address+i.size+o.mem.disp for o in i.operands if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP]if i.id else[]
  lines.append(f'{i.address:08X} {i.bytes.hex():32s} {i.mnemonic} {i.op_str}'+(' ; RIP -> '+','.join(hex(x)for x in refs)if refs else''))
 text='\n'.join(lines)+'\n';(HERE/(sys.argv[3]+'.asm.txt')).write_text(text);print(text)
