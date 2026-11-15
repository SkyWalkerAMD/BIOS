from pathlib import Path
import sys,struct,uuid,json,hashlib
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1];sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
p=pefile.PE(str(OUT/'HiiDatabase.efi'));b=p.get_memory_mapped_image();base=p.OPTIONAL_HEADER.ImageBase
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
guids={k:uuid.UUID(v).bytes_le for k,v in dict(database='ef9fc172-a1b2-4693-b327-6d32fc416042',string='0fd96974-23aa-4cdc-b9cb-98d17750322a').items()}
positions={k:[i for i in range(len(b)) if b.startswith(v,i)] for k,v in guids.items()}
print('base',hex(base),'entry',hex(p.OPTIONAL_HEADER.AddressOfEntryPoint),'positions',positions)
target={x for a in positions.values() for x in a}
ins=[]
for s in p.sections:
 if s.Characteristics&0x20:ins.extend(cs.disasm(b[s.VirtualAddress:s.VirtualAddress+s.Misc_VirtualSize],base+s.VirtualAddress))
for idx,i in enumerate(ins):
 if any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and i.address+i.size+o.mem.disp-base in target for o in i.operands):
  print('GUIDXREF')
  for x in ins[max(0,idx-12):idx+20]:print(f'{x.address-base:08x} {x.mnemonic} {x.op_str}')
(OUT/'hii-disasm.txt').write_text('\n'.join(f'{i.address-base:08x} {i.mnemonic} {i.op_str}' for i in ins)+'\n')
(OUT/'hii-guid-metadata.json').write_text(json.dumps(dict(sha256=hashlib.sha256((OUT/'HiiDatabase.efi').read_bytes()).hexdigest(),image_base=base,entry_rva=p.OPTIONAL_HEADER.AddressOfEntryPoint,guid_rvas=positions),indent=2)+'\n')
