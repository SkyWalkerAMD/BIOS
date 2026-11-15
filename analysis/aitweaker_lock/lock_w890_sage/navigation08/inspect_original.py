from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import capstone,pefile
p=B/'navigation/modules/AMITSE.efi';assert hashlib.sha256(p.read_bytes()).hexdigest()=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
pe=pefile.PE(str(p));im=pe.get_memory_mapped_image();md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
parts=[(0xfcb4,0xfd6c,'dispatch'),(0x64b2c,0x64d1c,'render'),(0x1d6e8,0x1d9c8,'destructor'),(0x190f4,0x19463,'initial_exit'),(0x1964f,0x196ff,'pre_loop'),(0x33ec8,0x34060,'render_descriptor')]
for lo,hi,name in parts:
 text='\n'.join(f'{x.address:05x} {x.bytes.hex():28} {x.mnemonic} {x.op_str}'for x in md.disasm(im[lo:hi],lo))+'\n'
 (H/(name+'.asm.txt')).write_text(text)
 if name in ['render_descriptor']:print(name+'\n'+text)
import struct
values=struct.unpack_from('<512Q',im,0xa9760);groups=[]
for i,x in enumerate(values):
 if x==0:break
 if 0xffff0000<=x<=0xffffffff:
  targets=[]
  for y in values[i+2:]:
   if not y or 0xffff0000<=y<=0xffffffff:break
   targets.append(hex(y))
  groups.append({'selector':hex(x),'index':i,'reserved_or_default':hex(values[i+1]),'targets':targets})
(H/'original_oem_groups.json').write_text(json.dumps(groups,indent=2)+'\n')
print(json.dumps([g for g in groups if g['selector']in ['0xffff002b','0xffff001e','0xffff002a','0xffff0022']],indent=2))
