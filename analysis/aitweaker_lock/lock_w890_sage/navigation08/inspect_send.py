"""Exact original-byte excerpts; Capstone evidence, not REA results."""
from pathlib import Path
import sys,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'))
import capstone,pefile
p=H.parent/'navigation/modules/AMITSE.efi'
assert hashlib.sha256(p.read_bytes()).hexdigest()=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
data=pefile.PE(str(p)).get_memory_mapped_image();md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for lo,hi,name in [(0x36da4,0x36e70,'send_prefix'),(0x372a3,0x373b7,'send_tail'),(0x12204,0x12270,'send_prepare'),(0x3711c,0x37155,'send_loop')]:
 text='\n'.join(f'{i.address:05x} {i.bytes.hex():28} {i.mnemonic} {i.op_str}'for i in md.disasm(data[lo:hi],lo))+'\n'
 (H/(name+'.asm.txt')).write_text(text)
