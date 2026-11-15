from pathlib import Path
import sys
H=Path(__file__).resolve().parent;sys.path.insert(0,str(H.parents[3]/'tools/pydeps'))
import pefile,capstone
p=pefile.PE(str(H.parent/'navigation/modules/AMITSE.efi'));b=p.get_memory_mapped_image();md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for lo,hi in [(0x1b814,0x1bcfd),(0x19463,0x19694),(0x22818,0x2289b),(0xfc40,0xfcaf),(0x59b50,0x59bc0)]:
 print('\nRANGE',hex(lo),hex(hi))
 for x in md.disasm(b[lo:hi],lo):print(f'{x.address:05x}: {x.bytes.hex():24} {x.mnemonic} {x.op_str}')
