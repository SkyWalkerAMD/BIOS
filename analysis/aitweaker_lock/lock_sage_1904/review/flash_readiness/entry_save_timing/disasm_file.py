import sys
sys.dont_write_bytecode=True
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[5]/'tools/pydeps'))
import pefile,capstone
path=Path(sys.argv[1]);pe=pefile.PE(str(path));data=pe.get_memory_mapped_image()
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
for arg in sys.argv[2:]:
 start,n=map(lambda x:int(x,0),arg.split(':'))
 print('RANGE',path.name,hex(start),hex(n))
 for x in cs.disasm(data[start:start+n],start):print(f'{x.address:08x} {x.bytes.hex():24} {x.mnemonic} {x.op_str}')
