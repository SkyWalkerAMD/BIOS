"""Local disassembly aid; this output is not REA Evidence."""
import sys, json, bisect
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
BASE=Path(__file__).resolve().parent
PE=pefile.PE(str(BASE.parent/'navigation/modules/AMITSE.efi'))
IMAGE=PE.get_memory_mapped_image()
INDEX=json.loads((ROOT/'analysis/aitweaker_lock/W890_SAGE_0603/AMITSE_code_index.json').read_text())
STARTS=INDEX['starts']
CS=Cs(CS_ARCH_X86,CS_MODE_64)
for arg in sys.argv[1:]:
    start=int(arg,0); end=STARTS[bisect.bisect_right(STARTS,start)]
    text='\n'.join(f'{i.address:08x}  {i.mnemonic:8} {i.op_str}' for i in CS.disasm(IMAGE[start:end],start))
    (BASE/f'disasm-{start:x}.txt').write_text(text,encoding='utf-8')
    print(f'{start:x}-{end:x}: {text.count(chr(10))+1} instructions; {BASE/f"disasm-{start:x}.txt"}')
