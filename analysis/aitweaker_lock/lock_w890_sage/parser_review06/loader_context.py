"""Static original-byte context; only REA records are labeled REA Evidence."""
from pathlib import Path
import json,sys,hashlib
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
source=B/'navigation/modules/AMITSE.efi';pe=pefile.PE(str(source));image=pe.get_memory_mapped_image()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
windows=[]
for title,lo,hi in [('SPF section load and signature scan',0x5efac,0x5f038),('startup initializer ordering',0x73b3,0x740c),('parser call at Setup entry',0x18e1c,0x18e52),('SPF pointer initialization',0x19cf8,0x19de9),('loop entry and tail',0x40fff,0x41139),('second static page loop uses exclusive count',0x41235,0x41284)]:
    code=image[lo:hi]
    windows.append({'title':title,'start_rva':hex(lo),'end_rva':hex(hi),'bytes_sha256':hashlib.sha256(code).hexdigest(),'bytes':code.hex(),'instructions':[{'rva':hex(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str}for i in md.disasm(code,lo)]})
out={'scope':__doc__,'original_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'windows':windows,
     'findings':['Original startup calls 5EFAC then 19CF8, 1B7DC, 1C17C; the three modeled initializers follow this observed order.',
                 '5EFAC points BABC0 at located SPF signature; the shown loader performs no count adjustment.',
                 '19CF8 derives BAB10 from SPF+0x2C offset and BAB18 from the declared formset table; it does not change the page count.',
                 '18E1C calls 40D94 before its shown FORM_OPEN traversal.',
                 'Later in 40D94, the independent static page GUID copy loop uses indices 0..count-1.'],
     'limits':['Intervening startup, indirect call effects and physical allocation context are not fully replayed or proved.',
               'No image modification is justified solely by this static comparison.']}
(H/'loader_context.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items()if k!='windows'},indent=2))
