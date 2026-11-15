from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'tools/pydeps'))
import pefile,capstone
p=pefile.PE(str(H.parent/'navigation/modules/AMITSE.efi'));b=p.get_memory_mapped_image();md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True;md.skipdata=True
ins=list(md.disasm(b[0x1000:0x92dda],0x1000));refs=[]
for i,x in enumerate(ins):
 if x.id and any(o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and x.address+x.size+o.mem.disp in [0xafde8,0xafde0,0xafe00,0xafddc]for o in x.operands):
  refs.append({'rva':x.address,'text':x.mnemonic+' '+x.op_str,'bytes':x.bytes.hex(),'nearby':[f'{y.address:x}: {y.mnemonic} {y.op_str}'for y in ins[max(0,i-2):i+4]]})
w=[]
for role,rva,n in [('allocator',0x59b50,32),('reallocator',0xfc40,32),('first',0x19463,32),('cleanup',0x19994,32),('menu_free',0x22862,16),('loop_free',0x19a5d,16)]:
 a=list(md.disasm(b[rva:rva+n],rva));w.append({'role':role,'instructions':[{'rva':i.address,'bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str}for i in a]})
(H/'history_refs.json').write_text(json.dumps({'original_sha256':hashlib.sha256((H.parent/'navigation/modules/AMITSE.efi').read_bytes()).hexdigest(),'refs':refs,'windows':w},indent=2)+'\n')
for x in refs:print(hex(x['rva']),x['text'])
for x in w:print(x)
