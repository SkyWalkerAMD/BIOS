"""Read-only native save caller inventory; no firmware mutations or device I/O."""
from pathlib import Path
import hashlib, json, sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[5]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone, pefile
MODULE=HERE.parents[2]/'analysis/modules/AMITSE.efi'
EXPECTED='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
assert hashlib.sha256(MODULE.read_bytes()).hexdigest()==EXPECTED
pe=pefile.PE(str(MODULE));mapped=pe.get_memory_mapped_image();base=pe.OPTIONAL_HEADER.ImageBase
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
sections=[(s.VirtualAddress,s.VirtualAddress+min(s.Misc_VirtualSize,s.SizeOfRawData)) for s in pe.sections if s.Characteristics & 0x20000000]
targets={0x1422c,0x1425c,0x330a8,0x11164};calls=[]
cs.skipdata=True
for start,end in sections:
 for ins in cs.disasm(mapped[start:end],start):
  if ins.mnemonic in ('call','jmp') and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm in targets:
   calls.append({'section_start':hex(start),'address':hex(ins.address),'instruction':ins.mnemonic,'target':hex(ins.operands[0].imm)})
refs=[]
for block in pe.DIRECTORY_ENTRY_BASERELOC:
 for entry in block.entries:
  if entry.type==10:
   value=int.from_bytes(mapped[entry.rva:entry.rva+8],'little')-base
   if value in targets:refs.append({'slot':hex(entry.rva),'target':hex(value)})
selected=[(0x1422c,0x148a3),(0x330a8,0x330bf)]
selected += [(int(x['address'],16),int(x['address'],16)+100) for x in calls if not 0x1422c<=int(x['address'],16)<0x148a3 and int(x['address'],16)!=0x330b1]
text=[]
for start,end in selected:
 text.append(f'RANGE {start:x}..{end:x}')
 text.extend(f'{i.address:08x} {i.bytes.hex():24} {i.mnemonic} {i.op_str}' for i in cs.disasm(mapped[start:end],start))
(HERE/'native_save_callers.txt').write_text('\n'.join(text)+'\n')
result={'status':'STATIC_CALLER_INVENTORY_ONLY','module_sha256':EXPECTED,'direct_callers':calls,'relocated_function_pointers':refs,'limits':['Original image has no parsed exception/unwind directory. Linear executable-section decoding and explicit known entry ranges are used; discovered call sites need separate native/control-flow validation. Indirect runtime callers and OEM event dispatch are not exhausted.','This inventory does not establish safe error propagation or a completed UI fix.']}
(HERE/'native_save_callers.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
