"""Prepare exact original DxeIpl input and inspect LZMA GUID references."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
candidate=next(x for x in json.loads((HERE/'lzma_native_candidates.json').read_text())['matches'] if x['sha256']=='87f73cdbb246b2457e687a41711673359bdc62c869de1398e3d932c02e07461f')
source=Path(candidate['path']);raw=source.read_bytes();assert hashlib.sha256(raw).hexdigest()==candidate['sha256']
baseline=json.loads((HERE/'original_static_review.json').read_text())['original']
capsule=Path(baseline['path']).read_bytes();assert hashlib.sha256(capsule).hexdigest()==baseline['sha256']
cap_offset=capsule.find(raw);assert cap_offset>=0 and capsule.find(raw,cap_offset+1)==-1
out=HERE/'native_inputs/DxeIplW890Normal.efi';out.write_bytes(raw)
pe=pefile.PE(data=raw);assert pe.FILE_HEADER.Machine in (0x8664,0x14c)
guid_rvas=[pe.get_rva_from_offset(n) for n in candidate['guid_offsets']]
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64 if pe.FILE_HEADER.Machine==0x8664 else capstone.CS_MODE_32);md.detail=True
xrefs=[]
for section in pe.sections:
 if not section.Characteristics&0x20000000:continue
 instructions=list(md.disasm(section.get_data(),section.VirtualAddress))
 for i,insn in enumerate(instructions):
  if any((op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP and insn.address+insn.size+op.mem.disp in guid_rvas) or
         (op.type==X86_OP_IMM and op.imm-pe.OPTIONAL_HEADER.ImageBase in guid_rvas) or
         (op.type==X86_OP_MEM and op.mem.disp-pe.OPTIONAL_HEADER.ImageBase in guid_rvas) for op in insn.operands):
   xrefs.append(dict(rva=hex(insn.address),context=[f'{x.address:08x}: {x.mnemonic} {x.op_str}' for x in instructions[max(0,i-12):i+15]]))
result=dict(original=candidate,copy=str(out),machine=hex(pe.FILE_HEADER.Machine),image_base=hex(pe.OPTIONAL_HEADER.ImageBase),entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
 original_capsule=baseline,original_capsule_offset=hex(cap_offset),source_bytes_directly_match_original_capsule=True,
 image_bytes=pe.OPTIONAL_HEADER.SizeOfImage,guid_rvas=[hex(x) for x in guid_rvas],guid_xrefs=xrefs,
 section_data=[dict(name=s.Name.rstrip(b'\0').decode(),rva=hex(s.VirtualAddress),bytes=s.Misc_VirtualSize) for s in pe.sections])
(HERE/'native_inputs/DxeIplW890Normal.derivation.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
