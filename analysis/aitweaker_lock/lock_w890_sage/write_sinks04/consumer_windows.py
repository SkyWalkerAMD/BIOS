from pathlib import Path
import sys,re,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];O=H/'build';sys.path[:0]=[str(R/'tools/pydeps'),str(R/'tools/kvm-pydeps')]
import pefile,capstone
p=O/'W890WriteBridge04.DENYONLY.dll';pe=pefile.PE(str(p));base=pe.OPTIONAL_HEADER.ImageBase;blob=pe.get_memory_mapped_image();symbols={}
for line in (O/'W890WriteBridge04.DENYONLY.map').read_text().splitlines():
 m=re.match(r'\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\w+)\s+([0-9a-fA-F]{16})',line)
 if m:symbols[m[1]]=int(m[2],16)-base
target=symbols['no_scope_enter'];rows=[];d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True
for section in pe.sections:
 if section.Characteristics&0x20000000:
  for i in d.disasm(blob[section.VirtualAddress:section.VirtualAddress+section.Misc_VirtualSize],section.VirtualAddress):
   if i.mnemonic=='call' and i.operands and i.operands[0].type==capstone.x86.X86_OP_IMM and i.operands[0].imm==target:
    ret=i.address+i.size;rows.append(dict(return_rva=ret,call_rva=i.address,no_call_kind=1,window=blob[ret-16:ret+16].hex()))
assert len(rows)==1,rows
result={'component_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'image_base_for_static_decode':base,'no_scope_enter_rva':target,'calls':rows,'not_installed':True,'note':'Diagnostic effects only. Call windows bind this exact linked component. Re-linking changes RVAs/bytes; regenerate. Original native caller admission and execution permission are not supplied by these windows.'}
(H/'consumer_windows.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
