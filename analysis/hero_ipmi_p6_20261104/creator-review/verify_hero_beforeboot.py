from pathlib import Path
import hashlib,json,sys,struct,uuid
P=Path(__file__).resolve().parent; ROOT=P.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
src=ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi'
raw=src.read_bytes(); pe=pefile.PE(data=raw)
g=uuid.UUID('3677770F-EFB2-43B2-B8AE-B302E9604882')
words=struct.unpack('<4I',g.bytes_le)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); cs.detail=True;cs.skipdata=True
groups=[]
for s in pe.sections:
 if not s.Characteristics&0x20000000:continue
 ins=list(cs.disasm(s.get_data(),s.VirtualAddress))
 for i,x in enumerate(ins):
  if not x.id or x.mnemonic!='mov' or len(x.operands)<2:continue
  if x.operands[1].type!=capstone.x86.X86_OP_IMM or x.operands[1].imm!=words[0]:continue
  stop=next((j for j in range(i+1,len(ins)) if ins[j].mnemonic=='ret'),min(len(ins),i+1000))
  nearby=ins[max(0,i-5):stop+1]
  found=[any(y.id and y.mnemonic=='mov' and len(y.operands)>1 and y.operands[1].type==capstone.x86.X86_OP_IMM and y.operands[1].imm==v for y in nearby) for v in words]
  calls=[];allhelper=[]
  stack=x.operands[0].mem
  for j,y in enumerate(nearby):
   if not(y.id and y.mnemonic=='call' and y.operands[0].type==capstone.x86.X86_OP_IMM and y.operands[0].imm==0x176c):continue
   allhelper.append(hex(y.address));prev=nearby[j-1]
   if prev.mnemonic=='lea' and prev.operands[0].reg==capstone.x86.X86_REG_RCX and prev.operands[1].type==capstone.x86.X86_OP_MEM and prev.operands[1].mem.base==stack.base and prev.operands[1].mem.disp==stack.disp:calls.append(hex(y.address))
  groups.append({'first_instruction_rva':hex(x.address),'guid_dwords_present':found,'publication_helper_calls_for_this_guid':calls,'all_publication_helper_calls_in_function':allhelper,
   'instructions':[f'{y.address:08x}: {y.bytes.hex()} {y.mnemonic} {y.op_str}' for y in nearby]})
helper=[f'{x.address:08x}: {x.bytes.hex()} {x.mnemonic} {x.op_str}' for x in cs.disasm(pe.get_data(0x176c,0x80),0x176c)]
result={'target':str(src.relative_to(ROOT)),'sha256':hashlib.sha256(raw).hexdigest(),'guid':str(g),
 'guid_encoding_dwords':[hex(v) for v in words],'groups':groups,'helper_0x176c':helper,
 'existing_helper_rea_directory':'analysis/hero_ipmi_p5_rea_review_20261103/amitse/responses',
 'observed': 'HERO AMITSE constructs the BeforeBoot marker and calls the same transient protocol-publishing helper used by SetupEnter.' if groups and all(all(x['guid_dwords_present']) and x['publication_helper_calls_for_this_guid'] for x in groups) else 'Review needed',
 'uefi_application_limit':'At RVA 0x4EB9C the marker is emitted after successful LoadImage and before StartImage. BeforeBoot is therefore not intrinsically OS-only; other UEFI applications may trigger it.',
 'limits':'Static publishing code confirms availability in this binary. Actual callback registration timing and boot paths on the new build still need live validation.'}
(P/'hero-beforeboot-publication.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('groups','helper_0x176c')},indent=2))
for group in groups:print(group['first_instruction_rva'],group['guid_dwords_present'],group['publication_helper_calls_for_this_guid'])
