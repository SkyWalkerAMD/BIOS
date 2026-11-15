"""Read-only ACE/SAGE original firmware mapping; no device access."""
from pathlib import Path
import hashlib, json, struct, sys, uuid

OUT=Path(__file__).resolve().parent; ROOT=OUT.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile, capstone
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_OP_REG,X86_REG_RIP
SAGE=ROOT/'analysis/aitweaker_lock/lock_sage_1904'
ACE=ROOT/'analysis/aitweaker_lock/hardware_20261102_W790_ACE_E9B906DF/modules'
TIMING=json.loads((SAGE/'review/flash_readiness/entry_save_timing/entry_save_timing_review.json').read_text())
OUT.mkdir(exist_ok=True); (OUT/'modules').mkdir(exist_ok=True)

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def normal(i):
 if not i.id:return ('undecodable-data',bytes(i.bytes))
 o=[]
 for x in i.operands:
  if x.type==X86_OP_REG:o.append(('reg',i.reg_name(x.reg),x.size))
  elif x.type==X86_OP_IMM:o.append(('imm','target' if i.mnemonic=='call' or i.mnemonic.startswith('j') else x.imm,x.size))
  elif x.type==X86_OP_MEM:
   m=x.mem;o.append(('mem',i.reg_name(m.base),i.reg_name(m.index),m.scale,'rip' if m.base==X86_REG_RIP else m.disp,x.size))
 return (i.mnemonic,tuple(o))

sources={'AMITSE':ACE/'AMITSE.efi','Setup':ACE/'Setup.efi'}
dump=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP.dump'
guid_defs={'BdsArch':'665e3ff6-46cc-11d4-9a38-0090273fc14d','TseBootManager':'8a91b1e1-56c7-4adc-abeb-1c2ca1729eff','EndOfDxe':'02ce967a-dd7e-4ffc-9ee7-810cf0470880'}
guid_bytes={k:uuid.UUID(v).bytes_le for k,v in guid_defs.items()}
hits=[]
for p in dump.rglob('body.bin'):
 if 'PE32 image section' not in p.parent.name:continue
 raw=p.read_bytes()
 found={k:hex(raw.find(v)) for k,v in guid_bytes.items() if v in raw}
 if found:hits.append({'path':str(p.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'guid_file_offsets':found})
 if 'D6A2CB7F-6A18-4E2F-B43B-9920A733700A' in str(p):sources['OriginalDxeCore']=p
 if all(k in found for k in guid_bytes):sources['OriginalBds']=p
(OUT/'ace_original_module_inventory.json').write_text(json.dumps({'hits':hits,'selected':{k:str(p.relative_to(ROOT)) for k,p in sources.items()},'guid_definitions':guid_defs},indent=2)+'\n')
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
mapped={};scan={};normalized={}
for name,path in sources.items():
 pe=pefile.PE(str(path));mem=pe.get_memory_mapped_image();mapped[name]=mem
 seq=[]
 for s in pe.sections:
  if s.Characteristics&0x20000000:
   seq+=list(cs.disasm(mem[s.VirtualAddress:s.VirtualAddress+min(s.Misc_VirtualSize,s.SizeOfRawData)],s.VirtualAddress))
 scan[name]=seq;normalized[name]=[normal(i) for i in seq]
 if name.startswith('Original'):(OUT/'modules'/f'{name}.efi').write_bytes(path.read_bytes())

blocks=[x for x in TIMING['native_blocks'] if x['module'] in sources]
extra=[('save_iterator',0x1425c,0x148a3),('boot_manager_entry_prefix',0x2780,0x2800),
       ('native_browser_entry_prefix',0xe1b8,0xe20c),('save_exit_action',0x448cc,0x448fc),
       ('save_reset_action',0x448fc,0x44968),('save_stay_action',0x44968,0x449a0),
       ('vendor_initializer',0x5f688,0x5f6e4)]
sage_amitse=pefile.PE(str(Path(TIMING['artifacts']['AMITSE']['path']))).get_memory_mapped_image()
for label,start,end in extra:
 blocks.append({'module':'AMITSE','rva':hex(start),'length':end-start,'label':label,'bytes_hex':sage_amitse[start:end].hex()})
rows=[]
for b in blocks:
 name=b['module'];start=int(b['rva'],16);raw=bytes.fromhex(b['bytes_hex'])
 sig=[]
 for instruction in cs.disasm(raw,start):
  if not instruction.id:break
  sig.append(instruction)
 pat=[normal(i) for i in sig];ns=normalized[name];seq=scan[name]
 matches=[]
 if pat:
  for j,item in enumerate(ns):
   if item==pat[0] and ns[j:j+len(pat)]==pat:
    found=seq[j:j+len(pat)];begin=found[0].address;end=found[-1].address+found[-1].size
    row={'ace_start':hex(begin),'ace_end_exclusive':hex(end),'ace_bytes_hex':mapped[name][begin:end].hex(),
         'ace_bytes_sha256':hashlib.sha256(mapped[name][begin:end]).hexdigest(),
         'direct_calls':[],'rip_references':[]}
    for i in found:
     if not i.id:continue
     for op in i.operands:
      if i.mnemonic=='call' and op.type==X86_OP_IMM:row['direct_calls'].append({'site':hex(i.address),'target':hex(op.imm)})
      if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:row['rip_references'].append({'site':hex(i.address),'target':hex(i.address+i.size+op.mem.disp)})
    matches.append(row)
 rows.append({'module':name,'label':b['label'],'sage_start':b['rva'],'sage_bytes_sha256':hashlib.sha256(raw).hexdigest(),
              'sage_instruction_count':len(sig),'sage_decoded_bytes':sum(i.size for i in sig),
              'unique_match':len(matches)==1,'matches':matches})
report={'status':'STATIC_NORMALIZED_BLOCK_MAPPING','modules':{name:{'source':str(p.relative_to(ROOT)),'sha256':sha(p),'bytes':p.stat().st_size} for name,p in sources.items()},
        'reference_report_sha256':sha(SAGE/'review/flash_readiness/entry_save_timing/entry_save_timing_review.json'),
        'rows':rows,'limitations':['Branch/call destinations and RIP displacements are normalized for candidate matching; used target/global identities must be separately corroborated.',
         'Short block signatures may be ambiguous; only unique matches are candidates, and function starts require original-code or REA confirmation.',
         'Linear executable-section decoding is bounded static evidence, not exhaustive indirect-alias analysis or hardware execution.']}
(OUT/'ace_entry_save_mapping.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'modules':report['modules'],'mappings':[{'label':x['label'],'sage':x['sage_start'],'ace':[y['ace_start'] for y in x['matches']][:5],'match_count':len(x['matches']),'unique':x['unique_match']} for x in rows]},indent=2))
