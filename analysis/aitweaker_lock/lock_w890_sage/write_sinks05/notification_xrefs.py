from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'tools/pydeps'))
import pefile,capstone
groups=json.loads((H/'save_notification_modules.json').read_text())
out=[]
for g in groups:
 for row in g['hits']:
  p=Path(row['file']); pe=pefile.PE(str(p)); b=pe.get_memory_mapped_image()
  targets={pe.get_rva_from_offset(x) for x in row['offsets']}; d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True;d.skipdata=True
  refs=[]
  for s in pe.sections:
   if not s.Characteristics&0x20000000: continue
   ins=list(d.disasm(b[s.VirtualAddress:s.VirtualAddress+s.Misc_VirtualSize],s.VirtualAddress))
   for i,x in enumerate(ins):
    if not x.id:continue
    for o in x.operands:
     if o.type==capstone.CS_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and x.address+x.size+o.mem.disp in targets:
      refs.append({'at':hex(x.address),'target':hex(x.address+x.size+o.mem.disp),'context':[f'{z.address:x}: {z.mnemonic} {z.op_str}' for z in ins[max(0,i-8):i+12]]})
  out.append({**row,'notification':g['name'],'guid_rvas':list(map(hex,targets)),'entry':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'xrefs':refs})
(H/'notification_xrefs.json').write_text(json.dumps(out,indent=2)+'\n')
for x in out:
 print(x['notification'],x['module'] or x['guid'],x['entry'],'refs',[(r['at'],r['target']) for r in x['xrefs']])
