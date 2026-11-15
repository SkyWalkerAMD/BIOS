from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path.insert(0,str(R/'tools/pydeps'))
import pefile,capstone
g=json.loads((H/'save_notification_modules.json').read_text())
row=next(x for group in g for x in group['hits'] if x['module']=='FirmwareConfigDrv')
p=Path(row['file']);e=pefile.PE(str(p));b=e.get_memory_mapped_image();d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True;d.skipdata=True
refs=[]
for sec in e.sections:
 if not sec.Characteristics&0x20000000:continue
 ins=list(d.disasm(b[sec.VirtualAddress:sec.VirtualAddress+sec.Misc_VirtualSize],sec.VirtualAddress))
 for i,x in enumerate(ins):
  if not x.id:continue
  if any(o.type==capstone.CS_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP and x.address+x.size+o.mem.disp==0x1c1b8 for o in x.operands):
   refs.append({'at':hex(x.address),'context':[f'{a.address:x}: {a.mnemonic} {a.op_str}'for a in ins[max(0,i-12):i+12]]})
out={'source':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'target':'0x1c1b8','xrefs':refs}
(H/'final_notify_refs.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
