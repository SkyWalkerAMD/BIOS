from pathlib import Path
import hashlib,json,sys,struct
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
MODULE=HERE.parent.parent/'boot_context/AMITSE.original.efi';pe=pefile.PE(str(MODULE))
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');refs=[];flags=[]
for i in cs.disasm(pe.get_data(sec.VirtualAddress,sec.Misc_VirtualSize),sec.VirtualAddress):
 if not i.id:continue
 for op in i.operands:
  if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
   rva=i.address+i.size+op.mem.disp
   if rva in [0x83580,0x93028,0x93038,0x6b9f0]:refs.append({'rva':hex(i.address),'target':hex(rva),'bytes':i.bytes.hex(),'op':i.mnemonic+' '+i.op_str})
 if i.mnemonic in ['mov','or','and'] and i.operands[0].type==capstone.x86.X86_OP_MEM and i.operands[0].size==1 and i.operands[0].mem.disp==0x5a:
  flags.append({'rva':hex(i.address),'bytes':i.bytes.hex(),'op':i.mnemonic+' '+i.op_str})
tables={hex(at):[hex(struct.unpack('<Q',pe.get_data(at+i*8,8))[0])for i in range(n)]for at,n in [(0x6b9d8,8),(0x7cfa0,180)]}
report={'module_sha256':hashlib.sha256(MODULE.read_bytes()).hexdigest(),'refs':refs,'byte_field_5a_stores_untyped':flags,'tables':tables}
(HERE/'exit_references.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'field_stores':flags,'hotkey_table':tables['0x6b9d8'],'pending_reset_refs':[x for x in refs if x['target']=='0x83580']}))
