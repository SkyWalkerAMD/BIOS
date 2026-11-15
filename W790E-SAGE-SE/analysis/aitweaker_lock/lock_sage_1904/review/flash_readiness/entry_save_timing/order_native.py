import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,hashlib,uuid
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[5]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
from capstone.x86 import X86_OP_MEM,X86_REG_RIP,X86_OP_IMM
def main():
 inv=json.loads((HERE/'dxe_order_inventory.json').read_text(encoding='utf-8'))
 for name,select in [('OriginalBds','8F4B8F82-9B91-4028-86E6-F4DB7D4C1DFF'),('OemEndDxe','70E1A818-0BE1-4449-BFD4-9EF68C7F02A8')]:
  entry=next(x for x in inv['hits'] if select in x['path'])
  raw=Path(entry['path']).read_bytes();(HERE/(name+'.efi')).write_bytes(raw)
  pe=pefile.PE(data=raw);image=pe.get_memory_mapped_image()
  cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
  s=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
  ops=list(cs.disasm(image[s.VirtualAddress:s.VirtualAddress+s.Misc_VirtualSize],s.VirtualAddress))
  targets={pe.get_rva_from_offset(int(o,16)):label for label,os in entry['guid_file_offsets'].items() for o in os}
  refs=[];calls=[]
  for i,op in enumerate(ops):
   if not op.id:continue
   for arg in op.operands:
    if arg.type==X86_OP_MEM and arg.mem.base==X86_REG_RIP:
     to=op.address+op.size+arg.mem.disp
     if to in targets:
      refs.append({'label':targets[to],'target':hex(to),'site':hex(op.address),'context':[f'{x.address:#x}: {x.mnemonic} {x.op_str}' for x in ops[max(0,i-8):i+18]]})
   if op.mnemonic=='call' and op.operands[0].type==X86_OP_IMM:calls.append({'from':hex(op.address),'to':hex(op.operands[0].imm)})
  result={'source':entry,'entry':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),'guid_rvas':{hex(k):v for k,v in targets.items()},'refs':refs,'direct_calls':calls}
  (HERE/(name+'_refs.json')).write_text(json.dumps(result,indent=2),encoding='utf-8')
  print(name,result['entry'])
  for r in refs:print('\n'+r['label']+'\n'+'\n'.join(r['context']))
if __name__=='__main__':main()
