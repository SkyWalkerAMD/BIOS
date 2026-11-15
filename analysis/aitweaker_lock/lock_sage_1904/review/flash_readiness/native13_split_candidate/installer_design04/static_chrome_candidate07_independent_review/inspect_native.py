"""Snapshot only the isolated candidate and inspect unchanged native bytes."""
from pathlib import Path
import hashlib,json,shutil,sys
HERE=Path(__file__).resolve().parent
D04=HERE.parent
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
CANDIDATE=D04/'static_chrome_candidate07'
SNAP=HERE/'input_candidate'
def main():
 assert not(SNAP/'snapshot.json').exists()
 rows=[]
 for p in sorted(CANDIDATE.rglob('*')):
  if not p.is_file()or any(x in ['__pycache__','zig-local','zig-global']for x in p.parts):continue
  rel=p.relative_to(CANDIDATE);out=SNAP/rel;out.parent.mkdir(parents=True,exist_ok=True)
  raw=p.read_bytes();out.write_bytes(raw)
  rows.append({'path':rel.as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
 (SNAP/'snapshot.json').write_text(json.dumps({'scope':'Unfrozen author input snapshot; not a deployment candidate','files':rows},indent=2)+'\n')
 module=D04.parent/'boot_context/AMITSE.original.efi'
 assert sha(module)=='531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1'
 pe=pefile.PE(data=module.read_bytes());cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
 section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
 refs=[]
 for i in cs.disasm(pe.get_data(section.VirtualAddress,section.Misc_VirtualSize),section.VirtualAddress):
  if not i.id:continue
  for op in i.operands:
   if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
    target=i.address+i.size+op.mem.disp
    if target in [0x93970,0x6b8b8,0x6bb20]:
     refs.append({'rva':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str,'target':hex(target)})
 (HERE/'native_slot_references.json').write_text(json.dumps({'module_sha256':sha(module),'refs':refs},indent=2)+'\n')
 ranges=[('frame_ctor',0x148e4,0x14a80),('static_ctor',0x16354,0x164d2),('page_render',0x16a90,0x16c20),('late_hii',0x171d4,0x17238),('subtitle_methods',0x1bd14,0x1c475),('base_initialize',0x1cafc,0x1cc20),('populate_frame',0x33634,0x33824),('expression_helper',0x31da4,0x31e36)]
 for name,start,end in ranges:
  lines=[]
  for i in cs.disasm(pe.get_data(start,end-start),start):
   suffix=''
   if i.id:
    rip=[i.address+i.size+op.mem.disp for op in i.operands if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP]
    if rip:suffix=' ; RIP -> '+','.join(hex(x)for x in rip)
   lines.append(f'{i.address:08X} {i.bytes.hex():32s} {i.mnemonic} {i.op_str}{suffix}')
  (HERE/(name+'.asm.txt')).write_text('\n'.join(lines)+'\n')
 print(json.dumps({'snapshot_files':len(rows),'slot_references':refs,'snapshot_sha256':sha(SNAP/'snapshot.json')}))
if __name__=='__main__':main()
