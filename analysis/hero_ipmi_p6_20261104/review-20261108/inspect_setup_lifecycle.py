"""Corroborate retained REA SetupEnter analysis with exact PE disassembly.

Read-only static reference search, and actual AMITSE helper execution with
synthetic Boot Services. This is not a full GUI or firmware boot simulation.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
IMAGE=ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi'
EXPECTED='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
FLAG=0x1908a0;FUNCTION=0x3d204

def main():
 raw=IMAGE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
 pe=pefile.PE(data=raw);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True;cs.skipdata=True
 refs=[];callers=[];contexts=[]
 for s in pe.sections:
  if not s.Characteristics&0x20000000:continue
  instructions=list(cs.disasm(s.get_data(),s.VirtualAddress))
  for i,x in enumerate(instructions):
   if not x.id:continue
   touches=[]
   for op in x.operands:
    if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
     ptr=x.address+x.size+op.mem.disp
     if ptr<=FLAG<ptr+op.size:
      touches.append(dict(address=hex(ptr),width=op.size,access=op.access))
   if touches:
    refs.append(dict(rva=hex(x.address),instruction=f'{x.mnemonic} {x.op_str}',bytes=x.bytes.hex(),access=touches))
    contexts.append([f'{y.address:08X}: {y.bytes.hex()} {y.mnemonic} {y.op_str}' for y in instructions[max(0,i-7):i+8]])
   if x.mnemonic=='call' and x.operands[0].type==capstone.x86.X86_OP_IMM and x.operands[0].imm==FUNCTION:
    callers.append(hex(x.address))
 mu=Uc(UC_ARCH_X86,UC_MODE_64);mu.mem_map(0,(pe.OPTIONAL_HEADER.SizeOfImage+0xfff)&~0xfff);mu.mem_write(0,pe.get_memory_mapped_image())
 mu.mem_map(0x3000000,0x10000);mu.mem_map(0x4000000,0x10000)
 events=[];other_calls=[];stop=0x3000f00
 def ret(value=0):
  sp=mu.reg_read(UC_X86_REG_RSP);dest=int.from_bytes(mu.mem_read(sp,8),'little');mu.reg_write(UC_X86_REG_RSP,sp+8);mu.reg_write(UC_X86_REG_RIP,dest);mu.reg_write(UC_X86_REG_RAX,value)
 def hook(mu,a,size,user):
  if a==0x176c:
   p=mu.reg_read(UC_X86_REG_RCX);events.append(str(uuid.UUID(bytes_le=bytes(mu.mem_read(p,16)))));ret()
  elif a in (0x3c38,0xb467c,0xb1c80):other_calls.append(hex(a));ret()
 mu.hook_add(UC_HOOK_CODE,hook)
 def call():
  sp=0x400f008;mu.mem_write(sp,struct.pack('<Q',stop));mu.reg_write(UC_X86_REG_RSP,sp);mu.emu_start(FUNCTION,stop,count=100000)
  assert mu.reg_read(UC_X86_REG_RIP)==stop
 mu.mem_write(FLAG,b'\0');call();first=list(events);call();second=list(events)
 assert first==['71202eee-5f53-40d9-ab3d-9e0c26d96657']*2 and second==first
 retained=ROOT/'analysis/hero_ipmi_p5_rea_review_20261103/amitse/responses/005-setupenter-signal.json'
 rr=json.loads(retained.read_text());content=rr['result']
 if 'structuredContent' in content:rea=content['structuredContent']
 else:rea=json.loads(content['content'][0]['text'])
 report=dict(image=str(IMAGE.relative_to(ROOT)),sha256=EXPECTED,flag_rva=hex(FLAG),function_rva=hex(FUNCTION),
   direct_rip_relative_flag_references=refs,direct_callers=callers,contexts=contexts,
   emulation=dict(first_call_publications=first,total_publications_after_second_call=second,other_mocked_calls=other_calls),
   reused_rea=dict(file=str(retained.relative_to(ROOT)),sha256=hashlib.sha256(retained.read_bytes()).hexdigest(),evidence_id=rea.get('evidence_id')),
   conclusion='The known SetupEnter publisher has a persistent per-image guard. Calling it again alone does not republish the marker. A stop-on-return guarantee needs separate evidence of guard reset or another return notification.',
   boundary='Direct RIP-relative executable-section references only; indirect writes/bulk state clearing and actual platform boot paths are not excluded by this scan.')
 (HERE/'setupenter-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items() if k!='contexts'},indent=2))
if __name__=='__main__':main()
