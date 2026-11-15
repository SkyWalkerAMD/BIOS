"""Replay AMITSE's unmodified boot-launch function with synthetic UEFI services.

Checks dispatch ordering for normal returning applications and failed LoadImage.
No target hardware. Retained REA decompilation is the structural evidence; this
test corroborates selected concrete machine-code paths, not all AMITSE callers.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
IMAGE=ROOT/'analysis/hero_rea_20261102/HERO-3107-AMITSE.efi'
SHA='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
BEFORE='3677770f-efb2-43b2-b8ae-b302e9604882'
AFTER='8c12a959-70bc-4362-b437-b80514a1916e'

def replay(pe,load_error=False,start_error=False,early_before=False):
 mu=Uc(UC_ARCH_X86,UC_MODE_64);mu.mem_map(0,(pe.OPTIONAL_HEADER.SizeOfImage+0xfff)&~0xfff);mu.mem_write(0,pe.get_memory_mapped_image())
 mu.mem_map(0x3000000,0x10000);mu.mem_map(0x4000000,0x10000)
 bs=0x3001000;st=0x3002000;loaded=0x3003000;arg=0x3004000;stop=0x300f000
 def put(a,v):mu.mem_write(a,struct.pack('<Q',v))
 def get(a):return int.from_bytes(mu.mem_read(a,8),'little')
 put(0x180188,bs);put(0x180180,st);put(0x1801a0,4);put(0x18026c,0)
 for a in (0x180200,0x190698,0x1906a0):put(a,0)
 mu.mem_write(arg,b'\x01\x01\x04\x00\x7f\xff\x04\x00')
 mu.mem_write(loaded+0x50,struct.pack('<I',1))
 calls=[];publications=[]
 services={}
 for off in (0x18,0x20,0x48,0x68,0x70,0x98,0xb8,0xc8,0xd0,0x100,0x170):
  services[0x3008000+off]=off;put(bs+off,0x3008000+off)
 cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
 direct={x.operands[0].imm for x in cs.disasm(pe.get_memory_mapped_image()[0xd090:0xdc68],0xd090) if x.mnemonic=='call' and x.operands[0].type==capstone.x86.X86_OP_IMM}
 def ret(value=0):
  sp=mu.reg_read(UC_X86_REG_RSP);dest=get(sp);mu.reg_write(UC_X86_REG_RSP,sp+8);mu.reg_write(UC_X86_REG_RIP,dest);mu.reg_write(UC_X86_REG_RAX,value)
 def hook(mu,a,size,_):
  if a in services:
   off=services[a];calls.append(dict(kind='service',offset=hex(off),return_site=hex(get(mu.reg_read(UC_X86_REG_RSP)))))
   if off==0x170:put(get(mu.reg_read(UC_X86_REG_RSP)+0x30),0x3005000)
   elif off==0xc8:
    if load_error:ret(0x800000000000000e);return
    put(get(mu.reg_read(UC_X86_REG_RSP)+0x30),0x1234)
   elif off==0xb8:ret(0x800000000000000e);return
   elif off==0x98:put(mu.reg_read(UC_X86_REG_R8),loaded)
   elif off==0xd0:
    ret(0x8000000000000007 if start_error else 0);return
   ret(4 if off==0x18 else 0)
  elif a in direct:
   return_site=get(mu.reg_read(UC_X86_REG_RSP));rec=dict(kind='function',rva=hex(a),return_site=hex(return_site))
   if a==0x176c:
    guid=str(uuid.UUID(bytes_le=bytes(mu.mem_read(mu.reg_read(UC_X86_REG_RCX),16))))
    rec['guid']=guid;publications.append(dict(guid=guid,call_rva=hex(return_site-5)))
   elif a==0x3c38:rec['callback_selector']=hex(mu.reg_read(UC_X86_REG_RCX))
   calls.append(rec)
   if a==0xfa54:ret(int(early_before))
   elif a==0x490a4:ret(0x800000000000000e)
   else:ret()
 mu.hook_add(UC_HOOK_CODE,hook)
 sp=0x400f008;put(sp,stop);mu.reg_write(UC_X86_REG_RSP,sp);mu.reg_write(UC_X86_REG_RCX,arg);mu.reg_write(UC_X86_REG_RDX,0);mu.reg_write(UC_X86_REG_R8,0);mu.reg_write(UC_X86_REG_R9,0)
 mu.emu_start(0xd090,stop,count=100000)
 assert mu.reg_read(UC_X86_REG_RIP)==stop
 assert [x['guid'] for x in publications]==[BEFORE,AFTER],publications
 return dict(load_error=load_error,start_error=start_error,early_before=early_before,publications=publications,calls=calls,return_status=hex(mu.reg_read(UC_X86_REG_RAX)))

def main():
 raw=IMAGE.read_bytes();assert hashlib.sha256(raw).hexdigest()==SHA
 pe=pefile.PE(data=raw)
 cases=[replay(pe),replay(pe,start_error=True),replay(pe,load_error=True,early_before=True)]
 retained=ROOT/'analysis/hero_ipmi_p6_20261104/native/rea-loopback/responses/012-boot-lifecycle.json'
 evidence=json.loads(retained.read_text())['result']['structuredContent']
 report=dict(image=str(IMAGE.relative_to(ROOT)),sha256=SHA,before_guid=BEFORE,after_guid=AFTER,cases=cases,
  reused_rea=dict(file=str(retained.relative_to(ROOT)),sha256=hashlib.sha256(retained.read_bytes()).hexdigest(),evidence_id=evidence['evidence_id']),
  conclusion='Normal StartImage success return and failure return both publish AfterBoot at RVA 0xDAEC; selected early BeforeBoot plus LoadImage failure publishes AfterBoot at RVA 0xDBF1.',
  boundary='Whole immutable AMITSE 0xD090 machine-code function with synthetic UEFI and mocked nonessential helpers. Special callback 0x4E93C and other direct/indirect launches need separate coverage.')
 (HERE/'afterboot-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
 print(json.dumps([{k:v for k,v in c.items() if k!='calls'} for c in cases],indent=2))
if __name__=='__main__':main()
