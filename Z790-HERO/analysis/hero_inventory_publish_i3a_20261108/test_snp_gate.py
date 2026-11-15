"""Actual SnpDxe machine-code gate replay; no target/host hardware operations."""
from pathlib import Path
import hashlib,json,sys,struct,uuid
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import *
original=(OUT/'reference/SnpDxe.efi').read_bytes();patched=(OUT/'staged-drivers/I3ASNP.EFI').read_bytes()
pe=pefile.PE(data=original);check=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
allowed=set(range(pe.get_offset_from_rva(0x613),pe.get_offset_from_rva(0x619)))|set(range(check,check+4))
assert len(original)==len(patched) and {i for i,(a,b) in enumerate(zip(original,patched)) if a!=b}<=allowed
def run(data,flag,read_status):
 u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);u.mem_map(0,0x10000);u.mem_write(0,pefile.PE(data=data).get_memory_mapped_image());u.mem_map(0x100000,0x20000);u.mem_map(0x200000,0x10000)
 def q(a,v):u.mem_write(a,struct.pack('<Q',v))
 stack=0x11f008;stop=0x208000;rt=0x201000;bs=0x202000
 q(0x5100,rt);q(0x50f8,bs);q(rt+0x48,0x204000);q(rt+0x58,0x206000);q(bs+0x148,0x205000);q(stack,stop)
 u.reg_write(UC_X86_REG_RSP,stack);u.reg_write(UC_X86_REG_RCX,0x207000);calls=[]
 def ret(v):
  sp=u.reg_read(UC_X86_REG_RSP);pc=struct.unpack('<Q',u.mem_read(sp,8))[0];u.reg_write(UC_X86_REG_RAX,v);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,pc)
 def hook(uc,a,n,_):
  if a==stop:u.emu_stop();return
  if a==0x204000:
   sp=u.reg_read(UC_X86_REG_RSP);buf=struct.unpack('<Q',u.mem_read(sp+0x28,8))[0]
   assert bytes(u.mem_read(u.reg_read(UC_X86_REG_RCX),32))=='NetworkStackVar\0'.encode('utf-16le')
   assert bytes(u.mem_read(u.reg_read(UC_X86_REG_RDX),16))==uuid.UUID('d1405d16-7afc-4695-bb12-41459d3695a2').bytes_le
   assert struct.unpack('<Q',u.mem_read(u.reg_read(UC_X86_REG_R9),8))[0]==8
   u.mem_write(buf,bytes([flag,1,1,0,0,1,0,0]));calls.append('GetVariable');ret(read_status)
  elif a==0x205000:calls.append('InstallBinding');ret(0)
  elif a==0x206000:raise AssertionError('No SetVariable allowed')
 u.hook_add(unicorn.UC_HOOK_CODE,hook);u.emu_start(0x5d0,stop+1,count=1000)
 assert u.reg_read(UC_X86_REG_RIP)==stop;return calls,u.reg_read(UC_X86_REG_RAX)
rows=[]
for label,data in [('original',original),('RAM-SNP',patched)]:
 for flag in (0,1,2,255):
  for status in (0,0x800000000000000e,0x8000000000000005,0x8000000000000007):
   calls,result=run(data,flag,status);expected=not status and (label=='RAM-SNP' or flag!=0)
   assert ('InstallBinding' in calls)==expected
   assert result==(0 if expected else 0x8000000000000003)
   rows.append({'image':label,'flag':flag,'get_status':hex(status),'binding':expected,'result':hex(result)})
report={'passed':True,'cases':len(rows),'only_gate_and_checksum_modified':True,'no_firmware_calls_executed':True,'source_sha256':hashlib.sha256(original).hexdigest(),'patched_sha256':hashlib.sha256(patched).hexdigest(),'results':rows}
(OUT/'snp-gate-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}))
