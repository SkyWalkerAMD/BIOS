"""Execute exact final lab entry with deliberately unmapped UEFI pointers."""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_INSN,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
efi=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else HERE/'build/W890-Installer04.TCG-ONLY.efi'
raw=efi.read_bytes();pe=pefile.PE(data=raw)
results=[]
for label,cpuvalues in [('bare_metal',(0,0,0,0)),('another_hypervisor',(0x40000001,0x7263694d,0x666f736f,0x76482074))]:
 u=Uc(UC_ARCH_X86,UC_MODE_64);base=pe.OPTIONAL_HEADER.ImageBase;size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
 u.mem_map(base,size);u.mem_write(base,pe.get_memory_mapped_image());before=bytes(u.mem_read(base,size))
 stack=0x20000000;stop=0x21000000;u.mem_map(stack,0x10000);u.mem_map(stop,0x1000)
 u.reg_write(UC_X86_REG_RSP,stack+0xff08);u.mem_write(stack+0xff08,struct.pack('<Q',stop))
 u.reg_write(UC_X86_REG_RCX,0xdead0000);u.reg_write(UC_X86_REG_RDX,0xdead1000)
 writes=[];calls=[]
 def cpuid(uc,unused):
  calls.append(uc.reg_read(UC_X86_REG_EAX))
  for reg,x in zip([UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX],cpuvalues):uc.reg_write(reg,x)
  return 1
 u.hook_add(UC_HOOK_INSN,cpuid,None,1,0,UC_X86_INS_CPUID)
 u.hook_add(UC_HOOK_MEM_WRITE,lambda uc,access,address,n,value,user:writes.append((address,n)))
 u.emu_start(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint,stop,count=2000)
 assert u.reg_read(UC_X86_REG_RIP)==stop and u.reg_read(UC_X86_REG_RAX)==0x8000000000000003
 assert calls==[0x40000000] and all(stack<=a and a+n<=stack+0x10000 for a,n in writes)
 assert bytes(u.mem_read(base,size))==before
 results.append({'case':label,'passed':True,'firmware_services_accessed':False,'image_unchanged':True})
report={'status':'PASS_ACTUAL_ENTRY_NON_TCG_REFUSAL','efi_sha256':hashlib.sha256(raw).hexdigest(),'cases':results,'scope':'Actual entry code; CPUID is explicitly modeled, all UEFI pointers unmapped. Not a physical deployment qualification.'}
dest=efi.with_suffix('.guard.json') if len(sys.argv)>1 else HERE/'build/entry_guard_tests.json'
dest.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
