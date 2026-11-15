"""Execute the actual lab entry with non-TCG CPUID; no firmware service is mapped."""
from pathlib import Path
import hashlib
import json
import struct
import sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent.parents[2]
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_INSN,UC_HOOK_MEM_WRITE
from unicorn.x86_const import *

folder=HERE/'runs/20261108_013828'
efi=folder/'W890-HII-LAB01.TCG-ONLY.efi';raw=efi.read_bytes();pe=pefile.PE(data=raw)
assert hashlib.sha256(raw).hexdigest()==json.loads((folder/'result.json').read_text())['efi_sha256']
results=[]
for name,cpuid in [('physical_vendor',(0,0,0,0)),('wrong_hypervisor',(0x40000001,0x7263694d,0x666f736f,0x76482074))]:
    u=Uc(UC_ARCH_X86,UC_MODE_64);base=pe.OPTIONAL_HEADER.ImageBase
    size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
    u.mem_map(base,size);u.mem_write(base,pe.get_memory_mapped_image())
    before=bytes(u.mem_read(base,size));u.mem_map(0x500000,0x10000);u.mem_map(0x600000,0x1000)
    u.reg_write(UC_X86_REG_RSP,0x50ff08);u.mem_write(0x50ff08,struct.pack('<Q',0x600000))
    u.reg_write(UC_X86_REG_RCX,0xdead0000);u.reg_write(UC_X86_REG_RDX,0xdead1000)
    writes=[];calls=[]
    def cpu(uc,unused):
        calls.append(uc.reg_read(UC_X86_REG_EAX))
        for reg,value in zip([UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX],cpuid):uc.reg_write(reg,value)
        return 1
    u.hook_add(UC_HOOK_INSN,cpu,None,1,0,UC_X86_INS_CPUID)
    u.hook_add(UC_HOOK_MEM_WRITE,lambda uc,access,address,length,value,user:writes.append((address,length)))
    u.emu_start(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint,0x600000,count=1000)
    assert u.reg_read(UC_X86_REG_RIP)==0x600000 and u.reg_read(UC_X86_REG_RAX)==0x8000000000000003
    assert calls==[0x40000000] and all(0x500000<=a and a+n<=0x510000 for a,n in writes)
    assert bytes(u.mem_read(base,size))==before
    results.append({'case':name,'passed':True,'firmware_service_access':False,'image_memory_unchanged':True})
report={'passed':True,'cases':results,'efi_sha256':hashlib.sha256(raw).hexdigest(),'scope':'Actual entry instructions. Non-TCG CPUID modeled; system table deliberately unmapped. Not a board safety guarantee.'}
(folder/'entry_guard_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report))
