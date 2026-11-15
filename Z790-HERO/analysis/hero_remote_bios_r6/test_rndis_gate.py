"""Emulate only the donor entry's feature gate; intercept all firmware calls.
No USB, NVRAM or native module code executes on this host.
"""
from pathlib import Path
import hashlib,json,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
import struct
original=(OUT/'reference/11E32C34-60B5-4991-8DEA-63D3E8C876DE.efi').read_bytes()
patched=(OUT/'staged-drivers/H6RNDIS.EFI').read_bytes()
pe=pefile.PE(data=original);check=pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
allowed=set(range(0x512,0x51b))|set(range(check,check+4))
actual={i for i,(a,b) in enumerate(zip(original,patched)) if a!=b}
assert len(original)==len(patched) and actual<=allowed and set(range(0x512,0x51b))<=actual
def run(data,feature,boot,read_status):
 u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
 u.mem_map(0,0x10000);u.mem_write(0,pefile.PE(data=data).get_memory_mapped_image())
 u.mem_map(0x100000,0x20000);u.mem_map(0x200000,0x10000)
 stack=0x11f008;stop=0x208000;runtime=0x201000;bs=0x202000;st=0x203000
 def q(addr,n):u.mem_write(addr,struct.pack('<Q',n))
 q(0x23d0,bs);q(st+0x58,runtime);q(runtime+0x48,0x204000);q(bs+0x148,0x205000);q(stack,stop)
 u.reg_write(UC_X86_REG_RSP,stack);u.reg_write(UC_X86_REG_RCX,0x206000);u.reg_write(UC_X86_REG_RDX,st)
 calls=[]
 def ret(value):
  sp=u.reg_read(UC_X86_REG_RSP);pc=struct.unpack('<Q',u.mem_read(sp,8))[0]
  u.reg_write(UC_X86_REG_RAX,value);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,pc)
 def hook(uc,addr,size,_):
  if addr==stop:u.emu_stop();return
  if addr==0x204000:
   sp=u.reg_read(UC_X86_REG_RSP);buffer=struct.unpack('<Q',u.mem_read(sp+0x28,8))[0]
   block=bytearray(3398);block[0xbf5]=feature;u.mem_write(buffer,bytes(block))
   q(u.reg_read(UC_X86_REG_R9),3398);calls.append('GetVariable');ret(read_status)
  elif addr==0x2038:calls.append('BootMode');ret(boot)
  elif addr==0x205000:calls.append('InstallBinding');ret(0)
 u.hook_add(unicorn.UC_HOOK_CODE,hook)
 u.emu_start(0x464,stop+1,count=1000)
 assert u.reg_read(UC_X86_REG_RIP)==stop
 return calls
cases=[]
for label,data in [('original',original),('adapted',patched)]:
 for feature in (0,1,2,255):
  for boot in (0,0x12,0x20):
   for read_status in (0,0x800000000000000e):
    calls=run(data,feature,boot,read_status)
    expected=read_status==0 and boot not in (0x12,0x20) and (label=='adapted' or feature==1)
    assert ('InstallBinding' in calls)==expected
    cases.append({'image':label,'donor_feature_byte':feature,'boot_mode':boot,'get_variable_status':hex(read_status),'binding_installed':'InstallBinding' in calls})
result={'passed':True,'cases':len(cases),'patched_sha256':hashlib.sha256(patched).hexdigest(),'only_feature_gate_and_pe_checksum_changed':True,'setup_read_error_and_recovery_boot_gates_preserved':True,'results':cases}
(OUT/'rndis-gate-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='results'},indent=2))
