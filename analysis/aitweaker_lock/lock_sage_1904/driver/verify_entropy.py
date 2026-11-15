"""Fault-inject CPUID and RDSEED into the actual compiled x64 provider.
Checks feature gating, CF retry behavior, bounded failures, and partial wiping.
No CPU random output is exposed or used by these deterministic tests.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile,unicorn as U
from unicorn import x86_const as R
BASE=0x140000000;STACK=0x20000000;OUT=0x30000000;STOP=0x40000000
symbols={name:int(value,16) for name,value in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(HERE/'build/driver.map').read_text(),re.M)}
image=pefile.PE(str(HERE/'build/AiTweakerLock1904.efi')).get_memory_mapped_image()
decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
checks=[]
def case(label,*,support=True,maxleaf=7,fail=(),always_fail=False,length=32,expected_ok=True,expected_calls=4):
 u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64)
 u.mem_map(BASE,(len(image)+4095)&~4095);u.mem_write(BASE,image)
 for address in [STACK,OUT,STOP]:u.mem_map(address,0x10000)
 u.mem_write(OUT,b'\xa5'*512)
 calls=0;words=[]
 def hook(vm,address,size,_):
  nonlocal calls
  if address==STOP:vm.emu_stop();return
  op=next(decoder.disasm(bytes(vm.mem_read(address,size)),address))
  if op.mnemonic=='cpuid':
   leaf=vm.reg_read(R.UC_X86_REG_EAX)
   for reg in [R.UC_X86_REG_EAX,R.UC_X86_REG_EBX,R.UC_X86_REG_ECX,R.UC_X86_REG_EDX]:vm.reg_write(reg,0)
   if leaf==0:vm.reg_write(R.UC_X86_REG_EAX,maxleaf)
   if leaf==7:vm.reg_write(R.UC_X86_REG_EBX,(1<<18) if support else 0)
   vm.reg_write(R.UC_X86_REG_RIP,address+size)
  if op.mnemonic=='rdseed':
   calls+=1;ok=not always_fail and calls not in fail
   value=(0x9c4731a5b286d0e0+calls) if ok else 0
   vm.reg_write(getattr(R,'UC_X86_REG_'+op.op_str.upper()),value)
   vm.reg_write(R.UC_X86_REG_EFLAGS,(vm.reg_read(R.UC_X86_REG_EFLAGS)&~1)|int(ok))
   if ok:words.append(struct.pack('<Q',value))
   vm.reg_write(R.UC_X86_REG_RIP,address+size)
 u.hook_add(U.UC_HOOK_CODE,hook)
 sp=STACK+0xff08;u.mem_write(sp,struct.pack('<Q',STOP));u.reg_write(R.UC_X86_REG_RSP,sp)
 u.reg_write(R.UC_X86_REG_RCX,OUT+16);u.reg_write(R.UC_X86_REG_RDX,length)
 u.emu_start(symbols['cpu_entropy'],0,count=100000)
 assert u.reg_read(R.UC_X86_REG_RIP)==STOP,label+' did not return'
 result=u.reg_read(R.UC_X86_REG_RAX)
 assert (result==0)==expected_ok,(label,result)
 assert calls==expected_calls,(label,calls)
 assert bytes(u.mem_read(OUT,16))==b'\xa5'*16,label+' prefix overwrite'
 assert bytes(u.mem_read(OUT+16+length,16))==b'\xa5'*16,label+' suffix overwrite'
 if expected_ok:assert bytes(u.mem_read(OUT+16,length))==b''.join(words)[:length],label+' incorrect CF/data handling'
 elif 0<length<=256:assert bytes(u.mem_read(OUT+16,length))==b'\0'*length,label+' partial data retained'
 checks.append({'case':label,'rdseed_attempts':calls,'passed':True})
case('four successful 64-bit seeds')
case('unsupported feature never executes RDSEED',support=False,expected_ok=False,expected_calls=0)
case('unsupported CPUID leaf never executes RDSEED',maxleaf=6,expected_ok=False,expected_calls=0)
case('temporary CF failures retry and do not copy invalid words',fail=(1,2,4,6),expected_calls=8)
case('CF exhaustion stops at 64 and wipes output',always_fail=True,expected_ok=False,expected_calls=64)
case('failure after first seed wipes entire partial result',fail=tuple(range(2,66)),expected_ok=False,expected_calls=65)
case('last permitted retry accepted',fail=tuple(range(1,64)),length=8,expected_calls=64)
case('odd-size request respects canaries',length=13,expected_calls=2)
case('empty request is rejected',length=0,expected_ok=False,expected_calls=0)
case('oversize request is rejected',length=257,expected_ok=False,expected_calls=0)
result={'passed':True,'driver_sha256':hashlib.sha256((HERE/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest(),'checks':checks,'scope':'Actual compiled CPU provider with explicitly mocked CPUID/RDSEED outcomes; not a hardware entropy certification.'}
(HERE/'build/entropy_test.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
