"""Execute exact original/private PE gates; UEFI services are mocked, no hardware."""
from pathlib import Path
import hashlib,json,struct,sys,uuid
BASE=Path(__file__).resolve().parents[1]; ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import *
manifest=json.loads((BASE/'staged-drivers/manifest.json').read_text())
gates={'SnpDxe':(0x5d0,0x619,0x5100),'MnpDxe':(0x5f4,0x63d,0x6828),'ArpDxe':(0x5f4,0x63d,0x2fc0),'Ip4Dxe':(0x6b4,0x705,0xc4a8),'TcpDxe':(0x640,0x697,0xb6f8)}
def machine(data):
 p=pefile.PE(data=data);u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
 u.mem_map(0,0x20000);u.mem_write(0,p.get_memory_mapped_image());u.mem_map(0x100000,0x20000);u.mem_map(0x200000,0x10000)
 stack=0x11f008;stop=0x208000;u.mem_write(stack,struct.pack('<Q',stop));u.reg_write(UC_X86_REG_RSP,stack);u.reg_write(UC_X86_REG_RCX,0x207000)
 return u,stop
def call_gate(data,start,end,rt_rva,flag,error):
 u,stop=machine(data);u.mem_write(rt_rva,struct.pack('<Q',0x201000));u.mem_write(0x201048,struct.pack('<Q',0x204000));calls=[]
 def hook(_,at,size,ctx):
  if at in (stop,end):calls.append('pass' if at==end else 'return');u.emu_stop();return
  if at!=0x204000:return
  sp=u.reg_read(UC_X86_REG_RSP);out=struct.unpack('<Q',u.mem_read(sp+0x28,8))[0]
  assert bytes(u.mem_read(u.reg_read(UC_X86_REG_RCX),32))=='NetworkStackVar\0'.encode('utf-16le')
  assert bytes(u.mem_read(u.reg_read(UC_X86_REG_RDX),16))==uuid.UUID('d1405d16-7afc-4695-bb12-41459d3695a2').bytes_le
  assert struct.unpack('<Q',u.mem_read(u.reg_read(UC_X86_REG_R9),8))[0]==8
  u.mem_write(out,bytes([flag,1,0,0,0,0,0,0]));calls.append('GetVariable')
  pc=struct.unpack('<Q',u.mem_read(sp,8))[0];u.reg_write(UC_X86_REG_RAX,error);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,pc)
 u.hook_add(unicorn.UC_HOOK_CODE,hook);u.emu_start(start,stop+1,count=1000)
 assert calls[0]=='GetVariable' and len(calls)==2,calls
 if calls[-1]=='return':assert u.reg_read(UC_X86_REG_RAX)==0x8000000000000003
 return calls[-1]=='pass'
rows=[]
for m in manifest[:6]:
 original=(BASE/'reference'/(m['name']+'.efi')).read_bytes();patched=(BASE/'staged-drivers'/m['file']).read_bytes()
 assert hashlib.sha256(original).hexdigest()==m['source_sha256'] and hashlib.sha256(patched).hexdigest()==m['sha256']
 p=pefile.PE(data=original);checksum=p.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum');allowed=set(range(checksum,checksum+4))
 for patch in m['patches']:
  off=patch['file_offset'];old=bytes.fromhex(patch['old']);new=bytes.fromhex(patch['new'])
  assert original[off:off+len(old)]==old and patched[off:off+len(new)]==new;allowed.update(range(off,off+len(old)))
 assert len(original)==len(patched) and {i for i,(a,b) in enumerate(zip(original,patched)) if a!=b}<=allowed
 if m['name'] not in gates:continue
 start,end,rt=gates[m['name']]
 for label,data in [('original',original),('private',patched)]:
  for flag in (0,1,2,255):
   for error in (0,0x800000000000000e,0x8000000000000005,0x8000000000000007):
    passed=call_gate(data,start,end,rt,flag,error);expected=not error and (label=='private' or flag!=0);assert passed==expected
    rows.append({'image':m['name'],'copy':label,'flag':flag,'get_status':hex(error),'passed_gate':passed})
ip4=(BASE/'staged-drivers/I5IP4DXE.EFI').read_bytes()
for entry,result in ((0x5bbc,0x800000000000000e),(0x5d88,0)):
 for param in (0,0x8000000000000000,0x207000):
  u,stop=machine(ip4);u.reg_write(UC_X86_REG_RCX,param);u.reg_write(UC_X86_REG_RDX,param)
  u.emu_start(entry,stop,count=20)
  assert u.reg_read(UC_X86_REG_RIP)==stop and u.reg_read(UC_X86_REG_RAX)==result
report={'passed':True,'gate_cases':len(rows),'ip4_no_persistence_cases':6,'exact_allowed_differences':True,'firmware_services':'mocked','results':rows}
(BASE/'tests/machine-patches.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='results'}))
