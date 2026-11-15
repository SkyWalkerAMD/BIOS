"""Execute the delivered PE against strict read-only UEFI doubles, no devices."""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
for sub in ['tools/pydeps','tools/kvm-pydeps']:sys.path.insert(0,str(ROOT/sub))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_READ
from unicorn.x86_const import *

ERR=lambda n:0x8000000000000000|n
PCI='4cf5b200-68b8-4ca5-9eec-b23e3f50029a'
PATH='09576e91-6d3f-11d2-8e39-00a0c969723b'
BLOCK='964e5b21-6459-11d2-8e39-00a0c969723b'
DISK='d432a67f-14dc-484b-b3bb-3f0291849327'
NVME='3ab14680-5d3f-4a4d-bcdc-cc380018c7f7'
AHCI='9e498932-4abc-45af-a34d-0247787be7c6'
USB='cb871572-c11a-47b5-b492-675eafa77727'
APP=P/'USB/EFI/BOOT/BOOTX64.EFI'

class Machine:
 def __init__(self,scenario='normal',keys='qq'):
  self.scenario=scenario;self.keys=list(keys);self.calls=[];self.logs=bytearray();self.screen='';self.owned=set();self.frees=[];self.identify_calls=0;self.config_calls=0
  self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.pe=pefile.PE(str(APP));self.base=self.pe.OPTIONAL_HEADER.ImageBase
  self.u.mem_map(self.base,(self.pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.u.mem_write(self.base,self.pe.get_memory_mapped_image())
  self.u.mem_map(0x1000000,0x800000);self.next=0x1000000
  self.u.mem_map(0x2000000,0x10000);self.stub_next=0x2000000;self.stubs={}
  self.u.mem_map(0x7000000,0x100000);self.stop=0x200fff0;self.u.mem_write(self.stop,b'\xf4')
  self.bs=self.alloc(bytes(0x178));self.st=self.alloc(bytes(0x78));self.out=self.alloc(bytes(80));self.inp=self.alloc(bytes(24))
  self.w64(self.st+0x60,self.bs);self.w64(self.st+0x40,self.out);self.w64(self.st+0x30,self.inp)
  self.stub(self.out+8,'Output');self.stub(self.inp+8,'Key');self.w64(self.inp+16,0x999)
  for offset in range(0x18,0x178,8):self.stub(self.bs+offset,'ForbiddenBootService')
  for offset,name in [(0x38,'GetMap'),(0x48,'FreePool'),(0x98,'Handle'),(0x138,'Handles'),(0x100,'Watchdog')]:self.stub(self.bs+offset,name)
  self.pci=self.alloc(bytes(160));self.block=self.alloc(bytes(48));self.disk=self.alloc(bytes(48));self.media=self.alloc(bytes(48))
  for off in range(0,144,8):self.stub(self.pci+off,'ForbiddenPCI')
  self.stub(self.pci+0x30,'Config');self.stub(self.pci+0x70,'Location')
  for off in (16,24,32,40):self.stub(self.block+off,'ForbiddenBlock')
  self.w64(self.block,0x2001f);self.w64(self.block+8,self.media)
  self.u.mem_write(self.media,struct.pack('<I5B3xII4xQQII',3,0,1,0,1,0,512,1,100,0,1,0))
  iface=USB if scenario=='unknown_disk' else (AHCI if scenario in ['ata','identify_overrun','short_identify'] else NVME)
  self.u.mem_write(self.disk,uuid.UUID(iface).bytes_le)
  for off in (16,24,32,40):self.stub(self.disk+off,'ForbiddenDisk')
  self.stub(self.disk+24,'Identify')
  self.path_data=bytes.fromhex('010106000000030A10000000000000000000000000007FFF0400')
  # Generic bounded path is retained verbatim; precise controller/namespace link
  # is deliberately left to the decoder rather than fabricated by the fixture.
  self.path_data=bytes.fromhex('0101060000007FFF0400')
  if scenario=='malformed_path':self.path_data=bytes.fromhex('01010000')
  if scenario=='maximum_records':self.path_data=b'\x01\x01\xfc\x03'+bytes(1016)+b'\x7f\xff\x04\0'
  self.path=self.alloc(self.path_data)
  self.media_reads=0
  if scenario=='media_changes':self.u.hook_add(UC_HOOK_MEM_READ,self.media_hook,begin=self.media,end=self.media+47)
  self.append=self.new_stub('Append')
  self.u.hook_add(UC_HOOK_CODE,self.hook)
 def alloc(self,data):
  p=self.next;self.next+=(len(data)+15)&~15;assert self.next<0x1800000;self.u.mem_write(p,data);return p
 def w64(self,p,v):self.u.mem_write(p,struct.pack('<Q',v))
 def r64(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
 def guid(self,p):return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(p,16))))
 def new_stub(self,name):
  p=self.stub_next;self.stub_next+=16;self.stubs[p]=name;self.u.mem_write(p,b'\xc3');return p
 def stub(self,slot,name):self.w64(slot,self.new_stub(name))
 def media_hook(self,u,access,address,size,value,user):
  if address==self.media:
   self.media_reads+=1
   if self.media_reads==2:self.w64(self.media+24,101)
 def hook(self,u,address,size,user):
  if address==self.stop:u.emu_stop();return
  if address not in self.stubs:return
  name=self.stubs[address];self.calls.append(name);assert not name.startswith('Forbidden'),name
  rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8,(name,hex(rsp))
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
  status=0
  if name=='Output':
   s=bytearray()
   for off in range(0,10000,2):
    ch=bytes(u.mem_read(b+off,2))
    if ch==b'\0\0':break
    s+=ch
   self.screen+=s.decode('utf-16le')
  elif name=='Key':
   assert self.keys,'unexpected key wait';k=ord(self.keys.pop(0));u.mem_write(b,struct.pack('<HH',0x17 if k==27 else 0,k))
  elif name=='Watchdog':
   assert (a,b,c,d)==(0,0,0,0);status=ERR(3) if self.scenario=='watchdog_fail' else 0
  elif name=='Append':
   assert a==0 and c<=256
   if self.scenario=='output_full' and len(self.logs)>1200:status=0
   else:self.logs+=bytes(u.mem_read(b,c));status=1
  elif name=='GetMap':
   if self.scenario=='map_error':self.w64(a,262145);status=ERR(5)
   else:
    ds=48;descs=[]
    for start,pages in [(0x1000000,0x800),(0x2000000,0x10),(self.base,(self.pe.OPTIONAL_HEADER.SizeOfImage+4095)//4096)]:
     typ=11 if self.scenario=='mmio_map' else 4
     descs.append(struct.pack('<IIQQQQ',typ,0,start,0,pages,0)+bytes(8))
    blob=b''.join(descs);assert self.r64(a)>=len(blob);u.mem_write(b,blob);self.w64(a,len(blob));self.w64(c,1);self.w64(d,ds);u.mem_write(self.r64(rsp+40),struct.pack('<I',1))
  elif name=='Handles':
   assert a==2 and c==0;g=self.guid(b);assert g in [PCI,BLOCK,DISK]
   out=self.r64(rsp+40)
   if self.scenario=='no_devices':status=ERR(14)
   else:
    hs=[{PCI:0x1111,BLOCK:0x2222,DISK:0x3333}[g]]
    if self.scenario=='count_cap' and g==PCI:hs=[0x5555]*129
    if self.scenario=='maximum_records':hs*=64 if g==DISK else 128
    ptr=self.alloc(b''.join(struct.pack('<Q',h) for h in hs));self.owned.add(ptr);self.w64(d,len(hs));self.w64(out,ptr)
    if self.scenario=='enum_error_with_buffer':status=ERR(7)
  elif name=='Handle':
   g=self.guid(b)
   if a==0x5555:status=ERR(14)
   elif g==PATH:
    if self.scenario=='path_missing':status=ERR(14)
    else:self.w64(c,0x90000000 if self.scenario=='path_outside_map' else self.path)
   elif (a,g) in [(0x1111,PCI),(0x2222,BLOCK),(0x3333,DISK)]:
    ptr={PCI:self.pci,BLOCK:self.block,DISK:self.disk}[g]
    self.w64(c,0x90000000 if self.scenario=='protocol_outside_map' else ptr)
   else:raise AssertionError((a,g))
  elif name=='FreePool':
   assert a in self.owned;self.owned.remove(a);self.frees.append(a);status=ERR(7) if self.scenario=='free_fail' else 0
  elif name=='Location':
   assert a==self.pci;self.w64(b,0);self.w64(c,1);self.w64(d,0);self.w64(self.r64(rsp+40),0)
   if self.scenario=='location_error':status=ERR(7)
  elif name=='Config':
   assert (a,b,c,d)==(self.pci,0,0,256);self.config_calls+=1
   ptr=self.r64(rsp+40);config=bytearray(256);struct.pack_into('<HH',config,0,0x8086,0x1234);config[9:12]=bytes((2,8,1));u.mem_write(ptr,bytes(config))
   if self.scenario=='config_error':status=ERR(7)
  elif name=='Identify':
   assert a==self.disk;self.identify_calls+=1;n=struct.unpack('<I',u.mem_read(c,4))[0];assert n in (512,4096)
   if self.scenario=='identify_error':status=ERR(7)
   elif self.scenario=='identify_too_large':u.mem_write(c,struct.pack('<I',8192));status=ERR(5)
   else:
    u.mem_write(b,bytes((i*7+3)&255 for i in range(n)))
    if self.scenario=='identify_overrun':u.mem_write(b+n,b'X')
    if self.scenario=='short_identify':u.mem_write(c,struct.pack('<I',256))
  else:raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,status)
  for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
 def run(self,entry=False):
  if entry:address=self.base+self.pe.OPTIONAL_HEADER.AddressOfEntryPoint;args=[0x100, self.st,0]
  else:
   text=(P/'launcher.map').read_text();match=re.search(r'\bpcie_storage_collect\s+([0-9a-fA-F]{16})',text);assert match
   address=int(match[1],16);args=[self.st,self.append,0]
  stack=0x70ffef8;self.w64(stack,self.stop);self.u.reg_write(UC_X86_REG_RSP,stack)
  for reg,value in zip((UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8),args):self.u.reg_write(reg,value)
  self.u.emu_start(address,self.stop,count=80_000_000)
  assert self.u.reg_read(UC_X86_REG_RIP)==self.stop,'instruction limit/abnormal exit'
  assert not self.owned,'unreleased enumeration buffers'
  return self.u.reg_read(UC_X86_REG_RAX)

def main():
 rows=[]
 for case in ['normal','ata','unknown_disk','identify_error','identify_too_large','short_identify','identify_overrun',
              'no_devices','map_error','mmio_map','count_cap','path_missing','path_outside_map','protocol_outside_map',
              'malformed_path','media_changes','location_error','config_error','enum_error_with_buffer','free_fail','output_full','maximum_records']:
  m=Machine(case);status=m.run();log=bytes(m.logs)
  assert status==(ERR(5) if case=='output_full' else ERR(7) if case=='free_fail' else 0),(case,hex(status))
  if case not in ['output_full']:assert log.endswith(b'I4_CATALOG_END\r\n')
  if case in ['normal','ata']:
   assert b'MEDIA_FIELDS_STABLE=01' in log and b'IDENTIFY_FORMAT_SIZE_MATCH=01' in log and b'CONFIG_CRC32=' in log
  if case=='normal':(P/'mock-catalog.TXT').write_bytes(log)
  if case=='unknown_disk':assert m.identify_calls==0 and b'INTERFACE_NOT_ALLOWLISTED' in log
  if case in ['identify_error','identify_too_large','identify_overrun']:assert b'IDENTIFY_HEX_BEGIN' not in log
  if case=='identify_too_large':assert m.identify_calls==1
  if case=='media_changes':assert b'MEDIA_FIELDS_STABLE=00' in log
  if case=='count_cap':assert b'ENUM_CAPTURED=00000080' in log and b'ENUM_TRUNCATED=01' in log
  if case=='maximum_records':
   assert len(log)<2097152-1024 and m.config_calls==128 and m.identify_calls==64
   assert log.count(b'BLOCK_BEGIN\r\n')==128 and b'COLLECTION_PARTIAL=00' in log
  if case in ['map_error','mmio_map','protocol_outside_map']:assert m.config_calls==0 and m.identify_calls==0
  assert len(m.frees)==(0 if case=='no_devices' else 1 if case=='output_full' else 3)
  rows.append(dict(case=case,passed=True,status=f'{status:016X}',log_bytes=len(log),free_calls=len(m.frees),calls=sorted(set(m.calls))))
  print(case+' PASS',flush=True)
 for name,keys,scenario in [('entry_no_auto_actions','\r\x1bq\rqq','normal'),('entry_capture_once','ddqq','normal'),('watchdog_failure_holds_capture','dqq','watchdog_fail')]:
  m=Machine(scenario,keys);status=m.run(entry=True);assert status==0 and not m.keys
  assert 'FIRST TEXT / WAITING FOR D' in m.screen and 'RETURNING TO FIRMWARE' in m.screen
  assert m.calls.count('Watchdog')==1
  if name=='entry_capture_once':assert m.config_calls==1 and m.identify_calls==1 and 'Snapshot already captured' in m.screen
  else:assert 'Handles' not in m.calls
  rows.append(dict(case=name,passed=True,calls=sorted(set(m.calls))))
  print(name+' PASS',flush=True)
 report=dict(passed=True,scope='Actual delivered EFI PE machine code in Unicorn with strict UEFI doubles; no hardware',
             app_sha256=hashlib.sha256(APP.read_bytes()).hexdigest(),cases=rows,
             forbidden_calls=['PCI writes or BAR methods','BlockIo methods','DiskInfo Inquiry/Sense/WhichIde','PassThru','driver load/connect','NVRAM','filesystem','BMC'])
 (P/'pe-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows)}))
if __name__=='__main__':main()
