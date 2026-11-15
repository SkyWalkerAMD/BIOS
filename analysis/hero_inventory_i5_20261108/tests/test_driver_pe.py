"""Execute delivered resident PE and actual dynamic SMBIOS parser in Unicorn.
Network preparation/TLS responses are doubles: this does NOT simulate .71 USB.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
BASE=Path(__file__).resolve().parents[1]; ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import *
PE=BASE/'USB/EFI/BOOT/I5AUTONET.EFI';data=PE.read_bytes();p=pefile.PE(data=data);IMAGE=p.OPTIONAL_HEADER.ImageBase
symbols={}
for line in (BASE/'build/I5AUTONET.EFI.map').read_text().splitlines():
 m=re.match(r'\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s',line)
 if m:symbols[m[1]]=int(m[2],16)
capture=(ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_text()
ORIGINAL=bytes.fromhex(capture.split('TABLE_HEX_BEGIN\n')[1].split('TABLE_HEX_END')[0])
ERR=lambda n:0x8000000000000000|n
class Machine:
 def __init__(self,case):
  self.case=case;self.u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
  self.u.mem_map(IMAGE,0x400000);self.u.mem_write(IMAGE,p.get_memory_mapped_image());self.u.mem_map(0x50000000,0x400000)
  self.st=0x50000000;self.bs=self.st+0x1000;self.rt=self.st+0x2000;self.table=self.st+0x10000;self.tpl=8 if case=='high_tpl' else 4;self.calls=[];self.published=0
  self.w64(self.st+0x60,self.bs);self.w64(self.st+0x58,self.rt)
  self.stubs={};self.next_stub=self.st+0x3f0000
  for off,name in ((0x18,'RaiseTPL'),(0x20,'RestoreTPL'),(0x38,'MemoryMap'),(0x80,'Install'),(0x140,'Locate')):self.stub(self.bs+off,name)
  raw=bytearray(ORIGINAL);at=0;entries=[]
  while at<len(raw):
   n=raw[at+1];end=raw.index(b'\0\0',at+n)+2;entries.append((raw[at],at,end));at=end
  if case=='bad_uuid':raw[next(a for t,a,b in entries if t==1)+8]^=1
  if case=='zero_uuid':raw[next(a for t,a,b in entries if t==1)+8:next(a for t,a,b in entries if t==1)+24]=b'\0'*16
  if case=='board':raw[raw.index(b'ROG MAXIMUS Z790 HERO')]=ord('X')
  if case=='bios':raw[raw.index(b'3107')]=ord('9')
  if case=='changed_dimm':
   pos=next(a for t,a,b in entries if t==17 and int.from_bytes(raw[a+12:a+14],'little'))
   raw[pos+12:pos+14]=(16384).to_bytes(2,'little')
  if case=='truncated':raw=raw[:-1]
  if case=='duplicate':raw=raw[:-6]+raw[next(a for t,a,b in entries if t==1):next(b for t,a,b in entries if t==1)]+raw[-6:]
  self.u.mem_write(self.table,bytes(raw));entry=bytearray(b'_SM3_\0'+bytes([24,3,5,0,1,0])+struct.pack('<IQ',len(raw),self.table));entry[5]=(-sum(entry))&255
  if case=='checksum':entry[5]^=1
  self.u.mem_write(self.st+0x3000,bytes(entry));self.u.mem_write(self.st+0x4000,uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',self.st+0x3000));self.w64(self.st+0x68,0 if case=='missing' else 1);self.w64(self.st+0x70,self.st+0x4000)
  for name in ('i5_prepare_network','private_tls_resource','private_tls_cleanup','network_cleanup'):
   self.stubs[symbols[name]]=name
  for address in self.stubs:self.u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=address,end=address)
 def w64(self,a,v):self.u.mem_write(a,struct.pack('<Q',v))
 def r64(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def stub(self,location,name):
  a=self.next_stub;self.next_stub+=16;self.w64(location,a);self.u.mem_write(a,b'\xc3');self.stubs[a]=name
 def hook(self,u,at,size,ctx):
  name=self.stubs[at];self.calls.append(name);sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=0
  if name=='RaiseTPL':e=self.tpl;self.tpl=a
  elif name=='RestoreTPL':self.tpl=a
  elif name=='MemoryMap':
   if self.case=='memory_map_failure':e=ERR(7)
   else:
    assert self.r64(a)==131072;self.w64(a,40);self.w64(c,1);self.w64(d,40);self.u.mem_write(self.r64(sp+0x28),struct.pack('<I',1));self.u.mem_write(b,struct.pack('<IIQQQQ',11 if self.case=='mmio' else 4,0,self.st,0,1024,0))
  elif name=='Locate':self.w64(c,self.published);e=0 if self.published else ERR(14)
  elif name=='Install':
   if self.case=='install_failure':e=ERR(9)
   else:self.published=d;self.w64(a,0x6000)
  elif name=='i5_prepare_network':e=ERR(14) if self.case=='no_usb' else (ERR(7) if self.case=='network_failure' else 0)
  elif name=='private_tls_resource':
   assert a in (0,1);self.calls.append('GET'+str(a));e=ERR(26) if self.case=='tls_pin_changed' else (ERR(18) if self.case=='timeout' else 0)
   self.u.mem_write(b,struct.pack('<I4xQQ',401 if self.case=='http401' else 200,self.st+0x5000,2));self.u.mem_write(self.st+0x5000,b'{}')
   if self.case=='source_changed_after_root' and a==0:self.u.mem_write(self.table+2,b'\xff')
  elif name=='private_tls_cleanup':e=ERR(7) if self.case=='cleanup_failure' else 0
  elif name!='network_cleanup':raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,e);u.reg_write(UC_X86_REG_RIP,self.r64(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def run(self,name='efi_main'):
  stack=self.st+0xf0008;stop=self.st+0x3ff000;self.w64(stack,stop);self.u.reg_write(UC_X86_REG_RSP,stack);self.u.reg_write(UC_X86_REG_RCX,0x77);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(symbols[name],stop,count=10000000);assert self.u.reg_read(UC_X86_REG_RIP)==stop
  return self.u.reg_read(UC_X86_REG_RAX)
 def api(self):return struct.unpack('<IIIIQQQQQ',self.u.mem_read(self.published,56))
 def log(self):r=self.api();return bytes(self.u.mem_read(r[6],r[7]))
rows=[]
badsource=('bad_uuid','zero_uuid','board','bios','truncated','duplicate','checksum','missing','memory_map_failure','mmio')
for case in ('success','changed_dimm','no_usb','network_failure','tls_pin_changed','timeout','http401','cleanup_failure','source_changed_after_root','high_tpl',*badsource):
 m=Machine(case);assert m.run()==0;info=m.api();assert info[0]==0x41354e49 and info[1]==1 and info[2]==56
 good=case in ('success','changed_dimm');assert info[3]==(2 if good else 3);assert (info[4]==0)==good
 assert info[5]==(8 if case=='high_tpl' else 4)
 if case in badsource or case=='high_tpl':assert 'i5_prepare_network' not in m.calls and 'GET0' not in m.calls
 if case in ('no_usb','network_failure'):assert 'GET0' not in m.calls
 if case in ('tls_pin_changed','timeout','http401','source_changed_after_root'):assert 'GET0' in m.calls and 'GET1' not in m.calls
 if good:assert m.calls.count('GET0')==1 and m.calls.count('GET1')==1
 before=list(m.calls);m.run('i5_run_once');assert m.calls==before
 assert m.run()==ERR(20);assert m.calls.count('i5_prepare_network')<=1 and m.calls.count('GET0')<=1
 assert b'I5_NO_AUTOMATIC_RETRY_THIS_BOOT' in m.log();assert b'I5_CURRENT_HOST_CAPTURE' in m.log()
 if case=='changed_dimm':
  # Catalogue is generated from the new DIMM size, not the previous .71 dump.
  assert b'16384' in bytes(m.u.mem_read(info[8],34608))
 rows.append({'case':case,'state':info[3],'result':hex(info[4]),'passed':True})
m=Machine('install_failure');assert m.run()==ERR(9) and 'i5_prepare_network' not in m.calls;rows.append({'case':'install_failure','passed':True})
for forbidden in (b'POST ',b'PATCH ',b'DELETE ',b'/Bios/Settings',b'/Bios/SD'):assert forbidden not in data,forbidden
assert b'GET ' in data
report={'passed':True,'cases':rows,'count':len(rows),'pe_sha256':hashlib.sha256(data).hexdigest(),'scope':'Actual driver PE entry/current-host parser with mocked network/TLS, no hardware and no native DXE scheduling claim'}
(BASE/'tests/driver-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='cases'}))
