"""Execute the delivered PE with strict UEFI/API doubles, no host device I/O."""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
ERR=lambda n:(1<<63)|n
API='7e575405-66a3-420d-88da-8ad70fd9e59b'
GOP='9042a9de-23dc-4a38-96fb-7adeD080516a'.lower()
IMAGE=0x9999
class Machine:
 def __init__(self,keys='q\r',resident=True,manual=False,writable=False,bad_marker=False):
  self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.u.mem_map(0x100000,0xf00000)
  self.pe=pefile.PE(str(P/'USB/EFI/BOOT/BOOTX64.EFI'));self.pe.relocate_image(0x100000)
  self.u.mem_write(0x100000,self.pe.get_memory_mapped_image());self.entry=0x100000+self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
  self.keys=list(keys);self.resident=resident;self.manual=manual;self.writable=writable;self.bad_marker=bad_marker
  self.calls=[];self.output=[];self.heap=0x400000;self.stubs={};self.ptr=0x800000;self.files={};self.pos=0;self.created=False
  self.bs=0x300000;self.rt=0x310000;self.st=0x320000;self.out=0x330000;self.inp=0x340000;self.mode=0x350000
  self.loaded=0x360000;self.fs=0x361000;self.root=0x362000;self.marker=0x363000;self.file=0x364000
  self.svc=0x370000
  self.log=b'HERO-IPMI-R2 CORE / HERO 3107 / BMC 1.3.13\r\nLOAD_MODE FIRMWARE; ReadyToBoot once\r\nREADY_TO_BOOT_AUTO_ENABLED\r\nOEM_TX 30/90 80\r\nRESULT: Verified sensor initialization completed.\r\n'
  self.logptr=self.alloc(self.log+b'\0')
  for off in range(24,0x178,8):self.stub(self.bs+off,'FORBIDDEN_BS_'+hex(off))
  for off in range(24,0x60,8):self.stub(self.rt+off,'FORBIDDEN_RT_'+hex(off))
  for off,name in [(0x40,'AllocatePool'),(0x48,'FreePool'),(0x60,'Wait'),(0x98,'Handle'),(0x100,'Watchdog'),(0x138,'Handles'),(0x140,'Locate')]:self.stub(self.bs+off,name)
  for off in range(0,72,8):self.stub(self.out+off,'FORBIDDEN_TEXT_'+hex(off))
  for off,name in [(8,'Output'),(24,'QueryText'),(40,'Attribute'),(48,'Clear'),(64,'Cursor')]:self.stub(self.out+off,name)
  self.w64(self.out+72,self.mode);self.u.mem_write(self.mode,struct.pack('<iiiiii',1,0,7,0,0,1))
  self.stub(self.inp+8,'Key');self.w64(self.inp+16,0x123)
  for off,val in [(0x30,self.inp),(0x40,self.out),(0x58,self.rt),(0x60,self.bs)]:self.w64(self.st+off,val)
  self.w64(self.loaded+0x18,0x7777)
  self.u.mem_write(self.svc,struct.pack('<IIII',2,64,int(manual),0))
  for off,name in [(16,'FORBIDDEN_R2_RUN'),(24,'R2Log'),(32,'R2Status'),(40,'R2Config'),(48,'FORBIDDEN_R2_ENABLE'),(56,'FORBIDDEN_R2_UNLOCK')]:self.stub(self.svc+off,name)
  self.stub(self.fs+8,'OpenVolume')
  for where in (self.root,self.marker,self.file):
   for off in range(8,88,8):self.stub(where+off,'FORBIDDEN_FILE_'+hex(off))
   self.stub(where+16,'FileClose')
  self.stub(self.root+8,'FileOpen');self.stub(self.marker+32,'FileRead')
  self.stub(self.file+40,'FileWrite');self.stub(self.file+56,'FileSeek');self.stub(self.file+80,'FileFlush')
  self.u.hook_add(UC_HOOK_CODE,self.hook)
 def w64(self,p,v):self.u.mem_write(p,struct.pack('<Q',v))
 def r64(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
 def alloc(self,data):
  p=self.heap;self.heap+=((len(data)+15)//16)*16+32;self.u.mem_write(p,data);return p
 def stub(self,p,name):
  addr=self.ptr;self.ptr+=16;self.stubs[addr]=name;self.u.mem_write(addr,b'\xc3');self.w64(p,addr)
 def wide(self,p):
  buf=bytearray()
  for i in range(2000):
   c=bytes(self.u.mem_read(p+2*i,2))
   if c==b'\0\0':return buf.decode('utf-16le')
   buf+=c
  raise AssertionError('unterminated UTF16')
 def guid(self,p):return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(p,16))))
 def hook(self,u,address,size,data):
  name=self.stubs.get(address)
  if name is None:return
  assert not name.startswith('FORBIDDEN'),name
  self.calls.append(name)
  rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
  result=0
  if name=='Locate':
   g=self.guid(a);assert g in (API,GOP)
   if g==API and self.resident:self.w64(c,self.svc)
   else:result=ERR(14)
  elif name=='Handles':result=ERR(14)
  elif name=='Output':self.output.append(self.wide(b))
  elif name=='Key':
   assert self.keys,'unexpected extra key request'
   k=self.keys.pop(0);u.mem_write(b,struct.pack('<HH',0x17 if k=='\x1b' else 0,0 if k=='\x1b' else ord(k)))
  elif name=='Watchdog':assert (a,b,c,d)==(0,0,0,0)
  elif name=='R2Log':self.w64(a,len(self.log));result=self.logptr
  elif name=='R2Config':u.mem_write(a,struct.pack('<IBBBB',0x31495048,1,1,0,0));u.mem_write(b,struct.pack('<I',0))
  elif name=='R2Status':
   r=bytearray(416);r[:24]=b'ROG MAXIMUS Z790 HERO\0\0\0\0';r[96:101]=b'3107\0'
   msg=b'Verified sensor initialization completed.\0';r[192:192+len(msg)]=msg
   struct.pack_into('<IIIIIIIIIIIII',r,352,200,4,16,8,38,1,1,1,0,1,0,0,0)
   u.mem_write(a,bytes(r))
  elif name=='Handle':
   g=self.guid(b)
   if a==IMAGE and g=='5b1b31a1-9562-11d2-8e3f-00a0c969723b':self.w64(c,self.loaded)
   elif a==0x7777 and g=='964e5b22-6459-11d2-8e39-00a0c969723b':self.w64(c,self.fs)
   else:result=ERR(14)
  elif name=='OpenVolume':self.w64(b,self.root)
  elif name=='FileOpen':
   path=self.wide(c)
   if path=='\\HERO_RC3.TAG':assert d==1;self.w64(b,self.marker)
   elif path=='\\R3LOG000.TXT':
    if d==1:
     if self.created:self.w64(b,self.file)
     else:result=ERR(14)
    else:
     assert d==0x8000000000000003
     if self.writable:self.created=True;self.files[path]=bytearray();self.w64(b,self.file)
     else:result=ERR(8)
   else:raise AssertionError(path)
  elif name=='FileRead':
   assert a==self.marker;v=b'WRONG\r\n' if self.bad_marker else b'HERO-IPMI-RC3-LOG\r\n';assert self.r64(b)>=len(v);self.w64(b,len(v));u.mem_write(c,v)
  elif name=='FileSeek':assert a==self.file and b==0;self.pos=0
  elif name=='FileWrite':
   assert self.writable and a==self.file;n=self.r64(b);v=bytes(u.mem_read(c,n));f=self.files['\\R3LOG000.TXT'];f[self.pos:self.pos+n]=v;self.pos+=n
  elif name=='FileFlush':assert a==self.file
  elif name=='FileClose':assert a in (self.root,self.marker,self.file)
  elif name=='QueryText':self.w64(c,80);self.w64(d,25)
  elif name in ('Attribute','Clear','Cursor'):pass
  elif name=='AllocatePool':self.w64(c,self.alloc(bytes(b)))
  elif name=='FreePool':pass
  else:raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,result)
  for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
 def run(self):
  rsp=0xeffff8;stop=0x8f0000;self.w64(rsp,stop)
  self.u.reg_write(UC_X86_REG_RSP,rsp);self.u.reg_write(UC_X86_REG_RCX,IMAGE);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(self.entry,stop,count=10000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==stop,'instruction budget exceeded'
  return self.u.reg_read(UC_X86_REG_RAX),''.join(self.output)
def main():
 rows=[]
 for name,kwargs,expect in [
  ('missing_resident_does_not_load',dict(keys='\r',resident=False),ERR(14)),
  ('manual_driver_rejected',dict(keys='\r',manual=True),ERR(15)),
  ('resident_summary_and_exit',dict(),0),
  ('all_old_write_keys_ignored',dict(keys='di01utq\r'),0),
  ('summary_text',dict(keys='r\x1bq\r'),0),
  ('full_text',dict(keys='v\x1bq\r'),0),
  ('qr_fallback_to_text',dict(keys='c\x1bq\r'),0),
  ('full_qr_fallback_to_text',dict(keys='a\x1bq\r'),0),
  ('read_only_iso_file_failure_returns_menu',dict(keys='lq\r'),0),
  ('unmarked_volume_cannot_write',dict(keys='lq\r',writable=True,bad_marker=True),0),
  ('writable_usb_exact_full_core_audit',dict(keys='lq\r',writable=True),0)]:
  m=Machine(**kwargs);status,out=m.run();assert status==expect,(name,hex(status),out)
  assert not any(x.startswith('FORBIDDEN') for x in m.calls)
  if 'text' in name or 'fallback' in name:assert 'TEXT PAGE 1/' in out and 'LAST_RUN_REPORT (lock may be unqueried)' in out
  if name=='missing_resident_does_not_load':assert 'No driver will be loaded' in out and not any(x.startswith('R2') for x in m.calls)
  if kwargs.get('writable') and not kwargs.get('bad_marker'):
   saved=bytes(m.files['\\R3LOG000.TXT']);assert saved.startswith(b'HERO-IPMI-RC3 AUTO FILE RUN=') and saved.endswith(m.log)
   (P/'test-file-log.TXT').write_bytes(saved)
  else:assert not m.files
  rows.append(dict(case=name,passed=True,status=f'{status:016X}',allowed_calls=sorted(set(m.calls))))
  print(name,'PASS',flush=True)
 report=dict(all_passed=True,count=len(rows),app_sha256=hashlib.sha256((P/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
  scope='Actual delivered PE machine code in Unicorn with strict API/UEFI doubles',
  forbidden_interfaces=['R2.run','R2.enable','R2.unlock','LoadImage','StartImage','UnloadImage','SetVariable','P5 APIs','PCI/KCS','GOP/Text SetMode'],
  cases=rows,limitations=['Synthetic protocols; not physical motherboard execution.','QR graphics appearance tested separately; this harness exercises GOP-unavailable text fallback.'])
 (P/'app-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
