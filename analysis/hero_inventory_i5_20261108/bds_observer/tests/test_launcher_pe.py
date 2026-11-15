"""Actual observer PE control flow; resident registration is a fixture.
ConnectController, SignalEvent, connect_probe and SetVariable are forbidden.
Two entries share only installed boot-service witness/report memory.
"""
from pathlib import Path
import hashlib,json,struct,sys,uuid
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import *
data=(BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes();pe=pefile.PE(data=data);image=pe.OPTIONAL_HEADER.ImageBase
REPORT='7e06fa9a-532e-44c6-928a-cf19d2718e4b';WITNESS='c7805d12-aa9f-4d20-93ea-16b2b9e06108';ERR=lambda x:0x8000000000000000|x
class Machine:
 def __init__(self,preexisting=False):
  self.u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);self.u.mem_map(image,0xc00000);self.u.mem_map(0x50000000,0x500000)
  self.base=0x50000000;self.st=self.base;self.bs=self.base+0x1000;self.rt=self.base+0x2000;self.report=self.base+0x3000;self.log=self.base+0x4000;self.heap=self.base+0x10000;self.witness=0;self.registered=preexisting;self.stubs={};self.calls=[];self.text='';self.fixture(0,0)
  self.w64(self.st+0x60,self.bs);self.w64(self.st+0x58,self.rt);self.w64(self.st+0x30,self.base+0x5000);self.w64(self.st+0x40,self.base+0x5100)
  for table,off,name in [(self.bs,0x40,'Allocate'),(self.bs,0x48,'Free'),(self.bs,0x80,'Install'),(self.bs,0x98,'Handle'),(self.bs,0xc8,'Load'),(self.bs,0xd0,'Start'),(self.bs,0x100,'Watchdog'),(self.bs,0x140,'Locate'),(self.bs,0x108,'ForbiddenConnect'),(self.bs,0x68,'ForbiddenSignal'),(self.rt,0x58,'ForbiddenSetVariable'),(self.base+0x5000,8,'ReadKey'),(self.base+0x5100,8,'Output')]:self.stub(table+off,name)
  self.stub(self.report+56,'ForbiddenProbe')
  for addr in self.stubs:self.u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=addr,end=addr)
 def w64(self,a,x):self.u.mem_write(a,struct.pack('<Q',x))
 def r64(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def stub(self,where,name):a=self.base+0x4f0000+len(self.stubs)*16;self.w64(where,a);self.stubs[a]=name;self.u.mem_write(a,b'\xc3')
 def fixture(self,starts,runs):
  log=b'HERO-INVENTORY-I5D\r\nMODE=AUTOMATIC_RAM_DRIVER_READONLY\r\n';self.u.mem_write(self.log,log)
  probe=self.r64(self.report+56)
  self.u.mem_write(self.report,struct.pack('<IIIIQQQQQQQII',0x42354e49,2,80,2 if runs else 0,0 if runs else ERR(6),4,self.log,len(log),0,probe,0x9000,starts,runs))
 def hook(self,u,at,size,ctx):
  name=self.stubs[at];self.calls.append(name);sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=0
  if name.startswith('Forbidden'):raise AssertionError(name)
  if name=='Allocate':assert a==4 and b==32;self.w64(c,self.heap);self.heap+=0x100
  elif name=='Install':assert str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==WITNESS;self.witness=d;self.w64(a,0xa000)
  elif name=='Locate':
   guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))));p=self.witness if guid==WITNESS else self.report if guid==REPORT and self.registered else 0;self.w64(c,p);e=0 if p else ERR(14)
  elif name=='Load':self.w64(self.r64(sp+0x30),0x9000)
  elif name=='Start':assert a==0x9000;self.registered=True
  elif name=='Handle':e=ERR(14)
  elif name=='ReadKey':u.mem_write(b,struct.pack('<HH',0,ord('Q')))
  elif name=='Output':
   chars=[]
   for i in range(1000):
    ch=struct.unpack('<H',u.mem_read(b+i*2,2))[0]
    if not ch:break
    chars.append(chr(ch))
   self.text+=''.join(chars)
  elif name=='Watchdog':assert a==b==c==d==0
  elif name=='Free':pass
  else:raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,e);u.reg_write(UC_X86_REG_RIP,self.r64(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def run(self):
  self.u.mem_write(image,pe.get_memory_mapped_image());self.text='';self.calls=[]
  stack=self.base+0x4e0008;stop=self.base+0x4ff000;self.w64(stack,stop);self.u.reg_write(UC_X86_REG_RSP,stack);self.u.reg_write(UC_X86_REG_RCX,0x77);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(image+pe.OPTIONAL_HEADER.AddressOfEntryPoint,stop,count=100000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==stop and self.u.reg_read(UC_X86_REG_RAX)==0
  assert not any(x.startswith('Forbidden') for x in self.calls)
  return self.text
rows=[]
m=Machine();t=m.run();assert 'I5N_LAUNCHER_ENTRY=0x0000000000000001' in t and 'I5_CORE_RUNS=0x0000000000000000' in t and m.calls.count('Start')==1;rows.append('first_entry_registration_only')
t=m.run();assert 'I5N_LAUNCHER_ENTRY=0x0000000000000002' in t and 'I5_CORE_RUNS=0x0000000000000000' in t and 'Start' not in m.calls;rows.append('second_entry_passive_zero_observation')
m.fixture(1,1);t=m.run();assert 'I5N_LAUNCHER_ENTRY=0x0000000000000003' in t and 'I5_BINDING_STARTS=0x0000000000000001' in t and 'Start' not in m.calls;rows.append('later_report_changes_only_observed')
m=Machine(preexisting=True);t=m.run();assert 'I5N_PREEXISTING_DRIVER=0x0000000000000001' in t and 'Load' not in m.calls;rows.append('preexisting_driver_not_clean_baseline')
m=Machine();m.run();m.u.mem_write(m.witness,b'\0'*4);t=m.run();assert 'I5N_WITNESS_INVALID' in t and 'Start' not in m.calls;rows.append('invalid_witness_refused')
report={'passed':True,'cases':len(rows),'results':rows,'actual_launcher_sha256':hashlib.sha256(data).hexdigest(),'forbidden_calls':['ConnectController','SignalEvent','connect_probe','SetVariable'],'limits':['Report changes in third scenario are synthetic; no claim that real BDS triggers the driver.']}
(BASE/'tests/launcher-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
