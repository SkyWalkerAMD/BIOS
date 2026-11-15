"""Execute the final app PE with bounded UEFI service doubles; never real IO."""
from pathlib import Path
import hashlib,json,struct,sys,uuid
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
ERR=lambda n:0x8000000000000000|n
V2='7e575405-66a3-420d-88da-8ad70fd9e59b';V3='61f3761c-a3a6-4fb5-98f9-4636c331bc39';LOADED='5b1b31a1-9562-11d2-8e3f-00a0c969723b'
SHA='7b715068892c7603a02648fb3739b7e90a79504634a1717e6c7ed49b5f9e6921'
class Machine:
 def __init__(self,case):
  self.case=case;self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.u.mem_map(0x100000,0x200000);self.u.mem_map(0x500000,0x100000);self.u.mem_map(0x700000,0x10000);self.u.mem_map(0x800000,0x100000)
  pe=pefile.PE(str(OUT/'USB/EFI/BOOT/BOOTX64.EFI'));pe.relocate_image(0x100000);self.u.mem_write(0x100000,pe.get_memory_mapped_image());self.entry=0x100000+pe.OPTIONAL_HEADER.AddressOfEntryPoint
  self.at=0x500000;self.stubs={};self.calls=[];self.output='';self.keys=list('QQ' if case.startswith('existing') else 'LFFQQ' if case.startswith('marker') else 'LQQ');self.protocols=case.startswith('existing');self.started=False;self.loaded=False
  self.st=self.alloc(bytes(128));self.bs=self.alloc(bytes(384));self.tin=self.alloc(bytes(24));self.tout=self.alloc(bytes(80));self.child=self.alloc(bytes(96));self.w64(self.st+0x60,self.bs);self.w64(self.st+0x30,self.tin);self.w64(self.st+0x40,self.tout)
  trap=self.stub('FORBIDDEN')
  for off in range(24,384,8):self.w64(self.bs+off,trap)
  for off,name in ((0x100,'Watchdog'),(0x140,'LocateProtocol'),(0xc8,'LoadImage'),(0xd0,'StartImage'),(0x98,'HandleProtocol')):self.w64(self.bs+off,self.stub(name))
  self.w64(self.tin+8,self.stub('ReadKey'));self.w64(self.tout+8,self.stub('Text'))
  status2=self.stub('Status2');status3=self.stub('Status3');log=self.stub('Log')
  mode=1 if case=='existing_manual' else 0
  self.api2=self.alloc(struct.pack('<4I6Q',2,64,mode,0,trap,log,status2,trap,trap,trap));self.api3=self.alloc(struct.pack('<4I4Q',3,48,mode,0,trap,log,status3,trap))
  self.logdata=b'HERO-IPMI-R3 CORE / test fixture\r\n';self.log=self.alloc(self.logdata+b'\0')
  self.ownloaded=self.alloc(bytes(96));self.w64(self.ownloaded+0x18,0x8888);self.fs=self.alloc(bytes(16));self.w64(self.fs+8,self.stub('OpenVolume'))
  self.root=self.alloc(bytes(88));self.marker=self.alloc(bytes(88));self.w64(self.root+8,self.stub('FileOpen'));self.w64(self.root+16,self.stub('RootClose'));self.w64(self.marker+16,self.stub('MarkerClose'));self.w64(self.marker+32,self.stub('MarkerRead'))
  if case=='loaded_options':self.u.mem_write(self.child+0x30,struct.pack('<I',8))
  if case=='corrupt_embedded':
   data=bytes(self.u.mem_read(0x100000,0x200000));frozen=(ROOT/'analysis/hero_sensor_r3_20261108/USB/EFI/HERO/HeroIpmiR3.efi').read_bytes();off=data.find(frozen);assert off>=0;self.u.mem_write(0x100000+off+100,b'X')
  self.u.hook_add(UC_HOOK_CODE,self.hook)
 def alloc(self,data):
  p=self.at;self.at=(p+len(data)+15)&~15;self.u.mem_write(p,data);return p
 def w64(self,p,v):self.u.mem_write(p,struct.pack('<Q',v))
 def r64(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
 def guid(self,p):return str(uuid.UUID(bytes_le=bytes(self.u.mem_read(p,16))))
 def stub(self,name):
  p=0x700000+len(self.stubs)*16;self.stubs[p]=name;self.u.mem_write(p,b'\xc3');return p
 def hook(self,u,addr,size,user):
  if addr not in self.stubs:return
  name=self.stubs[addr];self.calls.append(name);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];rsp=u.reg_read(UC_X86_REG_RSP);result=0
  if name=='FORBIDDEN':raise AssertionError('Forbidden UEFI/core operation')
  if name=='Text':
   data=bytearray()
   for i in range(1024):
    v=bytes(u.mem_read(b+i*2,2))
    if v==b'\0\0':break
    data+=v
   self.output+=data.decode('utf-16-le')
  elif name=='ReadKey':
   assert self.keys,'Unexpected extra key loop';u.mem_write(b,struct.pack('<HH',0,ord(self.keys.pop(0))))
  elif name=='Watchdog':
   assert (a,b,c,d)==(0,0,0,0);result=ERR(7) if self.case=='watchdog_error' else 0
  elif name=='LocateProtocol':
   g=self.guid(a);assert g in (V2,V3) and b==0
   if self.case=='lookup_error':result=ERR(7)
   elif self.protocols and not (self.case=='existing_missing_v2' and g==V2):self.w64(c,self.api3 if g==V3 else self.api2)
   else:result=ERR(14)
  elif name=='LoadImage':
   assert (a,b,c)==(0,0x9090,0);n=self.r64(rsp+0x28);assert n==31232 and hashlib.sha256(u.mem_read(d,n)).hexdigest()==SHA
   assert not self.loaded;self.loaded=True
   result=ERR(26) if self.case=='load_error' else 0
   if not result:self.w64(self.r64(rsp+0x30),0x9191)
  elif name=='HandleProtocol':
   g=self.guid(b)
   if a==0x9090:assert g==LOADED;self.w64(c,self.ownloaded)
   elif a==0x8888:assert g=='964e5b22-6459-11d2-8e39-00a0c969723b';self.w64(c,self.fs)
   else:
    assert a==0x9191 and g==LOADED;result=ERR(14) if self.case=='loaded_error' else 0
    if not result:self.w64(c,self.child)
  elif name=='OpenVolume':assert a==self.fs;self.w64(b,self.root)
  elif name=='FileOpen':
   assert a==self.root and d==1 and self.r64(rsp+0x28)==0;expected='\\HERO_R3A.TAG'.encode('utf-16-le')+b'\0\0';assert bytes(u.mem_read(c,len(expected)))==expected
   if self.case=='marker_missing_repeat':result=ERR(14)
   else:self.w64(b,self.marker)
  elif name=='MarkerRead':assert a==self.marker;u.mem_write(c,b'WRONG');self.w64(b,5)
  elif name=='RootClose':assert a==self.root
  elif name=='MarkerClose':assert a==self.marker
  elif name=='StartImage':
   assert (a,b,c)==(0x9191,0,0) and self.loaded;assert bytes(u.mem_read(self.child+0x30,16))==bytes(16),'LoadOptions changed'
   self.started=True;result=ERR(7) if self.case=='start_error' else 0
   if not result:self.protocols=True
  elif name=='Status2':u.mem_write(a,bytes(416))
  elif name=='Status3':
   data=bytearray(232);struct.pack_into('<II',data,0,3,232);struct.pack_into('<I',data,64,1 if self.case=='existing_ready' else 0);u.mem_write(a,bytes(data))
  elif name=='Log':self.w64(a,len(self.logdata));result=self.log
  else:raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,result)
  for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
 def run(self):
  rsp=0x8ff000-8;stop=0x70fff0;self.w64(rsp,stop);self.u.reg_write(UC_X86_REG_RSP,rsp);self.u.reg_write(UC_X86_REG_RCX,0x9090);self.u.reg_write(UC_X86_REG_RDX,self.st);self.u.emu_start(self.entry,stop,count=5000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==stop
  result=self.u.reg_read(UC_X86_REG_RAX)
  if self.case in ('first','existing_ready') or self.case.startswith('marker'):assert result==0
  else:assert result!=0
  assert 'FORBIDDEN' not in self.calls
  if self.case=='first':assert self.calls.count('LoadImage')==self.calls.count('StartImage')==1 and 'FIRST_PASS_NO_BMC_QUERY' in self.output
  if self.case.startswith('existing'):assert 'LoadImage' not in self.calls and 'StartImage' not in self.calls
  if self.case=='existing_ready':assert 'SECOND_PASS_OBSERVER' in self.output and 'READY_TO_BOOT_OBSERVED' in self.output
  if self.case.startswith('marker'):assert self.calls.count('OpenVolume')==2 and self.calls.count('RootClose')==2 and self.calls.count('FileOpen')==2,'Marker gate must run on every failed retry'
  if self.case in ('loaded_options','loaded_error','load_error','lookup_error','watchdog_error','corrupt_embedded'):assert 'StartImage' not in self.calls
  return dict(case=self.case,passed=True,status=f'{result:016X}',load_calls=self.calls.count('LoadImage'),start_calls=self.calls.count('StartImage'),calls=self.calls)
def main():
 rows=[Machine(c).run() for c in ('first','existing_ready','existing_manual','existing_missing_v2','watchdog_error','lookup_error','load_error','loaded_error','loaded_options','start_error','corrupt_embedded','marker_missing_repeat','marker_bad_repeat')]
 result=dict(all_passed=True,count=len(rows),pe_sha256=hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),cases=rows,limits=['UEFI services are synthetic. Actual driver lifetime and real ReadyToBoot behavior are separately tested with OVMF BDS.'])
 (OUT/'launcher-verification.json').write_text(json.dumps(result,indent=2)+'\n');print('ACTUAL LAUNCHER PE PASS',len(rows))
if __name__=='__main__':main()
