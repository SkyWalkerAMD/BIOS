"""Actual launcher PE tests. Firmware services and P6 cached API are fixtures.
The exact driver bytes are inspected at LoadImage; real driver behavior is not
simulated as proof of native setup dispatch. Forbidden calls fail immediately.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid,zlib
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import *
data=(BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes();pe=pefile.PE(data=data);image=pe.OPTIONAL_HEADER.ImageBase
DRIVER=(BASE/'USB/EFI/BOOT/HEROP6.EFI').read_bytes();EXPECTED='abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75'
API='1f771753-bb7b-4e4c-b698-e71e8db25e7a';CFG='bef09fe1-8540-4be1-9082-e6624328f435';ERR=lambda x:0x8000000000000000|x
DEFAULT=bytes([0,0,0,10,1])+bytes(27)
symbols={m[1]:int(m[2],16) for line in (BASE/'build/BOOTX64.map').read_text().splitlines() if (m:=re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})',line,re.I))}
def journal(**kw):
 b=bytearray(144);struct.pack_into('<IIIIII',b,0,0x36504948,1,144,0,kw.get('phase',0),kw.get('blocked',0));b[24:56]=kw.get('applied',DEFAULT);b[56:88]=kw.get('request',DEFAULT)
 if kw.get('results'):b[88:]=bytes(range(56))
 struct.pack_into('<I',b,12,zlib.crc32(b));return bytes(b)
def record(t,body,strings=()):
 x=bytes([t,len(body)+4,t,0])+body
 return x+(b'\0'.join(strings)+b'\0\0' if strings else b'\0\0')
def table(board=b'ROG MAXIMUS Z790 HERO',bios=b'3107',bad_uuid=False,extra=b''):
 ident=bytearray(20);ident[4:20]=bytes.fromhex('46f522b2b3dbc89abbfb581122d8be9f');ident[4]^=1 if bad_uuid else 0
 return record(0,bytes([1,2,0,0,3]),[b'AMI',bios,b'11/28/2025'])+record(1,bytes(ident))+record(2,b'\x01\x02',[b'ASUS',board])+extra+record(127,b'')
class Machine:
 def __init__(self,settings=None,state=None,keys='LQQ',board=b'ROG MAXIMUS Z790 HERO',bios=b'3107',bad_uuid=False,corrupt_sha=False,preexisting=False,extra=b'',watchdog_error=0,locate_error=0):
  self.u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);self.u.mem_map(image,0x2000000);self.u.mem_map(0x50000000,0x500000)
  self.base=0x50000000;self.st=self.base;self.bs=self.base+0x1000;self.rt=self.base+0x2000;self.api=self.base+0x3000;self.log=self.base+0x4000;self.textp=self.base+0x4800;self.heap=self.base+0x10000
  self.stubs={};self.calls=[];self.text='';self.keys=list(keys);self.registered=preexisting;self.settings=settings;self.state=state;self.attrs={};self.errors={};self.sizes={};self.count={};self.mutate=None;self.corrupt_sha=corrupt_sha;self.watchdog_error=watchdog_error;self.locate_error=locate_error;self.load_error=0;self.start_error=0;self.low_log_space=0
  self.seed_width=32
  self.w64(self.st+0x60,self.bs);self.w64(self.st+0x58,self.rt);self.w64(self.st+0x30,self.base+0x5000);self.w64(self.st+0x40,self.base+0x5100)
  self.w64(self.st+0x68,1);self.w64(self.st+0x70,self.base+0x6000);self.u.mem_write(self.base+0x6000,uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le);self.w64(self.base+0x6010,self.base+0x6100)
  tab=table(board,bios,bad_uuid,extra);self.u.mem_write(self.base+0x7000,tab)
  ep=bytearray(24);ep[:5]=b'_SM3_';ep[6]=24;ep[7:9]=b'\x03\x06';struct.pack_into('<IQ',ep,12,len(tab),self.base+0x7000);ep[5]=(-sum(ep))&255;self.u.mem_write(self.base+0x6100,bytes(ep))
  for tab,off,name in [(self.bs,0x38,'GetMap'),(self.bs,0x40,'Allocate'),(self.bs,0x48,'Free'),(self.bs,0x98,'Handle'),(self.bs,0xc8,'Load'),(self.bs,0xd0,'Start'),(self.bs,0x100,'Watchdog'),(self.bs,0x140,'Locate'),(self.bs,0x108,'ForbiddenConnect'),(self.bs,0x68,'ForbiddenSignal'),(self.bs,0xe0,'ForbiddenUnload'),(self.rt,0x48,'GetVariable'),(self.rt,0x58,'ForbiddenSetVariable'),(self.base+0x5000,8,'ReadKey'),(self.base+0x5100,8,'Output')]:self.stub(tab+off,name)
  self.u.mem_write(self.api,struct.pack('<II',6,24));self.stub(self.api+8,'CachedLog');self.stub(self.api+16,'CachedValue')
  self.log_data=b'HERO-IPMI-P6-RC4 / cached fixture only\r\nP6_SETUP_AUTO_REFRESH\r\nP6_READ_STATUS=0000000000000000\r\nP6_PUBLISH_STATUS=0000000000000000\r\n';self.u.mem_write(self.log,self.log_data);self.u.mem_write(self.textp,b'Cached fixture\0'+bytes(160))
  for addr in self.stubs:self.u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=addr,end=addr)
 def w64(self,a,x):self.u.mem_write(a,struct.pack('<Q',x))
 def r64(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def wide(self,a):
  s=''
  for i in range(1000):
   c=struct.unpack('<H',self.u.mem_read(a+i*2,2))[0]
   if not c:return s
   s+=chr(c)
  raise AssertionError('unterminated')
 def stub(self,where,name):a=self.base+0x4f0000+len(self.stubs)*16;self.w64(where,a);self.stubs[a]=name;self.u.mem_write(a,b'\xc3')
 def hook(self,u,at,size,ctx):
  name=self.stubs[at];self.calls.append(name);sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=0
  if name.startswith('Forbidden'):raise AssertionError(name)
  if name=='GetMap':
   desc=b''.join(struct.pack('<IIQQQQ',4,0,addr,0,size//4096,0) for addr,size in [(image,0x2000000),(self.base,0x500000)])
   assert self.r64(a)>=len(desc);u.mem_write(b,desc);self.w64(a,len(desc));self.w64(c,1);self.w64(d,40);u.mem_write(self.r64(sp+0x28),struct.pack('<I',1))
  elif name=='Allocate':self.w64(c,self.heap);self.heap+=(b+15)&~15
  elif name=='Locate':
   guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(a,16))));p=self.api if guid==API and self.registered else 0;self.w64(c,p);e=self.locate_error if guid==API and self.locate_error else 0 if p else ERR(14)
  elif name=='GetVariable':
   assert str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))==CFG
   var=self.wide(a);assert var in ('HeroIpmiSettings','HeroIpmiState');n=self.count.get(var,0)+1;self.count[var]=n
   if self.mutate:self.mutate(self,var,n)
   val=self.settings if var=='HeroIpmiSettings' else self.state
   e=self.errors.get(var,ERR(14) if val is None else 0)
   if not e:
    length=self.sizes.get(var,len(val));u.mem_write(c,struct.pack('<I',self.attrs.get(var,3)));capacity=self.r64(d);self.w64(d,length)
    if length<=capacity:u.mem_write(self.r64(sp+0x28),val[:length])
    else:e=ERR(5)
  elif name=='Load':
   assert a==0 and b==0x77 and c==0;size=self.r64(sp+0x28);raw=bytes(u.mem_read(d,size));assert raw==DRIVER and hashlib.sha256(raw).hexdigest()==EXPECTED;self.w64(self.r64(sp+0x30),0x9000);e=self.load_error
  elif name=='Start':
   assert a==0x9000 and b==c==0;e=self.start_error
   if not e:
    self.registered=True
    if self.settings is None:self.settings=DEFAULT[:self.seed_width] # Explicit fixture, not actual P6 execution.
  elif name=='Handle':e=ERR(14)
  elif name=='ReadKey':
   if not self.keys:raise AssertionError('Unexpected extra key request')
   k=self.keys.pop(0);u.mem_write(b,struct.pack('<HH',0,ord(k)))
   if k=='L' and self.low_log_space:
    if self.low_log_space==1:u.mem_write(symbols['audit_bad'],struct.pack('<I',1))
    else:self.w64(symbols['audit_len'],262144-147455)
  elif name=='Output':self.text+=self.wide(b)
  elif name=='Watchdog':assert a==b==c==d==0;e=self.watchdog_error
  elif name=='Free':pass
  elif name=='CachedLog':self.w64(a,len(self.log_data));e=self.log
  elif name=='CachedValue':assert a<41;e=self.textp
  else:raise AssertionError(name)
  u.reg_write(UC_X86_REG_RAX,e);u.reg_write(UC_X86_REG_RIP,self.r64(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def run(self):
  mapped=bytearray(pe.get_memory_mapped_image())
  if self.corrupt_sha:
   at=mapped.find(DRIVER);assert at>=0;mapped[at+512]^=1
  self.u.mem_write(image,bytes(mapped));stack=self.base+0x4e0008;stop=self.base+0x4ff000;self.w64(stack,stop);self.u.reg_write(UC_X86_REG_RSP,stack);self.u.reg_write(UC_X86_REG_RCX,0x77);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(image+pe.OPTIONAL_HEADER.AddressOfEntryPoint,stop,count=350000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==stop and self.u.reg_read(UC_X86_REG_RAX)==0
  assert not any(x.startswith('Forbidden') for x in self.calls)
  return self.text
rows=[]
def check(name,m,loads=0,token=None):
 text=m.run();assert m.calls.count('Load')==loads,(name,text[-1800:]);assert not token or token in text,(name,text[-1800:]);rows.append(name)
for s in (None,DEFAULT,DEFAULT[:21]):
 for j in (None,journal()):check('safe missing/default '+str((s is None,j is None)),Machine(s,j),1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x0000000000000000')
check('safe journal historical result fields',Machine(DEFAULT,journal(results=True)),1)
for i in range(32):
 b=bytearray(DEFAULT);b[i]^=1;check('reject settings byte '+str(i),Machine(bytes(b),None))
for i in range(21):
 b=bytearray(DEFAULT[:21]);b[i]^=1;check('reject21 settings byte '+str(i),Machine(bytes(b),None))
for n in (20,22,23,24,25,26,27,28,29,30):
 check('reject other settings length '+str(n),Machine(DEFAULT[:n],None))
for kw in ({'phase':6},{'phase':1},{'blocked':1},{'applied':bytes([1])+DEFAULT[1:]},{'request':bytes([1])+DEFAULT[1:]}):check('reject journal '+str(kw),Machine(DEFAULT,journal(**kw)))
b=bytearray(journal());b[12]^=1;check('reject journal CRC',Machine(DEFAULT,bytes(b)))
for var in ('HeroIpmiSettings','HeroIpmiState'):
 for attr in (0,1,7):
  m=Machine(DEFAULT,journal());m.attrs[var]=attr;check('reject attrs '+var+str(attr),m)
 for size in (0,31 if var=='HeroIpmiSettings' else 143,33 if var=='HeroIpmiSettings' else 145):
  m=Machine(DEFAULT,journal());m.sizes[var]=size;check('reject size '+var+str(size),m)
 for err in (ERR(5),ERR(7),ERR(26)):
  m=Machine(DEFAULT,journal());m.errors[var]=err;check('reject status '+var+str(err),m)
check('reject wrong board',Machine(board=b'ProArt Z790-CREATOR WIFI'))
check('reject wrong BIOS',Machine(bios=b'3001'))
check('reject wrong UUID',Machine(bad_uuid=True))
check('unused OEM binary strings accepted',Machine(extra=record(200,b'',(b'\xff\xfe',))),1)
check('runtime SHA corruption refused',Machine(corrupt_sha=True),0,'LOAD_REFUSED_DRIVER_SHA256')
check('preexisting P6 captured but not loaded',Machine(DEFAULT,journal(),preexisting=True,keys='LC\x1bQQ'),0,'P6 RAM log viewer closed')
check('bad protocol discovery refuses load',Machine(locate_error=ERR(7)))
check('application watchdog failure refuses load',Machine(watchdog_error=ERR(7)))
check('no explicit L means no load',Machine(keys='QQ'))
check('L cannot replay',Machine(keys='LLQQ'),1,'LOAD_REFUSED_ALREADY_ATTEMPTED')
m=Machine();m.load_error=ERR(26);check('LoadImage failure no Start or retry',m,1);assert 'Start' not in m.calls
m=Machine();m.start_error=ERR(7);check('StartImage failure no Unload or retry',m,1)
for nth in (2,3):
 m=Machine(DEFAULT,journal())
 def change(machine,var,n,point=nth):
  if var=='HeroIpmiSettings' and n==point:machine.settings=bytes([1])+DEFAULT[1:]
 m.mutate=change;check('variable race at read '+str(nth),m)
m=Machine(DEFAULT,None)
def safe_change(machine,var,n):
 if var=='HeroIpmiState' and n==2:machine.state=journal()
m.mutate=safe_change;check('safe but changed presence also refused',m,0,'LOAD_REFUSED_CHANGED_SINCE_ENTRY')
for mode in (1,2):
 m=Machine();m.low_log_space=mode;check('insufficient log evidence space '+str(mode),m,0,'LOAD REFUSED: insufficient space')
m=Machine();m.seed_width=21;check('unexpected missing-to21 not claimed as expected seed32',m,1,'POST_START_ONLY_EXPECTED_NV_CHANGE=0x8000000000000021')
report={'passed':True,'cases':len(rows),'results':rows,'actual_launcher_sha256':hashlib.sha256(data).hexdigest(),'driver_sha256_checked_at_LoadImage':EXPECTED,'forbidden_calls':['ConnectController','SignalEvent','SetVariable','UnloadImage'],'limits':['P6 StartImage and cached API are firmware-service fixtures; these tests prove the actual launcher gates, not actual native P6 refresh.']}
(BASE/'tests/launcher-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
