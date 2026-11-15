"""Execute original W890 AMITSE parser, with explicitly modeled UEFI services.

No original parser function is replaced. This is NOT a full firmware boot.
"""
from pathlib import Path
import sys,struct,json,hashlib,uuid,collections
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock'))
from inspect_setup import string_packages
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_BLOCK, UC_HOOK_MEM_INVALID
from unicorn.x86_const import *
TSE=0x2000000; BS=0x4000000; RT=BS+0x1000; DB=BS+0x2000; STR=BS+0x3000
STUB=BS+0x10000; STOP=BS+0x20000; STACK=0x5000000; POOL=0x10000000
HII=0x4870000; ERR=0x8000000000000000
Q=lambda x:struct.pack('<Q',x); D=lambda x:struct.pack('<I',x)
REGS=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
class VM:
 def __init__(self,changed=True,hii=HII):
  self.hii=hii
  self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.u.mem_map(TSE,0x200000);self.u.mem_map(BS,0x100000);self.u.mem_map(STACK,0x400000);self.u.mem_map(POOL,0x8000000)
  self.pe=pefile.PE(str(HERE.parent/'navigation/modules/AMITSE.efi'));self.original_sha=hashlib.sha256(self.pe.__data__).hexdigest();self.pe.relocate_image(TSE);self.u.mem_write(TSE,self.pe.get_memory_mapped_image())
  self.next=POOL;self.allocs={};self.live={};self.events=[];self.uefi_events={};self.frees=[];self.writes=[];self.calls=collections.Counter();self.trace=collections.deque(maxlen=24);self.error=None;self.handlers={}
  for off in range(0x18,0x180,8):self.u.mem_write(BS+off,Q(self.stub('bs'+hex(off),self.unknown)))
  for off in range(0x18,0x90,8):self.u.mem_write(RT+off,Q(self.stub('rt'+hex(off),self.unknown)))
  for off in range(0,0x60,8):self.u.mem_write(DB+off,Q(self.stub('db'+hex(off),self.unknown)))
  for off in range(0,0x40,8):self.u.mem_write(STR+off,Q(self.stub('str'+hex(off),self.unknown)))
  for off,name,fun in [(0x40,'allocate',self.allocate),(0x48,'free',self.free),(0x160,'copy',self.copy),(0x168,'set',self.setmem),(0x140,'locate',self.locate),(0x98,'handleprotocol',lambda a:ERR|14),(0xb0,'locatehandle',self.locatehandle)]:self.u.mem_write(BS+off,Q(self.stub(name,fun)))
  for off,name,fun in [(0x50,'create_event',self.create_event),(0x58,'set_timer',self.set_timer)]:self.u.mem_write(BS+off,Q(self.stub(name,fun)))
  self.u.mem_write(RT+0x48,Q(self.stub('getvariable',lambda a:ERR|14)))
  self.u.mem_write(RT+0x58,Q(self.stub('volatile_dynamic_page_count',self.volatile_count)))
  for off,name,fun in [(0x18,'list',self.listpkg),(0x20,'export',self.export),(0x28,'register',self.register),(0x30,'unregister',lambda a:0),(0x50,'getdriver',self.getdriver)]:self.u.mem_write(DB+off,Q(self.stub(name,fun)))
  self.u.mem_write(STR+8,Q(self.stub('getstring',self.getstring)))
  self.st=self.put(bytes(0x80));self.u.mem_write(self.st+8,D(0x20064))
  self.wq(TSE+0xafbc0,self.st);self.wq(TSE+0xafbc8,BS);self.wq(TSE+0xafbd8,RT);self.wq(TSE+0xafc38,DB);self.wq(TSE+0xafc18,STR)
  raw=next((ROOT/'analysis/workstation_20261008/W890_SAGE_0603').rglob('434 AMITSESetupData/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/0 FE612B72-203C-47B1-8560-A66D946EB371/body.bin')).read_bytes()
  self.static_sha=hashlib.sha256(raw).hexdigest();idx=raw.index(b'$SPF');self.static=self.put(raw[idx:]);self.wq(TSE+0xbabc0,self.static)
  profile=json.loads((HERE.parent/'password/profile_0603.json').read_text());setup=(ROOT/profile['sources']['Setup']['path']).read_bytes()
  assert hashlib.sha256(setup).hexdigest()==profile['sources']['Setup']['sha256']
  self.strings={int(k):v for k,v in string_packages(setup)[0]['strings'].items()};self.firstnew=max(self.strings)+1
  forms=bytearray((HERE.parent/'password/official_forms_0603.pack').read_bytes())
  self.insert_offset=3938
  if changed:
   actions=b''.join(struct.pack('<BBHHHHHBH',0x0c,15,self.firstnew+2*i,self.firstnew+2*i+1,0xffd0+i,0,0xffff,4,0) for i in range(3))
   assert len(actions)==45
   forms=forms[:3938]+actions+forms[3938:];forms[:4]=D((2<<24)|len(forms))
   for i,s in enumerate(['Set Ai Tweaker password','Create an independent password','Change Ai Tweaker password','Replace the independent password','Clear Ai Tweaker password','Remove the independent password']):self.strings[self.firstnew+i]=s
  self.forms=bytes(forms);self.package=uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le+D(24+len(forms))+forms+b'\x04\x00\x00\xdf'
  self.hii_pkg=self.put(self.package)
  self.u.hook_add(UC_HOOK_CODE,self.code,begin=STUB,end=STOP)
  if '--trace' in sys.argv:self.u.hook_add(UC_HOOK_BLOCK,lambda u,a,n,_:self.trace.append(hex(a-TSE)),begin=TSE,end=TSE+0x200000)
  self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
 def rq(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def rd(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def rw(self,a):return struct.unpack('<H',self.u.mem_read(a,2))[0]
 def wq(self,a,v):self.u.mem_write(a,Q(v))
 def put(self,b):a=self.next;self.next=(a+max(len(b),1)+15)&~15;assert self.next<POOL+0x8000000;self.u.mem_write(a,bytes(b));return a
 def stub(self,name,fun):a=STUB+len(self.handlers)*16;self.handlers[a]=(name,fun);self.u.mem_write(a,b'\xc3');return a
 def ret(self,v):s=self.u.reg_read(UC_X86_REG_RSP);self.u.reg_write(UC_X86_REG_RAX,v);self.u.reg_write(UC_X86_REG_RIP,self.rq(s));self.u.reg_write(UC_X86_REG_RSP,s+8)
 def code(self,u,a,n,_):
  if a==STOP:u.emu_stop();return
  if a not in self.handlers:return
  name,fn=self.handlers[a];self.calls[name]+=1
  sp=u.reg_read(UC_X86_REG_RSP);args=[u.reg_read(r) for r in REGS]+[self.rq(sp+40),self.rq(sp+48)]
  try:self.ret(fn(args))
  except Exception as e:self.error=f'{name} {e} args={[hex(x) for x in args]}';u.emu_stop()
 def invalid(self,u,access,a,size,value,_):self.error=f'memory {access} {a:x}/{size} RIP={u.reg_read(UC_X86_REG_RIP):x}';return False
 def unknown(self,a):raise RuntimeError('unsupported modeled boundary')
 def allocate(self,a):
  p=self.put(bytes(a[1]));self.allocs[p]=a[1];self.live[p]=a[1];self.events.append(['allocate',p,a[1]]);self.wq(a[2],p);return 0
 def free(self,a):
  p=a[0];assert p in self.live,('free of nonlive allocation',hex(p));n=self.live.pop(p);self.u.mem_write(p,b'\xdd'*n);self.events.append(['free',p,n]);self.frees.append(p);return 0
 def copy(self,a):self.u.mem_write(a[0],bytes(self.u.mem_read(a[1],a[2])));return 0
 def setmem(self,a):self.u.mem_write(a[0],bytes([a[2]&255])*a[1]);return 0
 def create_event(self,a):
  assert a[0]==0x80000200 and a[1]==8 and TSE<a[2]<TSE+0x93000
  h=0x4900000+len(self.uefi_events)*8;self.uefi_events[h]={'type':a[0],'tpl':a[1],'notify':a[2],'context':a[3]};self.wq(a[4],h);return 0
 def set_timer(self,a):
  assert a[0]in self.uefi_events and a[1]in[0,1,2];self.uefi_events[a[0]].update(timer=a[1],trigger=a[2]);return 0
 def locate(self,a):return ERR|14
 def locatehandle(self,a):return ERR|14
 def listpkg(self,a):
  cap=self.rq(a[3]);self.wq(a[3],8)
  if cap<8:return ERR|5
  self.wq(a[4],self.hii);return 0
 def export(self,a):
  assert a[1]==self.hii,hex(a[1]);cap=self.rq(a[2]);self.wq(a[2],len(self.package))
  if not a[3] or cap<len(self.package):return ERR|5
  self.u.mem_write(a[3],self.package);return 0
 def register(self,a):self.wq(a[5],0x90000000+self.calls['register']);return 0
 def getdriver(self,a):
  if a[1]!=self.hii:return ERR|14
  self.wq(a[2],0x4890000);return 0
 def volatile_count(self,a):
  name=bytes(self.u.mem_read(a[0],128)).decode('utf-16le',errors='replace').split('\0')[0]
  guid=bytes(self.u.mem_read(a[1],16));data=bytes(self.u.mem_read(a[4],a[3]))
  expected={'DynamicPageCount':('b63bf800-f267-4f55-9217-e97fb3b69846',4),'DynamicPageGroupCount':('537f1f99-6fc4-40b5-80b2-390b0753c4d0',2),'DynamicPageGroupClass':('551941e5-0011-4d7f-83ed-e462cbabccc9',14)}
  assert name in expected,(name,guid.hex(),a[2:4],data.hex())
  g,n=expected[name];assert guid==uuid.UUID(g).bytes_le and a[2:4]==[2,n] and data==bytes(n),(name,guid.hex(),a[2:4],data.hex())
  self.writes.append({'name':name,'guid':g,'attributes':2,'value':data.hex(),'effect':'volatile modeled service only'})
  return 0
 def getstring(self,a):
  if a[3] not in self.strings:return ERR|14
  p=(self.strings[a[3]]+'\0').encode('utf-16le');cap=self.rq(a[5]);self.wq(a[5],len(p))
  if cap<len(p):return ERR|5
  self.u.mem_write(a[4],p);return 0
 def call(self,rva,args=(),count=200000000):
  self.error=None;sp=STACK+0x300000-8;self.wq(sp,STOP);self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(REGS):self.u.reg_write(r,args[i] if i<len(args) else 0)
  for i,x in enumerate(args[4:]):self.wq(sp+40+i*8,x)
  try:self.u.emu_start(TSE+rva,STOP+1,count=count)
  except Exception as e:
   if not self.error:self.error=str(e)
  if self.error or self.u.reg_read(UC_X86_REG_RIP)!=STOP:raise RuntimeError(json.dumps({'error':self.error,'rip':hex(self.u.reg_read(UC_X86_REG_RIP)),'trace':list(self.trace),'calls':dict(self.calls)}))
  return self.u.reg_read(UC_X86_REG_RAX)
 def run(self,parser_rva=0x40d94):
  self.call(0x19cf8) # native initializer has no defined return contract
  self.call(0x1b7dc)
  self.call(0x1c17c)
  return self.call(parser_rva)
if __name__=='__main__':
 vm=VM(changed='--original' not in sys.argv)
 try:r=vm.run();print(json.dumps({'return':hex(r),'calls':dict(vm.calls),'pool':vm.next-POOL,'pages':hex(vm.rq(TSE+0xbaaf0))},indent=2))
 except Exception as e:print(e);raise
