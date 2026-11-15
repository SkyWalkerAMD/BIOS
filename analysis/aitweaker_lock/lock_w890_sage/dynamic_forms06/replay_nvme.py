"""Original NvmeDynamicSetup event -> original opcode builder -> original HII update.

All UEFI services are explicit in-process models; no hardware is touched. The
database has original forms plus END only. NewString's returned ID is a modeled
input, not a claim about the physical string database. No target code is patched.
"""
from pathlib import Path
import json,struct,uuid,hashlib,sys,collections
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_WRITE
from unicorn.x86_const import *
BASE=0x2000000; BS=0x3000000; STR=BS+0x1000;DB=BS+0x2000;STUB=BS+0x8000;STOP=BS+0xf000;STACK=0x4000000;POOL=0x5000000;HANDLE=0x990000
ERR=1<<63;Q=lambda n:struct.pack('<Q',n);D=lambda n:struct.pack('<I',n)
REGS=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]
class VM:
 def __init__(self,first_id=30,locate_error=14):
  self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.u.mem_map(BASE,0x10000);self.u.mem_map(BS,0x10000);self.u.mem_map(STACK,0x20000);self.u.mem_map(POOL,0x400000)
  self.pe_bytes=(H/'inputs/NvmeDynamicSetup.efi').read_bytes();assert hashlib.sha256(self.pe_bytes).hexdigest()=='5e30ac30aa2cc1df3c8134f828e05d120e74b1a12487d470f21b9ef9e57399b6'
  p=pefile.PE(data=self.pe_bytes);p.relocate_image(BASE);self.u.mem_write(BASE,p.get_memory_mapped_image())
  sec=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text')
  self.text_extent=(BASE+sec.VirtualAddress,sec.Misc_VirtualSize)
  self.native_text_before=hashlib.sha256(bytes(self.u.mem_read(*self.text_extent))).hexdigest()
  self.forms=(H/'inputs/NvmeDynamicSetup.forms.bin').read_bytes();body=self.forms+b'\x04\x00\x00\xdf'
  self.package=uuid.UUID('668706b2-bcfc-4ad4-a185-75e79f3fe169').bytes_le+D(20+len(body))+body
  self.handlers={};self.next=POOL;self.live={};self.calls=collections.Counter();self.trace=[];self.updates=[];self.strings=[];self.allocations=[];self.error=None;self.first_id=first_id;self.next_id=first_id
  self.locate_error=locate_error;assert locate_error in (7,14)
  self.native_calls=collections.Counter();self.chain={0x2b30:'EventNoDeviceBranch',0x1958:'EnumerateAMIControllers',0x16fc:'AddString',0x4a1c:'AllocateOpcodeHandle',0x4c50:'CreateGuidOpcode',0x4cac:'CreateSubtitle',0x4b00:'CreateOpcode',0x5064:'HiiUpdateForm',0x4dc0:'UpdateFormPackage'}
  for offset in range(0x18,0x180,8):self.wq(BS+offset,self.stub('unknown-bs-'+hex(offset),self.unknown))
  for offset in range(0,0x40,8):self.wq(STR+offset,self.stub('unknown-string-'+hex(offset),self.unknown))
  for offset in range(0,0x60,8):self.wq(DB+offset,self.stub('unknown-db-'+hex(offset),self.unknown))
  for offset,name,fn in [(0x40,'AllocatePool',self.allocate),(0x48,'FreePool',self.free),(0x138,'LocateHandleBuffer_AMI_error',self.locate)]:self.wq(BS+offset,self.stub(name,fn))
  for offset,name,fn in [(0,'NewString',self.new_string),(0x10,'SetString',self.set_string),(0x18,'GetLanguages',self.languages)]:self.wq(STR+offset,self.stub(name,fn))
  for offset,name,fn in [(0x20,'ExportPackageLists',self.export),(0x10,'UpdatePackageList',self.update)]:self.wq(DB+offset,self.stub(name,fn))
  for rva,val in [(0x7b38,BS),(0x7b18,STR),(0x7b70,DB),(0x7b28,HANDLE)]:self.wq(BASE+rva,val)
  self.u.hook_add(UC_HOOK_CODE,self.code,begin=STUB,end=STOP)
  self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
  for rva in self.chain:self.u.hook_add(UC_HOOK_CODE,self.native_entry,begin=BASE+rva,end=BASE+rva)
  self.u.hook_add(UC_HOOK_MEM_WRITE,self.reject_code_write,begin=self.text_extent[0],end=sum(self.text_extent)-1)
 def rq(self,p):return struct.unpack('<Q',self.u.mem_read(p,8))[0]
 def wq(self,p,n):self.u.mem_write(p,Q(n))
 def stub(self,n,fn):a=STUB+len(self.handlers)*16;self.handlers[a]=(n,fn);self.u.mem_write(a,b'\xc3');return a
 def unknown(self,a):raise RuntimeError('unmodeled UEFI operation')
 def put(self,b):p=self.next;self.next=(p+max(len(b),1)+15)&~15;assert self.next<POOL+0x400000;self.u.mem_write(p,b);self.live[p]=len(b);return p
 def allocate(self,a):assert a[0]==4 and a[1]<=0x100000;p=self.put(bytes(a[1]));self.wq(a[2],p);self.allocations.append({'address':p,'bytes':a[1]});return 0
 def free(self,a):assert a[0]in self.live,('not owned allocation',hex(a[0]));n=self.live.pop(a[0]);self.u.mem_write(a[0],b'\xdd'*n);return 0
 def locate(self,a):assert a[0]==2 and a[1]==BASE+0x70e0;guid=uuid.UUID(bytes_le=bytes(self.u.mem_read(a[1],16)));assert str(guid)=='afa4cf3f-af71-4c30-a4fb-2910e771f9b0',str(guid);return ERR|self.locate_error
 def native_entry(self,u,p,n,_):self.native_calls[self.chain[p-BASE]]+=1
 def reject_code_write(self,u,access,p,size,value,_):self.error={'native_code_write':hex(p),'size':size};u.emu_stop()
 def cstr(self,p,wide=False):
  out=bytearray();step=2 if wide else 1
  for i in range(512):
   c=bytes(self.u.mem_read(p+i*step,step))
   if c==bytes(step):return out.decode('utf-16le'if wide else'ascii')
   out+=c
  raise RuntimeError('unterminated modeled string')
 def languages(self,a):
  assert a[0]==STR and a[1]==HANDLE;raw=b'en-US\0';cap=self.rq(a[3]);self.wq(a[3],len(raw))
  if not a[2]or cap<len(raw):return ERR|5
  self.u.mem_write(a[2],raw);return 0
 def new_string(self,a):
  assert a[0]==STR and a[1]==HANDLE and not a[4] and not a[6];assert self.cstr(a[3])=='en-US'
  n=self.next_id;self.next_id+=1;self.u.mem_write(a[2],struct.pack('<H',n));self.strings.append({'operation':'NewString','id':n,'text':self.cstr(a[5],True),'modeled_id':True});return 0
 def set_string(self,a):
  assert a[0]==STR and a[1]==HANDLE and not a[5];self.strings.append({'operation':'SetString','id':a[2],'language':self.cstr(a[3]),'text':self.cstr(a[4],True)});return 0
 def export(self,a):
  assert a[0]==DB and a[1]==HANDLE;cap=self.rq(a[2]);self.wq(a[2],len(self.package))
  if not a[3]or cap<len(self.package):return ERR|5
  assert a[3]in self.live and self.live[a[3]]>=len(self.package);self.u.mem_write(a[3],self.package);return 0
 def update(self,a):
  assert a[0]==DB and a[1]==HANDLE;size=int.from_bytes(self.u.mem_read(a[2]+16,4),'little');assert 24<=size<0x100000 and a[2]in self.live and size<=self.live[a[2]]
  data=bytes(self.u.mem_read(a[2],size));assert data[:16]==self.package[:16];self.package=data;at=20;forms=[]
  while at<len(data):
   head=int.from_bytes(data[at:at+4],'little');n=head&0xffffff;typ=head>>24;assert n>=4 and at+n<=len(data)
   if typ==2:forms.append(data[at:at+n])
   at+=n
  assert at==len(data) and len(forms)==1;self.updates.append(forms[0]);return 0
 def ret(self,v):sp=self.u.reg_read(UC_X86_REG_RSP);self.u.reg_write(UC_X86_REG_RAX,v);self.u.reg_write(UC_X86_REG_RIP,self.rq(sp));self.u.reg_write(UC_X86_REG_RSP,sp+8)
 def code(self,u,p,n,_):
  if p==STOP:u.emu_stop();return
  if p not in self.handlers:return
  name,fn=self.handlers[p];sp=u.reg_read(UC_X86_REG_RSP);a=[u.reg_read(r)for r in REGS]+[self.rq(sp+40+8*i)for i in range(4)]
  self.calls[name]+=1
  try:self.ret(fn(a))
  except Exception as e:self.error={'operation':name,'message':str(e),'args':[hex(x)for x in a]};u.emu_stop()
 def invalid(self,u,access,p,size,value,_):self.error={'invalid':hex(p),'rip':hex(u.reg_read(UC_X86_REG_RIP)-BASE),'size':size};return False
 def run(self):
  sp=STACK+0x18000-8;self.wq(sp,STOP);self.u.reg_write(UC_X86_REG_RSP,sp)
  for r in REGS:self.u.reg_write(r,0)
  try:self.u.emu_start(BASE+0x2b30,STOP+1,count=10000000)
  except Exception as e:
   if not self.error:self.error=str(e)
  if self.error or self.u.reg_read(UC_X86_REG_RIP)!=STOP:raise RuntimeError(str(self.error))
  assert hashlib.sha256(bytes(self.u.mem_read(*self.text_extent))).hexdigest()==self.native_text_before
  return self.updates
if __name__=='__main__':
 first=int(sys.argv[1],0)if len(sys.argv)>1 else 30;v=VM(first);r={'scope':__doc__,'modeled_NewString_first_id':first,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'status':'RUNNING','target_rva':'0x2b30','code_patches':0,'firmware_or_hardware_actions':0}
 try:
  forms=v.run();assert len(forms)==1;r['status']='PASS_ORIGINAL_NATIVE_UPDATE_WITH_MODELED_SERVICES';out=forms[0];r['generated_forms']={'bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),'physical_sha256_match':hashlib.sha256(out).hexdigest()=='06213876bb686f42b602d87fc5c6b10682bb3d20bc6f5bdea02e6d84791d0861'};(H/('nvme_model_id%d.forms.bin'%first)).write_bytes(out)
 except Exception as e:r['status']='FAIL_MODEL_BOUNDARY';r['error']=str(e)
 r.update(services=dict(v.calls),native_entries=dict(v.native_calls),strings=v.strings,live_allocations=v.live)
 (H/('nvme_model_id%d.json'%first)).write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
