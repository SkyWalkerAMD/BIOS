"""Actual final-app platform/transaction byte replay with explicit UEFI services.

Initial inventory is seeded from exact original fixture identities; this suite
does not certify the complete production inventory collector or actual firmware
services. The real cached-map validator/pagewalker/allocator guards/builder,
transaction, LoadImage-content validation and EBS gates execute unchanged.
"""
from pathlib import Path
import hashlib,importlib.util,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=D04.parents[6];BUILD=HERE/'app_build';CORE=D04/'split_core'
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,unicorn as U,capstone
from unicorn import x86_const as R
meta=json.loads((CORE/'build/split_build.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
FILE=BUILD/'SageNative13RamTest05.efi';PE=pefile.PE(str(FILE));BASE=PE.OPTIONAL_HEADER.ImageBase
S={name:int(a,16)for name,a in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',(BUILD/'app.map').read_text(),re.M)}
q=lambda x:struct.pack('<Q',x);d=lambda x:struct.pack('<I',x);ERR=lambda n:(1<<63)|n
DATA=0x50000000;STACK=0x70000000;STOP=0x51000000;TABLE=0x52000000;PBASE=0x60000000
SERV={n:STOP+0x100+i*0x20 for i,n in enumerate(['map','alloc','attr','raise','restore','load','handle','start','locate'])}
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);pause_addresses=[]
for section in PE.sections:
 if section.Characteristics&0x20000000:pause_addresses.extend(x.address for x in md.disasm(section.get_data(),BASE+section.VirtualAddress)if x.mnemonic=='pause')
class VM:
 def __init__(self,accelerate=True):
  self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);self.tpl=4;self.calls=[];self.foreign_writes=[];self.held=None;self.fault=None;self.fired=0;self.allocated=[];self.fail_alloc=False;self.bad_alloc=None;self.fail_attr=False;self.change_foreign=False;self.provider_mode=False;self.bounds=[];self.bases=[0x10000000,0x20000000]
  self.map(BASE,PE.OPTIONAL_HEADER.SizeOfImage);self.u.mem_write(BASE,PE.get_memory_mapped_image())
  for section in PE.sections:
   perms=U.UC_PROT_READ|(U.UC_PROT_WRITE if section.Characteristics&0x80000000 else 0)|(U.UC_PROT_EXEC if section.Characteristics&0x20000000 else 0)
   self.u.mem_protect(BASE+section.VirtualAddress,(max(section.Misc_VirtualSize,section.SizeOfRawData)+4095)&~4095,perms)
  for a,n in [(DATA,0x10000),(STACK,0x100000),(STOP,0x10000),(TABLE,0x100000)]:self.map(a,n)
  self.original=[];self.lis=[DATA+0x1000,DATA+0x1100];self.selfli=DATA+0x1200;self.extras=[DATA+0x1300,DATA+0x1400]
  for i,name in enumerate(['AMITSE','Setup']):
   raw=bytearray((CORE/'build'/(name+'.memory-fixture.bin')).read_bytes())
   for row in meta['patches']:
    if row['module']==name:raw[int(row['rva'],16):int(row['rva'],16)+row['length']]=bytes.fromhex(row['old'])
   self.original.append(bytes(raw));self.map(self.bases[i],len(raw));self.u.mem_write(self.bases[i],bytes(raw))
   self.u.mem_write(self.lis[i]+0x40,q(self.bases[i])+q(meta['module_fixtures'][name]['original_image_size']))
   self.put('loaded',q(self.lis[i]),i*8);self.put('images',q(self.bases[i]),i*8)
   peoff=struct.unpack_from('<I',raw,0x3c)[0];self.put('original_pe',d(peoff),i*4);self.put('original_headers',raw[peoff:peoff+0x108],i*0x108)
  self.u.mem_write(self.selfli+0x40,q(BASE)+q(PE.OPTIONAL_HEADER.SizeOfImage));self.put('self_loaded',q(self.selfli))
  for i,a in enumerate(self.extras):self.u.mem_write(a+0x40,q(0x40000000+i*0x1000000)+q(0x21000));self.put('extra_loaded',q(a),i*8)
  spans=[(self.bases[0],len(self.original[0])),(self.bases[1],len(self.original[1])),(BASE,PE.OPTIONAL_HEADER.SizeOfImage),(0x40000000,0x21000),(0x41000000,0x21000)]
  self.put('image_count',q(len(spans)));self.put('all_images',b''.join(q(a)+q(n)for a,n in spans))
  self.st=DATA+0x2000;self.bs=DATA+0x3000;self.rt=DATA+0x4000;self.cpu=DATA+0x5000
  self.u.mem_write(self.st+0x58,q(self.rt)+q(self.bs));self.u.mem_write(self.cpu+0x38,q(SERV['attr']))
  for name,a in [('system_table',self.st),('app_st',self.st),('app_image',0xabcd),('cpu',self.cpu),('setup_config',self.bases[1]+0x2bdd0),('app_browser',self.bases[0]+0x6b000)]:self.put(name,q(a))
  for offset,name in [(0x18,'raise'),(0x20,'restore'),(0x28,'alloc'),(0x38,'map'),(0x98,'handle'),(0xc8,'load'),(0xd0,'start'),(0x140,'locate')]:self.u.mem_write(self.bs+offset,q(SERV[name]))
  self.env=struct.pack('<5Q2I',0x80010013,TABLE,0x668,0xd00,0x0007040600070406,46,0);self.put('environment',self.env)
  self.tables_next=TABLE+0x2000;self.u.mem_write(TABLE,q(TABLE+0x1000|3))
  for i in range(8):self.u.mem_write(TABLE+0x1000+i*8,q(i*(1<<30)|0x83))
  self.base_regions=[(self.bases[i],(len(self.original[i])+4095)&~4095,3)for i in range(2)]+[(BASE,PE.OPTIONAL_HEADER.SizeOfImage,3),(DATA,0x10000,4),(STOP,0x10000,3),(TABLE,0x100000,4),(STACK,0x100000,4)]
  self.update_map();self.put('inventory_ready',d(1))
  self.u.reg_write(R.UC_X86_REG_CR4,0x600)
  if accelerate:self.u.hook_add(U.UC_HOOK_CODE,self.hash_hook,begin=S['ap_sha256'],end=S['ap_sha256'])
  for a in [STOP,*SERV.values(),S['read_cpu_env'],S['app_hold'],*pause_addresses]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=a,end=a)
  for i,b in enumerate(self.bases):self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.write,begin=b,end=b+len(self.original[i])-1)
  assert self.call('capture_foreign')==1
 def map(self,a,n):n=(n+4095)&~4095;self.u.mem_map(a,n);self.bounds.append((a,n))
 def put(self,name,b,offset=0):self.u.mem_write(S[name]+offset,bytes(b))
 def hash_hook(self,u,a,n,_):
  # Fault matrix acceleration: compute the exact requested SHA over actual
  # fixture bytes with hashlib, never return a constant accepted digest. The
  # real SHA machine code is separately exercised in the joint P13 ownership
  # and true OVMF app-loaded validator suites; this boundary model is explicit.
  assert self.arg(1)<=1024*1024;u.mem_write(self.arg(2),hashlib.sha256(bytes(u.mem_read(self.arg(0),self.arg(1)))).digest());self.ret(0)
 def getq(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def getd(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def arg(self,n):return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][n])if n<4 else self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+0x28+8*(n-4))
 def ret(self,v):sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,v);self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
 def records(self):
  regions=sorted(self.base_regions+[(a,p*4096,t)for a,p,t in self.allocated]);last=0;out=[]
  for a,n,t in regions:
   assert a>=last,(hex(a),hex(last));out.append(struct.pack('<II4Q',t,0,a,0,n//4096,0));last=a+n
  return b''.join(out)
 def update_map(self):raw=self.records();self.put('map',raw);self.put('map_bytes',q(len(raw)));self.put('stride',q(40))
 def pte(self,a):
  index=a>>30;pdpt=TABLE+0x1000+index*8;value=self.getq(pdpt)
  if value&128:
   pd=self.tables_next;self.tables_next+=4096
   for j in range(512):self.u.mem_write(pd+j*8,q(index*(1<<30)+j*(1<<21)|0x83))
   self.u.mem_write(pdpt,q(pd|3))
  pd=self.getq(pdpt)&~4095;entry=pd+((a>>21)&511)*8;value=self.getq(entry)
  if value&128:
   pt=self.tables_next;self.tables_next+=4096;base=a&~((1<<21)-1)
   for j in range(512):self.u.mem_write(pt+j*8,q(base+j*4096|3))
   self.u.mem_write(entry,q(pt|3))
  return (self.getq(entry)&~4095)+((a>>12)&511)*8
 def finish_service(self,name,result):
  self.calls.append((name,self.tpl));assert self.tpl==4 or name in ['raise','restore'],('firmware call at highTPL',name,self.tpl)
  if self.fault==len(self.calls):
   self.fired=1;tramp=STOP+0x8000;ending=S['ending']
   code=b'\x48\x83\xec\x28\x31\xc9\x31\xd2\x48\xb8'+q(ending)+b'\xff\xd0\x48\xb8'+q(result)+b'\x48\x83\xc4\x28\xc3'
   self.u.mem_write(tramp,code);self.u.reg_write(R.UC_X86_REG_RIP,tramp)
  else:self.ret(result)
 def hook(self,u,a,n,_):
  if a==STOP:u.emu_stop();return
  if a==S['app_hold']:self.held=self.arg(0);u.emu_stop();return
  if a in pause_addresses:
   self.held=self.getd(S['app_hold_reason']);assert self.held;u.emu_stop();return
  if a==S['read_cpu_env']:u.mem_write(self.arg(0),self.env);self.ret(1);return
  name=next(k for k,v in SERV.items()if v==a)
  if name=='map':
   raw=self.records();capacity=self.getq(self.arg(0));assert capacity>=len(raw)
   u.mem_write(self.arg(1),raw);u.mem_write(self.arg(0),q(len(raw)));u.mem_write(self.arg(2),q(1));u.mem_write(self.arg(3),q(40));u.mem_write(self.arg(4),d(1));self.finish_service(name,0);return
  if name=='alloc':
   assert self.arg(0)==1;typ,pages,out=self.arg(1),self.arg(2),self.arg(3)
   if self.fail_alloc:self.finish_service(name,ERR(9));return
   address=self.bad_alloc if self.bad_alloc is not None else [0x2ffff000,0x3000f000,0x3001f000,0x30fff000,0x3100f000,0x3101f000][len(self.allocated)]
   if self.bad_alloc is None:self.map(address,pages*4096);self.allocated.append((address,pages,typ))
   u.mem_write(out,q(address));self.finish_service(name,0);return
  if name=='attr':
   assert self.arg(0)==self.cpu;base,size,attr=self.arg(1),self.arg(2),self.arg(3)
   assert any(a+4096==base and (pages-2)*4096==size for a,pages,t in self.allocated),('foreign attribute change',hex(base),size)
   if not self.fail_attr:
    for address in range(base,base+size,4096):
     entry=self.pte(address);value=address|1|(0 if attr&0x20000 else 2)|((1<<63)if attr&0x4000 else 0);u.mem_write(entry,q(value))
     u.mem_protect(address,4096,U.UC_PROT_READ|(0 if attr&0x20000 else U.UC_PROT_WRITE)|(0 if attr&0x4000 else U.UC_PROT_EXEC))
   if self.change_foreign:u.mem_write(self.pte(self.bases[0]+0xe000),q((self.bases[0]+0xe000)|1))
   self.finish_service(name,ERR(3)if self.fail_attr else 0);return
  if name=='raise':old=self.tpl;self.tpl=self.arg(0);self.finish_service(name,old);return
  if name=='restore':self.tpl=self.arg(0);self.finish_service(name,0);return
  if name=='load':
   assert self.arg(0)==0 and self.arg(4)==51200;source=bytes(u.mem_read(self.arg(3),51200));assert hashlib.sha256(source).hexdigest()=='caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9'
   provider=pefile.PE(data=source);provider.relocate_image(PBASE);raw=provider.get_memory_mapped_image();self.map(PBASE,provider.OPTIONAL_HEADER.SizeOfImage);u.mem_write(PBASE,raw);self.base_regions.append((PBASE,provider.OPTIONAL_HEADER.SizeOfImage,3))
   self.provider_li=DATA+0x6000;u.mem_write(self.provider_li+0x40,q(PBASE)+q(provider.OPTIONAL_HEADER.SizeOfImage));u.mem_write(self.arg(5),q(0xf013));self.finish_service(name,0);return
  if name=='handle':assert self.arg(0)==0xf013;u.mem_write(self.arg(2),q(self.provider_li));self.finish_service(name,0);return
  if name=='start':
   # Real DXE Core may destroy this interface after StartImage failure.
   u.mem_protect(self.provider_li&~4095,4096,U.UC_PROT_NONE);self.finish_service(name,ERR(3));return
  if name=='locate':self.finish_service(name,ERR(14));return
  raise AssertionError(name)
 def write(self,u,access,a,n,v,_):
  assert self.tpl==31,('foreign target write outside TPL31',hex(a),self.tpl)
  assert any(int(r['address'],16)<=a and a+n<=int(r['address'],16)+r['length']for r in meta['patches']),('non-site foreign store',hex(a),n)
  self.foreign_writes.append((a,n))
 def call(self,name,*args):
  self.held=None;sp=STACK+0xffe08;self.u.mem_write(sp,q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for i,x in enumerate(args):self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i],x)
  self.u.emu_start(S[name],0,count=500000000);rip=self.u.reg_read(R.UC_X86_REG_RIP)
  assert rip==STOP or self.held is not None,(name,hex(rip))
  return self.u.reg_read(R.UC_X86_REG_RAX)if self.held is None else 'HOLD'
 def session(self,i=0):return S['app_sessions']+i*856
 def prepare(self,i=0):self.u.mem_write(self.session(i)+832,d(i+1));return self.call('platform_prepare',self.session(i),i+1)
 def originals(self):return all(bytes(self.u.mem_read(a,len(raw)))==raw for a,raw in zip(self.bases,self.original))
def main():
 checks=[]
 def check(label,value):assert value,label;checks.append(label)
 v=VM();check('actual allocator/builder/pure validator prepare mode1',v.prepare()==1 and not v.foreign_writes)
 ctx=v.session();check('actual adapter all12 install',v.call('platform_install',ctx)==0 and v.tpl==4 and bool(v.foreign_writes))
 constructed=[]
 for i,name in enumerate(['AMITSE','Setup']):
  address=0x30000000+i*0x10000;n=meta['module_fixtures'][name]['guard_bytes'];actual=bytes(v.u.mem_read(address,n));constructed.append(actual)
  check('runtime '+name+' guard equals independently frozen builder bytes',actual==(CORE/'build'/(name+'.split-guard.bin')).read_bytes())
 check('actual adapter exact rollback',v.call('platform_remove',ctx)==2 and v.originals()and v.tpl==4)
 check('retired mode1 allocations retained',len(v.allocated)==3 and all(n not in ['free','unload']for n,t in v.calls))
 # Import definitions only; this does not invoke frozen test main/report writes.
 spec=importlib.util.spec_from_file_location('tx05_frozen_owner',D04/'provider13/verify_owner.py');owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
 o=owner.OwnerVM()
 for i,raw in enumerate(constructed):o.u.mem_write(0x30000000+i*0x10000,raw)
 check('runtime-constructed detached guards accepted by actual frozen P13 owner',o.bind()==1)
 o.initialize();o.start();check('actual P13 begins on runtime-constructed native wrapper',o.query()==3);o.end();check('actual P13 outer end clears session on runtime guards',o.query()==1)
 print(json.dumps({'phase':'construct install rollback P13 joint','checks':len(checks)}),flush=True)
 v2=VM();check('mode2 exact embedded provider loader relocation identity',v2.prepare(1)==1)
 ctx=v2.session(1);check('mode2 exact12 commit before provider start',v2.call('platform_install',ctx)==0)
 check('mode2 StartImage failure recorded resident once',v2.call('platform_start_provider',ctx)==0 and v2.getd(ctx+844)==1)
 before=list(v2.calls);check('failed provider cannot be started again',v2.call('platform_start_provider',ctx)==0 and v2.calls==before)
 check('failed provider start with unreadable destroyed LoadedImage still permits exact hook rollback',v2.call('platform_remove',ctx)==2 and v2.originals())
 for address,label in [(0x10000000,'original AMITSE'),(BASE,'resident app'),(0x41000000,'known BDS'),(STACK,'stack descriptor')]:
  x=VM();x.bad_alloc=address;check('allocator overlap '+label+' is refused before attributes or original stores',x.prepare()==0 and not x.foreign_writes and not any(n=='attr'for n,t in x.calls))
 x=VM();x.fail_alloc=True;check('allocation failure has zero original stores',x.prepare()==0 and not x.foreign_writes)
 x=VM();x.fail_attr=True;check('owned attribute error has zero original stores',x.prepare()==0 and not x.foreign_writes)
 x=VM();x.change_foreign=True;check('foreign permission mutation during owned service is terminal hold',x.prepare()=='HOLD'and not x.foreign_writes)
 x=VM();x.u.mem_write(x.bases[0]+0x300,b'\xcc');check('full original text mutation rejects before allocation',x.prepare()==0 and not any(n=='alloc'for n,t in x.calls))
 x=VM();entry=x.pte(x.bases[0]+0xe000);x.u.mem_write(entry,q((x.bases[0]+0xe000)|1));check('actual read-only target page rejects before allocation',x.prepare()==0 and not x.foreign_writes)
 # Every prepare service boundary in the observed normal mode1 trace. Actual
 # app ending callback and tx_end execute; post-ending service calls forbidden.
 y=VM();assert y.prepare()==1;boundaries=len(y.calls)
 for at in range(1,boundaries+1):
  x=VM();x.fault=at;result=x.prepare();check('ending at prepare service '+str(at)+' stops without later firmware service',result=='HOLD'and x.fired and len(x.calls)==at and not x.foreign_writes)
 print(json.dumps({'phase':'adapter service and faults','checks':len(checks),'boundaries':boundaries}),flush=True)
 result={'status':'PASS_ACTUAL_APP_PLATFORM_TRANSACTION_WITH_EXPLICIT_SERVICE_MODELS','checks':len(checks),'check_names':checks,'efi_sha256':sha(FILE),'build_sha256':sha(BUILD/'app_build.json'),'test_source_sha256':sha(Path(__file__)),'p13_efi_sha256':sha(D04/'provider13/build/AiTweakerSplitProvider13.UNSIGNED.local.efi'),'limits':['Initial inventory is seeded with exact fixture modules, not a complete actual firmware inventory acceptance.','CPU register reads and UEFI map/allocation/attribute/TPL/image services are modeled; actual bounded pagewalker, platform validator, emitted binding, transaction and app ending gate execute.','Fault-matrix SHA calls use exact Python hashlib over real requested bytes for speed, not a fixed accepted digest. Joint actual P13 and separate real OVMF loaded-app validator execute native crypto.','Provider joint ownership test uses explicit native body/service fixtures; ASUS GUI not executed.','No hardware access, no flash, no physical RAM installation.']}
 (BUILD/'platform_verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':len(checks),'efi_sha256':result['efi_sha256']}))
if __name__=='__main__':main()
