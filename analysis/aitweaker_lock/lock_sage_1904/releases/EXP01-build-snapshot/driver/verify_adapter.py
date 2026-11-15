"""Run the actual compiled adapter and relocated original AMITSE hook bytes in
Unicorn. UI outcome, firmware services and full browser body are explicit stubs.
No OEM instructions execute on the Windows host. This is bounded path testing,
not execution of an ASUS platform or an AMITSE visual desktop."""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];CASE=HERE.parent/'analysis'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
DRV=0x140000000;TSE=0x10000000;SETUP=0x20000000;HEAP=0x60000000;STACK=0x70000000;STOP=0x50000000
def q(n):return struct.pack('<Q',n)
def d(n):return struct.pack('<I',n)
def w(n):return struct.pack('<H',n)
symbols={name:int(value,16) for name,value in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s', (HERE/'build/driver.map').read_text(encoding='utf8'),re.M)}
class VM:
 def __init__(self):
  self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);self.ranges=[];self.calls={'render':0,'page_input':0,'app_input':0,'frame_input':0,'poll':0,'ui':0};self.accept=False;self.hii_ok=True;self.body_context=None;self.count=0
  for base,size in [(HEAP,0x400000),(STACK,0x400000),(STOP,0x10000)]:self.map(base,size)
  for path,base in [(HERE/'build/AiTweakerLock1904.efi',DRV),(CASE/'modules/AMITSE.efi',TSE),(CASE/'modules/Setup.efi',SETUP)]:
   p=pefile.PE(str(path));p.relocate_image(base);data=p.get_memory_mapped_image();self.map(base,(len(data)+4095)&~4095);self.u.mem_write(base,data)
  self.st=HEAP;self.bs=HEAP+0x1000;self.app=HEAP+0x2000;self.array=HEAP+0x3000;self.table=HEAP+0x4000;self.records=HEAP+0x5000;self.handle=0x12345678
  self.u.mem_write(symbols['system_table'],q(self.st));self.u.mem_write(self.st+0x60,q(self.bs));self.u.mem_write(self.bs+0x28,q(STOP+0x100));self.u.mem_write(self.bs+0x140,q(STOP+0x110))
  self.u.mem_write(TSE+0x83588,q(self.app));self.u.mem_write(TSE+0x930b0,q(self.table));self.u.mem_write(TSE+0x93948,q(self.records));self.u.mem_write(TSE+0x83468,d(5))
  self.u.mem_write(TSE+0x837d8,q(HEAP+0x6000));self.u.mem_write(HEAP+0x6000,q(STOP+0x200))
  self.u.mem_write(self.app+0x28,d(0)+d(8)+q(self.array));self.u.mem_write(self.table,d(8))
  self.pages=[]
  for i,form in enumerate([0x2713,0x2714,0x2712,0x272c,0x6000,0x6001,0x6002,0x271b]):
   page=HEAP+0x10000+i*0x1000;self.pages.append(page);self.u.mem_write(self.array+i*8,q(page));self.u.mem_write(page+0x20,q(self.handle));self.u.mem_write(page+0x30,w(i));self.u.mem_write(self.table+4+i*4,d(i*64));self.u.mem_write(self.records+i*64+10,w(form))
  for i,source_handle in [(4,self.handle),(5,0x99998888),(7,self.handle)]:
   page=self.pages[i];frame=page+0x100;array=page+0x200;control=page+0x300;ifr=page+0x400
   self.u.mem_write(page+0x4c,d(1)+q(array));self.u.mem_write(array,q(frame));self.u.mem_write(frame+0x3c,d(1));self.u.mem_write(frame+0x48,q(array+8));self.u.mem_write(array+8,q(control));self.u.mem_write(control+0x20,q(source_handle));self.u.mem_write(control+0x48,q(ifr));self.u.mem_write(ifr,bytes.fromhex('05910000000034121d0010000010000100'))
   if i==7:self.u.mem_write(ifr,bytes.fromhex(json.loads((HERE/'policy.json').read_text(encoding='utf8'))['permanently_disabled_exit_descriptors'][0]['ifr_hex']))
  self.u.mem_write(self.pages[6]+0x4c,d(0xffffffff))
  self.u.mem_write(symbols['setup_hii'],q(self.handle));self.u.mem_write(symbols['password_core']+196,d(1))
  targets=[STOP,STOP+0x100,STOP+0x110,STOP+0x200,TSE+0x16a90,TSE+0x16c20,TSE+0x12168,TSE+0x1532f,TSE+0xe1ca]
  targets += [symbols[n] for n in ['memory_present','patch_memory','install_variable_guard','install_hii_management','ensure_unlocked']]
  for address in targets:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=address,end=address)
  # x64 SSE enabled as in the firmware execution environment.
  self.u.reg_write(R.UC_X86_REG_CR4,0x600)
 def map(self,b,n):self.u.mem_map(b,n);self.ranges.append((b,b+n))
 def getq(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def getd(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def arg(self,i):return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i])
 def ret(self,value):
  sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,value&((1<<64)-1));self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
 def hook(self,u,address,size,data):
  self.count+=1
  if address==STOP:u.emu_stop();return
  if address==symbols['memory_present']:
   a,n=self.arg(0),self.arg(1);self.ret(int(n>0 and any(lo<=a and a+n<=hi for lo,hi in self.ranges)));return
  if address==symbols['patch_memory']:
   a,b,n=self.arg(0),self.arg(1),self.arg(2);u.mem_write(a,bytes(u.mem_read(b,n)));self.ret(1);return
  if address==symbols['install_variable_guard']:self.ret(1);return
  if address==symbols['install_hii_management']:self.ret(int(self.hii_ok));return
  if address==symbols['ensure_unlocked']:
   self.calls['ui']+=1
   if self.accept:u.mem_write(symbols['password_core']+201,b'\1')
   self.ret(int(self.accept));return
  if address==STOP+0x100:u.mem_write(self.arg(3),q(HEAP+0x300000));self.ret(0);return
  if address==STOP+0x110:self.ret((1<<63)|14);return
  if address==STOP+0x200:self.calls['poll']+=1;self.ret(0);return
  for name,rva in [('render',0x16a90),('page_input',0x16c20),('app_input',0x12168),('frame_input',0x1532f)]:
   if address==TSE+rva:self.calls[name]+=1;self.ret(0 if name!='app_input' else (1<<63)|3);return
  if address==TSE+0xe1ca:self.body_context=u.context_save();u.emu_stop()
 def call(self,address,*args):
  sp=STACK+(0x30fe08 if self.body_context is not None else 0x3ffe08);self.u.mem_write(sp,q(STOP)+b'\xcc'*0x100);self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for i,value in enumerate(args):
   if i<4:self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i],value)
   else:self.u.mem_write(sp+40+(i-4)*8,q(value))
  self.u.emu_start(address,0,count=200000000)
  if self.u.reg_read(R.UC_X86_REG_RIP)!=STOP and self.u.reg_read(R.UC_X86_REG_RIP)!=TSE+0xe1ca:raise AssertionError(('instruction bound',hex(self.u.reg_read(R.UC_X86_REG_RIP))))
  return self.u.reg_read(R.UC_X86_REG_RAX)
 def start(self,hii_ok=True):
  self.hii_ok=hii_ok;self.body_context=None;self.call(TSE+0xe1b8);assert self.body_context is not None
 def end(self,result=0x123456789abcdef0):
  self.u.context_restore(self.body_context);sp=self.u.reg_read(R.UC_X86_REG_RSP)
  for i,reg in enumerate([R.UC_X86_REG_R15,R.UC_X86_REG_R14,R.UC_X86_REG_R13,R.UC_X86_REG_R12,R.UC_X86_REG_RDI,R.UC_X86_REG_RSI,R.UC_X86_REG_RBX,R.UC_X86_REG_RBP]):self.u.reg_write(reg,self.getq(sp+i*8))
  self.u.reg_write(R.UC_X86_REG_RSP,sp+64);self.ret(result);self.u.emu_start(self.u.reg_read(R.UC_X86_REG_RIP),0,count=100000)
  assert self.u.reg_read(R.UC_X86_REG_RIP)==STOP and self.u.reg_read(R.UC_X86_REG_RAX)==result
 def current(self,i):self.u.mem_write(self.app+0x28,d(i))
 def unlocked(self):return bool(self.u.mem_read(symbols['password_core']+201,1)[0])

checks=[]
def check(name,value):assert value,name;checks.append(name)
v=VM();check('exact verified modules accepted',v.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a6000)==1)
nav=v.getq(TSE+0x7d4f8);render=v.getq(TSE+0x6b928);inp=v.getq(TSE+0x6b930);appinp=v.getq(TSE+0x6b840);poll=v.getq(v.getq(TSE+0x837d8))
v.start();check('actual wrapper begins locked session',not v.unlocked() and v.u.mem_read(symbols['password_core']+200,1)==b'\1')
v.current(1);v.call(TSE+0x34b2c);check('initial denied page redirected before native reader',v.getd(v.app+0x28)==0 and v.calls['ui']==1 and v.calls['poll']==1)
# Simulate the observed old-page veto after poll. Both secondary gates must deny.
v.current(1);before=v.calls['render'];v.call(render,v.pages[1]);check('stale protected render never reaches OEM renderer',v.calls['render']==before and v.getd(v.app+0x28)==0)
v.current(1);before=v.calls['page_input'];status=v.call(inp,v.pages[1],HEAP+0x8000);check('stale PageInput consumed with zero',status==0 and v.calls['page_input']==before)
v.current(1);before=v.calls['app_input'];status=v.call(appinp,v.app,HEAP+0x8000);check('protected AppInput consumed with zero',status==0 and v.calls['app_input']==before)
for i,name in [(2,'Favorites'),(3,'Profile'),(4,'dynamic OC source control'),(6,'malformed frame count')]:
 v.current(i);before=v.calls['render'];v.call(render,v.pages[i]);check(name+' blocked while locked',v.calls['render']==before)
for form,name in [(0x2eb8,'SAGE Overclocking Presets'),(0x2eba,'SAGE Memory Presets')]:
 v.u.mem_write(v.records+64+10,w(form));v.current(1);before=v.calls['render'];v.call(render,v.pages[1]);check(name+' blocked while locked',v.calls['render']==before and v.getd(v.app+0x28)==0)
v.u.mem_write(v.records+64+10,w(0x2714))
for i,name in [(0,'Main'),(5,'foreign HII varstore ID collision'),(7,'Exit with permanently disabled OC descriptors')]:
 v.current(i);before=v.calls['render'];v.call(render,v.pages[i]);check(name+' remains usable',v.calls['render']==before+1)
v.current(0);before=v.calls['frame_input'];status=v.call(TSE+0x15320,v.pages[4]+0x100,HEAP+0x8000)
check('modal frame OC edit blocked even with Main current page',status==0 and v.calls['frame_input']==before)
v.call(TSE+0x15320,v.pages[5]+0x100,HEAP+0x8000);check('foreign HII modal frame keeps working',v.calls['frame_input']==before+1)
before=v.calls['frame_input'];v.call(TSE+0x15320,v.pages[7]+0x100,HEAP+0x8000);check('Exit disabled legacy descriptors do not consume frame input',v.calls['frame_input']==before+1)
v.u.mem_write(v.pages[7]+0x402,b'\x01');before=v.calls['render'];v.call(render,v.pages[7]);check('changed legacy descriptor loses exemption and remains guarded',v.calls['render']==before);v.u.mem_write(v.pages[7]+0x402,b'\0')
old_guid=HEAP+0x9000;old_form=old_guid+16;new_guid=old_guid+32;new_form=old_guid+48
v.u.mem_write(old_guid,uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le);v.u.mem_write(new_guid,uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le);v.u.mem_write(old_form,w(0x2713));v.u.mem_write(new_form,w(0x2714))
v.u.mem_write(new_form,w(0x271b));before=v.calls['ui'];check('native Exit navigation needs no password',v.call(TSE+0x626c,old_guid,old_form,new_guid,new_form)==0 and v.calls['ui']==before);v.u.mem_write(new_form,w(0x2714))
check('native dispatcher four-pointer ABI denies correct new form',v.call(TSE+0x626c,old_guid,old_form,new_guid,new_form)==((1<<63)|15))
v.accept=True;check('accepted password permits native navigation',v.call(TSE+0x626c,old_guid,old_form,new_guid,new_form)==0 and v.unlocked())
before=v.calls['render'];v.current(1);v.call(render,v.pages[1]);check('unlocked protected renderer chains once',v.calls['render']==before+1)
before=v.calls['frame_input'];v.call(TSE+0x15320,v.pages[4]+0x100,HEAP+0x8000);check('unlocked modal frame trampoline chains once',v.calls['frame_input']==before+1)
outer=v.body_context;v.call(TSE+0xe1b8);check('nested browser within same BIOS session preserves grant',v.unlocked());v.end(0x11223344);v.body_context=outer
check('nested browser return does not terminate outer session',v.unlocked() and v.u.mem_read(symbols['password_core']+200,1)==b'\1')
v.end();check('actual wrapper preserves return and relocks exit',not v.unlocked() and v.u.mem_read(symbols['password_core']+200,1)==b'\0')
v.accept=False;v.start();check('reentry clears former unlock',not v.unlocked());v.end()
v.start(False);check('HII manager failure makes credential state fault',v.getd(symbols['password_core']+196)==3)
v.current(1);before=v.calls['render'];v.call(render,v.pages[1]);check('core active cleared by fault cannot bypass render lock',v.calls['render']==before);v.end()
# Reject a one-byte wrong-build mutation before installing a single hook.
bad=VM();old=bytes(bad.u.mem_read(TSE+0x6b928,8));bad.u.mem_write(TSE+0x300,b'\0');check('changed text fingerprint rejected',bad.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a6000)==0);check('wrong build left original callback untouched',bytes(bad.u.mem_read(TSE+0x6b928,8))==old)
ace=HERE.parent.parent/'hardware_20261102_W790_ACE_E9B906DF/modules'
for module,base in [('AMITSE',TSE),('Setup',SETUP)]:
 other=VM();pe=pefile.PE(str(ace/(module+'.efi')));pe.relocate_image(base);other.u.mem_write(base,pe.get_memory_mapped_image())
 before=bytes(other.u.mem_read(TSE+0x6b928,8))
 check('real ACE '+module+' fingerprint rejected',other.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a6000)==0)
 check('real ACE '+module+' mismatch leaves native callback untouched',bytes(other.u.mem_read(TSE+0x6b928,8))==before)
report={'status':'PASS','cases':len(checks),'checks':checks,'intercepted_function_entries':v.count+bad.count,'driver_sha256':hashlib.sha256((HERE/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest(),'amitse_sha256':hashlib.sha256((CASE/'modules/AMITSE.efi').read_bytes()).hexdigest(),'limits':['UI authentication success/failure is stubbed here; actual UI/core/storage separately run in OVMF.','Memory attributes, HII installation, and full browser body are explicit stubs.','Page/control structures follow REA-derived layouts; complete OEM UI and non-HII raw hardware paths are not executed.']}
(HERE/'build/adapter_emulation.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report,indent=2))
