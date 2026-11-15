"""Original0603 Save + compiled mid-function gate/thunk, explicit owner/service
models. This is a machine-code integration test, not physical authority proof.
"""
from pathlib import Path
import json,sys,struct,hashlib,uuid
H=Path(__file__).resolve().parent;R=H.parents[3];sys.path[:0]=[str(R/'tools/pydeps'),str(R/'tools/kvm-pydeps')]
import pefile,unicorn
from unicorn.x86_const import *
BASE=0x10000000;STACK=0x20000000;MEM=0x30000000;STOP=0x40000000;DLL=0x50000000;SETUP=0x60000000
original_path=H.parent/'navigation/modules/AMITSE.efi';module_path=H/'build/W890SaveGuard05.MODEL.dll'
p=pefile.PE(str(original_path));p.relocate_image(BASE);original=p.get_memory_mapped_image().ljust(p.OPTIONAL_HEADER.SizeOfImage,b'\0')
m=pefile.PE(str(module_path));m.relocate_image(DLL);component=m.get_memory_mapped_image().ljust(m.OPTIONAL_HEADER.SizeOfImage,b'\0');exports={e.name.decode():DLL+e.address for e in m.DIRECTORY_ENTRY_EXPORT.symbols}
setup_path=H.parent/'navigation/modules/Setup.efi';p=pefile.PE(str(setup_path));p.relocate_image(SETUP);setup=p.get_memory_mapped_image().ljust(p.OPTIONAL_HEADER.SizeOfImage,b'\0')
catalog=json.loads((H.parent/'write_sinks04/native_variable_catalog.json').read_text())['items'];blob=(H.parent/'write_sinks04/inputs/AMITSESetupData.bin').read_bytes();at=struct.unpack_from('<I',blob,0x34)[0];table=blob[at:at+488+121*124]
def q(x):return struct.pack('<Q',x)
def jmp(x):return b'\xff\x25\0\0\0\0'+q(x)
cases=[]
def check(label,passed,**data):
 assert passed,(label,data);cases.append({'name':label,'pass':True,**data})
class Lab:
 def __init__(self,patched=True,flags=3,mode=0,change='ordinary',fail_timeout=False):
  self.u=u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64)
  for a,n in [(BASE,(len(original)+4095)&~4095),(STACK,0x100000),(MEM,0x800000),(STOP,0x10000),(DLL,(len(component)+4095)&~4095),(SETUP,(len(setup)+4095)&~4095)]:u.mem_map(a,n)
  u.mem_write(BASE,original);u.mem_write(DLL,component);u.mem_write(SETUP,setup);self.events=[];self.writes=[];self.refresh=[];self.alloc=MEM+0x400000;self.fail_timeout=fail_timeout;self.profile=False;self.profile_calls=[];self.freed=[];self.ports=[]
  self.rt=MEM+0x10000;self.bs=MEM+0x11000;self.tab=MEM+0x20000;self.cache=MEM+0x25000;self.replay=MEM+0x8000
  u.mem_write(self.tab,table);u.mem_write(BASE+0xbaaf8,q(self.tab));u.mem_write(BASE+0xafcd8,q(self.cache));u.mem_write(BASE+0xafbd8,q(self.rt));u.mem_write(BASE+0xafbc8,q(self.bs));u.mem_write(BASE+0xafc48,q(self.bs));u.mem_write(BASE+0xafdd0,q(0));u.mem_write(BASE+0xafe11,b'\1')
  services={'SetVariable':self.rt+0x58,'GetVariable':self.rt+0x48,'Install':self.bs+0x80,'Uninstall':self.bs+0x90,'CopyMem':self.bs+0x160,'SetMem':self.bs+0x168,'FreePool':self.bs+0x48,'LocateProtocol':self.bs+0x140,'AllocatePool':self.bs+0x40}
  self.service={STOP+0x100+i*0x10:name for i,name in enumerate(services)}
  for addr,name in self.service.items():u.mem_write(services[name],q(addr))
  self.nv={};self.pending={};self.old=[]
  for k,index in enumerate([94,99,95]):
   item=catalog[index];n=item['declared_size'];old=MEM+0x30000+k*0x10000;pending=MEM+0x80000+k*0x10000;u.mem_write(old,b'\0'*n);u.mem_write(pending,b'\0'*n);self.old.append(old);self.pending[index]=pending;u.mem_write(self.cache+index*16,q(pending)+q(n));self.nv[item['name']]=bytes(n)
  self.nv['Timeout']=b'\0\0';u.mem_write(MEM+0xc0000,b'\x05\0');u.mem_write(self.cache+2*16,q(MEM+0xc0000)+q(2))
  if change=='oc':u.mem_write(self.pending[94]+7,b'\1')
  if change=='alias':u.mem_write(self.pending[95]+3,b'\1')
  if change.startswith('memory:'):u.mem_write(self.pending[99]+int(change.split(':')[1]),b'\1')
  for index,prefix,rec,count,baseptr in [(7,'Boot',0xbab88,0xbab90,MEM+0xd0000),(23,'Driver',0xbab80,0xbab78,MEM+0xd1000)]:
   u.mem_write(BASE+rec,q(baseptr));u.mem_write(BASE+count,q(1));u.mem_write(baseptr,struct.pack('<HI',0,0)+bytes(2));u.mem_write(baseptr+4,struct.pack('<I',1));u.mem_write(self.cache+index*16,q(baseptr+0x100)+q(2));u.mem_write(baseptr+0x100,b'\0\0');self.nv[prefix+'0000']=b'\1\0\0\0\0\0\0\0';self.nv[prefix+'Order']=b'\0\0'
  u.mem_write(BASE+0xbaa98,q(0));u.mem_write(BASE+0xbaaa0,q(0));u.mem_write(BASE+0xaff28,q(0));u.mem_write(BASE+0xafff8,q(0));u.mem_write(BASE+0xafdc8,b'\0')
  replay=b'\x48\x8d\x0d'+struct.pack('<i',BASE+0x93458-(self.replay+7))+b'\xe8'+struct.pack('<i',BASE+0x10704-(self.replay+12))+b'\x44\x38\x2d'+struct.pack('<i',BASE+0xafdc8-(self.replay+19))+jmp(BASE+0x1fd6b)
  u.mem_write(self.replay,replay);u.mem_write(MEM+0x9000,b''.join(q(x)for x in self.old))
  self.action_calls=[]
  for addr in list(self.service)+[STOP+0xf000]+[BASE+x for x in [0x497e8,0x495f4,0x2ae44,0x1e6f8,0x1d594,0x59b50,0x7758,0x17908,0x1f4ac,0x82154,0x5761c,0x8221c]]:
   u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=addr,end=addr)
  assert self.call(exports['ws05_fixture_init'],[BASE,self.replay,len(replay),MEM+0x9000,flags])==0
  self.call(exports['ws05_fixture_mode'],[mode])
  if patched:u.mem_write(BASE+0x1fd58,jmp(exports['ws05_save_mid_thunk'])+b'\x90'*5)
  self.trace=[];self.incoming=None;self.restored=None
  self.preserve_regs=[UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_EFLAGS,UC_X86_REG_RSP]+[UC_X86_REG_XMM0+i for i in range(6)]
  def preserve(cpu,a,n,user):
   snap=[cpu.reg_read(reg)for reg in self.preserve_regs]
   if a==BASE+0x1fd58:self.incoming=snap
   elif self.incoming is not None:self.restored=snap
  for a in [BASE+0x1fd58,self.replay,BASE+0x202f4]:u.hook_add(unicorn.UC_HOOK_CODE,preserve,begin=a,end=a)
 def text(self,a):
  chars=[]
  for i in range(256):
   c=int.from_bytes(self.u.mem_read(a+2*i,2),'little')
   if not c:return ''.join(chars)
   chars.append(chr(c))
  raise AssertionError('unterminated name')
 def ret(self,v=0):
  u=self.u;sp=u.reg_read(UC_X86_REG_RSP);to=int.from_bytes(u.mem_read(sp,8),'little');u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RAX,v);u.reg_write(UC_X86_REG_RIP,to)
 def malloc(self,n):
  a=self.alloc;self.alloc+=(n+15)&~15;self.alloc+=16;assert self.alloc<MEM+0x800000;return a
 def hook(self,u,a,n,user):
  rcx=u.reg_read(UC_X86_REG_RCX);rdx=u.reg_read(UC_X86_REG_RDX);r8=u.reg_read(UC_X86_REG_R8);r9=u.reg_read(UC_X86_REG_R9);sp=u.reg_read(UC_X86_REG_RSP)
  fifth=lambda:int.from_bytes(u.mem_read(sp+0x28,8),'little')
  if a in self.service:
   name=self.service[a]
   if name=='SetVariable':
    key=self.text(rcx);data=bytes(u.mem_read(fifth(),r9))if r9 else b'';status=0x8000000000000007 if self.fail_timeout and key=='Timeout' else 0
    self.writes.append({'name':key,'attrs':r8,'size':r9,'sha256':hashlib.sha256(data).hexdigest(),'status':hex(status)});self.events.append('set:'+key)
    if not status:self.nv[key]=data
    self.ret(status)
   elif name=='GetVariable':
    key=self.text(rcx);data=self.nv.get(key)
    if data is None:self.ret(0x800000000000000e)
    else:
     size=int.from_bytes(u.mem_read(r9,8),'little');u.mem_write(r9,q(len(data)))
     if size<len(data):self.ret(0x8000000000000005)
     else:
      u.mem_write(fifth(),data)
      if r8:u.mem_write(r8,struct.pack('<I',7))
      self.ret()
   elif name=='Install':self.events.append('notify:'+str(uuid.UUID(bytes_le=bytes(u.mem_read(rdx,16)))));u.mem_write(rcx,q(MEM+0x17000));self.ret()
   elif name=='Uninstall':self.ret()
   elif name=='CopyMem':
    if r8:u.mem_write(rcx,bytes(u.mem_read(rdx,r8)))
    self.ret()
   elif name=='SetMem':u.mem_write(rcx,bytes([r8&255])*rdx);self.ret()
   elif name=='LocateProtocol':
    if self.profile and bytes(u.mem_read(rcx,16))==uuid.UUID('451175cf-377b-4bbc-b0c3-f592c4920871').bytes_le:u.mem_write(r8,q(MEM+0x1a000));self.ret()
    else:self.ret(0x800000000000000e)
   elif name=='AllocatePool':u.mem_write(r8,q(self.malloc(rdx)));self.ret()
   elif name=='FreePool':self.freed.append(rcx);self.ret()
   else:self.ret()
  elif a in [BASE+0x497e8,BASE+0x495f4,BASE+0x2ae44]:self.ret()
  elif a==BASE+0x1e6f8:self.events.append('boot_prepare_model');self.ret()
  elif a==BASE+0x1d594:self.refresh.append(rcx);self.ret()
  elif a==BASE+0x59b50:self.ret(self.malloc(rdx))
  elif a==BASE+0x7758:
   data=self.nv.get(self.text(rcx))
   if data is None:self.ret(0)
   else:
    ptr=self.malloc(len(data));u.mem_write(ptr,data);u.mem_write(r9,q(len(data)));self.ret(ptr)
  elif a==BASE+0x17908:
   fmt=self.text(r8);text=('Driver' if fmt.startswith('Driver')else'Boot')+f'{r9&65535:04X}';u.mem_write(rcx,text.encode('utf-16le')+b'\0\0');self.ret()
  elif a in [STOP+0xf000,BASE+0x1f4ac,BASE+0x82154,BASE+0x5761c,BASE+0x8221c]:self.action_calls.append([hex(a),rcx,rdx]);self.events.append('action-model:'+hex(a));self.ret()
  elif a==STOP+0xe020:u.mem_write(r8,q(MEM+0xc1000));u.mem_write(r9,q(459));self.ret()
  elif a in [STOP+0xe000,STOP+0xe028]:self.ret()
  elif a in [SETUP+x for x in [0x13dd8,0x13a54,0x124bc,0x12394,0x125d0]]:self.profile_calls.append([hex(a),rcx,rdx]);self.events.append('profile-model:'+hex(a));self.ret()
 def profile_attach(self):
  self.profile=True;u=self.u;u.mem_write(SETUP+0x483d8,q(self.bs));u.mem_write(SETUP+0x48288,q(MEM+0x1b000));u.mem_write(SETUP+0x2fd60,q(MEM+0x12340));u.mem_write(SETUP+0x55180,q(SETUP+0x55180));u.mem_write(MEM+0xc1000+0x156,b'\3');u.mem_write(MEM+0xc1000+0x155,b'\2')
  for off in [0,0x20,0x28]:u.mem_write(MEM+0x1a000+off,q(STOP+0xe000+off));u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=STOP+0xe000+off,end=STOP+0xe000+off)
  for rva in [0x13dd8,0x13a54,0x124bc,0x12394,0x125d0]:u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=SETUP+rva,end=SETUP+rva)
  for rva in [0x2ca48,0x2ca58,0x2ca68]:u.mem_write(SETUP+rva,q(exports['ws05_native_profile']))
  u.mem_write(SETUP+0x2ca78,q(exports['ws05_native_profile_policy']))
 def notification_attach(self):
  self.profile=True;u=self.u
  for off in [0x483d8,0x48460]:u.mem_write(SETUP+off,q(self.bs))
  for off in [0x483e8,0x48468]:u.mem_write(SETUP+off,q(self.rt))
  u.mem_write(SETUP+0x481b8,q(MEM+0x1d000));u.mem_write(MEM+0x1a020,q(BASE+0x89244))
  def port(cpu,port,size,value,user):self.ports.append([port,size,value])
  u.hook_add(unicorn.UC_HOOK_INSN,port,None,1,0,UC_X86_INS_OUT)
 def call(self,addr,args=()):
  u=self.u;sp=STACK+0xff008;u.mem_write(sp,q(STOP));u.reg_write(UC_X86_REG_RSP,sp)
  for reg,v in zip([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9],list(args)+[0]*4):u.reg_write(reg,v)
  for i,v in enumerate(args[4:]):u.mem_write(sp+0x28+i*8,q(v))
  u.emu_start(addr,STOP,count=12000000)
  assert u.reg_read(UC_X86_REG_RIP)==STOP,hex(u.reg_read(UC_X86_REG_RIP))
  assert u.reg_read(UC_X86_REG_RSP)==sp+8
  return u.reg_read(UC_X86_REG_RAX)
 def save(self):return self.call(BASE+0x1fcb4,[0,0,0])&255
 def report(self):assert self.call(exports['ws05_last_report'],[MEM+0x7000]);return struct.unpack('<IIIIQ',self.u.mem_read(MEM+0x7000,24))
def run(label,**kwargs):
 v=Lab(**kwargs);res=v.save();return v,res
baseline,b=run('original ordinary',patched=False);ordinary,o=run('guarded ordinary')
check('original Save vs guarded normal Save retain full modeled effect order',b==o==1 and baseline.events==ordinary.events and baseline.writes==ordinary.writes and ordinary.nv['Timeout']==b'\x05\0',events=ordinary.events)
check('ordinary Save does not prompt for unchanged protected cache',ordinary.call(exports['ws05_fixture_requests'])==0)
check('allow thunk restores exact GPR/XMM/flags and native RSP before replay',ordinary.incoming==ordinary.restored)
denied,r=run('locked OC cancel',mode=2,change='oc');check('locked OC cancelled before first native notification or write',r==0 and not denied.events and not denied.writes and denied.report()[1]==1)
check('deny thunk restores exact volatile state before original cleanup',denied.incoming==denied.restored)
alias,r=run('locked OcSetup alias',mode=2,change='alias');check('changed OcSetup requires authorization before all native effects',r==0 and not alias.events and alias.report()[2]==1)
granted,r=run('already authorized',flags=7,change='oc');check('authorized OC reaches actual original commit and Save succeeds',r==1 and granted.nv[catalog[94]['name']][7]==1 and granted.call(exports['ws05_fixture_requests'])==0)
prompt,r=run('new authorization model',change='oc');check('successful request is followed by fresh provider and cache revalidation',r==1 and prompt.call(exports['ws05_fixture_requests'])==1)
import re
text=(H.parent/'password/w890_policy_data.h').read_text();part=text.split('w890_memory_offsets[]')[1].split('};')[0];protected=[int(x,0)for x in re.findall(r'0x[0-9a-f]+|\b\d+\b',part)]
memory,r=run('protected memory',change='memory:'+str(protected[0]),mode=2);check('protected SocketMemoryConfig byte requires authentication',r==0 and not memory.events)
ordinary_offset=next(x for x in range(1219)if x not in protected)
memory,r=run('ordinary memory',change='memory:'+str(ordinary_offset),mode=2);check('ordinary SocketMemoryConfig byte remains saveable while locked',r==1 and memory.call(exports['ws05_fixture_requests'])==0)
for mode,label in [(1,'owner rejected'),(4,'variable changed between reads'),(5,'wrong actual NV attributes')]:
 v,r=run(label,mode=mode);check(label+' before all effects',r==0 and not v.events and not v.writes)
fault,r=run('provider fault',flags=35);check('provider FAULT blocks original Save',r==0 and not fault.events)
for enabled in [False,True]:
 v,r=run('native IO failure retained',patched=enabled,fail_timeout=True)
 check(('guarded' if enabled else 'original')+' native IO failure behavior remains explicit',r==1 and v.nv['Timeout']==b'\0\0' and any(x['status']!='0x0' for x in v.writes),warning='Native ignores this EFI error; gate is authentication only, not I/O transaction repair.')
v=Lab(mode=2);check('protected-action primitive cancels before its body',v.call(exports['ws05_before_protected_action'])==0 and not v.events)
v=Lab(flags=7);check('protected-action primitive permits an authenticated session',v.call(exports['ws05_before_protected_action'])==1 and not v.events)
v=Lab(mode=2);v.call(exports['ws05_native_dispatch'],[0xffff001d,BASE+0x4f458,MEM+0x25000,0]);check('defaults selector cancellation consumes entire native dispatcher group',not v.action_calls and not v.events)
v=Lab(flags=7);v.call(exports['ws05_native_dispatch'],[0xffff001d,BASE+0x4f458,MEM+0x25000,0]);check('authorized defaults executes actual native dispatcher in original group order',[x[0]for x in v.action_calls]==[hex(BASE+x)for x in [0x1f4ac,0x82154,0x5761c]],calls=v.action_calls)
v=Lab(mode=2);v.call(exports['ws05_native_dispatch'],[0x123456,STOP+0xf000,0x1234,0x5678]);check('non-default generic selector preserves fallback and exact arguments without prompting',v.action_calls==[[hex(STOP+0xf000),0x1234,0x5678]] and v.call(exports['ws05_fixture_requests'])==0)
v=Lab(mode=2);v.call(exports['ws05_native_defaults'],[MEM+0x25000,0]);check('direct defaults entry cancellation has no original side effect',not v.action_calls and not v.events)
v=Lab(flags=7);v.call(exports['ws05_native_defaults'],[MEM+0x25000,0x11223344]);check('direct defaults entry preserves both original arguments',v.action_calls==[[hex(BASE+0x1f4ac),MEM+0x25000,0x11223344]])
v=Lab(mode=2);r=v.call(exports['ws05_native_load_defaults_save']);check('851A4 early gate cancels before8221C and preliminary SetVariable',r==0x8000000000000015 and not v.events and not v.action_calls)
v=Lab(flags=7);r=v.call(exports['ws05_native_load_defaults_save'],[0x11223344,0x55667788]);check('authorized851A4 actual bytes retain both arguments preliminary write and complete Save behavior',r==0 and v.action_calls[0]==[hex(BASE+0x8221c),0x11223344,0x55667788] and len(v.writes)>len(ordinary.writes),events=v.events)
for qid in [0x2bfb,0x2bfd,0x2bfe,0x2bff]:
 v=Lab(mode=2);v.profile_attach();r=v.call(SETUP+0x2250,[MEM+0x12340,1,qid,0,MEM+0xc1000,MEM+0x7000]);check('actual Setup callback table profile QID '+hex(qid)+' cancels before original handler effects',r==0x800000000000000f and not v.profile_calls and not v.events)
v=Lab(flags=7);v.profile_attach();r=v.call(SETUP+0x2250,[MEM+0x12340,1,0x2bfd,0,MEM+0xc1000,MEM+0x7000]);check('actual callback2250 to gated1457C reaches profile load with original HII and UINT8 slot',r==0 and v.profile_calls[0][:2]==[hex(SETUP+0x13dd8),MEM+0x12340] and v.profile_calls[0][2]&255==3,calls=v.profile_calls)
v=Lab(flags=7);v.profile_attach();r=v.call(SETUP+0x2250,[MEM+0x12340,1,0x2bfe,0,MEM+0xc1000,MEM+0x7000]);check('actual profile handler retains save-to-profile UINT8 slot',r==0 and v.profile_calls[0][0]==hex(SETUP+0x13a54) and v.profile_calls[0][1]&255==2)
v=Lab();v.u.mem_write(v.tab+int.from_bytes(v.u.mem_read(v.tab+4+94*4,4),'little')+16,b'X\0');r=v.save();check('native descriptor name drift rejected',r==0 and not v.events)
v=Lab();v.u.mem_write(v.cache+94*16+8,q(22954));r=v.save();check('native cache size drift rejected',r==0 and not v.events)
v=Lab();v.u.mem_write(v.replay,b'\x90');r=v.save();check('replay code drift rejected before original notification',r==0 and not v.events)
for qid,action,typ in [(0x2bfb,0,0x0c),(0x2bfd,1,0),(0x2bfe,1,0),(0x2bff,0x1000,0)]:
 v=Lab(mode=2);args=[MEM+0x12340,action,qid,typ,MEM+0xc1000,MEM+0x7000,BASE+0x3e4f0];v.u.mem_write(MEM+0x7000,q(0x12345678));before=bytes(v.u.mem_read(MEM+0xc1000,32));r=v.call(exports['ws05_fixture_profile_call'],args)
 check('ConfigAccess gate effect predicate '+hex(qid)+' cancels without OUT mutation',r==0 and v.call(exports['ws05_fixture_requests'])==1 and bytes(v.u.mem_read(MEM+0xc1000,32))==before and bytes(v.u.mem_read(MEM+0x7000,8))==q(0x12345678))
for qid,action,typ in [(0x2bfb,1,0x0c),(0x2bfd,0,0),(0x2bfe,0x1000,0),(0x1234,1,0)]:
 v=Lab(mode=2);r=v.call(exports['ws05_fixture_profile_call'],[MEM+0x12340,action,qid,typ,MEM+0xc1000,MEM+0x7000,BASE+0x3e4f0]);check('native no-effect callback delegates without prompt '+hex(qid)+'/'+str(action),r==1 and not v.call(exports['ws05_fixture_requests']))
v=Lab(flags=7);args=[MEM+0x12340,1,0x2bfd,0,MEM+0xc1000,MEM+0x7000,BASE+0x3e4f0];check('authorized profile callback accepts exact compiled return and native caller',v.call(exports['ws05_fixture_profile_call'],args)==1)
check('direct gate call cannot substitute for pinned ConfigAccess bridge return',v.call(exports['ws05_profile_callback_gate'],args)==0)
args[6]+=1;check('profile gate rejects shifted original native caller',v.call(exports['ws05_fixture_profile_call'],args)==0)
args[6]-=1;args[0]+=8;check('profile gate rejects different ConfigAccess object',v.call(exports['ws05_fixture_profile_call'],args)==0)
for index in [94,99,95]:
 v=Lab();off=int.from_bytes(v.u.mem_read(v.tab+4+index*4,4),'little');descriptor=v.tab+off;r=v.call(BASE+0x89244,[descriptor+16,descriptor,MEM+0x6500,MEM+0x6508])
 check('original cache protocol89244 resolves exact GUID/name to native pair '+str(index),r==0 and bytes(v.u.mem_read(MEM+0x6500,16))==q(v.pending[index])+q(catalog[index]['declared_size']))
for at in [0x1660c,0x788c]:
 v=Lab();v.notification_attach();oldnv=dict(v.nv);pending=bytes(v.u.mem_read(v.pending[94],22955));v.call(SETUP+at)
 check('actual Setup preSave consumer '+hex(at)+' unchanged OC has no derived write or reset publication',v.nv==oldnv and bytes(v.u.mem_read(v.pending[94],22955))==pending and not v.writes and not v.ports and not v.events)
v=Lab();v.notification_attach();v.u.mem_write(v.pending[94]+0x486,b'\x01');pending=bytes(v.u.mem_read(v.pending[94],22955));oldnv=dict(v.nv);v.call(SETUP+0x1660c)
check('actual changed-training OC consumer writes only CMOS training flag',v.ports==[[0x70,1,0x4b],[0x71,1,1]] and not v.writes and v.nv==oldnv and bytes(v.u.mem_read(v.pending[94],22955))==pending,ports=v.ports)
v=Lab();v.notification_attach();v.u.mem_write(v.pending[94]+0x422,b'\x01');pending=bytes(v.u.mem_read(v.pending[94],22955));oldnv=dict(v.nv);v.call(SETUP+0x788c)
check('actual clock-change consumer only publishes downstream reset-needed GUID',v.events==['notify:8731bf4a-654d-4af8-b9a2-2115c8070cf9'] and not v.writes and v.nv==oldnv and bytes(v.u.mem_read(v.pending[94],22955))==pending,events=v.events)
v=Lab();v.notification_attach();v.u.mem_write(v.pending[94]+1,b'\x01');v.nv[catalog[94]['name']]=bytes(v.u.mem_read(v.pending[94],22955));v.u.mem_write(MEM+0x1d01c,b'\x01');pending=bytes(v.u.mem_read(v.pending[94],22955));oldnv=dict(v.nv);v.call(SETUP+0x788c)
check('native platform condition may publish reset-needed even with unchanged OC but cannot modify OC bytes',v.events==['notify:8731bf4a-654d-4af8-b9a2-2115c8070cf9'] and not v.writes and v.nv==oldnv and bytes(v.u.mem_read(v.pending[94],22955))==pending)
v=Lab();u=v.u;first=MEM+0x1e000;second=MEM+0x1e100;data1=MEM+0x1e200;data2=MEM+0x1e300;u.mem_write(first,q(data1)+q(0)+q(second));u.mem_write(second,q(data2)+q(0)+q(0));u.mem_write(BASE+0xb8c28,q(first));u.mem_write(MEM+0x1e400,q(0));oldnv=dict(v.nv);v.call(BASE+0x8eefc,[MEM+0x1e400]);check('actual postSave protocol method18 frees only owned cached string chain',v.freed==[data1,first,data2,second] and bytes(u.mem_read(BASE+0xb8c28,8))==q(0) and not v.writes and oldnv==v.nv,freed=list(map(hex,v.freed)))
for flags,label,prompts in [(3,'new unlock',1),(7,'already unlocked',0),(11,'explicit disabled provider',0)]:
 v=Lab(mode=6,flags=flags)
 for i in [94,99,95]:v.nv.pop(catalog[i]['name'])
 r=v.save();check('genuine NOT_FOUND snapshot permits native creation only after '+label,r==1 and all(catalog[i]['name']in v.nv for i in [94,99,95]) and v.call(exports['ws05_fixture_requests'])==prompts and v.report()[1:3]==(1,1))
v=Lab(mode=62)
for i in [94,99,95]:v.nv.pop(catalog[i]['name'])
r=v.save();check('locked NOT_FOUND protected additions cancelled before any native effects',r==0 and not v.events and not v.writes and v.call(exports['ws05_fixture_requests'])==1 and all(catalog[i]['name']not in v.nv for i in [94,99,95]))
for mode,label in [(7,'absent variable appears'),(8,'present variable disappears'),(9,'non-NOT_FOUND read error')]:
 v=Lab(mode=mode,flags=7);r=v.save();check(label+' rejects original Save before any side effect',r==0 and not v.events and not v.writes)
report={'status':'PASS','checks':len(cases),'original_sha256':hashlib.sha256(original_path.read_bytes()).hexdigest(),'setup_sha256':hashlib.sha256(setup_path.read_bytes()).hexdigest(),'compiled_model_sha256':hashlib.sha256(module_path.read_bytes()).hexdigest(),'cases':cases,'boundaries':['Actual original Save1FCB4, commit1C958, notification publisher10704, FD18/FD6C callback dispatch, counter576E4, outer851A4, Setup2250 and Setup1457C execute in Unicorn.','Exact compiled gate/thunk object is shared with real-observer product.','Native owner/HII/provider services are explicitly replaced by fixture05; this is not native authority proof.','UEFI services are models. Boot preprocessing1E6F8, allocation/string helpers, validation UI, cache refresh1D594, defaults body1F4AC/82154/5761C and8221C are explicit stubs.','Native profile cache protocol, slot-load13DD8/save13A54/status helpers are explicit models in profile-handler cases; original callback table and profile handler routing execute.','Separate original89244 and Setup preSave1660C/164E0/788C/74CC cases execute actual bytes with original cache lookup and explicit UEFI models. OUT instructions are emulated, never physical I/O. Original postSave protocol8EEFC cleanup executes actual bytes.','This tests selected notification paths; static exact-module closure is a separate evidence set, not all possible runtime third-party code.','No physical Save, NVRAM, firmware write or CAP. Original Save status semantics are deliberately preserved.']}
(H/'build/native_save_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='cases'},indent=2))
