"""Run exact S21R PE callbacks through captured registration and UEFI doubles.

The driver, publisher, transport and settings execute real machine code. Only
UEFI HII/events/NVRAM and the BMC responses are simulated. No target hardware.
"""
from pathlib import Path
import gc,hashlib,importlib.util,json,struct,sys,uuid
HERE=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('s21r_runtime',HERE/'verify_runtime.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
import unicorn
from unicorn.x86_const import *

SETUP='71202eee-5f53-40d9-ab3d-9e0c26d96657'
AFTER='8c12a959-70bc-4362-b437-b80514a1916e'
READY='7ce88fb3-4bd7-4679-87a8-a8d8dee50d2b'
BEFORE='3677770f-efb2-43b2-b8ae-b302e9604882'
DB='ef9fc172-a1b2-4693-b327-6d32fc416042'
STR='0fd96974-23aa-4cdc-b9cb-98d17750322a'
forms=(HERE/'native/Setup-forms-P6.bin').read_bytes()
package=uuid.UUID('a85810b5-ad33-4350-b7f5-37905d0dbdb9').bytes_le+struct.pack('<I',24+len(forms))+forms+b'\x04\0\0\xdf'
meta=json.loads((HERE/'native/native-payload.json').read_text())
ids=list(meta['value_ids'].values())
langs=[x['language'] for x in json.loads((HERE.parent/'hero_ipmi_p5/native-payload.json').read_text())['languages']]

class Machine(v.Machine):
 def __init__(self,config=None,*,setup_present=False,**kwargs):
  super().__init__(v.cfg()[:21] if config is None else config,**kwargs)
  self.setup_present=setup_present;self.hii_available=True;self.bad_package=False
  self.timer_calls=[];self.arm_error=0;self.timer_active=False;self.hii_sets=[]
  self.boundary={n:0 for n in ('p5_bind','p1_collect','p5_publish','p6_stop_os_watchdog')}
  self.event_order=[];self.pools={};self.pool_next=0x2000000
  self.u.mem_map(0x2000000,0x200000)
  self.db=self.alloc(bytes(40));self.strings=self.alloc(bytes(24))
  self.stub(self.db+24,'HiiList');self.stub(self.db+32,'HiiExport')
  self.stub(self.strings+8,'HiiGet');self.stub(self.strings+16,'HiiSet')
  self.stub(self.bs+0x40,'HiiAllocate')
  self.hii={(lang,i):'Not queried' for lang in langs for i in ids}
  for name in self.boundary:
   addr=self.functions[name]
   self.u.hook_add(unicorn.UC_HOOK_CODE,self.count_entry,begin=addr,end=addr,user_data=name)
 def count_entry(self,u,at,size,name):
  self.boundary[name]+=1;self.event_order.append(name)
 def cstr(self,p):
  out=bytearray()
  for _ in range(64):
   b=self.u.mem_read(p,1)[0]
   if not b:return out.decode('ascii')
   out.append(b);p+=1
  raise AssertionError('unterminated language')
 def u32(self,name):return int.from_bytes(self.u.mem_read(self.functions[name],4),'little')
 def put32(self,name,value):self.u.mem_write(self.functions[name],struct.pack('<I',value))
 def invoke(self,addr,event):
  sp=0xef0000-8;stop=0x8f0000;self.w64(sp,stop)
  self.u.reg_write(UC_X86_REG_RSP,sp);self.u.reg_write(UC_X86_REG_RCX,event);self.u.reg_write(UC_X86_REG_RDX,0)
  self.u.emu_start(addr,stop,count=100000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==stop,'callback instruction bound'
  assert not self.pools,'UEFI allocations leaked'
  for p,n in self.guard:
   assert bytes(self.u.mem_read(p-16,16))==b'\xa5'*16 and bytes(self.u.mem_read(p+n,16))==b'\xa5'*16
 def dispatch(self,guid):
  events=[h for g,h in self.notifications if g==guid]
  events += [h for h,item in self.events.items() if item[3]==guid]
  assert len(events)==1,(guid,events)
  h=events[0];self.invoke(self.events[h][2],h)
 def tick(self,n=1):
  matches=[h for h,item in self.events.items() if item[0]==0x80000200]
  assert len(matches)==1;h=matches[0]
  for _ in range(n):
   assert self.timer_active,'test should not invent a timer signal after cancel'
   self.invoke(self.events[h][2],h)
 def hook(self,u,addr,size,user):
  name=self.stubs.get(addr)
  if name is None:return
  sp=u.reg_read(UC_X86_REG_RSP)
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
  e=self.r64(sp+0x28);f=self.r64(sp+0x30);result=0
  if name=='LocateProtocol' and self.guid(a) in (DB,STR,SETUP):
   guid=self.guid(a)
   if guid==SETUP:
    result=0 if self.setup_present else v.ERR(14)
    if not result:self.w64(c,0)
   elif not self.hii_available:result=v.ERR(14)
   else:self.w64(c,self.db if guid==DB else self.strings)
  elif name=='P6SetTimer':
   assert a in self.events and b in (0,1)
   assert (b==0 and c==0) or (b==1 and c==5000000)
   self.timer_calls.append((b,c));self.event_order.append('timer_arm' if b else 'timer_cancel')
   if b and self.arm_error:result=self.arm_error;self.arm_error=0
   else:self.timer_active=bool(b)
  elif name=='HiiAllocate':
   assert a==4 and b<=8*1024*1024
   p=self.pool_next+16;self.pool_next+=(b+47)&~15
   assert self.pool_next<0x2200000
   self.pools[p]=b;u.mem_write(p-16,b'\xa5'*16);u.mem_write(p,bytes(b));u.mem_write(p+b,b'\xa5'*16);self.w64(c,p)
  elif name=='FreePool' and a in self.pools:
   n=self.pools.pop(a)
   assert bytes(u.mem_read(a-16,16))==b'\xa5'*16 and bytes(u.mem_read(a+n,16))==b'\xa5'*16
   if not self.pools:self.pool_next=0x2000000
  elif name=='HiiList':
   assert a==self.db and b&255==2 and c==0
   if not e:self.w64(d,8);result=v.ERR(5)
   else:assert self.r64(d)>=8;self.w64(e,100);self.w64(d,8)
  elif name=='HiiExport':
   assert a==self.db and b==100
   data=package if not self.bad_package else package[:28]+bytes([package[28]^1])+package[29:]
   if not d:self.w64(c,len(data));result=v.ERR(5)
   else:assert self.r64(c)>=len(data);u.mem_write(d,data);self.w64(c,len(data))
  elif name=='HiiGet':
   assert a==self.strings and c==100
   key=(self.cstr(b),d&65535);raw=(self.hii[key]+'\0').encode('utf-16le')
   assert self.r64(f)>=len(raw);u.mem_write(e,raw);self.w64(f,len(raw))
  elif name=='HiiSet':
   assert a==self.strings and b==100
   key=(self.cstr(d),c&65535);assert key in self.hii
   self.hii[key]=self.wide(e);self.hii_sets.append(key)
  else:return super().hook(u,addr,size,user)
  self.ret(u,result,name)
 def start(self):
  assert self.call('efi_main',v.IMAGE,self.st)==0 and self.api
  return self
 def clean_reads(self):
  assert not self.dev.mutations and not self.dev.oem_packets and not self.nv_writes
  assert len(self.vars['HeroIpmiSettings'][1])==21
  self.no_leak()
 def good_refresh(self):
  assert self.boundary['p1_collect']==self.boundary['p5_publish']==1
  assert 'P6_READ_STATUS=0000000000000000' in self.audit(),self.audit()[-2500:]
  assert 'P6_PUBLISH_STATUS=0000000000000000' in self.audit(),self.audit()[-2500:]
  assert len(self.hii_sets)==len(langs)*41
  assert self.u32('attempted')==1 and self.u32('active')==0 and not self.timer_active
  assert any(text!='Not queried' for text in self.hii.values())

rows=[]
def run(name,fn):
 fn();rows.append(name);print(name,'PASS',flush=True);gc.collect()

def early():
 m=Machine(setup_present=True).start()
 assert m.timer_calls==[(1,5000000)] and m.boundary['p6_stop_os_watchdog']==1
 assert not m.dev.packets
 m.tick();m.good_refresh();m.clean_reads()
run('early SetupEnter still arms original bounded timer once',early)

def late():
 m=Machine().start();assert not m.timer_calls and not m.dev.packets
 m.dispatch(AFTER);assert not m.dev.packets and m.timer_calls==[(1,5000000)]
 assert m.event_order[:2]==['p6_stop_os_watchdog','timer_arm']
 m.tick();m.good_refresh();m.clean_reads()
 (HERE/'tests/OFFLINE-S21R-AFTERBOOT.txt').write_text('OFFLINE MACHINE-CODE TEST / SYNTHETIC UEFI AND BMC\n'+m.audit(),encoding='utf-8')
run('late load missing SetupEnter reads and publishes after real registered AfterBoot callback',late)

def repeats():
 m=Machine().start();m.dispatch(AFTER);m.tick();m.good_refresh();count=len(m.dev.packets)
 for _ in range(4):m.dispatch(AFTER);m.dispatch(SETUP)
 assert len(m.dev.packets)==count and m.boundary['p1_collect']==1 and m.timer_calls==[(1,5000000),(0,0)]
 m.clean_reads()
run('repeat AfterBoot and SetupEnter cannot replay a completed query',repeats)

def active():
 m=Machine().start();m.hii_available=False;m.dispatch(AFTER);m.tick(7)
 for _ in range(3):m.dispatch(AFTER);m.dispatch(SETUP)
 assert m.u32('ticks')==7 and m.timer_calls==[(1,5000000)] and not m.dev.packets
 m.hii_available=True;m.tick();m.good_refresh();m.clean_reads()
run('notifications while active preserve tick budget and pending timer',active)

def timeout(bad=False):
 m=Machine().start();m.bad_package=bad;m.hii_available=bad;m.dispatch(AFTER);m.tick(20)
 assert m.u32('ticks')==20 and m.boundary['p5_bind']==20 and m.boundary['p1_collect']==0
 m.tick();assert m.u32('ticks')==21 and m.boundary['p5_bind']==20 and not m.timer_active and not m.dev.packets
 assert 'P6_NO_MATCHING_NATIVE_RESOURCE' in m.audit()
 m.bad_package=False;m.hii_available=True;m.dispatch(AFTER);m.tick();m.good_refresh();m.clean_reads()
run('missing HII resource stops after 20 attempts and next genuine event may rearm',timeout)
run('wrong exact forms never query and bounded timer may later bind correct package',lambda:timeout(True))

def read_failure():
 m=Machine(case='wrong_board').start();m.dispatch(AFTER);m.tick()
 assert m.boundary['p1_collect']==1 and m.u32('attempted')==1 and not m.dev.packets
 for _ in range(3):m.dispatch(AFTER);m.dispatch(SETUP)
 assert m.boundary['p1_collect']==1 and len(m.timer_calls)==2;m.clean_reads()
run('attempted collection failure is terminal for this boot',read_failure)

def arm_failure():
 m=Machine().start();m.arm_error=v.ERR(7);m.dispatch(AFTER)
 assert not m.timer_active and m.u32('active')==0 and m.boundary['p1_collect']==0
 assert 'P6_TIMER_ARM_FAILED' in m.audit()
 m.dispatch(AFTER);m.tick();m.good_refresh();m.clean_reads()
run('timer service failure causes no direct read and a later genuine event may arm',arm_failure)

def busy():
 m=Machine().start();m.put32('busy',1);m.dispatch(AFTER);m.dispatch(SETUP)
 assert not m.timer_calls and m.boundary['p6_stop_os_watchdog']==0 and not m.dev.packets
 m.put32('busy',0);m.dispatch(AFTER);m.tick();m.good_refresh();m.clean_reads()
run('busy callback guard prevents nested watchdog stop or refresh',busy)

def not_ready():
 m=Machine(entry_fault='install');assert m.call('efi_main',v.IMAGE,m.st)&v.ERR(0)
 m.dispatch(AFTER);m.dispatch(SETUP)
 assert not m.timer_calls and not m.dev.packets and m.boundary['p6_stop_os_watchdog']==0
 assert set(m.events)==set(m.closed)
run('failed installation callbacks cannot arm after cleanup',not_ready)

def watchdog():
 m=Machine(v.cfg(enabled=1,minutes=7,action=3)[:21]).start();m.dispatch(READY);m.dispatch(BEFORE)
 assert m.dev.sim.wdt[0]&0x40;prior=len(m.dev.mutations);m.event_order.clear()
 m.dispatch(AFTER)
 assert not m.dev.sim.wdt[0]&0x40 and len(m.dev.mutations)==prior+1
 assert m.dev.mutations[-1][:2]==(6,0x24) and m.event_order[:2]==['p6_stop_os_watchdog','timer_arm']
 assert m.boundary['p6_stop_os_watchdog']==1
 m.tick();m.good_refresh();m.no_leak();assert len(m.dev.mutations)==prior+1
 for _ in range(2):m.dispatch(AFTER)
 assert len(m.dev.mutations)==prior+1 and m.boundary['p1_collect']==1
run('existing watchdog stop occurs once before arm and read cannot start it',watchdog)

def foreign_watchdog():
 m=Machine(v.cfg(enabled=1)[:21]).start();m.dev.sim.wdt[0]=0x44;m.dispatch(READY);m.dispatch(AFTER);m.tick()
 assert m.dev.sim.wdt[0]==0x44 and not m.dev.mutations;m.no_leak()
 assert m.boundary['p1_collect']==1
run('foreign running watchdog is not taken over by AfterBoot refresh',foreign_watchdog)

report={'passed':True,'cases':len(rows),'results':rows,'driver_sha256':hashlib.sha256((HERE/'HeroIpmiP6.efi').read_bytes()).hexdigest(),
 'scope':'Actual exact PE entry, registered callbacks, native HII binding/publication and KCS collection. UEFI timer delivery and BMC responses are synthetic, not a hardware claim.',
 'production_files_changed_from_S21':['source/driver.c'],'settings_forms_backend_unchanged':True}
(HERE/'tests/refresh-lifecycle-pe.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
