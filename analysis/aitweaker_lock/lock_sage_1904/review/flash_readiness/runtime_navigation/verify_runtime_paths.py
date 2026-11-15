"""Read-only execution of EXP02 runtime state paths in Unicorn.

Actual driver machine code executes. Firmware variables, memory permissions,
protocol enumeration and full browser body are fixtures, not a host firmware.
"""
from pathlib import Path
import hashlib,json,struct,uuid,zlib
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[2];DRIVER=CASE/'driver'
assert hashlib.sha256((DRIVER/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest()=='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
prefix=(DRIVER/'verify_adapter.py').read_text(encoding='utf8').split('\nchecks=[]',1)[0]
ns={'__file__':str(DRIVER/'verify_adapter.py')};exec(compile(prefix,str(DRIVER/'verify_adapter.py'),'exec'),ns)
for name in ['VM','U','R','TSE','SETUP','HEAP','STOP','symbols','q','d','w']:globals()[name]=ns[name]
ERR=lambda x:0x8000000000000000|x
GET=STOP+0x1000;SET=STOP+0x1010;CRC=STOP+0x1020
LOCATE=STOP+0x1100;HANDLE=STOP+0x1110;FREE=STOP+0x1120
OC='VARSTORE_OCMR_SETTINGS_NAME';MEM='SocketMemoryConfig'
OCGUID=uuid.UUID('a3a3b874-7636-4182-ba1e-f52c584494e3').bytes_le
MEMGUID=uuid.UUID('98cf19ed-4109-4681-b79d-9196757c7824').bytes_le
BROWSER=uuid.UUID('b9d4c360-bcfb-4f9b-9298-53c136982258').bytes_le
events=[]

class RuntimeVM(VM):
 def __init__(self):
  self.variables={(OC,OCGUID):(7,bytes(26681)),(MEM,MEMGUID):(7,bytes(1392))}
  self.set_calls=[];self.patch_fail=False;self.patch_fail_target=None;self.crc_fail=False
  self.browser_ready=True;self.images_ready=True;self.patches=[]
  super().__init__()
  self.rt=HEAP+0x1e0000
  self.u.mem_write(self.st+0x58,q(self.rt))
  self.u.mem_write(self.rt,q(0x56524553544e5552)+d(0x200b0)+d(0x88)+d(0)+d(0))
  self.u.mem_write(self.rt+0x48,q(GET));self.u.mem_write(self.rt+0x58,q(SET))
  self.u.mem_write(symbols['original_set_variable'],q(SET))
  self.u.mem_write(self.bs+0x158,q(CRC))
  self.u.mem_write(self.bs+0x138,q(LOCATE));self.u.mem_write(self.bs+0x98,q(HANDLE));self.u.mem_write(self.bs+0x48,q(FREE))
  for target in [GET,SET,CRC,LOCATE,HANDLE,FREE]:self.u.hook_add(U.UC_HOOK_CODE,self.hook,begin=target,end=target)
  self.u.mem_write(TSE+0x83468,d(3));self.setup_discovery()
 def argn(self,i):return self.arg(i) if i<4 else self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+40+(i-4)*8)
 def c16(self,a):
  text=[]
  for i in range(128):
   code=int.from_bytes(self.u.mem_read(a+i*2,2),'little')
   if not code:return ''.join(text)
   text.append(chr(code))
  raise AssertionError('unterminated fixture name')
 def hook(self,u,address,size,data):
  if address==symbols['install_variable_guard']:return # execute production code
  if address==symbols['patch_memory']:
   a,b,n=self.arg(0),self.arg(1),self.arg(2)
   self.patches.append([a,n])
   if self.patch_fail or a==self.patch_fail_target:self.ret(0);return
   u.mem_write(a,bytes(u.mem_read(b,n)));self.ret(1);return
  if address==GET:
   name=self.c16(self.arg(0));guid=bytes(u.mem_read(self.arg(1),16));key=(name,guid)
   if key not in self.variables:self.ret(ERR(14));return
   attrs,value=self.variables[key];sizeptr=self.arg(3);capacity=self.getq(sizeptr)
   u.mem_write(sizeptr,q(len(value)))
   if self.arg(2):u.mem_write(self.arg(2),d(attrs))
   if capacity<len(value):self.ret(ERR(5));return
   if value:u.mem_write(self.argn(4),value)
   self.ret(0);return
  if address==SET:
   name=self.c16(self.arg(0));guid=bytes(u.mem_read(self.arg(1),16));attrs,n=self.arg(2),self.arg(3)
   value=bytes(u.mem_read(self.argn(4),n)) if n else b''
   self.set_calls.append({'name':name,'attrs':attrs,'size':n})
   if n:self.variables[(name,guid)]=(attrs,value)
   else:self.variables.pop((name,guid),None)
   self.ret(0);return
  if address==CRC:
   if self.crc_fail:self.ret(ERR(7));return
   u.mem_write(self.arg(2),d(zlib.crc32(bytes(u.mem_read(self.arg(0),self.arg(1))))));self.ret(0);return
  if address==STOP+0x110:
   if self.browser_ready and bytes(u.mem_read(self.arg(0),16))==BROWSER:
    u.mem_write(self.arg(2),q(HEAP+0x1b0000));self.ret(0)
   else:self.ret(ERR(14))
   return
  if address==LOCATE:
   if not self.images_ready:self.ret(ERR(14));return
   u.mem_write(self.arg(3),q(2));u.mem_write(self.argn(4),q(HEAP+0x1c0000));self.ret(0);return
  if address==HANDLE:
   handles={0xabc1:HEAP+0x1c1000,0xabc2:HEAP+0x1c2000}
   if self.arg(0) not in handles:self.ret(ERR(14));return
   u.mem_write(self.arg(2),q(handles[self.arg(0)]));self.ret(0);return
  if address==FREE:self.ret(0);return
  super().hook(u,address,size,data)
 def setup_discovery(self):
  def record(kind,length,strings):
   b=bytearray(length);b[0]=kind;b[1]=length
   if kind==0:b[5]=1
   if kind==2:b[4]=1;b[5]=2
   return bytes(b)+b'\0'.join(s.encode() for s in strings)+b'\0\0'
  table=HEAP+0x1d0000;entry=table+0x1000;ct=table+0x2000
  raw=record(0,24,['1904'])+record(2,15,['ASUSTeK COMPUTER INC.','Pro WS W790E-SAGE SE'])+record(127,4,[])
  self.u.mem_write(table,raw);ep=bytearray(24);ep[:5]=b'_SM3_';ep[6]=24;ep[7:11]=bytes([3,6,0,1]);struct.pack_into('<IQ',ep,12,len(raw),table);ep[5]=(-sum(ep))&255
  self.u.mem_write(entry,bytes(ep));self.u.mem_write(ct,uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+q(entry))
  self.u.mem_write(self.st+0x68,q(1)+q(ct))
  self.u.mem_write(HEAP+0x1c0000,q(0xabc1)+q(0xabc2))
  for offset,base,size,guid in [(0x1000,TSE,0xa2000,'b1da0adf-4f77-4070-a88e-bffe1c60529a'),(0x2000,SETUP,0x1a6000,'899407d7-99fe-43d8-9a21-79ec328cac21')]:
   li=HEAP+0x1c0000+offset;path=li+0x100
   self.u.mem_write(li+0x20,q(path));self.u.mem_write(li+0x40,q(base)+q(size))
   self.u.mem_write(path,b'\x04\x06\x14\0'+uuid.UUID(guid).bytes_le+b'\x7f\xff\x04\0')
 def state(self,mode,active=0,unlocked=0):
  self.u.mem_write(symbols['password_core']+196,d(mode)+bytes([active,unlocked,0,0]))
 def write(self,name,guid,value,attrs=7):
  nameptr=HEAP+0x1f0000;guidptr=nameptr+0x200;valueptr=nameptr+0x1000
  self.u.mem_write(nameptr,name.encode('utf-16le')+b'\0\0');self.u.mem_write(guidptr,guid)
  if value:self.u.mem_write(valueptr,bytes(value))
  return self.call(self.getq(self.rt+0x58),nameptr,guidptr,attrs,len(value),valueptr)
 def guard(self):assert self.call(symbols['install_variable_guard'])==1
 def discover(self):self.call(symbols['discover'],0,0)
 def observation(self):
  return {'attempted':self.getd(symbols['attempted']),'platform_ready':self.getd(symbols['platform_ready']),
          'runtime_guard_installed':self.getq(self.rt+0x58)==symbols['guarded_set'],
          'core_active':self.u.mem_read(symbols['password_core']+200,1)[0],
          'core_unlocked':self.u.mem_read(symbols['password_core']+201,1)[0],
          'boot_services_ended':self.getd(symbols['boot_services_ended'])}

v=RuntimeVM();v.guard();changed=bytearray(26681);changed[4]=1
matrix=[]
for name,mode,active,unlocked,data,expected in [
 ('enabled ordinary boot exact same OC bytes',1,0,0,bytes(26681),0),
 ('enabled ordinary boot changed OC bytes',1,0,0,bytes(changed),ERR(15)),
 ('unconfigured ordinary boot changed OC bytes',0,0,0,bytes(changed),ERR(15)),
 ('enabled locked browser changed OC bytes',1,1,0,bytes(changed),ERR(15)),
 ('enabled authorized browser changed OC bytes',1,1,1,bytes(changed),0),
 ('disabled outside browser changed OC bytes',2,0,0,bytes(changed),0),
]:
 v.variables[(OC,OCGUID)]=(7,bytes(26681));v.state(mode,active,unlocked);before=len(v.set_calls)
 status=v.write(OC,OCGUID,data);assert status==expected
 matrix.append({'case':name,'status':hex(status),'reached_original_SetVariable':len(v.set_calls)>before})
v.state(0);v.variables.pop((OC,OCGUID));status=v.write(OC,OCGUID,bytes(26681));assert status==ERR(15)
matrix.append({'case':'unconfigured boot creating missing OC variable','status':hex(status)})
v.state(1);memory=bytearray(1392);memory[0x11]=1;assert v.write(MEM,MEMGUID,memory)==0
memory[0x10]=1;assert v.write(MEM,MEMGUID,memory)==ERR(15)
matrix.append({'case':'outside browser unprotected memory byte permitted / protected byte denied','passed':True})

# Execute real outer wrapper boundaries and real guarded SetVariable.
v=RuntimeVM();assert v.call(symbols['attach_platform'],TSE,0xa2000,SETUP,0x1a6000)==1
v.state(1);v.start();v.u.mem_write(symbols['password_core']+201,b'\1')
assert v.write(OC,OCGUID,bytes(changed))==0
outer=v.body_context;v.call(TSE+0xe1b8);assert v.unlocked();v.end();v.body_context=outer
assert v.unlocked();v.end();assert not v.unlocked()
changed[4]=2;outside=v.write(OC,OCGUID,bytes(changed));assert outside==ERR(15)
v.start();assert not v.unlocked();next_token=v.getq(symbols['password_core']+168);v.end()
session={'write_before_outer_return':'allowed','write_after_outer_return':hex(outside),'nested_wrapper_preserves_unlock':True,'next_outer_wrapper_relocks':True,'session_token_after_second_outer':next_token,
         'limit':'Does not yet establish whether the real OEM Save commits before or after the outer wrapper returns.'}

exits=[]
for failure in [None,'patch','crc','another_interposer']:
 v=RuntimeVM();v.guard();v.state(1,1,1)
 if failure=='patch':v.patch_fail=True
 if failure=='crc':v.crc_fail=True
 if failure=='another_interposer':v.u.mem_write(v.rt+0x58,q(STOP+0x2000))
 v.call(symbols['exiting'],0,0);observed=v.observation()
 assert observed['boot_services_ended']==1 and observed['core_active']==0
 if failure is None:assert v.getq(v.rt+0x58)==SET
 if failure in ['patch','crc']:assert v.getq(v.rt+0x58)==symbols['guarded_set']
 if failure=='another_interposer':assert v.getq(v.rt+0x58)==STOP+0x2000
 exits.append({'condition':failure or 'success','runtime_pointer':hex(v.getq(v.rt+0x58)),**observed,
               'note':'other interposer fixture assumes its next pointer chains to guarded_set' if failure=='another_interposer' else ''})

discovery=[]
v=RuntimeVM();v.browser_ready=False;v.discover();assert not v.observation()['attempted']
v.browser_ready=True;v.discover();assert v.observation()['platform_ready']==1
discovery.append({'case':'FormBrowser publication after initial discover','observed':v.observation()})
v=RuntimeVM();v.u.mem_write(TSE+0x83468,d(5));v.discover();assert v.observation()['attempted']==0
during=v.observation();v.u.mem_write(TSE+0x83468,d(7));v.discover();assert v.observation()['platform_ready']==1
discovery.append({'case':'first available discovery while native browser already active','during_first_browser':during,'after_browser':v.observation(),'first_browser_was_hooked':False})
v=RuntimeVM();v.patch_fail_target=TSE+0x6b928;v.discover();first=v.observation();count=len(v.patches)
assert first['attempted']==1 and first['platform_ready']==0
v.patch_fail_target=None;v.discover();assert len(v.patches)==count and v.observation()['platform_ready']==0
discovery.append({'case':'transient first attach patch failure','first_result':first,'later_discover':v.observation(),'retry_attempted':False})

report={'status':'OBSERVED_CONDITIONAL_FAILURES_AND_TIMING_BOUNDARIES','driver_sha256':hashlib.sha256((DRIVER/'build/AiTweakerLock1904.efi').read_bytes()).hexdigest(),
        'source_sha256':{n:hashlib.sha256((DRIVER/n).read_bytes()).hexdigest() for n in ['entry.c','services.c','platform.c']},
        'ordinary_boot_write_matrix':matrix,'outer_browser_session_timing':session,'ExitBootServices_cases':exits,'discovery_cases':discovery,
        'limits':['All firmware services and memory mapping are fixtures; no BMC, flash write, or actual firmware code on the Windows CPU.',
                  'Authorized state is set in the fixture; password cryptography is covered by existing tests and is not re-tested here.',
                  'Normal OEM boot write frequency, real Save timing, real event dispatch order, and chained runtime hook presence remain hardware/native integration questions.',
                  'Only a new diagnostic report is written; published artifacts and production source are unchanged.']}
(HERE/'runtime_paths.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report,indent=2))
