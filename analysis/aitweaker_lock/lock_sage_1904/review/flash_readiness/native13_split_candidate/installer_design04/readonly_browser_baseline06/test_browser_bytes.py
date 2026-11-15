"""Execute the exact full-app browser code; explicit UEFI/native-browser mocks.
No target firmware execution, no real variable writes, no devices or network.
Read-only platform inventory/map predicates are boundary models here; actual
inventory/entry and OVMF unsupported-board refusal need separate evidence.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn
from unicorn.x86_const import *
P=HERE/'build/SageNative13BrowserBaseline06.efi';PE=pefile.PE(str(P));BASE=PE.OPTIONAL_HEADER.ImageBase
MAP=(HERE/'build/app.map').read_text();S={}
for name in ['app_st','app_browser','app_ended','app_hold_reason','browser_capture','browser_publish','browser_invoke','baseline_private_absent','baseline_compare_stores','baseline_callback','baseline_extract','baseline_route','baseline_map','baseline_access','baseline_original_unchanged','baseline_globals','app_hold','app_log','app_number','app_result']:
 hits=re.findall(r'^\s*\d{4}:[a-fA-F0-9]+\s+'+name+r'\s+([a-fA-F0-9]+)\s',MAP,re.M);assert len(hits)==1,(name,hits);S[name]=int(hits[0],16)
ARENA=0x70000000;STACK=0x78000000;STOP=0x79000000
NAMES=['get','forbidden_set','raise','restore','locate','handle','list','export','install','new','send','forbidden_load','forbidden_start']
STUB={n:ARENA+0x8000+i*0x20 for i,n in enumerate(NAMES)}
PACKAGE=(HERE.parent/'provider13/build/management.pack').read_bytes()
U64=lambda n:struct.pack('<Q',n&0xffffffffffffffff)
ERR=lambda n:0x8000000000000000|n
class Model:
 def __init__(self):
  self.u=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);self.u.mem_map(BASE,(PE.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.u.mem_write(BASE,bytes(PE.get_memory_mapped_image()));self.u.mem_map(ARENA,0x10000);self.u.mem_map(STACK,0x20000);self.u.mem_map(STOP,4096)
  self.events=[];self.logs=[];self.hold=0;self.tpl=4;self.private='absent';self.oc=b'\x31'*26681;self.mem=b'\x42'*1392;self.oc_attrs=3;self.mem_attrs=3;self.get_fault=None;self.hii_fault=None;self.published=False;self.sent=0;self.sets=0;self.installs=0;self.newcalls=0;self.native_status=0;self.native_request=0;self.native_tpl=None;self.native_change=None;self.original_ok=True;self.fail_after=None;self.service_count=0;self.ended_index=None;self.stop=False
  self.putq(S['app_st'],ARENA);self.putq(S['app_browser'],ARENA+0x400)
  self.putq(ARENA+0x58,ARENA+0x600);self.putq(ARENA+0x60,ARENA+0x100);self.putq(ARENA+0x40,ARENA+0x1000);self.putq(ARENA+0x38,0x9999)
  for off,n in [(0x18,'raise'),(0x20,'restore'),(0x80,'install'),(0x98,'handle'),(0x140,'locate'),(0xc8,'forbidden_load'),(0xd0,'forbidden_start')]:self.putq(ARENA+0x100+off,STUB[n])
  self.putd(ARENA+0x600+12,136);self.putq(ARENA+0x600+0x48,STUB['get']);self.putq(ARENA+0x600+0x58,STUB['forbidden_set'])
  for off,n in [(0,'new'),(24,'list'),(32,'export')]:self.putq(ARENA+0x300+off,STUB[n])
  self.putq(ARENA+0x400,STUB['send']);self.putq(ARENA+0x1000+0x48,ARENA+0x1100);self.putd(ARENA+0x1100+4,3)
  self.putq(ARENA+0x1200+24,ARENA+0x1300);self.putq(ARENA+0x1300+8,ARENA+0x1400);self.putq(ARENA+0x1300+16,36);self.putd(ARENA+0x1400+4,800);self.putd(ARENA+0x1400+8,600)
  for address in set(STUB.values())|{STOP}|{S[n]for n in ['app_hold','app_log','app_number','app_result','baseline_map','baseline_access','baseline_original_unchanged','baseline_globals']}:
   self.u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=address,end=address)
  def hold_store(u,access,address,size,value,unused):self.hold=value;self.stop=True;u.emu_stop()
  self.u.hook_add(unicorn.UC_HOOK_MEM_WRITE,hold_store,begin=S['app_hold_reason'],end=S['app_hold_reason']+3)
 def q(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def d(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def putq(self,a,n):self.u.mem_write(a,U64(n))
 def putd(self,a,n):self.u.mem_write(a,struct.pack('<I',n))
 def cstr(self,a,wide=False):
  out=[]
  for i in range(1000):
   v=self.u.mem_read(a+i*(2 if wide else 1),2 if wide else 1);n=int.from_bytes(v,'little')
   if not n:return ''.join(out)
   out.append(chr(n))
  raise AssertionError('unterminated model string')
 def arg(self,n):
  if n<4:return self.u.reg_read([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9][n])
  return self.q(self.u.reg_read(UC_X86_REG_RSP)+0x28+(n-4)*8)
 def ret(self,v):
  sp=self.u.reg_read(UC_X86_REG_RSP);dest=self.q(sp);self.u.reg_write(UC_X86_REG_RAX,v&0xffffffffffffffff);self.u.reg_write(UC_X86_REG_RSP,sp+8);self.u.reg_write(UC_X86_REG_RIP,dest)
 def hook(self,u,a,size,data):
  if a==STOP:self.stop=True;u.emu_stop();return
  if a==S['app_hold']:self.hold=self.arg(0);self.stop=True;u.emu_stop();return
  if a in [S['app_log'],S['app_number'],S['app_result']]:
   self.logs.append((self.cstr(self.arg(0)),self.arg(1)if a!=S['app_log']else None));self.ret(0);return
  if a in [S['baseline_map'],S['baseline_access'],S['baseline_original_unchanged'],S['baseline_globals']]:
   self.ret(int(self.original_ok)if a==S['baseline_original_unchanged']else 1);return
  name=next((n for n,p in STUB.items()if p==a),None)
  if name is None:return
  assert self.ended_index is None,'Firmware service after injected EBS'
  self.service_count+=1;self.events.append(name);status=0
  if name.startswith('forbidden_'):raise AssertionError(name+' unexpectedly called')
  if name=='raise':status=self.tpl;self.tpl=self.arg(0)
  elif name=='restore':self.tpl=self.arg(0)
  elif name=='get':
   var=self.cstr(self.arg(0),True);attrs,np,out=self.arg(2),self.arg(3),self.arg(4);n=self.q(np)
   if var=='AiTweakerPassword1904':
    assert n==0 and out==0,'Private content must never be read'
    if self.private=='absent':status=ERR(14)
    elif self.private=='present':self.putq(np,128);status=ERR(5)
    else:status=ERR(7)
   else:
    expected='oc'if var=='VARSTORE_OCMR_SETTINGS_NAME'else'mem';assert var in ['VARSTORE_OCMR_SETTINGS_NAME','SocketMemoryConfig']
    value=self.oc if expected=='oc'else self.mem;at=self.oc_attrs if expected=='oc'else self.mem_attrs
    if self.get_fault==expected+'_error':status=ERR(7)
    else:
     self.putq(np,len(value));self.putd(attrs,at)
     if n<len(value):status=ERR(5)
     else:self.u.mem_write(out,value)
  elif name=='locate':self.putq(self.arg(2),ARENA+0x300)
  elif name=='handle':self.putq(self.arg(2),ARENA+0x1200)
  elif name=='list':
   np,out=self.arg(3),self.arg(4);handles=[0x1111]+([0x2222]if self.published else[])
   if self.hii_fault=='duplicate':handles+=[0x3333]
   if self.hii_fault=='list_error':status=ERR(7)
   elif self.hii_fault=='list_overflow':self.putq(np,4097)
   elif self.hii_fault=='list_misaligned':self.putq(np,7)
   else:self.putq(np,8*len(handles));self.u.mem_write(out,b''.join(U64(n)for n in handles))
  elif name=='export':
   handle,np,out=self.arg(1),self.arg(2),self.arg(3);raw=PACKAGE if handle!=0x1111 else bytes(16)+struct.pack('<I',24)+bytes([4,0,0,0xdf])
   if self.hii_fault=='existing'and not self.published:raw=PACKAGE
   if self.hii_fault=='mutated'and handle==0x2222:raw=raw[:-1]+bytes([raw[-1]^1])
   if not out:self.putq(np,4*1024*1024+1 if self.hii_fault=='export_oversize'else len(raw));status=ERR(5)
   elif self.hii_fault=='export_error':status=ERR(7)
   else:self.putq(np,len(raw));self.u.mem_write(out,raw)
  elif name=='install':
   self.installs+=1;cfg=self.arg(3);assert self.q(cfg)==S['baseline_extract']and self.q(cfg+8)==S['baseline_route']and self.q(cfg+16)==S['baseline_callback']
   if self.hii_fault=='install_error':status=ERR(7)
   else:self.putq(self.arg(0),0x4444)
  elif name=='new':
   self.newcalls+=1;assert bytes(u.mem_read(self.arg(1),len(PACKAGE)))==PACKAGE and self.arg(2)==0x4444
   if self.hii_fault=='new_error':status=ERR(7)
   else:self.published=True;self.putq(self.arg(3),0x2222)
  elif name=='send':
   self.sent+=1;assert self.arg(0)==ARENA+0x400 and self.q(self.arg(1))==0x2222 and self.arg(2)==1 and bytes(u.mem_read(self.arg(3),16))==PACKAGE[26:42] and self.arg(4)==1 and self.arg(5)==0
   request=self.arg(6);assert self.q(request)==0,'ActionRequest must start NONE';self.putq(request,self.native_request);status=self.native_status
   if self.native_tpl is not None:self.tpl=self.native_tpl
   if self.native_change=='private':self.private='present'
   if self.native_change=='oc':self.oc=b'\x32'+self.oc[1:]
   if self.native_change=='mem':self.mem=b'\x43'+self.mem[1:]
   if self.native_change=='identity':self.original_ok=False
  if self.fail_after==self.service_count:
   self.putd(S['app_ended'],1);self.ended_index=len(self.events)
  self.ret(status)
 def call(self,name,*args):
  self.stop=False;sp=STACK+0x1eff8;self.putq(sp,STOP)
  for i,v in enumerate(args):
   if i<4:self.u.reg_write([UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9][i],v)
   else:self.putq(sp+0x28+(i-4)*8,v)
  self.u.reg_write(UC_X86_REG_RSP,sp);self.u.emu_start(S[name],0,count=2000000);assert self.stop,name
  return 'HOLD'if self.hold else self.u.reg_read(UC_X86_REG_RAX)
 def prepare(self):assert self.call('browser_capture')==1 and self.call('browser_publish')==1
results=[]
def passed(name):results.append({'name':name,'status':'PASS'});print('PASS '+name,flush=True)
m=Model();m.prepare();assert m.call('browser_invoke')==1 and m.sent==1 and m.installs==m.newcalls==1;assert m.call('browser_invoke')==0 and m.sent==1;passed('Exact frozen package, native SendForm ABI, ActionRequest NONE, one invocation and no write/load endpoint')
for mode in ['present','error']:
 m=Model();m.private=mode;assert m.call('browser_capture')==0 and m.events.count('get')==1 and not m.installs;passed('Initial private '+mode+' refuses with size-only NULL query')
for var in ['oc','mem']:
 for fault in ['error','size','attrs']:
  m=Model()
  if fault=='error':m.get_fault=var+'_error'
  if fault=='size':setattr(m,var,getattr(m,var)[:-1])
  if fault=='attrs':setattr(m,var+'_attrs',1)
  assert m.call('browser_capture')==0;passed('Initial '+var+' '+fault+' refuses')
for fault in ['duplicate','existing','list_error','list_overflow','list_misaligned','export_oversize','export_error','install_error','new_error','mutated']:
 m=Model();assert m.call('browser_capture')==1;m.hii_fault=fault;assert m.call('browser_publish')==0 and m.sent==0;calls=m.installs+m.newcalls;assert m.call('browser_publish')==0 and m.installs+m.newcalls==calls;passed('HII '+fault+' refuses and publication never retries')
for change in ['private','oc','mem','identity']:
 m=Model();m.prepare();m.native_change=change;assert m.call('browser_invoke')==0 and m.sent==1;passed('Post-native '+change+' difference observed without repair write')
for request,status in [(1,0),(3,0),(0,ERR(7))]:
 m=Model();m.prepare();m.native_request=request;m.native_status=status;assert m.call('browser_invoke')==0;passed('Native request/status '+str((request,status))+' not accepted')
for tpl in [8,16,31]:
 m=Model();m.tpl=tpl;assert m.call('browser_capture')=='HOLD'and m.events==['raise'];passed('Initial TPL '+str(tpl)+' holds without restore/later service')
 m=Model();m.prepare();m.native_tpl=tpl;assert m.call('browser_invoke')=='HOLD'and m.events[-1]=='raise';passed('Returned native TPL '+str(tpl)+' holds before variable/display service')
for ended in [False,True]:
 for name,args in [('baseline_extract',(0,1,2,3)),('baseline_route',(0,1,2)),('baseline_callback',(0,0,0xffe0,4,1,2)),('baseline_callback',(0,1,0xffe0,4,1,2)),('baseline_callback',(0,2,0,0,1,2)),('baseline_callback',(0,3,0,0,1,2)),('baseline_callback',(0,4,0,0,1,2)),('baseline_callback',(0,0xffff,0xffff,0xff,1,2))]:
  m=Model();m.putd(S['app_ended'],int(ended));assert m.call(name,*args)==ERR(15 if ended else 3)and not m.events;passed(name+' metadata-only rejects action '+str(args[1])+' ended='+str(ended))
for phase in ['browser_capture','browser_publish','browser_invoke']:
 base=Model()
 if phase!='browser_capture':assert base.call('browser_capture')==1
 if phase=='browser_invoke':assert base.call('browser_publish')==1
 begin=base.service_count;assert base.call(phase)==1;count=base.service_count-begin
 for after in range(1,count+1):
  m=Model()
  if phase!='browser_capture':assert m.call('browser_capture')==1
  if phase=='browser_invoke':assert m.call('browser_publish')==1
  m.fail_after=m.service_count+after;assert m.call(phase)=='HOLD'and m.ended_index==len(m.events);passed(phase+' EBS boundary '+str(after)+' no later service')
result={'status':'PASS_ACTUAL_FINAL_PE_BROWSER_WITH_EXPLICIT_BOUNDARY_MODELS','efi_sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'cases':len(results),'results':results,'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'limits':['Original module inventory/map/pagewalk predicates are explicit models in this suite.','The exact production browser/app lifecycle code executes; native ASUS SendForm, UEFI protocols and pure log sink are model endpoints.','This does not prove native page rendering, firmware internal absence of writes or physical input handling.']}
(HERE/'browser_byte_test_result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k]for k in ['status','efi_sha256','cases']}))
