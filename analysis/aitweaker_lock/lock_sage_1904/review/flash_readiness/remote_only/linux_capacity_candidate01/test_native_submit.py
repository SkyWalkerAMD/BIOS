"""Execute unchanged production ELF submit/perform/retry/emit machine code.

Only explicit OS/selection/display API boundaries are synthesized in Unicorn.
No real Linux kernel or device is called; actual Linux ownership is covered by
OVMF tests. Every returned packet, CDB, open mode, and command count is checked.
"""
from pathlib import Path
import copy,hashlib,json,struct,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_INSN
from unicorn.x86_const import *
from decode_linux_log import decode
ELF=HERE/'build/production/init';B=ELF.read_bytes();SHA=hashlib.sha256(B).hexdigest();OUT=HERE/'native_submit_tests';OUT.mkdir(exist_ok=True)
phoff=struct.unpack_from('<Q',B,32)[0];phent,phnum=struct.unpack_from('<HH',B,54)
segments=[struct.unpack_from('<IIQQQQQQ',B,phoff+i*phent) for i in range(phnum)]
shoff=struct.unpack_from('<Q',B,40)[0];shent,shnum=struct.unpack_from('<HH',B,58)
sections=[struct.unpack_from('<IIQQQQIIQQ',B,shoff+i*shent) for i in range(shnum)];symbols={}
for section in sections:
 if section[1]!=2:continue
 st=sections[section[6]];names=B[st[4]:st[4]+st[5]]
 for pos in range(section[4],section[4]+section[5],section[9]):
  n,info,other,idx,addr,size=struct.unpack_from('<IBBHQQ',B,pos);name=names[n:names.find(b'\0',n)].decode()
  if name and addr:symbols[name]=(addr,size)
SUCCESS={'ret':0,'errno':0,'status':0,'masked':0,'msg':0,'host':0,'driver':0,'resid':0,'info':0,'sense':b'','data':bytes.fromhex('00007fff00000200')}
UA={**SUCCESS,'status':2,'masked':1,'driver':8,'resid':8,'info':1,'sense':bytes.fromhex('700006000000000a00000000290000000000'),'data':bytes(8)}
class Harness:
 def __init__(self,case):
  self.case=case;self.u=Uc(UC_ARCH_X86,UC_MODE_64);self.error=None;self.calls=[];self.logs=[];self.opens=[];self.closes=[];self.emit_mode=False
  pages=set()
  for typ,flags,offset,vaddr,paddr,filesz,memsz,align in segments:
   if typ!=1:continue
   for page in range(vaddr&~4095,(vaddr+memsz+4095)&~4095,4096):
    if page not in pages:self.u.mem_map(page,4096);pages.add(page)
   if filesz:self.u.mem_write(vaddr,B[offset:offset+filesz])
  self.stack=0x70000000;self.stop=0x71000000;self.errptr=0x72000000
  self.u.mem_map(self.stack,0x200000);self.u.mem_map(self.stop,4096);self.u.mem_write(self.stop,b'\xf4');self.u.mem_map(self.errptr,4096)
  self.u.hook_add(UC_HOOK_CODE,lambda u,a,s,d:u.emu_stop(),begin=self.stop,end=self.stop)
  hooks={'locate_target':self.locate,'text':self.text,'open':self.open,'open64':self.open,'fstat':self.fstat,'fstat64':self.fstat,'ioctl':self.ioctl,'close':self.close,'__errno_location':lambda a:self.errptr,'emit':self.emit,'lc_display':lambda a:-1,'write':self.write}
  unique={}
  for name,fn in hooks.items():
   if name in symbols:unique[symbols[name][0]]=(name,fn)
  for addr,(name,fn) in unique.items():self.u.hook_add(UC_HOOK_CODE,self.callback,(name,fn),begin=addr,end=addr)
  self.u.hook_add(UC_HOOK_INSN,self.syscall,None,1,0,UC_X86_INS_SYSCALL)
  for name,val in [('stage',8),('devices',1),('interfaces',1),('sgcount',1),('loaded',8),('checks',511),('dmi_match',1)]:self.putint(name,val)
  for name,value in [('target','1-1:1.0'),('sgname','sg0'),('interface_path','/sys/devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0'),('sgpath','/sys/devices/pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0/host0/target0:0:0/0:0:0:0')]:self.u.mem_write(symbols[name][0],value.encode()+b'\0')
 def putint(self,name,n):self.u.mem_write(symbols[name][0],struct.pack('<I',n&0xffffffff))
 def integer(self,name):return struct.unpack('<I',self.u.mem_read(symbols[name][0],4))[0]
 def cstr(self,p):
  b=bytes(self.u.mem_read(p,4096));assert b'\0' in b;return b.split(b'\0',1)[0].decode('ascii')
 def callback(self,u,address,size,hook):
  name,fn=hook
  if name=='emit' and self.emit_mode:return
  try:
   args=[u.reg_read(r) for r in [UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RDX,UC_X86_REG_RCX,UC_X86_REG_R8,UC_X86_REG_R9]];ret=fn(args)
   sp=u.reg_read(UC_X86_REG_RSP);dest=struct.unpack('<Q',u.mem_read(sp,8))[0];u.reg_write(UC_X86_REG_RAX,ret&0xffffffffffffffff);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,dest)
  except BaseException as e:self.error=f'{name}: {e!r}';u.emu_stop()
 def syscall(self,*args):self.error='Unexpected real syscall boundary';self.u.emu_stop()
 def locate(self,a):
  self.putint('devices',self.case.get('devices',1));self.putint('interfaces',self.case.get('interfaces',1));return -1 if self.case.get('selection_error') else 0
 def text(self,a):
  assert self.cstr(a[0])=='/sys/class/scsi_generic/sg0/dev';value=self.case.get('sysfs_dev','21:0').encode()+b'\0';assert len(value)<=a[2];self.u.mem_write(a[1],value);return 0
 def open(self,a):
  path=self.cstr(a[0]);self.opens.append({'path':path,'flags':a[1]})
  if path=='/dev/sg0':assert a[1]==0xa0800;return -1 if self.case.get('open_failure') else 41
  if path=='/dev/tty0':assert a[1]==0xa0001;return 42
  raise AssertionError('Unallowed open '+path)
 def fstat(self,a):
  assert a[0]==41;b=bytearray(144);struct.pack_into('<I',b,24,0o020600 if not self.case.get('regular_fd') else 0o100600);struct.pack_into('<Q',b,40,self.case.get('rdev',21<<8));self.u.mem_write(a[1],bytes(b));return 0
 def close(self,a):assert a[0] in [41,42];self.closes.append(a[0]);return 0
 def write(self,a):assert a[0]==42;self.logs.append(bytes(self.u.mem_read(a[1],a[2])));return a[2]
 def emit(self,a):return 0
 def ioctl(self,a):
  fd,req,arg=a[:3];assert fd==41
  if req==0x2282:self.u.mem_write(arg,struct.pack('<I',self.case.get('sg_version',30536)));return 0
  if req==0x2276:self.u.mem_write(arg,struct.pack('<5i2h2i',self.case.get('host',0),self.case.get('channel',0),self.case.get('scsi_id',0),self.case.get('lun',0),self.case.get('type',0),1,1,0,0));return 0
  assert req==0x2285 and len(self.calls)<2,'Only <=2 SG_IO allowed'
  p=bytearray(self.u.mem_read(arg,88));interface,direction,cmdlen,sblen,iovec,length=struct.unpack_from('<iiBBHI',p,0);data,cdb,sense=struct.unpack_from('<QQQ',p,16)
  assert (interface,direction,cmdlen,sblen,iovec,length)==(83,-3,10,32,0,8)
  assert bytes(self.u.mem_read(cdb,10))==b'\x25'+bytes(9) and bytes(self.u.mem_read(data,8))==bytes(8) and bytes(self.u.mem_read(sense,32))==bytes(32)
  assert struct.unpack_from('<IIi',p,40)==(2000,0,0) and struct.unpack_from('<Q',p,56)[0]==0
  responses=self.case['responses'];assert len(self.calls)<len(responses),'Unplanned extra retry';r=responses[len(self.calls)];self.calls.append({'cdb':'25000000000000000000','data_length':8,'direction':-3,'timeout_ms':2000})
  self.u.mem_write(data,r['data']);self.u.mem_write(sense,r['sense']);p[64:68]=bytes([r['status'],r['masked'],r['msg'],r.get('sense_length',len(r['sense']))]);struct.pack_into('<HH',p,68,r['host'],r['driver']);struct.pack_into('<iII',p,72,r['resid'],1,r['info'])
  if r.get('length_mutation'):struct.pack_into('<I',p,12,9)
  if r.get('guard_mutation'):self.u.mem_write(data+8,b'\xff')
  if r.get('cdb_mutation'):self.u.mem_write(cdb+1,b'\x01')
  self.u.mem_write(arg,bytes(p));self.u.mem_write(self.errptr,struct.pack('<I',r['errno']));return r['ret']
 def call(self,name):
  sp=self.stack+0x180000-8;self.u.mem_write(sp,struct.pack('<Q',self.stop));self.u.reg_write(UC_X86_REG_RSP,sp);self.u.reg_write(UC_X86_REG_RBP,0)
  self.u.emu_start(symbols[name][0],self.stop+1,count=3000000)
  if self.error:raise AssertionError(self.error)
  assert self.u.reg_read(UC_X86_REG_RIP)==self.stop,'Instruction bound reached';return self.u.reg_read(UC_X86_REG_RAX)&0xffffffff
 def run(self):
  ret=self.call('submit');self.putint('failure',ret);self.emit_mode=True;self.call('emit');assert self.logs
  raw=b''.join(self.logs);start=raw.index(b'LC01_LOG_BEGIN\r\n')+16;body,tail=raw[start:].split(b'LC01_LOG_END BYTES=',1)
  assert int(tail.split(b' ',1)[0])==len(body);decoded=decode(body)
  assert len(self.calls)==self.case['calls'] and decoded['userspace_rc10_calls']==self.case['calls']
  assert decoded['capacity_valid']==self.case['valid'] and decoded['complete'];assert len(self.closes)==len([o for o in self.opens if not(self.case.get('open_failure') and o['path']=='/dev/sg0')])
  if self.case['calls']==2:assert decoded['packets'][0]['sense']=='700006000000000A00000000290000000000'
  return body,decoded
def changed(base,**values):return {**base,**values}
CASES=[{'id':'direct_success','responses':[SUCCESS],'calls':1,'valid':True},{'id':'exact_ua_then_success','responses':[UA,SUCCESS],'calls':2,'valid':True},{'id':'second_ua_never_third','responses':[UA,UA],'calls':2,'valid':False}]
for key,value in [('ret',-1),('status',0),('masked',0),('msg',1),('host',1),('driver',0),('driver',0x18),('resid',0),('resid',7),('info',0),('info',3),('sense_length',17),('sense_length',32),('guard_mutation',True),('cdb_mutation',True),('length_mutation',True),('data',bytes.fromhex('0000000100000000'))]:
 r=changed(UA,**{key:value});CASES.append({'id':f'ua_reject_{key}_{len(CASES)}','responses':[r],'calls':1,'valid':False})
for index in range(32):
 sense=bytearray(UA['sense'].ljust(32,b'\0'));sense[index]^=1;CASES.append({'id':f'ua_sense_byte_{index:02}','responses':[changed(UA,sense=bytes(sense),sense_length=18)],'calls':1,'valid':False})
for key,value in [('ret',-1),('status',2),('host',1),('driver',1),('resid',1),('guard_mutation',True),('length_mutation',True),('cdb_mutation',True),('data',bytes(8)),('data',bytes.fromhex('ffffffff00000200'))]:
 CASES.append({'id':f'second_failure_{key}_{len(CASES)}','responses':[UA,changed(SUCCESS,**{key:value})],'calls':2,'valid':False})
for key,value in [('devices',2),('interfaces',2),('selection_error',True),('sysfs_dev','22:0'),('open_failure',True),('regular_fd',True),('rdev',22<<8),('sg_version',29999),('host',1),('channel',1),('scsi_id',1),('lun',1),('type',1)]:CASES.append({'id':'identity_'+key,key:value,'responses':[],'calls':0,'valid':False})
rows=[]
for case in CASES:
 try:
  body,decoded=Harness(case).run();(OUT/(case['id']+'.txt')).write_bytes(body);rows.append({'id':case['id'],'status':'PASS','calls':case['calls'],'capacity_valid':case['valid'],'log_bytes':len(body),'log_sha256':hashlib.sha256(body).hexdigest()})
 except BaseException as e:rows.append({'id':case['id'],'status':'FAIL','error':repr(e)});print(json.dumps(rows[-1]),flush=True);break
report={'status':'PASS' if len(rows)==len(CASES) and all(r['status']=='PASS' for r in rows) else 'FAIL','elf_sha256':SHA,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':rows,'case_count':len(rows),'expected_cases':len(CASES),'actual_machine_code_functions':{k:{'address':hex(symbols[k][0]),'bytes':symbols[k][1]} for k in ['submit','perform','lc_retry_ua','lc_response','lc_capacity','emit']},'scope':'Unchanged production ELF x64 instructions with explicit synthetic selection/POSIX/ioctl/display boundaries. No physical I/O; not execution of kernel driver bytes. Runtime Linux driver ownership is separately covered by QEMU/OVMF.','hardware_access':False}
(OUT/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({k:report[k] for k in ['status','case_count','expected_cases','elf_sha256']}));sys.exit(0 if report['status']=='PASS' else 1)
