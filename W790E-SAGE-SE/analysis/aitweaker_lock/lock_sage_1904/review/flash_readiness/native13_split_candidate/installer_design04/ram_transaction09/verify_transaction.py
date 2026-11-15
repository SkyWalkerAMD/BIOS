"""Actual transaction PE fault matrix, original OEM memory, no hardware.

TPL and validator services are explicit models. Exact target stores and rollback
instructions are executed; validation does not stand in for production adapter
validation or a real multiprocessor concurrency guarantee.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;N13=D04.parent;ROOT=N13.parents[5]
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile,unicorn as U
from unicorn import x86_const as R
BUILD=HERE/'build';CORE=D04/'diagnostic_guard09';meta=json.loads((CORE/'build/split_build.json').read_text())
TX=0x140000000;CTX=0x60000000;PLAN=CTX+0x1000;HOST=CTX+0x2000;RESULT=CTX+0x3000;STACK=0x70000000;STOP=0x50000000
RAISE=STOP+0x100;RESTORE=STOP+0x110;VALIDATE=STOP+0x120;TRAMP=STOP+0x1000
STATE=int(meta['state_base'],16);q=lambda x:struct.pack('<Q',x);d=lambda x:struct.pack('<I',x)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=pefile.PE(str(BUILD/'TransactionCore09.TESTONLY.efi'))
symbols={name:int(addr,16)-p.OPTIONAL_HEADER.ImageBase+TX for name,addr in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})', (BUILD/'transaction.map').read_text(),re.M)}
class VM:
 def __init__(self):
  self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);self.tpl=4;self.calls=[];self.writes=[];self.pending=None;self.ignore_site=None;self.corrupt_site=None;self.corrupt_once=False;self.bad_validation=None;self.reenter=None;self.ending=None;self.validations=0;self.fault_fired=0
  self.baseline={};self.patched={};self.guard=[];self.limits=[]
  for base,size in [(CTX,0x10000),(STACK,0x100000),(STOP,0x2000)]:self.u.mem_map(base,size)
  pe=pefile.PE(str(BUILD/'TransactionCore09.TESTONLY.efi'));pe.relocate_image(TX);raw=pe.get_memory_mapped_image();self.u.mem_map(TX,(len(raw)+4095)&~4095);self.u.mem_write(TX,raw)
  for s in pe.sections:
   attrs=U.UC_PROT_READ|(U.UC_PROT_EXEC if s.Characteristics&0x20000000 else 0)|(U.UC_PROT_WRITE if s.Characteristics&0x80000000 else 0)
   self.u.mem_protect(TX+s.VirtualAddress,(max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)&~4095,attrs)
  for name in ['AMITSE','Setup']:
   base=int(meta['original_bases'][name],16);raw=(CORE/'build'/(name+'.memory-fixture.bin')).read_bytes();self.patched[name]=raw;original=bytearray(raw)
   for row in meta['patches']:
    if row['module']==name:
     at=int(row['rva'],16);original[at:at+row['length']]=bytes.fromhex(row['old']);self.limits.append((base+at,base+at+row['length']))
   self.baseline[name]=bytes(original);self.u.mem_map(base,(len(raw)+4095)&~4095);self.u.mem_write(base,bytes(original))
   guard=int(meta['guard_bases'][name],16);blob=(CORE/'build'/(name+'.split-guard.bin')).read_bytes();self.guard.append(guard);self.u.mem_map(guard,(len(blob)+4095)&~4095);self.u.mem_write(guard,blob);self.u.mem_protect(guard,(len(blob)+4095)&~4095,U.UC_PROT_READ|U.UC_PROT_EXEC)
  self.u.mem_map(STATE,4096);self.u.mem_write(STATE,(CORE/'build/owned-state-fixture.bin').read_bytes());self.u.mem_protect(STATE,4096,U.UC_PROT_READ|U.UC_PROT_WRITE)
  vals=[int(meta['original_bases'][x],16)for x in ['AMITSE','Setup']]+[meta['module_fixtures'][x]['original_image_size']for x in ['AMITSE','Setup']]+self.guard+[meta['module_fixtures'][x]['guard_bytes']for x in ['AMITSE','Setup']]+[STATE,4096]
  self.u.mem_write(PLAN,struct.pack('<10Q',*vals));self.u.mem_write(HOST,q(RAISE)+q(RESTORE)+q(VALIDATE))
  self.u.reg_write(R.UC_X86_REG_CR4,0x600)
  self.u.hook_add(U.UC_HOOK_CODE,self.code)
  self.u.hook_add(U.UC_HOOK_MEM_WRITE,self.store)
 def getq(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def getd(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def arg(self,n):return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][n])
 def ret(self,value):
  sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,value);self.u.reg_write(R.UC_X86_REG_RIP,self.getq(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
 def callback_call(self,name,result):
  code=b'\x48\x83\xec\x28\x48\xb9'+q(CTX)+b'\x48\xb8'+q(symbols[name])+b'\xff\xd0\x48\xba'+q(RESULT)+b'\x48\x89\x02\xb8'+d(result)+b'\x48\x83\xc4\x28\xc3'
  self.u.mem_write(TRAMP,code);self.u.reg_write(R.UC_X86_REG_RIP,TRAMP)
 def code(self,u,a,n,data):
  if self.pending:
   at,raw=self.pending;self.pending=None;u.mem_write(at,raw)
  if a==STOP:u.emu_stop();return
  if a==RAISE:
   assert self.arg(0)==31;self.calls.append(('raise',self.tpl));old=self.tpl;self.tpl=31
   if self.ending=='raise':self.ending=None;self.callback_call('tx_end',old)
   else:self.ret(old)
   return
  if a==RESTORE:
   self.calls.append(('restore',self.arg(0)));self.tpl=self.arg(0)
   if self.ending=='restore':self.ending=None;self.callback_call('tx_end',0)
   else:self.ret(0)
   return
  if a==VALIDATE:
   assert self.arg(0)==CTX;mode=self.arg(1);self.validations+=1;self.calls.append(('validate',mode,self.tpl))
   if self.ending=='validate':self.ending=None;self.callback_call('tx_end',1);return
   if self.reenter==self.validations:self.callback_call('tx_install',1);return
   if self.bad_validation==self.validations:self.ret(0);return
   ok=True
   if mode in [0,1]:
    expected=self.baseline if mode==0 else self.patched
    ok=all(bytes(u.mem_read(int(meta['original_bases'][name],16),len(raw)))==raw for name,raw in expected.items())
   self.ret(int(ok));return
 def store(self,u,access,a,n,value,data):
  # Exactly the transaction object, own state, scratch stack and 12 declared
  # original targets are permitted writes by the actual compiled code.
  allowed=(CTX<=a and a+n<=CTX+720)or(STATE<=a and a+n<=STATE+32)or(STACK<=a and a+n<=STACK+0x100000)or(RESULT<=a and a+n<=RESULT+8)or any(lo<=a and a+n<=hi for lo,hi in self.limits)
  assert allowed,('unexpected actual store',hex(a),n)
  if any(lo<=a<hi for lo,hi in self.limits):
   assert self.tpl==31,('foreign write outside high TPL',hex(a),self.tpl)
   self.writes.append((a,n))
   for i,row in enumerate(meta['patches']):
    lo=int(row['address'],16);hi=lo+row['length']
    if lo<=a<hi:
     if self.ignore_site==i:self.pending=(a,bytes(u.mem_read(a,n)));self.fault_fired+=1
     if self.corrupt_site==i and not self.corrupt_once:self.pending=(a,bytes([0xcc])*n);self.corrupt_once=True;self.fault_fired+=1
 def call(self,name,*args):
  sp=STACK+0xffe08;self.u.mem_write(sp,q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for i,x in enumerate(args):self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i],x)
  self.u.emu_start(symbols[name],0,count=1000000)
  assert self.u.reg_read(R.UC_X86_REG_RIP)==STOP,hex(self.u.reg_read(R.UC_X86_REG_RIP))
  return self.u.reg_read(R.UC_X86_REG_RAX)
 def prepare(self):return self.call('tx_prepare',CTX,PLAN,HOST)
 def install(self):return self.call('tx_install',CTX)
 def remove(self):return self.call('tx_remove',CTX)
 def exact(self,patched=False):
  return all(bytes(self.u.mem_read(int(meta['original_bases'][name],16),len(raw)))==raw for name,raw in(self.patched if patched else self.baseline).items())

def main():
 checks=[]
 def check(n,c):assert c,n;checks.append(n)
 v=VM();check('prepare validates without any original module write',v.prepare()==0 and not v.writes and v.tpl==4)
 check('all12 actual stores install exact frozen detached targets',v.install()==0 and v.exact(True)and v.getd(CTX+8)==2 and v.tpl==4)
 check('successful install restores only original TPL',v.calls.count(('raise',4))==1 and v.calls.count(('restore',4))==1)
 check('successful removal restores every original byte',v.remove()==2 and v.exact()and v.getd(CTX+8)==3 and v.getd(STATE+24)==2 and v.tpl==4)
 check('retired instance cannot reinstall or remove twice',v.install()==1 and v.remove()==1)
 for i,row in enumerate(meta['patches']):
  x=VM();check('site '+str(i)+' prepare',x.prepare()==0);x.ignore_site=i
  status=x.install();check('ignored site '+str(i)+' safely rolls back prior writes',status==2 and x.exact()and x.tpl==4 and x.fault_fired>0 and x.getd(STATE+24)==2)
  x=VM();assert x.prepare()==0;x.corrupt_site=i;status=x.install()
  check('unknown site '+str(i)+' is not overwritten and holds high TPL',status==4 and x.getd(CTX+20)==1 and x.tpl==31 and x.getd(STATE+24)==2 and not any(c[0]=='restore'for c in x.calls))
 for old in [8,16,31]:
  x=VM();assert x.prepare()==0;x.tpl=old
  check('nonapplication TPL '+str(old)+' rejects before target writes',x.install()==1 and not x.writes and x.tpl==old)
 for at,label in [(1,'prepare validation'),(2,'prewrite validation')]:
  x=VM();x.bad_validation=at;prepared=x.prepare();result=x.install()if not prepared else prepared
  check(label+' failure has zero foreign writes',result==1 and not x.writes and x.exact()and x.tpl==4)
 x=VM();assert x.prepare()==0;x.bad_validation=3
 check('postwrite validation failure rolls back exact complete transaction',x.install()==2 and x.exact()and x.tpl==4)
 x=VM();assert x.prepare()==0 and x.install()==0;x.bad_validation=4
 check('remove prevalidation failure holds without unknown target overwrite',x.remove()==4 and x.tpl==31 and x.exact(True)and x.getd(STATE+24)==2)
 x=VM();assert x.prepare()==0 and x.install()==0;x.bad_validation=5
 check('rollback permission failure retains all pointers and holds',x.remove()==4 and x.tpl==31 and x.exact(True))
 x=VM();assert x.prepare()==0 and x.install()==0;x.bad_validation=6
 check('failed final restore validation holds even if target bytes look original',x.remove()==4 and x.tpl==31 and x.exact())
 for which in ['ui','save']:
  x=VM();assert x.prepare()==0 and x.install()==0;x.u.mem_write(STATE+(0 if which=='ui'else 8),q(0xdead0000))
  check('active '+which+' frame rejects removal without edits',x.remove()==3 and x.tpl==4 and x.exact(True)and x.getd(STATE+24)==1)
 for nth in [1,2,3]:
  x=VM();x.reenter=nth;assert x.prepare()==0;result=x.install()
  check('actual nested install at validation '+str(nth)+' is busy and outer succeeds',result==0 and x.getq(RESULT)==3 and x.exact(True))
 for where in ['raise','validate','restore']:
  x=VM();assert x.prepare()==0;x.ending=where;status=x.install()
  check('actual tx_end at '+where+' is terminal',status==5 and x.getd(CTX+16)==1 and x.getd(STATE+24)==3)
  before=list(x.calls);check('ended instance calls no more services '+where,x.install()==5 and x.remove()==5 and x.calls==before)
 x=VM();x.u.mem_write(PLAN+16,q(0xa6020));check('expanded original size is rejected before validation',x.prepare()==1 and not x.calls and not x.writes)
 x=VM();x.u.mem_write(PLAN+64,q(int(meta['original_bases']['AMITSE'],16)));check('state overlapping original module rejected',x.prepare()==1 and not x.calls and not x.writes)
 for i,row in enumerate(meta['patches']):
  x=VM();x.u.mem_write(int(row['address'],16),b'\xcc');check('initial target mismatch '+str(i)+' rejects before any write',x.prepare()==1 and not x.writes)
 r={'status':'PASS_ACTUAL_TRANSACTION_CORE_WITH_MODELED_TPL_AND_VALIDATION','checks':len(checks),'check_names':checks,'transaction_efi_sha256':sha(BUILD/'TransactionCore09.TESTONLY.efi'),'build_sha256':sha(BUILD/'build.json'),'test_source_sha256':sha(Path(__file__)),'guard_split_build_sha256':sha(CORE/'build/split_build.json'),'asserted_write_scope':['private720B transaction object','own32B state','bounded fixture stack','12 exact original patch windows','explicit test result8B'],'limits':['The exact transaction copy/readback/rollback/phase code runs; Host.validate and TPL services are explicit fixtures.','Fault injection models ignored stores or post-store corruption; a CPU page fault is not converted to a recoverable status.','No production UEFI validator/allocator/app/cleanup lifecycle, provider publication, native GUI or physical install is established by this core test.','No protection against arbitrary AP/SMM concurrent mutation; TPL is a BSP premise.']}
 (BUILD/'transaction_verification.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'checks':len(checks)}))

if __name__=='__main__':main()
