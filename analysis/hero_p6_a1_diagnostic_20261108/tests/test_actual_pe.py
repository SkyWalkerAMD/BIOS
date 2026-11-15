"""Actual A1 PE execution. Synthetic UEFI/HII/PCI/KCS; no hardware.

Reuse only the class definitions of the frozen lifecycle fixture. A1's actual
publisher, KCS transport, policy, identity/preflight and control flow execute.
The QR presentation boundary is captured here; OVMF tests the real renderer.
"""
from pathlib import Path
import copy,gc,hashlib,json,re,struct,sys,uuid,zlib
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[1]
old=ROOT/'analysis/hero_p6_settings21r_20261108/tests/test_refresh_lifecycle.py'
ns={'__file__':str(old),'__name__':'fixture_definitions'}
exec(compile(old.read_text().split('\nrows=[]')[0],str(old),'exec'),ns)
Fixture=ns['Machine'];v=ns['v'];unicorn=ns['unicorn'];ids=ns['ids'];langs=ns['langs'];package=ns['package']
from unicorn.x86_const import *
import pefile
raw=(BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes();pe=pefile.PE(data=raw);IMAGE=pe.OPTIONAL_HEADER.ImageBase
symbols={m[1]:int(m[2],16) for line in (BASE/'build/BOOTX64.map').read_text().splitlines() if (m:=re.match(r'\s+\d+:[0-9a-f]+\s+([\w.]+)\s+([0-9a-f]{16})',line,re.I))}
ERR=v.ERR;API=v.API;DEFAULT=v.cfg()
def record(t,body,strings=()):return bytes([t,len(body)+4,t,0])+body+(b'\0'.join(strings)+b'\0\0' if strings else b'\0\0')
def table(bad=False):
 ident=bytearray(20);ident[4:20]=bytes.fromhex('9565299beb5589e65fd208bfb8eeda44');ident[4]^=int(bad)
 return record(0,bytes([1,2,0,0,3]),[b'AMI',b'3107',b'11/28/2025'])+record(1,bytes(ident))+record(2,b'\1\2',[b'ASUS',b'ROG MAXIMUS Z790 HERO'])+record(127,b'')
def journal(phase=0):
 b=bytearray(144);struct.pack_into('<IIIIII',b,0,0x36504948,1,144,0,phase,0);b[24:56]=DEFAULT;b[56:88]=DEFAULT;struct.pack_into('<I',b,12,zlib.crc32(b));return bytes(b)
class Machine(Fixture):
 def __init__(self,keys='B\rR\rP\rP\rMQQ',settings=DEFAULT[:21],bad_uuid=False,**kwargs):
  super().__init__(config=settings,**kwargs)
  if settings is None:self.vars={}
  self.keys=list(keys);self.p6_present=False;self.var_mutate=None;self.key_mutate=None;self.watchdog_error=0
  self.call_fault=None;self.captures=[];self.counts={};self.hii_write_values=[]
  self.u.mem_map(IMAGE,0x2000000);self.u.mem_write(IMAGE,pe.get_memory_mapped_image());self.functions=symbols.copy();self.w64(symbols['gST'],self.st)
  self.boundary={n:0 for n in ('p5_bind','p1_collect','p5_probe_same_value','p5_publish')}
  for name in self.boundary:self.u.hook_add(unicorn.UC_HOOK_CODE,self.count_entry,begin=symbols[name],end=symbols[name],user_data=name)
  self.u.hook_add(unicorn.UC_HOOK_CODE,self.qr_capture,begin=symbols['kvm_present'],end=symbols['kvm_present'])
  for off in (0x18,0x20,0x50,0x58,0x68,0x70,0x80,0x88,0x90,0xa8,0xb8,0xc0,0xc8,0xd0,0xe0,0xe8,0x108,0x110,0x148,0x150,0x170):self.stub(self.bs+off,'FORBIDDEN_SERVICE_'+hex(off))
  self.stub(self.bs+0x38,'GetMap');self.stub(self.rt+0x58,'FORBIDDEN_NV_WRITE')
  data=table(bad_uuid);self.sm_addr=self.alloc(data)
  ep=bytearray(24);ep[:5]=b'_SM3_';ep[6]=24;ep[7:9]=b'\3\6';struct.pack_into('<IQ',ep,12,len(data),self.sm_addr);ep[5]=(-sum(ep))&255
  entries=self.alloc(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',self.alloc(ep)))
  self.w64(self.st+0x68,1);self.w64(self.st+0x70,entries)
  for lang in langs:self.hii[(lang,ids[-1])]='existing configuration status '+lang
 def audit(self):
  n=self.r64(symbols['audit_len']);assert n<2097152;return bytes(self.u.mem_read(symbols['audit'],n)).decode('ascii')
 def qr_capture(self,u,at,size,ctx):
  assert u.reg_read(UC_X86_REG_RCX)==self.st
  p=u.reg_read(UC_X86_REG_RDX);n=u.reg_read(UC_X86_REG_R8);warning=u.reg_read(UC_X86_REG_R9)
  self.captures.append((bytes(u.mem_read(p,n)),warning));sp=u.reg_read(UC_X86_REG_RSP)
  u.reg_write(UC_X86_REG_RAX,0);u.reg_write(UC_X86_REG_RIP,self.r64(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def hook(self,u,at,size,ctx):
  name=self.stubs.get(at)
  if not name:return
  assert not name.startswith('FORBIDDEN'),name
  sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
  e=self.r64(sp+0x28);self.counts[name]=self.counts.get(name,0)+1
  result=None
  if self.call_fault:result=self.call_fault(self,name,(a,b,c,d,e),self.counts[name])
  if result is not None:return self.ret(u,result,name)
  if name=='GetMap':
   data=b''.join(struct.pack('<IIQQQQ',4,0,p,0,n//4096,0) for p,n in ((0x100000,0x100000),(0x600000,0x300000),(0xd00000,0x200000),(0x2000000,0x200000),(IMAGE,0x2000000)))
   assert self.r64(a)>=len(data);u.mem_write(b,data);self.w64(a,len(data));self.w64(c,1);self.w64(d,40);u.mem_write(e,struct.pack('<I',1));return self.ret(u,0,name)
  if name=='LocateProtocol' and self.guid(a)==API:
   if self.p6_present:self.w64(c,0)
   return self.ret(u,0 if self.p6_present else ERR(14),name)
  if name=='GetVariable' and self.var_mutate:self.var_mutate(self,self.wide(a),self.counts[name])
  if name=='ReadKey' and self.key_mutate:self.key_mutate(self,self.keys[0])
  if name=='Watchdog':assert a==b==c==d==0;return self.ret(u,self.watchdog_error,name)
  if name=='HiiSet':self.hii_write_values.append(((self.cstr(d),c&65535),self.wide(e)))
  return super().hook(u,at,size,ctx)
 def run(self):
  assert self.call('efi_main',0x77,self.st)==0
  assert not self.pools and not self.events and not self.notifications and not self.nv_writes and not self.dev.mutations and not self.dev.oem_packets
  assert not any(x.startswith('FORBIDDEN') for x in self.calls)
  return self

rows=[]
def check(name,fn):fn();rows.append(name);print(name,'PASS',flush=True);gc.collect()
def full():
 m=Machine().run();assert set(m.boundary.values())=={1};assert len(m.hii_sets)==411;assert m.config[4]&2==0
 assert m.hii_write_values[0][1]=='Not queried'
 assert all(m.hii[(lang,ids[-1])]=='existing configuration status '+lang for lang in langs)
 snap,warn=m.captures[0];assert not warn and b'P5_NATIVE_STRINGS_PUBLISHED_AND_READ_BACK' in snap and b'PCI_RESTORE' in snap
 assert b'TX 06/01' in snap and b'HII_HANDLE_INDEX' in snap and b'LAST_COMPLETED' in snap and b'> HII_GET_STRING' not in snap
 assert len(snap)<24000
 (BASE/'tests/OFFLINE-A1-FULL.txt').write_bytes(b'OFFLINE ACTUAL-PE / SYNTHETIC UEFI HII BMC\n'+m.audit().encode('ascii'))
 (BASE/'tests/OFFLINE-A1-COMPACT.txt').write_bytes(snap)
check('B R same-value P full P real machine-code pipeline and unchanged config field',full)
def count(keys,expected,**kw):
 m=Machine(keys,**kw).run();assert list(m.boundary.values())==expected,(m.boundary,m.audit()[-1000:]);return m
check('no automatic stages on entry',lambda:count('QQ',[0,0,0,0]))
check('cancel B checkpoint then exit',lambda:count('BQ'+'QQ',[0,0,0,0]))
check('cancel with escape then retry explicit B permitted',lambda:count('B\x1bB\rQQ',[1,0,0,0]))
check('R and P require B',lambda:count('RPQQ',[0,0,0,0]))
check('P requires completed R',lambda:count('B\rPQQ',[1,0,0,0]))
check('all completed stages cannot replay',lambda:count('B\rBR\rRP\rP\rPQQ',[1,1,1,1]))
check('lowercase accepted only explicit confirmation',lambda:count('b\rr\rp\rp\rqq',[1,1,1,1]))
check('wrong UUID refuses all stage calls',lambda:count('B\rQQ',[0,0,0,0],bad_uuid=True))
for width in (None,DEFAULT,DEFAULT[:21]):
 def safe(width=width):
  m=count('B\rQQ',[1,0,0,0],settings=width)
  assert ('HeroIpmiSettings' not in m.vars) if width is None else m.vars['HeroIpmiSettings'][1]==width
 check('safe settings retained no seeding '+str(None if width is None else len(width)),safe)
for length in (21,32):
 for off in range(length):
  def invalid(length=length,off=off):
   b=bytearray(DEFAULT[:length]);b[off]^=1;count('B\rQQ',[0,0,0,0],settings=bytes(b))
  check('reject nondefault settings width%d byte%d'%(length,off),invalid)
def existing():
 m=Machine('B\rQQ');m.p6_present=True;m.run();assert not any(m.boundary.values())
check('resident P6 even NULL marker refuses stages',existing)
def wd():
 m=Machine('B\rQQ');m.watchdog_error=ERR(7);m.run();assert not any(m.boundary.values())
check('UEFI watchdog-disable failure refuses stages',wd)
def changed():
 m=Machine('B\rQQ')
 def alter(m,name,n):
  if n==3:m.vars['HeroIpmiSettings']=(3,DEFAULT)
 m.var_mutate=alter;m.run();assert not any(m.boundary.values())
check('safe21 to safe32 race refused as changed',changed)
def pending():
 m=Machine('B\rQQ');m.vars['HeroIpmiState']=(3,journal(1));m.run();assert not any(m.boundary.values())
check('pending journal refuses stages without consumption',pending)
def bind_error(kind):
 m=Machine('B\rRPBQQ')
 if kind=='forms':m.bad_package=True
 else:
  def fault(m,name,args,n):
   if name==kind:return ERR(9)
  m.call_fault=fault
 m.run();assert list(m.boundary.values())==[1,0,0,0] and not m.dev.packets
for kind in ('forms','HiiAllocate','HiiGet'):check('bind failure prevents R P retry '+kind,lambda kind=kind:bind_error(kind))
def full_limit():
 m=Machine('B\rQQ')
 def mutate(m,k):
  if k=='B':m.u.mem_write(symbols['audit_bad'],struct.pack('<I',1))
 m.key_mutate=mutate;m.run();assert not any(m.boundary.values())
check('log already incomplete refuses B',full_limit)
def probe_error():
 m=Machine('B\rR\rP\rPQQ')
 def fault(m,name,args,n):
  if name=='HiiGet' and m.hii_sets:
   m.hii[(langs[0],ids[0])]='unexpected concurrent text'
 m.call_fault=fault;m.run();assert list(m.boundary.values())==[1,1,1,0] and len(m.hii_sets)==1
check('same-value readback mismatch blocks full publish and retry',probe_error)
def unicode_same():
 m=Machine('B\rR\rP\rQQ');m.hii[(langs[0],ids[0])]='真实旧值 Ω';m.run();assert m.hii_write_values==[((langs[0],ids[0]),'真实旧值 Ω')]
check('single P copies current Unicode string exactly',unicode_same)
def r_failure(case):
 m=count('B\rR\rRPQQ',[1,1,0,0],case=case)
 assert not m.hii_sets
 if case!='restore_failure':assert m.config[4]&2==0
for case in ('wrong_location','resident_transport','startup_busy','restore_failure'):check('R failure no P no replay '+case,lambda case=case:r_failure(case))
def read_fail():
 m=Machine('B\rR\rPQQ');m.dev.fault=lambda f,c,p:b'\x1c\x04' if (f,c)==(6,4) else None;m.run();assert list(m.boundary.values())==[1,1,0,0] and m.config[4]&2==0
check('KCS malformed response restores PCI and forbids publication',read_fail)
def policy():
 m=Machine('QQ')
 p=m.alloc(bytes(32))
 for f,c in ((6,0x22),(6,0x24),(6,0x2e),(12,1),(10,0x42),(10,0x46),(10,0x47),(0x30,0x94),(0x30,0x9a)):
  for n in (0,1,6,15):assert m.call('p1_read_allowed',f,c,p,n)==0
check('actual immutable GET allowlist denies config watchdog SEL and OEM',policy)
for forbidden in ('p6_transport_open','p6_transport_close','p6_exchange','p6_delay','p6_write_armed','p6_seed_settings','p6_apply_settings','p6_start_os_watchdog','p6_stop_os_watchdog','candidate_query','candidate_arm','candidate_step','fan_query','fan_arm','fan_packet'):
 assert forbidden not in symbols,forbidden
rows.append('final link removes configuration and OEM helper functions and write-armed global')
report={'passed':True,'cases':len(rows),'results':rows,'actual_pe_sha256':hashlib.sha256(raw).hexdigest(),'fixture_definition_sha256':hashlib.sha256(old.read_bytes()).hexdigest(),'limits':['UEFI HII/PCI/KCS responses are synthetic. These tests do not prove behavior on AMI HERO.','QR presentation is intercepted in these tests only; separate OVMF verifies real boot and QR renderer.']}
(BASE/'tests/actual-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
