"""Actual S23 PE with exact P5/P6 Forms and independently controlled HII service.
This tests resource classification/publication and callback suppression only;
firmware APIs, BMC and PCI are fakes, not real hardware.
"""
from pathlib import Path
import gc,hashlib,json,struct,sys,uuid
HERE=Path(__file__).resolve().parents[1];ROOT=HERE.parents[1]
prior=ROOT/'analysis/hero_p6_settings21r_20261108/tests/test_refresh_lifecycle.py'
ns={'__file__':str(__file__),'__name__':'s23_hii_fixture'}
exec(compile(prior.read_text().split('\nrows=[]')[0],str(prior),'exec'),ns)
Fixture=ns['Machine'];v=ns['v'];AFTER=ns['AFTER'];langs=ns['langs'];ids=ns['ids']
from unicorn.x86_const import *
P5=(HERE/'native/Setup-forms-P5.bin').read_bytes();P6=(HERE/'native/Setup-forms-P6.bin').read_bytes()
def package(*forms):
 tail=b''.join(forms)+b'\x04\0\0\xdf'
 return uuid.UUID('a85810b5-ad33-4350-b7f5-37905d0dbdb9').bytes_le+struct.pack('<I',20+len(tail))+tail
PACK5=package(P5);PACK6=package(P6);mutant=bytearray(P6);mutant[-10]^=1;UNKNOWN=package(bytes(mutant))
class Machine(Fixture):
 def __init__(self,packages=(PACK6,),count=41,**kwargs):
  super().__init__(**kwargs);self.packages=list(packages);self.current_count=count
  self.hii={(lang,i):'Not queried' for lang in langs for i in ids[:count]}
  self.get_calls=[];self.set_calls=[];self.export_calls=[];self.hii_error=None;self.export_fault=None;self.set_fault=None
 def hook(self,u,at,size,ctx):
  name=self.stubs.get(at)
  if name is None:return
  sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=self.r64(sp+0x28);f=self.r64(sp+0x30);status=0
  if name=='HiiList':
   assert a==self.db and b&255==2 and c==0
   if not e:self.w64(d,8*len(self.packages));status=v.ERR(5)
   else:
    assert self.r64(d)>=8*len(self.packages)
    for i in range(len(self.packages)):self.w64(e+8*i,100+i)
    self.w64(d,8*len(self.packages))
  elif name=='HiiExport':
   assert a==self.db and 100<=b<100+len(self.packages)
   data=self.packages[b-100];self.export_calls.append((b,bool(d)))
   action=self.export_fault(b,bool(d)) if self.export_fault else None
   if action=='error':status=v.ERR(7)
   elif action=='oversize':self.w64(c,8*1024*1024+1);status=v.ERR(5)
   elif action=='growth':self.w64(c,self.r64(c)+1)
   elif not d:self.w64(c,len(data));status=v.ERR(5)
   else:assert self.r64(c)>=len(data);u.mem_write(d,data);self.w64(c,len(data))
  elif name=='HiiGet':
   assert a==self.strings and 100<=c<100+len(self.packages)
   key=(self.cstr(b),d&65535);self.get_calls.append(key)
   action=self.hii_error(key) if self.hii_error else None
   if key not in self.hii or action=='error':status=v.ERR(14)
   elif action=='zero':self.w64(f,0)
   elif action=='odd':self.w64(f,3);u.mem_write(e,b'\0\0\0')
   elif action=='oversize':self.w64(f,322)
   elif action=='unterminated':self.w64(f,4);u.mem_write(e,b'A\0B\0')
   else:
    raw=(self.hii[key]+'\0').encode('utf-16le');assert len(raw)<=self.r64(f);u.mem_write(e,raw);self.w64(f,len(raw))
  elif name=='HiiSet':
   assert a==self.strings and 100<=b<100+len(self.packages)
   key=(self.cstr(d),c&65535);assert key in self.hii
   self.set_calls.append(key)
   if self.set_fault and self.set_fault(key):status=v.ERR(7)
   else:self.hii[key]=self.wide(e);self.hii_sets.append(key)
  else:return super().hook(u,at,size,ctx)
  self.ret(u,status,name)
 def bind(self):
  e=self.call('p5_bind');assert not self.pools;return e
 def publish(self):
  e=self.call('p5_publish');assert not self.pools;return e
 def no_hardware(self):assert not self.dev.packets and not self.pci_writes and not self.nv_writes

rows=[]
def case(name,fn):fn();rows.append(name);print(name,'PASS',flush=True);gc.collect()
for label,pack,kind,count in [('P5',PACK5,1,40),('P6',PACK6,2,41)]:
 def positive(label=label,pack=pack,kind=kind,count=count):
  m=Machine((pack,),count);p=m.alloc(pack)
  assert m.call('p5_package_kind',p,len(pack))==kind
  # The unused legacy wrapper is deliberately /OPT:REF stripped from shipping
  # PE; its source contract remains strict P6 while classifier is exercised.
  assert 'int p5_package_matches(const uint8_t *b,UN n){return p5_package_kind(b,n)==RESOURCE_P6;}' in (HERE/'source/publisher.c').read_text()
  assert m.bind()==0 and len(m.get_calls)==10*count
  assert 'P6_NATIVE_STAGE=BIND_ENUM_COMPLETE STATUS=0000000000000000 A=00000001 B=00000001' in m.audit()
  assert m.publish()==0 and len(m.set_calls)==10*count and len(m.get_calls)==30*count
  if kind==1:assert all(i!=ids[40] for _,i in m.get_calls+m.set_calls)
  assert ('P5_READONLY VALUES=40' if kind==1 else 'P6_CONFIG VALUES=41') in m.audit()
  m.no_hardware()
 case('known '+label+' classification full ID preflight publish count',positive)
 def after(label=label,pack=pack,count=count):
  m=Machine((pack,),count).start();m.dispatch(AFTER)
  assert m.boundary['p5_bind']==m.boundary['p1_collect']==m.boundary['p5_publish']==1
  assert len(m.hii_sets)==10*count and not m.dev.mutations and not m.dev.oem_packets and not m.nv_writes
  n=len(m.dev.packets);sets=len(m.hii_sets);m.dispatch(AFTER)
  assert len(m.dev.packets)==n and len(m.hii_sets)==sets
 case('known '+label+' actual AfterBoot standard reads publish once no repeat',after)

bad_package_cases=[('unknown whole Forms',(UNKNOWN,)),('duplicate P5 handles',(PACK5,PACK5)),('duplicate P6 handles',(PACK6,PACK6)),('mixed P5 P6 handles',(PACK5,PACK6)),('two P5 Forms one package',(package(P5,P5),)),('P5 plus P6 Forms one package',(package(P5,P6),)),('P6 plus unknown Forms one package',(package(P6,bytes(mutant)),)),('missing END',(PACK6[:-4],)),('bad declared size',(PACK6[:16]+bytes(4)+PACK6[20:],)),('trailing after END',(PACK6+bytes(4),)),('known plus malformed hidden second',(PACK5,PACK6[:-4]))]
for name,packs in bad_package_cases:
 def reject(packs=packs):
  m=Machine(packs);assert m.bind()&v.ERR(0);assert not m.get_calls and not m.set_calls;m.no_hardware()
 case(name,reject)
def one_unknown_valid():
 m=Machine((UNKNOWN,PACK5),40);assert m.bind()==0 and m.publish()==0 and len(m.set_calls)==400;m.no_hardware()
case('valid unknown form can coexist without becoming selected',one_unknown_valid)
for which in ('first_query','first_export','later_query','later_export','oversize','growth'):
 def failed(which=which):
  m=Machine((PACK5,UNKNOWN),40)
  def fault(handle,have_buffer):
   if which=='first_query' and handle==100 and not have_buffer:return 'error'
   if which=='first_export' and handle==100 and have_buffer:return 'error'
   if which=='later_query' and handle==101 and not have_buffer:return 'error'
   if which=='later_export' and handle==101 and have_buffer:return 'error'
   if which=='oversize' and handle==101:return 'oversize'
   if which=='growth' and handle==101 and have_buffer:return 'growth'
  m.export_fault=fault;assert m.bind()&v.ERR(0);assert not m.get_calls and not m.set_calls;m.no_hardware()
  assert 'P6_NATIVE_STAGE=BIND_EXPORT_HANDLE' in m.audit()
 case('incomplete enumeration '+which+' is terminal',failed)
for before,after,name,count in [(PACK5,PACK6,'P5 to P6',40),(PACK6,PACK5,'P6 to P5',41),(PACK5,UNKNOWN,'P5 to unknown',40)]:
 def changed(before=before,after=after,count=count):
  m=Machine((before,),count);assert m.bind()==0;m.packages=[after]
  assert m.publish()==v.ERR(33) and not m.set_calls
  assert m.publish()==v.ERR(6);m.no_hardware()
 case('publication repins exact resource kind '+name,changed)
for label,pack,count in [('P5',PACK5,40),('P6',PACK6,41)]:
 for stage in ('bind','publish'):
  for action in ('error','zero','odd','oversize','unterminated'):
   def invalid(label=label,pack=pack,count=count,stage=stage,action=action):
    m=Machine((pack,),count)
    if stage=='publish':assert m.bind()==0
    target=(langs[-1],ids[count-1]);m.hii_error=lambda key:action if key==target else None
    assert (m.bind() if stage=='bind' else m.publish())==v.ERR(33)
    assert 'P6_NATIVE_STAGE='+stage.upper()+'_STRING_CHECK' in m.audit() and 'P6_NATIVE_STRING_LANGUAGE='+langs[-1] in m.audit()
    assert not m.set_calls;m.no_hardware()
   case(label+' '+stage+' final language/ID '+action+' before any SetString',invalid)
def p5_final_id_missing():
 m=Machine((PACK5,),40);del m.hii[(langs[0],ids[39])];assert m.bind()==v.ERR(33) and not m.set_calls
case('P5 last existing ID is mandatory',p5_final_id_missing)
def midset():
 m=Machine((PACK5,),40).start();m.set_fault=lambda key:len(m.set_calls)==37;m.dispatch(AFTER)
 assert len(m.set_calls)==37 and len(m.hii_sets)==36
 assert 'P6_AFTER_SYNC_PUBLISH_STATUS=8000000000000007' in m.audit()
 m.dispatch(AFTER);assert len(m.set_calls)==37
case('partial publication failure is reported and not replayed by AfterBoot',midset)
report={'passed':True,'cases':len(rows),'rows':rows,'driver_sha256':hashlib.sha256((HERE/'HeroIpmiP6.efi').read_bytes()).hexdigest(),'exact_forms':{'P5':hashlib.sha256(P5).hexdigest(),'P6':hashlib.sha256(P6).hexdigest()},'limits':['Synthetic HII, PCI and BMC service returns only.','A synchronous firmware service itself cannot be preempted by the local bounds.','No exact .15 HII export or F10 configuration verification here.']}
(HERE/'tests/resource-compatibility-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
