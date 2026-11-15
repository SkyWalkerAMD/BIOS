"""Original parser/constructors + original 3E700/3E424 + actual MP/Runtime/observer.
The outer App/Page/Frame containers, UEFI services and CPU maps remain explicit
fixtures. No raw control, opcode, button object or callback action is fabricated.
"""
from pathlib import Path
import ast,struct,json,hashlib,zipfile,re,time
HERE=Path(__file__).resolve().parent
f=HERE.parent/'management_live04/verify_observer_chain.py';tree=ast.parse(f.read_text());nodes=[]
for n in tree.body:
 if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='cases'for t in n.targets):break
 nodes.append(n)
g={'__file__':str(f),'__name__':'mp04_fixture_definitions'};exec(compile(ast.Module(nodes,type_ignores=[]),str(f),'exec'),g)
oldscope=g['scope'];pefile=g['pefile'];ns=g['ns'];TSE=g['TSE'];DATA=g['DATA'];Q=g['Q'];I=g['I'];ERR=g['ERR']
op=pefile.PE(str(HERE/'build/W890NativeObserver05.TESTONLY.dll'));ob=op.OPTIONAL_HEADER.ImageBase
os={e.name.decode():ob+e.address for e in op.DIRECTORY_ENTRY_EXPORT.symbols};sy={n:int(a,16)for n,a in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(HERE/'build/observer.map').read_text(),re.M)}
oldscope.update(OP=op,OB=ob,OS=os,SY=sy);g.update(OS=os,SY=sy)
with zipfile.ZipFile(HERE/'parser-snapshot.zip')as z:SN=json.loads(z.read('state.json'));POOL=z.read('pool.bin');IMAGE=z.read('tse-mapped.bin');FORMS=z.read('forms.pack')
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RIP
class Native(g['Composed']):
 def __init__(self,record=ns['ENABLED']):
  super().__init__();self.record=record;self.extra=ns['HOOK']+0x9000;self.w(self.extra,b'\xc3');self.w(self.extra+16,b'\xc3');self.w(self.bs+0x160,Q(self.extra));self.w(self.bs+0x168,Q(self.extra+16));self.w(self.st+8,I(0x20064));self.interesting.update([self.extra,self.extra+16])
  self.native_callbacks=[];self.callback_returns=[];self.is_native=False;self.rng_seed=0x7b if record is None else (record[32]+1)&255
 def hook(self,u,a,n,x):
  if hasattr(self,'extra')and a==self.extra:
   self.w(self.arg(0),self.r(self.arg(1),self.arg(2)));self.ret(0);return
  if hasattr(self,'extra')and a==self.extra+16:
   self.w(self.arg(0),bytes([self.arg(2)&255])*self.arg(1));self.ret(0);return
  if hasattr(self,'rng_seed')and a==self.hooks['rng']:
   # The original deterministic service fixture reused the prior salt; the
   # actual core correctly rejected that change. Give this explicit RNG model
   # a distinct stream for each new credential instead of weakening the core.
   self.calls.append('rng');self.w(self.arg(3),bytes((self.rng_seed+i)&255 for i in range(self.arg(2))));self.rng_seed=(self.rng_seed+17)&255;self.ret(self.rng_status);return
  if hasattr(self,'is_native')and self.is_native and a==TSE+0x3e4ed:
   self.native_callbacks.append({'action':self.arg(1),'question':self.arg(2)&65535,'type':self.arg(3)&255})
  if hasattr(self,'is_native')and self.is_native and a==TSE+0x3e4f0:self.callback_returns.append(self.u.reg_read(UC_X86_REG_RAX))
  return super().hook(u,a,n,x)
 def parsed(self):
  assert self.publish()==0
  assert next(p for p in g['packages'](self.package)if p[3]==2)==FORMS
  n=(len(POOL)+4095)&~4095;self.u.mem_map(SN['pool_base'],n);self.w(SN['pool_base'],POOL);self.descriptors.append((4,SN['pool_base'],n))
  # Import original parser's data after publication; preserve installed text.
  self.w(TSE+0x93000,IMAGE[0x93000:])
  for rva,p in [(0xafbc0,self.st),(0xafbc8,self.bs),(0xafbd8,self.rt),(0xafc38,self.hii),(0xafc18,self.strings)]:self.w(TSE+rva,Q(p))
  assert self.bind_real_host() in (0,6)
 def select(self,qid):
  button=next(x for x in SN['buttons']if x['question']==qid);self.control=button['object'];index=button['page_index'];self.buttons=SN['buttons']
  # Explicit outer native browser container fixture; the selected control and
  # raw descriptors/opcode pointers are imported without mutation.
  self.w(TSE+0xafdd0,Q(self.app));self.w(self.app+0x28,I(index)+I(len(SN['pages']))+Q(self.pa));self.w(self.pa+8*index,Q(self.page))
  self.w(self.page+0x20,Q(self.setup_hii));self.w(self.page+0x2a,struct.pack('<H',0x271d));self.w(self.page+0x30,struct.pack('<H',index));self.w(self.page+0x4c,I(1)+Q(self.fa));self.w(self.fa,Q(self.framep))
  self.w(self.framep+0x3c,I(3));self.w(self.framep+0x44,I(qid-0xffd0)+Q(self.ca));self.w(self.ca,b''.join(Q(x['object'])for x in SN['buttons']))
  assert self.q(self.control)==TSE+0x95620 and int.from_bytes(self.r(self.control+0x34,2),'little')==27
 def activate(self,qid=0xffd0):
  self.select(qid);self.is_native=True;self.inside=(TSE+0x3e700,[self.control+0x20,qid,0,1])
  r=self.run('no_native_loop',return_to=TSE+0xb8e1);self.is_native=False;return r
 def run(self,name,*args,return_to=None):
  self.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)))
  address=os[name]if name in os else ns['SYMBOLS'][name]
  sp=ns['STACK']+0x1ff008;stop=return_to or ns['STOP'];self.target_stop=stop
  self.w(sp,bytes(0x400));self.w(sp,Q(stop));self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
  for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
  try:self.u.emu_start(address,0,count=200000000)
  except Exception:
   rip=self.u.reg_read(UC_X86_REG_RIP);sp=self.u.reg_read(UC_X86_REG_RSP)
   print(json.dumps({'fault_rip':hex(rip),'rsp':hex(sp),'callbacks':self.native_callbacks,'callback_returns':[hex(x)for x in self.callback_returns],'nv_write_count':self.set_count,'keys_remaining':len(self.keys)}),flush=True);raise
  assert self.u.reg_read(UC_X86_REG_RIP)==stop,('instruction budget',name,hex(self.u.reg_read(UC_X86_REG_RIP)))
  return self.u.reg_read(UC_X86_REG_RAX)
def main():
 # Public local TEST FIXTURES, never production or hardware passwords.
 pa,pb=b'FixtureA8',b'FixtureB8';core=ns['core'];enabled=core.signed_record(password=pa);cases=[]
 def case(name,record,keys,qid,check,mutation=None):
  started=time.monotonic();v=Native(record);v.parsed();before=v.frame
  if mutation:mutation(v)
  if keys:v.queue(keys)
  assert v.activate(qid)==0
  assert v.native_callbacks and all(c['type']==10 and c['question']==qid for c in v.native_callbacks)
  assert v.frame==before and not v.keys and pa.decode()not in v.transcript and pb.decode()not in v.transcript
  assert check(v),(name,v.native_callbacks,v.callback_returns,v.set_count)
  row={'name':name,'status':'PASS','native_callbacks':v.native_callbacks,'callback_statuses':[hex(x)for x in v.callback_returns],'modeled_private_record_writes':v.set_count,'ui_restored':True,'seconds':round(time.monotonic()-started,3)};cases.append(row);print(json.dumps(row),flush=True)
  return v.record
 case('Original type27 action activation cancels through 3E700 and restores screen',enabled,'\x1b',0xffd0,lambda v:v.set_count==0 and v.record==enabled and v.callback_returns==[ERR(15)])
 stored=case('Original type27 set action enrolls absent private credential and original CHANGED completes',None,pa.decode()+'\r'+pa.decode()+'\r!',0xffd0,lambda v:v.set_count==1 and v.record==core.signed_record(password=pa,salt=v.record[32:64])and v.callback_returns==[0,0])
 changed=case('Original type27 set action authenticates current password and changes credential',stored,pa.decode()+'\r'+pb.decode()+'\r'+pb.decode()+'\r!',0xffd0,lambda v:v.set_count==1 and v.record==core.signed_record(password=pb,salt=v.record[32:64],generation=2)and v.callback_returns==[0,0])
 case('Changed password verified via original type27 verification action in a new session',changed,pb.decode()+'\r',0xffd2,lambda v:v.set_count==0 and v.record==changed and v.callback_returns==[0,0]and v.run('w890_provider_query',v.p)==1)
 case('Old password rejected after change via original type27 action',changed,pa.decode()+'\r!',0xffd2,lambda v:v.set_count==0 and v.record==changed and v.callback_returns==[ERR(15)])
 case('Original type27 clear action authenticates then stores exact DISABLED record',enabled,pa.decode()+'\ry!',0xffd1,lambda v:v.set_count==1 and v.record==core.signed_record(disabled=True,generation=2)and v.callback_returns==[0,0])
 case('Original type27 clear cancellation preserves existing record',enabled,pa.decode()+'\rn',0xffd1,lambda v:v.set_count==0 and v.record==enabled and v.callback_returns==[ERR(15)])
 def forged(v):
  b=SN['buttons'][0];v.w(b['object'],Q(TSE+0x93f90));v.w(b['object']+0x34,struct.pack('<H',10));v.w(b['descriptor']+0x14,struct.pack('<H',10))
 # Allow the test to exercise the native bridge, then demand denial before UI.
 original_select=Native.select
 def select_without_positive_assert(self,qid):
  b=next(x for x in SN['buttons']if x['question']==qid);saved=self.r(b['object'],8);ty=self.r(b['object']+0x34,2)
  self.w(b['object'],Q(TSE+0x95620));self.w(b['object']+0x34,struct.pack('<H',27));original_select(self,qid);self.w(b['object'],saved);self.w(b['object']+0x34,ty)
 Native.select=select_without_positive_assert
 case('Matching synthetic native type10 class and raw descriptor are rejected by observer05',enabled,'',0xffd0,lambda v:v.set_count==0 and v.record==enabled and v.callback_returns==[ERR(15)],forged)
 Native.select=original_select
 report={'status':'PASS','cases':cases,'case_count':len(cases),'original_native_code':['40D94','3CCF8','3B96C','68AE8','68B38','3E700','3E424','3E4ED','3E4F0'],'parser_snapshot_sha256':hashlib.sha256((HERE/'parser-snapshot.zip').read_bytes()).hexdigest(),'observer05_sha256':hashlib.sha256(bytes(op.__data__)).hexdigest(),'mp04_runtime02_sha256':g['component_sha256'],'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'remaining_models':['UEFI HII/variable/GOP/console/timer/RNG and memory-map/page-table services','Outer App/Page/Frame containers; three buttons/raw descriptors/opcodes are actual parser and constructors','BrowserLoop body outside native action activation','SHA/PBKDF/memcpy/memset independent Python oracles as inherited fixture, not a firmware crypto timing test'],'hardware_nv_writes':0,'flashable':False}
 (HERE/'native_chain_tests.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
