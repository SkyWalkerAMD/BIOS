"""Canonical static PE: real bootstrap -> MP/observer -> original full parser.
UEFI services and DXE dispatch/entry body are explicit fixtures. The original
SPF initializers, publisher, ownership, identity and parser execute native code.
No owner bool/session is injected. No hardware or firmware file is written.
"""
from pathlib import Path
import ast,hashlib,json,struct,re,sys,time,inspect,textwrap
H=Path(__file__).resolve().parent;B=H.parent
f=B/'management_live04/verify_observer_chain.py';nodes=[]
for n in ast.parse(f.read_text()).body:
 if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='cases'for t in n.targets):break
 nodes.append(n)
g={'__file__':str(f),'__name__':'static_fixture_dependencies'};exec(compile(ast.Module(nodes,type_ignores=[]),str(f),'exec'),g)
ns=g['ns'];scope=g['scope'];pefile=g['pefile'];Q=g['Q'];I=g['I'];ERR=g['ERR'];TSE=0x2000000;SETUP=0x4000000;DATA=g['DATA']
latest=json.loads((B/'packaging05/latest_aggregate.json').read_text());candidate=Path(latest['pe']).read_bytes();assert hashlib.sha256(candidate).hexdigest()==latest['sha256']
composition=json.loads(Path(latest['report']).read_text());build=json.loads((H/'aggregate_build/build.json').read_text())
assert build['sha256']==composition['extension_sha256'],(build['sha256'],composition['extension_sha256'])
p=pefile.PE(data=candidate);p.relocate_image(TSE);size=p.OPTIONAL_HEADER.SizeOfImage
symbols={k:TSE+composition['extension_rva']+v for k,v in build['map_symbols'].items()};symbols.update({k:TSE+v for k,v in composition['exports'].items()})
ns.update(PE=p,BASE=TSE,SYMBOLS=symbols)
scope.update(OP=p,OB=TSE,OS=symbols,SY=symbols,SETUP=SETUP,WINDOWS=[])
g.update(PE=p,BASE=TSE,symbols=symbols,OS=symbols,SY=symbols,SETUP=SETUP)
# Construct the same explicitly modeled service fixture around a single merged
# image, instead of the older separately mapped observer/runtime/original TSE.
fixture_source=(B/'native_observer04/verify_observer.py').read_text();src=ast.get_source_segment(fixture_source,next(x for x in ast.parse(fixture_source).body if isinstance(x,ast.ClassDef)and x.name=='VM'))
src=src.replace('self.u.mem_map(OB,(OP.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.w(OB,OP.get_memory_mapped_image())','')
src=src.replace("(3,OB,(OP.OPTIONAL_HEADER.SizeOfImage+4095)&~4095),",'')
src=src.replace("[(TSE,'AMITSE'),(SETUP,'Setup')]","[(SETUP,'Setup')]")
src=src.replace('(self.li_tse,TSE,0xde000,self.fv_tse,TSEGUID)','(self.li_tse,TSE,ns[\'PE\'].OPTIONAL_HEADER.SizeOfImage,self.fv_tse,TSEGUID)')
exec(compile(src,'explicit_static_fixture.py','exec'),scope)
g['Composed'].__bases__=(scope['VM'],)
from unicorn.x86_const import *
sys.path.insert(0,str(H));import parser_lab
class Static(g['Composed']):
 def __init__(self,record=None):
  super().__init__();self.record=record;self.start_events=[];self.native_writes=[];self.running_parser=False;self.livealloc={}
  self.w(self.st+8,I(0x20064))
  self.u.mem_map(self.pool+0x2000000,0x6000000);self.descriptors=[(ty,a,0x8000000 if a==self.pool else n)for ty,a,n in self.descriptors]
  self.extra=ns['HOOK']+0x9000;self.w(self.extra,b'\xc3'*64);self.w(self.bs+0x160,Q(self.extra));self.w(self.bs+0x168,Q(self.extra+16));self.w(self.bs+0x60,Q(self.extra+32));self.w(self.input+16,Q(self.extra+48))
  self.interesting.update([self.extra,self.extra+16,self.extra+32,TSE+0x6480,TSE+0x40d94])
  # Actual original FV bytes, with original initializer functions modifying it.
  seed=parser_lab.VM(False,hii=self.setup_hii);self.raw=0x18000000;raw=bytes(seed.u.mem_read(seed.static,0xf245c));self.u.mem_map(self.raw,0xf3000);self.w(self.raw,raw);self.descriptors.append((4,self.raw,0xf3000))
  self.w(TSE+0xbabc0,Q(self.raw));self.w(TSE+0xafc38,Q(self.hii));self.w(TSE+0xafc18,Q(self.strings))
  self.original_string={int(k):v for k,v in g['ss']['strings'].items()}
  self.init_trace=[];self.init_returns={};self.init_targets={symbols[k]:k for k in ['no_initialize','no_prepare','w890_runtime_bind','mp_bind','n05_bind','n05_bridges_bind','ws05_prepare']};self.interesting.update(self.init_targets)
 def hook(self,u,a,n,x):
  if hasattr(self,'extra'):
   if hasattr(self,'init_targets')and a in self.init_targets:
    self.init_returns[self.q(self.u.reg_read(UC_X86_REG_RSP))]=self.init_targets[a];self.interesting.update(self.init_returns)
   if hasattr(self,'init_returns')and a in self.init_returns:self.init_trace.append([self.init_returns.pop(a),hex(self.u.reg_read(UC_X86_REG_RAX))])
   if a==TSE+0x6480:
    self.start_events.append('DXE init body boundary modeled; original 6480 byte identity remains checked');self.ret(0);return
   if a==self.extra:self.w(self.arg(0),self.r(self.arg(1),self.arg(2)));self.ret(0);return
   if a==self.extra+16:self.w(self.arg(0),bytes([self.arg(2)&255])*self.arg(1));self.ret(0);return
   if a==self.extra+32:raise AssertionError('unexpected wait in preparse test')
   if a==self.hooks['allocate']:
    n=self.arg(1);assert 0<=n<=0x8000000,('allocation size',n);p=self.pool_next;self.pool_next=(p+max(1,n)+15)&~15;assert self.pool_next<self.pool+0x8000000;self.livealloc[p]=n;self.w(self.arg(2),Q(p));self.ret(0);return
   if a==self.hooks['free']:
    ptr=self.arg(0)
    if ptr in self.livealloc:del self.livealloc[ptr]
    self.ret(0);return
   if a==self.hooks['locate']and self.r(self.arg(0),16)==g['G']('0fd96974-23aa-4cdc-b9cb-98d17750322a'):
    self.w(self.arg(2),Q(self.strings));self.ret(0);return
   if a==self.oh['hiilist']:
    cap=self.q(self.arg(3));self.w(self.arg(3),Q(8));out=self.arg(4)
    if not out or cap<8:self.ret(ERR(5))
    else:self.w(out,Q(self.setup_hii));self.ret(0)
    return
   if a==self.oh['export']:
    cap=self.q(self.arg(2));self.w(self.arg(2),Q(len(self.package)))
    if not self.arg(3)or cap<len(self.package):self.ret(ERR(5))
    else:self.w(self.arg(3),self.package);self.ret(0)
    return
   if a==self.oh['handles']and self.r(self.arg(1),16)!=g['G']('5b1b31a1-9562-11d2-8e3f-00a0c969723b'):self.ret(ERR(14));return
   if a==self.mh['string']and self.arg(3)not in self.new_strings:
    text=self.original_string.get(self.arg(3));cap=self.q(self.arg(5))
    if text is None:self.ret(ERR(14));return
    data=(text+'\0').encode('utf-16le');self.w(self.arg(5),Q(len(data)))
    if cap<len(data):self.ret(ERR(5))
    else:self.w(self.arg(4),data);self.ret(0)
    return
   if a==self.hooks['get']and self.r(self.arg(1),16)!=ns['GUID']:self.ret(ERR(14));return
   if a==self.hooks['set']and self.r(self.arg(1),16)!=ns['GUID']:
    name=g['c16'](self,self.arg(0)).decode('utf-16le');assert self.running_parser and name in ['DynamicPageCount','DynamicPageGroupCount','DynamicPageGroupClass'];assert self.arg(2)==2;self.native_writes.append(name);self.ret(0);return
  return super().hook(u,a,n,x)
 def run(self,name,*args,return_to=None):
  address=symbols[name]if isinstance(name,str)else name
  self.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)));sp=ns['STACK']+0x1ff008;stop=return_to or ns['STOP'];self.target_stop=stop
  self.w(sp,bytes(0x400));self.w(sp,Q(stop));self.u.reg_write(UC_X86_REG_RSP,sp)
  for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
  for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
  try:self.u.emu_start(address,0,count=300000000)
  except Exception:print(json.dumps({'fault':name,'rip':hex(self.u.reg_read(UC_X86_REG_RIP)),'rcx':hex(self.u.reg_read(UC_X86_REG_RCX)),'rax':hex(self.u.reg_read(UC_X86_REG_RAX)),'bab18':hex(self.q(TSE+0xbab18)),'bab10':hex(self.q(TSE+0xbab10)),'hii_updates':self.hii_updates,'events':self.start_events}),flush=True);raise
  assert self.u.reg_read(UC_X86_REG_RIP)==stop,(name,hex(self.u.reg_read(UC_X86_REG_RIP)))
  return self.u.reg_read(UC_X86_REG_RAX)
 def begin(self):
  r=self.run('i05_entry',self.tse_handle,self.st);assert r==0,('entry',hex(r))
  for rva in [0x19cf8,0x1b7dc,0x1c17c]:self.run(TSE+rva)
 def parse(self,caller=0x18e46):
  self.running_parser=True;r=self.run(TSE+0x40d94,return_to=TSE+caller);self.running_parser=False;return r
def main():
 v=Static();v.begin();print('ENTRY_AND_NATIVE_STATIC_INITIALIZERS_PASS',flush=True)
 r=v.run('i05_services');print('SERVICES',hex(r),v.init_trace,flush=True);assert r==0
 assert v.q(v.config+16)==symbols['mp_callback']
 r=v.parse();print('PARSE',hex(r),'updates',v.hii_updates,'new_strings',len(v.new_strings),'pool',v.pool_next-v.pool,flush=True);assert r==0
 assert v.hii_updates==1 and len(v.new_strings)==6 and v.set_count==0 and len(v.native_writes)==3
 table=v.q(TSE+0xbaaf0);blob=v.q(TSE+0xbabc0);cb=v.q(TSE+0xbab08);pages=int.from_bytes(v.r(table,4),'little');buttons=[]
 for i in range(pages):
  pd=blob+int.from_bytes(v.r(table+4+4*i,4),'little')
  if v.q(pd)!=v.setup_hii:continue
  for j in range(int.from_bytes(v.r(pd+28,4),'little')):
   cd=cb+int.from_bytes(v.r(pd+32+4*j,4),'little');op=v.q(cd+40)
   if v.r(op,2)!=b'\x0c\x0f':continue
   q=int.from_bytes(v.r(op+6,2),'little')
   if 0xffd0<=q<=0xffd2:buttons.append((q,int.from_bytes(v.r(cd+20,2),'little')))
 assert buttons==[(0xffd0,27),(0xffd1,27),(0xffd2,27)],buttons
 result={'status':'PASS_STATIC_BOOTSTRAP_PREPARSE_NATIVE_PARSER','candidate':latest,'component_sha256':build['sha256'],'native_pages':pages,'buttons':buttons,'hii_updates':v.hii_updates,'notifications':v.notification_results,'private_nv_writes':v.set_count,'volatile_parser_writes':v.native_writes,'scope':__doc__,'remaining_models':['DXE6480 dispatcher body','UEFI HII/string/CPU/memory/variable services','SHA/libc oracles'],'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
 (H/'static_chain_tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
