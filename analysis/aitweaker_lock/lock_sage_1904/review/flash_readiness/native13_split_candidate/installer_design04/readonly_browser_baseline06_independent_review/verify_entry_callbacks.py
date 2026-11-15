"""Independently execute the exact whole baseline06 PE, with modeled UEFI.

No firmware code is executed on the host. Inventory is not replaced: its real
first missing-method check refuses the synthetic firmware environment. Callback
tests pass deliberately unmapped input/output pointers and execute real bytes.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;SRC=HERE.parent/'readonly_browser_baseline06'
ROOT=next(p for p in HERE.parents if(p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,unicorn as U
from unicorn import x86_const as R
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
Q=lambda n:struct.pack('<Q',n)
D=lambda n:struct.pack('<I',n)
ERR=lambda n:(1<<63)|n
BASE=0x140000000;DATA=0x50000000;STACK=0x70000000
ST=DATA;BS=DATA+0x1000;RT=DATA+0x2000;OUT=DATA+0x3000;IN=DATA+0x4000
STOP=DATA+0x10000;TRAMP=STOP+0x2000
F={n:STOP+0x100+16*i for i,n in enumerate(['raise','restore','create','create_ex','watchdog','attribute','clear','output','input','stall'])}

class VM:
 def __init__(self,efi,symbols,ending=None,failed=None,missing=None,fail_handle=False,tpl=4):
  self.symbols=symbols;self.ending=ending;self.failed=failed;self.fail_handle=fail_handle;self.tpl=tpl
  self.callback=0;self.end_fired=False;self.calls=[];self.after_end=[];self.result=None;self.stop_on_input=True
  self.u=U.Uc(U.UC_ARCH_X86,U.UC_MODE_64);p=pefile.PE(str(efi));p.relocate_image(BASE)
  self.image_size=(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
  self.u.mem_map(BASE,self.image_size);self.u.mem_write(BASE,p.get_memory_mapped_image())
  self.u.mem_map(DATA,0x20000);self.u.mem_map(STACK,0x20000)
  for off,val in [(0x60,BS),(0x58,RT),(0x40,OUT),(0x30,IN)]:self.u.mem_write(ST+off,Q(val))
  for n,off in [('raise',0x18),('restore',0x20),('create',0x50),('create_ex',0x170),('watchdog',0x100),('stall',0xf8)]:self.u.mem_write(BS+off,Q(0 if n==missing else F[n]))
  for n,off in [('attribute',0x28),('clear',0x30),('output',8)]:self.u.mem_write(OUT+off,Q(0 if n==missing else F[n]))
  self.u.mem_write(IN+8,Q(F['input']))
  self.u.hook_add(U.UC_HOOK_CODE,self.code);self.u.hook_add(U.UC_HOOK_MEM_INVALID,self.invalid)
 def u32(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def u64(self,a):return struct.unpack('<Q',self.u.mem_read(a,8))[0]
 def invalid(self,u,access,addr,size,value,ctx):raise AssertionError(('Unexpected unmapped access',access,hex(addr),size,hex(u.reg_read(R.UC_X86_REG_RIP))))
 def arg(self,i):return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i]) if i<4 else self.u64(self.u.reg_read(R.UC_X86_REG_RSP)+0x28+8*(i-4))
 def ret(self,v):
  sp=self.u.reg_read(R.UC_X86_REG_RSP);self.u.reg_write(R.UC_X86_REG_RAX,v);self.u.reg_write(R.UC_X86_REG_RIP,self.u64(sp));self.u.reg_write(R.UC_X86_REG_RSP,sp+8)
 def end_return(self,status):
  assert self.callback;self.end_fired=True
  raw=b'\x48\x83\xec\x28\x48\xb9'+Q(0xdead0000)+b'\x31\xd2\x48\xb8'+Q(self.callback)+b'\xff\xd0\x48\xb8'+Q(status)+b'\x48\x83\xc4\x28\xc3'
  self.u.mem_write(TRAMP,raw);self.u.reg_write(R.UC_X86_REG_RIP,TRAMP)
 def code(self,u,address,size,ctx):
  hold=self.u32(self.symbols['app_hold_reason'])
  if hold:self.result=('hold',hold);u.emu_stop();return
  if address==STOP:self.result=('return',u.reg_read(R.UC_X86_REG_RAX));u.emu_stop();return
  n=next((k for k,v in F.items() if v==address),None)
  if n is None:return
  self.calls.append(n)
  if self.end_fired:self.after_end.append(n)
  status=ERR(7) if self.failed==n else 0
  if n=='raise':assert self.arg(0)==31;status=self.tpl
  if n=='restore':assert self.arg(0)==4;self.tpl=4
  if n in ['create','create_ex']:
   self.callback=self.arg(2);self.u.mem_write(self.arg(4 if n=='create' else 5),Q(0 if status and not self.fail_handle else 0xdead0000))
  if self.ending==n:self.end_return(status);return
  if n=='input' and self.stop_on_input:self.result=('refused_menu',0);u.emu_stop();return
  self.ret(status)
 def call(self,name,*args):
  self.result=None;sp=STACK+0x1fe08;self.u.mem_write(sp,Q(STOP)+bytes(0x100));self.u.reg_write(R.UC_X86_REG_RSP,sp)
  for i,arg in enumerate(args):
   if i<4:self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i],arg)
   else:self.u.mem_write(sp+0x28+8*(i-4),Q(arg))
  self.u.emu_start(self.symbols[name],0,count=2000000);assert self.result is not None;return self.result

def main():
 assert len(sys.argv)==2 and re.fullmatch('[a-f0-9]{64}',sys.argv[1]);expected=sys.argv[1]
 efi=SRC/'build/SageNative13BrowserBaseline06.efi';bp=SRC/'build/build.json';mp=SRC/'build/app.map'
 assert sha(efi)==expected;build=json.loads(bp.read_text());assert build['efi_sha256']==expected
 for row in build['sources']:assert sha(SRC/row['path'])==row['sha256'],row['path']
 for name,digest in build['objects'].items():assert sha(SRC/'build'/name)==digest,name
 dest=HERE/('whole_app_edges_'+expected[:16]);dest.mkdir(exist_ok=True)
 for p in [efi,bp,mp,Path(__file__)]: (dest/p.name).write_bytes(p.read_bytes())
 symbols={n:int(a,16) for n,a in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})',mp.read_text(),re.M)}
 cases=[]
 for event in ['create','create_ex','watchdog','attribute','clear','output','input']:
  for fail in [False,True]:
   v=VM(efi,symbols,ending=event,failed=event if fail else None);r=v.call('app_main',0x12345000,ST)
   assert r==('hold',0xb606e001) and not v.after_end
   cases.append({'case':event+' ending with '+('error'if fail else 'success'),'result':r,'firmware_calls':v.calls,'calls_after_ending':v.after_end})
 for label,kw,expect in [
  ('create failure no handle',{'failed':'create'},('hold',0xb606e00a)),
  ('create failure nonzero handle',{'failed':'create','fail_handle':True},('hold',0xb606e00a)),
  ('create_ex failure after registration',{'failed':'create_ex'},('hold',0xb606e00b)),
  ('watchdog missing',{'missing':'watchdog'},('hold',0xb606e009)),
  ('watchdog failure',{'failed':'watchdog'},('hold',0xb606e00c)),
  ('TPL method absent',{'missing':'raise'},('hold',0xb606e002)),
  ('normal initial TPL 4 then actual inventory refusal',{},('refused_menu',0)),
 ]:
  v=VM(efi,symbols,**kw);r=v.call('app_main',0x12345000,ST);assert r==expect,(label,r)
  cases.append({'case':label,'result':r,'firmware_calls':v.calls})
 for tpl in [8,16,31]:
  v=VM(efi,symbols,tpl=tpl);r=v.call('app_main',0x12345000,ST)
  assert r==('hold',0xb606e003) and v.calls==['raise'];cases.append({'case':'entry TPL '+str(tpl),'result':r,'firmware_calls':v.calls})
 # Unmapped arguments prove these callbacks neither dereference inputs nor
 # touch output storage. All modifications must be their private bounded log.
 for ended in [0,1]:
  for name,kind,args in [
   ('baseline_extract',1,[0x800000001,0x800010001,0x800020001,0x800030001]),
   ('baseline_route',2,[0x800000001,0x800010001,0x800020001]),
   ('baseline_callback',3,[0x800000001,0x123456789abcdef0,0xabcd,0xef,0x800020001,0x800030001]),
  ]:
   v=VM(efi,symbols);v.u.mem_write(symbols['app_ended'],D(ended));before=bytes(v.u.mem_read(BASE,v.image_size))
   r=v.call(name,*args);assert r==('return',ERR(15 if ended else 3)) and not v.calls
   assert v.u32(symbols['call_count'])==1
   row=bytes(v.u.mem_read(symbols['calls'],24));action,qid,typ,k,status=struct.unpack('<QHBB4xQ',row)
   assert (action,qid,typ,k,status)==(args[1]if kind==3 else 0,args[2]if kind==3 else 0,args[3]if kind==3 else 0,kind,r[1])
   after=bytes(v.u.mem_read(BASE,v.image_size));allowed=[(symbols['calls']-BASE,symbols['calls']-BASE+24),(symbols['call_count']-BASE,symbols['call_count']-BASE+4)]
   assert all(any(a<=i<b for a,b in allowed) for i,(x,y)in enumerate(zip(before,after))if x!=y)
   cases.append({'case':name+' with unmapped pointers and ended='+str(ended),'result':r,'firmware_calls':v.calls,'output_pointer_accesses':0,'only_owned_log_modified':True})
 v=VM(efi,symbols)
 for i in range(65):assert v.call('baseline_callback',0x800000001,i,0x8000+i,0xef,0x800020001,0x800030001)==('return',ERR(3))
 assert v.u32(symbols['call_count'])==64 and v.u32(symbols['call_overflow'])==1 and not v.calls
 for i in range(64):assert v.u64(symbols['calls']+i*24)==i
 cases.append({'case':'65 callbacks retain exactly first 64 bounded records, overflow flagged','firmware_calls':v.calls,'records':64,'overflow':1})
 assert sha(efi)==expected and sha(bp)==sha(dest/'build.json') and sha(mp)==sha(dest/'app.map')
 report={'status':'PASS_INDEPENDENT_EXACT_PE_ENTRY_CALLBACK_MATRIX','efi_sha256':expected,'build_sha256':sha(bp),'map_sha256':sha(mp),'test_source_sha256':sha(Path(__file__)),'cases':len(cases),'records':cases,'all_sources_and_objects_verified':True,'recompiled_or_relinked_candidate':False,'limitations':['Only actual application PE instructions execute in Unicorn; UEFI service behavior/event delivery/TPL values are explicit models.','Original inventory code refuses the model due missing map/discovery methods; positive hardware identity is not synthesized.','No actual ASUS SendForm is executed in this matrix.','No claim of zero OEM variable writes or successful hardware UI; rejecting lifecycle callbacks can alter OEM behavior.','Entry ending callback is actual full app code; this does not substitute for transport and browser-invocation boundary suites.']}
 out=dest/'result.json';out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'cases':len(cases),'path':str(out),'sha256':sha(out)}))

if __name__=='__main__':main()
