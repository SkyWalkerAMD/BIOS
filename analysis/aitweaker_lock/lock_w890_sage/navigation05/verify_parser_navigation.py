"""Composed actual parser output, native history, observer and Main fallback.

The immutable sibling snapshot was produced by actual original parser/control
constructors. APP/PAGE/FRAME outer containers remain explicit test fixtures;
this is not execution of a complete original GUI or physical owner evidence.
"""
import zipfile,json,hashlib,struct,time
from pathlib import Path
from verify_navigation import VM,H,B,m,ns,TSE,DATA,Q,I,OS,IMAGE_SHA
Z=B/'integration05/parser-snapshot.zip'
ZS=hashlib.sha256(Z.read_bytes()).hexdigest();assert ZS=='4b65d173ec3a9d4a3e8d02aa8d3becbf9ee61abbb688584cc96e18c93f5fdfbb'
with zipfile.ZipFile(Z)as z:
 S=json.loads(z.read('state.json'));POOL=z.read('pool.bin');MAPPED=z.read('tse-mapped.bin');FORMS=z.read('forms.pack')
TOKENS=[struct.unpack_from('<H',FORMS,3938+15*i+j)[0]for i in range(3)for j in [2,4]]

class ParserVM(VM):
 def hook(self,u,address,size,opaque):
  if hasattr(self,'oh')and address==self.oh['publisher']and self.publish_mode=='parser':
   ticket=self.arg(1);ta=DATA+0x28000;ha=ta+32;self.w(ta,struct.pack('<6H',*TOKENS));self.w(ha,hashlib.sha256(FORMS).digest())
   self.package=m.SETGUID+I(24+len(FORMS))+FORMS+bytes.fromhex('040000df')
   self.script=[(self.notify_callback,[2,0,0,self.setup_hii,2]),(OS['no_publication_validate'],[0,ticket]),(self.notify_callback,[2,0,0,self.setup_hii,8]),(OS['no_publication_validate'],[0,ticket]),(OS['no_publication_finished'],[0,ticket,ta,ha])]
   self.script_sp=u.reg_read(ns['UC_X86_REG_RSP']);self.start_script();return
  return super().hook(u,address,size,opaque)
 def ready_parser(self):
  n=(len(POOL)+4095)&~4095;self.u.mem_map(S['pool_base'],n);self.w(S['pool_base'],POOL);self.descriptors.append((4,S['pool_base'],n))
  assert self.initialize()==0 and self.run('n05_bind')==0 and self.packet()==0;self.apply();self.publish_mode='parser'
  assert self.run('no_native_entry',self.tse_handle,self.st)==0 and self.script_values==[0,1,0,1,1]
  assert self.bind_real_host()==0
  for rva in [0xbaaf0,0xbabc0,0xbab08,0xbaae8]:self.w(TSE+rva,MAPPED[rva:rva+8])
  # Do not overwrite original executable bytes, patched windows, native
  # service globals, or modeled UEFI pointers with another VM's addresses.
  self.page_list=[DATA+0x40000+i*0x80 for i in range(len(S['pages']))];self.pa=DATA+0x60000
  self.main=next(p['index']for p in S['pages']if p['hii']==self.setup_hii and p['form']==0x2712)
  self.ai=next(p['index']for p in S['pages']if p['hii']==self.setup_hii and p['form']==0x2713)
  self.security=next(p['index']for p in S['pages']if p['hii']==self.setup_hii and p['form']==0x271d)
  self.w(self.app,bytes(96));self.w(self.app+0x28,I(self.ai)+I(len(S['pages']))+Q(self.pa));self.w(self.pa,b''.join(Q(p)for p in self.page_list));self.w(TSE+0xafdd0,Q(self.app))
  for page,raw in zip(self.page_list,S['pages']):
   self.w(page,bytes(104));self.w(page+0x20,Q(raw['hii']));self.w(page+0x2a,struct.pack('<H',raw['form']));self.w(page+0x30,struct.pack('<H',raw['index']))
  self.w(TSE+0xafddc,bytes(0x28));self.free_trace.clear()

started=time.time();v=ParserVM();v.ready_parser();v.queue('\x1b')
v.loop([(TSE+0x1b928,[0,v.ai]),('n05_first',[]),(TSE+0x1b928,[v.main,v.security]),(TSE+0x1b814,[v.security,DATA+0x29000,DATA+0x29008])])
p=v.hist();assert v.sequence_values[1]==2 and v.sequence_values[-1]==0 and v.index()==v.main and v.used()==2
assert v.r(p,32)==Q(v.setup_hii)+I(0x2712)+bytes(20)
assert int.from_bytes(v.r(DATA+0x29000,2),'little')==v.main and p not in v.free_trace and not v.set_count
out={'status':'PASS','checks':1,'seconds':round(time.time()-started,3),'component_sha256':IMAGE_SHA,'parser_zip_sha256':ZS,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'parser_raw_pages':len(S['pages']),'indices':{'main':v.main,'ai':v.ai,'security':v.security},'history_requested_bytes':v.alloc_trace[0][1],'native_scope':'original 1B928 allocation/update and 1B814 parent lookup; compiled native Loop Begin/End, observer HII notifications and independent publication digest, real Runtime02 masked UI Escape, compiled Main transfer','explicit_models':['UEFI services and CPU map','native App/Page/Frame outer containers','BrowserLoop body surrounding the selected actual functions','SHA/PBKDF/RDSEED oracles'],'not_proved':['Full original Page/Frame construction or UI rendering','Physical installation or native hardware lifetime','All BIOS entry/side-effect paths']}
(H/'build/parser_navigation_tests.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
