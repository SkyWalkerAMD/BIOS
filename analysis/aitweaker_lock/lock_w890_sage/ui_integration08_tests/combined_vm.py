"""Actual combined PE/private-loop VM over the explicit13-instance native data.

Only the UEFI/CPU/browser-body services are modelled. No no_identity,
no_observe, fp08, n05_check or ticket implementation is replaced by a boolean.
Frozen test mains are never called. Data import never modifies AMITSE .text.
"""
from pathlib import Path
import ctypes,hashlib,importlib.util,json,re,struct,sys,zipfile
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
spec=importlib.util.spec_from_file_location('ui08_frozen_navigation_definitions',B/'navigation05/verify_navigation.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
m=n.m;ns=n.ns;Q=n.Q;I=n.I;TSE=n.TSE;SETUP=n.SETUP;DATA=n.DATA
import pefile
from unicorn.x86_const import *

class Snapshot(ctypes.Structure):
 _fields_=[(x,ctypes.c_uint64)for x in ('session','native_base','application','page','hii','control','history')]+[
  (x,ctypes.c_uint32)for x in ('page_index','application_index','history_count','history_root','owner','proof','ifr_size')]+[
  ('form',ctypes.c_uint16),('formset',ctypes.c_uint8*16),('ifr',ctypes.c_uint8*127),
  ('catalog_generation',ctypes.c_uint64),('classification',ctypes.c_int32),('reserved_scope',ctypes.c_uint32)]

VTABLE={14:0x95680,1:0xa5520,2:0xa51f0,3:0xa5250,19:0xa5190,4:0xa5380,
 5:0xa5440,6:0x93f90,10:0x93f90,8:0x93ff0,11:0xa52c0,15:0xa53e0,13:0xa54c0,27:0x95620,28:0xa5320}
OS={};SY={};CANDIDATE={}

def sha(data):return hashlib.sha256(data).hexdigest()
def bind_candidate(directory=None):
 global OS,SY,CANDIDATE
 directory=Path(directory or B/'ui_integration08/build')
 dll=directory/'W890UI08.TESTONLY.dll';mapfile=directory/'navigation.map';callfile=directory/'consumer_windows.json'
 m.OP.close();m.OP=pefile.PE(str(dll));m.OB=m.OP.OPTIONAL_HEADER.ImageBase
 m.OS={e.name.decode():m.OB+e.address for e in m.OP.DIRECTORY_ENTRY_EXPORT.symbols}
 m.SY={k:int(v,16)for k,v in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',mapfile.read_text(),re.M)}
 n.OS=m.OS;n.SY=m.SY;ns['SYMBOLS']=m.SY;OS=m.OS;SY=m.SY
 n.CALLS=json.loads(callfile.read_text())
 for name in ('no_native_loop','no_identity','no_observe','no_scope_enter','no_scope_validate_cached',
  'no_catalog_generation','fp08_describe_page','fp08_describe_control','n05_check','n05_first','n05_fallback_main','ui08_snapshot_bytes'):
  assert name in OS or name in SY,name
 assert not any(k.startswith(('og08_test_','fp08_test_'))for k in OS)
 CANDIDATE={'path':str(dll.relative_to(R)),'sha256':sha(dll.read_bytes()),
  'map_sha256':sha(mapfile.read_bytes()),'consumer_windows_sha256':sha(callfile.read_bytes()),
  'export_count':len(OS),'snapshot_bytes_expected':ctypes.sizeof(Snapshot),'test_host_linked':False}
 return CANDIDATE

class VM(n.VM):
 def __init__(self):
  assert CANDIDATE,'bind_candidate first'
  super().__init__()
  self.export_trace=[];self.driver_trace=[];self.cached_trace=[];self.cached_pending=[]
  self.service_trace=[];self.protected_handlers_executed=[];self.notifications=[]
  self.raw_calls={};self.package_overrides={};self.exclusion_mutation=None
  self.snapshot_path=H/'parser13_snapshot.zip'
  with zipfile.ZipFile(self.snapshot_path)as z:
   self.snapshot=json.loads(z.read('state.json'))
   self.package_models={p['handle']:{**p,'data':z.read(p['member'])}for p in self.snapshot['packages']}
   assert self.snapshot['tse_base']==TSE
   for basekey,sizekey,member in [('pool_base','pool_bytes','pool.bin'),('static_base','static_bytes','static.bin')]:
    base=self.snapshot[basekey];size=self.snapshot[sizekey];data=z.read(member);assert len(data)==size
    extent=(size+4095)&~4095;self.u.mem_map(base,extent);self.w(base,data);self.descriptors.append((4,base,extent))
  assert self.package_models[self.setup_hii]['module']=='Setup'
  assert self.package_models[self.setup_hii]['data']==self.package
  self.native_rows=self.snapshot['pages'];self.row_by_index={p['index']:p for p in self.native_rows}
  self.main=next(p for p in self.native_rows if p['hii']==self.setup_hii and p['form']==0x2712)
  self.ai=next(p for p in self.native_rows if p['hii']==self.setup_hii and p['form']==0x2713)
  self.security=next(p for p in self.native_rows if p['hii']==self.setup_hii and p['form']==0x271d)
  self.selected_controls={};self.included_original_branches={}
  for rva,expect in [(0x41010,'0f8223010000'),(0x4112c,'0f86eefeffff')]:
   actual=self.r(TSE+rva,6).hex();assert actual==expect,(hex(rva),actual)
   self.included_original_branches[hex(rva)]=actual
  self.service_addresses=set(self.hooks.values())|set(self.oh.values())|{self.copyhook}

 def hook(self,u,address,size,opaque):
  if hasattr(self,'cached_pending'):
   # Observe real calls/returns without changing registers or control flow.
   for p in list(self.cached_pending):
    if address==p['return'] and u.reg_read(UC_X86_REG_RSP)==p['sp']+8:
     self.cached_pending.remove(p);p['return_value']=u.reg_read(UC_X86_REG_RAX)
     p['services']=self.service_trace[p.pop('service_start'):];self.cached_trace.append(p)
   if address==OS.get('no_scope_validate_cached',SY.get('no_scope_validate_cached')):
    sp=u.reg_read(UC_X86_REG_RSP);self.cached_pending.append({'return':self.q(sp),'sp':sp,'ticket':self.arg(0),
     'tpl':self.current_tpl,'service_start':len(self.service_trace)})
   if address in self.service_addresses:
    self.service_trace.append({'address':address,'tpl':self.current_tpl})
   if address==self.oh['raise']and self.arg(0)==16 and self.exclusion_mutation:
    fn=self.exclusion_mutation;self.exclusion_mutation=None;fn(self)
   for name in ('no_observe','no_identity','no_scope_enter','no_scope_validate_cached','fp08_describe_page','fp08_describe_control'):
    if address==OS.get(name,SY.get(name)):self.raw_calls[name]=self.raw_calls.get(name,0)+1
   if address in (SETUP+0x2250,):
    # No test needs to execute an actual password-management callback.
    qid=self.arg(2)&0xffff
    if qid in (0x271e,0x271f):raise AssertionError('password management handler must not run')
   if address in (self.oh['hiilist'],self.oh['export'],self.oh['driver']):
    name=next(k for k,v in self.oh.items()if v==address);self.uefi_calls.append('observer:'+name)
    if name=='hiilist':
     data=b''.join(Q(h)for h in sorted(self.package_models));cap=self.q(self.arg(3));self.w(self.arg(3),Q(len(data)))
     if cap<len(data):self.ret(ns['ERR'](5));return
     self.w(self.arg(4),data);self.ret(0);return
    if name=='export':
     h=self.arg(1);model=self.package_models.get(h);self.export_trace.append({'hii':h,'tpl':self.current_tpl})
     assert self.current_tpl==4,'HII export outside TPL_APPLICATION'
     if model is None:self.ret(ns['ERR'](14));return
     data=self.package if h==self.setup_hii else self.package_overrides.get(h,model['data'])
     cap=self.q(self.arg(2));self.w(self.arg(2),Q(len(data)))
     if cap<len(data):self.ret(ns['ERR'](5));return
     self.w(self.arg(3),data);self.ret(0);return
    h=self.arg(1);self.driver_trace.append(h)
    # Only Setup has a verified loaded-driver/ConfigAccess fixture. Foreign
    # FORMS identity never gives these objects a fictitious Setup owner.
    if h!=self.setup_hii:self.ret(ns['ERR'](14));return
    self.w(self.arg(2),Q(self.setup_handle));self.ret(0);return
  return super().hook(u,address,size,opaque)

 def pages(self):
  count=len(self.native_rows);self.page_list=[DATA+0x40000+i*0x80 for i in range(count)]
  self.pa=DATA+0x60000;self.w(self.app,bytes(96));self.w(self.app+0x28,I(self.main['index'])+I(count)+Q(self.pa))
  self.w(self.pa,b''.join(Q(p)for p in self.page_list))
  for p,row in zip(self.page_list,self.native_rows):
   self.w(p,bytes(104));self.w(p+0x20,Q(row['hii']));self.w(p+0x2a,struct.pack('<H',row['form']));self.w(p+0x30,struct.pack('<H',row['index']))
  for rva,value in self.snapshot['globals'].items():self.w(TSE+int(rva,16),Q(value))
  self.w(TSE+0xafddc,bytes(0x28));self.w(TSE+0xafdd0,Q(self.app))
  self.page=self.page_list[self.main['index']]

 def ready(self):
  super().ready();assert self.run('ui08_snapshot_bytes')==ctypes.sizeof(Snapshot)
  assert self.run('no_identity',self.idbuf)==1
  assert self.q(self.idbuf+16)==self.setup_hii
  assert self.q(self.idbuf+56)==TSE
  self.service_trace.clear();self.cached_trace.clear();self.export_trace.clear();self.driver_trace.clear();self.raw_calls.clear()

 def find_page(self,module,form=None):
  found=[p for p in self.native_rows if p['module']==module and (form is None or p['form']==form)]
  assert found,(module,form);return found[0]

 def set_current(self,row):
  """Explicit initial-state fixture. Not evidence of a native transition."""
  self.w(self.app+0x28,I(row['index']))

 def view(self):
  s=Snapshot.from_buffer_copy(self.r(self.obs,ctypes.sizeof(Snapshot)))
  return {k:getattr(s,k)for k in ('session','page','hii','control','form','page_index','application_index','owner','proof','catalog_generation','classification','ifr_size')}

 def prepare_menu(self,target):
  cookie=TSE+0x94758;self.w(cookie,I(8)+I(0)+struct.pack('<H',target['index']))
  current=self.page_list[self.index()];p=DATA+0x80000;frame=p+0x100;fa=p+0x180;ca=p+0x188
  self.w(p,bytes(0x100));self.w(frame,bytes(0x80));self.w(current+0x4c,I(1)+Q(fa));self.w(fa,Q(frame))
  self.w(frame+0x20,I(4));self.w(frame+0x3c,I(1));self.w(frame+0x48,Q(ca));self.w(ca,Q(p))
  self.w(p,Q(TSE+0x95680));self.w(p+0x10,Q(frame)+Q(cookie));return self.app,p,cookie

 def prepare_control(self,row,question=None,opcode=None):
  found=[c for c in row['controls']if c['ifr'] and c['type']in VTABLE and
   (question is None or c['question']==question)and(opcode is None or bytes.fromhex(c['ifr'])[0]==opcode)]
  assert (len(found)==1 if question is not None else bool(found)),(row['module'],row['form'],question,len(found))
  c=found[0];p=DATA+0x82000;frame=p+0x100;fa=p+0x180;ca=p+0x188
  self.w(p,bytes(0x100));self.w(frame,bytes(0x80));self.w(p,Q(TSE+VTABLE[c['type']]))
  self.w(p+0x20,bytes.fromhex(c['raw_hex']));self.w(p+0x10,Q(frame))
  self.w(self.page_list[row['index']]+0x4c,I(1)+Q(fa));self.w(fa,Q(frame));self.w(frame+0x20,I(1))
  self.w(frame+0x3c,I(1));self.w(frame+0x48,Q(ca));self.w(ca,Q(p))
  self.selected_controls[p]={'module':row['module'],'page_index':row['index'],'form':row['form'],
   'raw':c['raw'],'type':c['type'],'question':c['question'],'ifr':c['ifr']}
  return p

 def main_ok(self):
  p=self.hist();index=self.main['index']
  return self.index()==index and self.used()==1 and int.from_bytes(self.r(TSE+0xafddc,4),'little')==index and self.r(p,32)==Q(self.setup_hii)+I(0x2712)+bytes(20)

 def actual_identity_summary(self):
  return {'original_AMITSE_sha256':self.snapshot['original_AMITSE_sha256'],
   'original_Setup_sha256':sha((B/'navigation/modules/Setup.efi').read_bytes()),
   'original_parser_branches_unmodified':self.included_original_branches,
   'actual_component_calls':self.raw_calls,'cached_calls':self.cached_trace,
   'hii_export_count':len(self.export_trace),'exports_only_at_application':all(x['tpl']==4 for x in self.export_trace),
   'settings_writes':self.set_count}
