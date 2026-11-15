"""Execute the actual compiled PE, real SHA/parser/classifier, explicit HII fixture.
Native containers and private observer roots are isolated host models. No BIOS,
callback handler, password operation or firmware write is executed.
"""
from pathlib import Path
import ctypes as C,json,struct,uuid,hashlib,sys,time,collections
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'));import pefile
class ID(C.Structure):
 _fields_=[(x,C.c_uint64)for x in('st','database','hii','setup_driver','tse_driver','config','setup_base','tse_base','setup_size','tse_size','epoch')]+[(x,C.c_uint32)for x in('loop_depth','send_depth','fault','ended')]
class Range(C.Structure):_fields_=[('start',C.c_uint64),('bytes',C.c_uint64),('access',C.c_uint32),('reserved',C.c_uint32)]
class View(C.Structure):
 _fields_=[('revision',C.c_uint32),('size',C.c_uint32)]+[(x,C.c_uint64)for x in('visit','epoch','catalog_generation','native_base','application','page','raw_page','hii','control')]+[(x,C.c_uint32)for x in('page_index','application_index','owner')]+[('classification',C.c_int32)]+[(x,C.c_uint32)for x in('review_flags','form_offset','ifr_offset','ifr_size')]+[('form',C.c_uint16),('native_type',C.c_uint16),('formset',C.c_uint8*16),('package_guid',C.c_uint8*16),('hash',C.c_uint8*32),('ifr',C.c_uint8*127)]
lib=C.CDLL(str(H/'build/W890ForeignPage08.TESTONLY.dll'))
lib.fp08_test_bind.argtypes=[C.POINTER(ID),C.c_uint64,C.c_uint64,C.c_void_p,C.c_void_p,C.c_uint64,C.POINTER(Range),C.c_uint32]
lib.fp08_test_mode.argtypes=[C.c_uint32,C.c_uint64,C.c_uint64,C.c_uint32,C.c_uint64]
lib.fp08_describe_page.argtypes=[C.c_uint64,C.c_uint32,C.POINTER(View)]
lib.fp08_describe_control.argtypes=[C.c_uint64,C.c_uint64,C.POINTER(View)]
assert lib.fp08_view_bytes()==C.sizeof(View) and lib.fp08_test_identity_bytes()==C.sizeof(ID)
catalog=json.loads((H/'scope_catalog.json').read_text())['packages'];byname={p['name']:p for p in catalog}
source_inputs=json.loads((B/'callback_shapes07/inputs.json').read_text())
bound_desc={(x['form'],x['qid']):x['bounded_native_descriptor_bindings'][0]for x in source_inputs['questions']}
Q=lambda x:struct.pack('<Q',x);D=lambda x:struct.pack('<I',x);W=lambda x:struct.pack('<H',x)
VT={1:0xa5520,2:0xa51f0,3:0xa5250,19:0xa5190,6:0x93f90,11:0xa52c0,27:0x95620,4:0xa5380,15:0xa53e0}
setup_hii=0x555100;foreign_hii=0x555200
def record_form(p,f):return next(x for x in p['forms']if x['form']==f)

class Fixture:
 def __init__(self,p,f,q=None,forms_override=None,package_override=None,hii=None,setup_identity=None):
  self.tse_buffer=C.create_string_buffer(0xdf000);self.tse=(C.addressof(self.tse_buffer)+4095)&~4095
  self.arena=C.create_string_buffer(0x10000);self.base=C.addressof(self.arena)
  self.app=self.base+0x1000;self.pages=self.base+0x1100;self.page=self.base+0x1200;self.table=self.base+0x1400
  self.blob=self.base+0x2000;self.raw=self.blob+0x100;self.cb=self.base+0x3000;self.desc=self.cb+0x100
  self.control=self.base+0x4000;self.frame=self.base+0x5000;self.fa=self.base+0x5100;self.ca=self.base+0x5200;self.op=self.base+0x6000
  self.out=View();self.p=p;self.f=f;self.q=q
  self.hii=(setup_hii if p['name']=='Setup' else foreign_hii)if hii is None else hii
  self.w(self.tse+0xafdd0,Q(self.app));self.w(self.tse+0xbaaf0,Q(self.table));self.w(self.tse+0xbabc0,Q(self.blob));self.w(self.tse+0xbab08,Q(self.cb))
  self.w(self.app+0x28,D(0)+D(1)+Q(self.pages));self.w(self.pages,Q(self.page));self.w(self.table,D(1)+D(0x100))
  self.w(self.page+0x20,Q(self.hii));self.w(self.page+0x2a,W(f['form']));self.w(self.page+0x30,W(0))
  self.w(self.raw,Q(self.hii));self.w(self.raw+0xa,W(f['form']));self.w(self.raw+0x1c,D(1 if q else 0))
  self.descriptor_provenance='EXPLICIT_NATIVE_LAYOUT_FIXTURE'
  if q:
   op=bytes.fromhex(q['hex']);kind={5:6,6:4,7:11,8:19,12:27,15:1,28:19,35:15,2:2,3:3}[op[0]]
   existing=bound_desc.get((q['form'],q.get('question')))
   desc=bytearray.fromhex(existing['descriptor_hex'])if existing else bytearray(64)
   if existing:
    kind=existing['native_kind'];self.descriptor_provenance='FROZEN_ORIGINAL_PARSER_DESCRIPTOR_RELOCATED_HII_AND_IFR'
   else:desc[12:16]=D(q.get('question',0));desc[0x14:0x16]=W(kind)
   desc[:8]=Q(self.hii);desc[0x28:0x30]=Q(self.op)
   self.w(self.desc,desc);self.w(self.control+0x20,desc);self.w(self.control,Q(self.tse+VT[kind]));self.w(self.op,op)
   self.w(self.raw+0x20,D(0x100));self.w(self.page+0x4c,D(1)+Q(self.fa));self.w(self.fa,Q(self.frame))
   self.w(self.frame+0x3c,D(1));self.w(self.frame+0x48,Q(self.ca));self.w(self.ca,Q(self.control))
  forms=(R/p['blob_path']).read_bytes()if forms_override is None else forms_override
  guid=uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21'if self.hii==setup_hii else f['formset']).bytes_le
  package=guid+D(20+len(forms)+4)+forms+b'\x04\x00\x00\xdf'
  self.package=C.create_string_buffer(package if package_override is None else package_override)
  self.package_bytes=len(package if package_override is None else package_override)
  self.id=ID(st=0x10000,hii=setup_hii if setup_identity is None else setup_identity,setup_driver=0x111100,tse_driver=0x111200,config=0x111300,
             setup_base=0x4000000,tse_base=self.tse,setup_size=2154496,tse_size=909312,epoch=31,loop_depth=1)
  self.ranges=(Range*3)(Range(self.tse,0xde000,3,0),Range(self.base,0x10000,3,0),Range(C.addressof(self.out),C.sizeof(self.out),3,0))
  self.bind()
 def w(self,a,b):C.memmove(a,bytes(b),len(b))
 def bind(self):lib.fp08_test_bind(C.byref(self.id),41,71,self.hii,self.package,self.package_bytes,self.ranges,len(self.ranges))
 def call(self,control=None):
  is_control=bool(self.q)if control is None else control
  r=lib.fp08_describe_control(self.page,self.control,C.byref(self.out))if is_control else lib.fp08_describe_page(self.page,0,C.byref(self.out))
  return r,self.out.classification,lib.fp08_test_exports()
 def mode(self,m,a=0,v=0,n=0):lib.fp08_test_mode(m,a,v,n,self.page)

def main():
 started=time.time();cases=[];mechanical=0
 def check(name,fn):
  result=fn();assert result,name;cases.append({'name':name,'pass':True})
 def exact(p,f,q=None,risk=None):
  v=Fixture(p,f,q);r,cls,calls=v.call();want=(q or f)['storage_risk']if risk is None else risk
  if q and risk is None:
   page_risk=(1 if f.get('reason')=='ORIGINAL_SETUP_AI_PROTECTED_FORM'else 0)if p['name']=='Setup'else f['storage_risk']
   if page_risk==1 or want==1:want=1
   elif page_risk==-1:want=-1
  assert (r,cls,calls)==(1,want,1),(p['name'],f['form'],q and q.get('question'),r,cls,calls,want)
  assert v.out.hii==v.hii and bytes(v.out.formset)==uuid.UUID(f['formset']).bytes_le
  assert v.out.epoch==31 and v.out.visit==41 and v.out.catalog_generation==71 and v.out.owner==(1 if p['name']=='Setup'else 2)
  assert bytes(v.out.hash).hex()==p['sha256']
  if q:assert bytes(v.out.ifr[:v.out.ifr_size])==bytes.fromhex(q['hex'])
  return v
 for p in catalog:
  # Real full Export, parser, SHA and finite description dispatch for everypage.
  for f in p['forms']:
   risk=f['storage_risk']
   if p['name']=='Setup':
    # Frozen original Setup UI page policy, independently derived from profile.
    # Original Setup protected page set is the frozen profile underlying policy.
    risk=1 if f.get('reason')=='ORIGINAL_SETUP_AI_PROTECTED_FORM' else 0
   exact(p,f,risk=risk);mechanical+=1
  ordinary=next((q for q in p['controls']if q['storage_risk']==0 and q['review_flags']&1),None)
  if ordinary:exact(p,record_form(p,ordinary['form']),ordinary);mechanical+=1
 check('All19 exact package signatures and595 real FORM classifications execute the compiled PE',lambda:mechanical>=595)
 # All specified cross-menu OC aliases remain protected, including physical
 # Socket offset migration. Runtime callback review flags do not change scope.
 protected_count=0
 for name in('SocketSetup','SocketSetup_PHYSICAL_D7','Platform'):
  p=byname[name]
  for q in p['controls']:
   if q['storage_risk']==1 and q.get('reason')in('EXACT_PROTECTED_GUID_AND_NAME','SHARED_MEMORY_PROTECTED_BYTE_OVERLAP'):
    exact(p,record_form(p,q['form']),q);protected_count+=1
 check('All861 original and physical Socket/Platform protected aliases remain protected',lambda:protected_count==861)
 scoped=next((p,f,q)for p in catalog if p['name']!='Setup'for f in p['forms']if f['storage_risk']==1 for q in p['controls']if q['form']==f['form']and q['formset']==f['formset']and q['storage_risk']==0)
 check('An ordinary control cannot downgrade its protected parent page',lambda:exact(*scoped).out.classification==1)
 sp=byname['SocketSetup_PHYSICAL_D7'];ref=next(q for q in sp['controls']if q.get('reason')=='REFERENCE_TO_DIRECTLY_PROTECTED_FORM')
 exact(sp,record_form(sp,ref['form']),ref)
 check('Protected child REF remains protected while its ordinary parent remains usable',lambda:exact(sp,record_form(sp,ref['form']),risk=0).out.classification==0)
 unknown=next(q for q in byname['Platform']['controls']if q['storage_risk']==-1)
 check('Unknown extension or target cannot become unprotected',lambda:exact(byname['Platform'],record_form(byname['Platform'],unknown['form']),unknown).out.classification==-1)
 nic=byname['NIC_D7_A'];q=next(q for q in nic['controls']if q['review_flags']&1);f=record_form(nic,q['form'])
 second=(B/'hardware_delta07/capture_6e7a57f9729b082c/object_04.forms.bin').read_bytes()
 first_instance=exact(nic,f,q).out.classification==0
 v=Fixture(nic,f,q,forms_override=second,hii=foreign_hii+0x100)
 check('Both physical NON_FV NIC instances bind their distinct HII without granting callback execution',lambda:'NIC_D7_B'in nic.get('equivalent_instances',[])and first_instance and v.call()[:2]==(1,0)and v.out.hii==foreign_hii+0x100)
 setup=byname['Setup'];prot=next(f for f in setup['forms']if f.get('reason')=='ORIGINAL_SETUP_AI_PROTECTED_FORM')
 check('Original AiTweaker protected page remains protected',lambda:exact(setup,prot,risk=1).out.classification==1)
 setup_ref=next(q for q in setup['controls']if q['opcode']==15 and q['storage_risk']==1)
 check('Original protected Setup REF remains protected',lambda:exact(setup,record_form(setup,setup_ref['form']),setup_ref).out.classification==1)
 # Mutations happen in isolated test memory, never firmware.
 mutations=[('raw HII mismatch',lambda v:v.w(v.raw,Q(0x777))),('native page index mismatch',lambda v:v.w(v.page+0x30,W(1))),
 ('raw FormId mismatch',lambda v:v.w(v.raw+0xa,W(0xffff))),('invalid page table count',lambda v:v.w(v.table,D(0))),
 ('pointer overflow',lambda v:v.w(v.tse+0xbabc0,Q(0xfffffffffffffff0))),('forged native vtable',lambda v:v.w(v.control,Q(v.tse+0x95620))),
 ('control HII mismatch',lambda v:v.w(v.control+0x20,Q(0x888))),('control missing from frame',lambda v:v.w(v.ca,Q(v.control+8))),
 ('control absent from raw origin',lambda v:v.w(v.desc+0x28,Q(v.op+1))),('raw QID mismatch',lambda v:v.w(v.desc+0xc,D(0xffff))),
 ('excess raw control count',lambda v:v.w(v.raw+0x1c,D(4097))),('canonical opcode mutation',lambda v:v.w(v.op+2,b'\xfe'))]
 for name,mut in mutations:
  v=Fixture(nic,f,q);mut(v);check(name+' rejected',lambda v=v:v.call()[0]==0)
 for name,mode in [('Export failure',1),('Export oversized length',2),('catalog change duringExport',4),('security epoch change',8),
  ('visit change',16),('protocol change',128),('private identity missing',256),('native visit missing',512),('catalog generation missing',1024)]:
  v=Fixture(nic,f,q);v.mode(mode);check(name+' rejected',lambda v=v:v.call()[0]==0)
 v=Fixture(nic,f,q);v.mode(32,v.raw+0xa,0xffff,2);check('Native descriptor changed duringExport rejected',lambda:v.call()[0]==0)
 v=Fixture(nic,f,q);v.mode(64);check('Reentrant description gets no view and does not overwrite the outer package buffer',lambda:v.call()[0]==1 and lib.fp08_test_nested()==0 and lib.fp08_test_exports()==1)
 raw=bytearray((R/nic['blob_path']).read_bytes());raw[79]^=1
 v=Fixture(nic,f,q,forms_override=bytes(raw));check('Uncatalogued forms remain unknown rather than ordinary',lambda:v.call()[:2]==(1,-1))
 sf=record_form(setup,setup_ref['form']);v=Fixture(setup,sf,setup_ref,hii=foreign_hii)
 check('Foreign handle cannot impersonate Setup FORM_SET',lambda:v.call()[0]==0)
 v=Fixture(nic,f,q,hii=setup_hii);check('Setup handle cannot impersonate foreign FORM_SET',lambda:v.call()[0]==0)
 original=(R/nic['blob_path']).read_bytes()
 wrapped=uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le+D(20+len(original)+4)+original+b'\x04\0\0\xdf'
 v=Fixture(nic,f,q,package_override=wrapped);check('Foreign handle cannot claim the pinned Setup package-list identity',lambda:v.call()[0]==0)
 v=Fixture(nic,f,q);v.w(v.table,D(2));check('Extra raw pages do not falsely reject the matched native page',lambda:v.call()[:2]==(1,0))
 v=Fixture(nic,f,q);v.w(v.app+0x2c,D(2));v.w(v.pages+8,Q(v.page));v.w(v.table,D(2));check('Duplicate App membership cannot impersonate a unique native page',lambda:v.call()[0]==0)
 orig=(R/nic['blob_path']).read_bytes();pkg=uuid.UUID(f['formset']).bytes_le+D(20+len(orig)*2+4)+orig+orig+b'\x04\0\0\xdf'
 v=Fixture(nic,f,q,package_override=pkg);check('Duplicate FormId across exported packages is rejected',lambda:v.call()[0]==0)
 other=bytearray(orig)
 for i,form_row in enumerate(nic['forms']):other[form_row['offset']+2:form_row['offset']+4]=W(0xf000+i)
 pkg=uuid.UUID(f['formset']).bytes_le+D(20+len(orig)+len(other)+4)+orig+bytes(other)+b'\x04\0\0\xdf'
 v=Fixture(nic,f,q,package_override=pkg);check('Duplicate FORM_SET with different FormIds cannot shadow storage identity',lambda:v.call()[0]==0)
 pkg=uuid.UUID(f['formset']).bytes_le+D(20+len(orig))+orig
 v=Fixture(nic,f,q,package_override=pkg);check('Missing package-list END rejected',lambda:v.call()[0]==0)
 # A frozen actual parser descriptor, not a caller supplied owner boolean.
 sq=next(q for q in setup['controls']if (q['form'],q['question'])in bound_desc and q['storage_risk']==1)
 v=exact(setup,record_form(setup,sq['form']),sq)
 check('Frozen original native Setup descriptor is retained apart from explicit pointer relocations',lambda:v.descriptor_provenance.startswith('FROZEN'))
 report={'status':'NATIVE_PE_UI_SCOPE_TESTS_PASS_NO_FIRMWARE_OR_CALLBACK_EXECUTION','cases':cases,'scenario_count':len(cases),
 'mechanical_page_and_callback_samples':mechanical,'protected_alias_controls':protected_count,
 'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'component_sha256':hashlib.sha256((H/'build/W890ForeignPage08.TESTONLY.dll').read_bytes()).hexdigest(),
 'actual_service_boundary':'Compiled helper calls real HII.ExportPackageLists function pointer; isolated TESTONLY service provides actual frozen/physical forms bytes and explicit complete package-list wrapper.',
 'models':['Native outer App/Page/Frame/control containers','Private observer identity and memory extents','Package-list wrapper and HII handles','Catalog/security generation and fault injection'],
 'native_code_executed':['Compiled foreign_page.c parser/classifier/binding checks','Compiled original password_crypto.c SHA256 only','Compiled frozen w890_policy.c classification only'],
 'not_executed':['Firmware native callback handlers','Password operations','Firmware variables','BMC','DXE startup'],
 'runtime_authorized':False,'hardware_actions':0,'firmware_changes':0,'seconds':round(time.time()-started,3)}
 (H/'test_results.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k]for k in('scenario_count','mechanical_page_and_callback_samples','protected_alias_controls','seconds')}))
if __name__=='__main__':main()
