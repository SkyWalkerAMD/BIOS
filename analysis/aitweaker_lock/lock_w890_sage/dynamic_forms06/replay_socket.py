"""Run original SocketSetup 61B0 Memory Topology builder, without its event/startup.

The cached HOB list, MemoryInfo and SPD branch selector are explicit synthetic
inputs; no DIMM or string ID in this model is asserted to be a physical reading.
UEFI allocation, HII strings and package database are bounded host substitutes.
The original formatter, selectors, opcode builder and HiiUpdateForm run as x64.
No firmware is patched, no physical hardware or NVRAM is accessed.
"""
from replay_nvme import *
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

HOB=0x6000000; SPD_PTR=HOB+0x100; MI=0x6100000; SPD=0x6200000
ORIGINAL_SHA='f2e7516f0a9fcccfc7ce45512dc105ff6af357b310e93df72068ed9d63003968'
PHYSICAL_SHA='ad272dae6eb1713db3f3a2364bb546bc1d694e7f7f4d435d769f43320177267e'
CHAIN={0x61b0:'MemoryTopology',0x5ecc:'FormatTopologyString',0x7c58:'Select3DSBranch',
       0x7cac:'SPDChannelAddress',0xae38:'GetCachedHobList',0xae68:'GetNextGuidHob',
       0xb87c:'HiiSetString',0xd118:'GetSupportedLanguages',0xcabc:'AllocateOpcodeHandle',
       0xcbcc:'CreateGuidOpcode',0xcb70:'CreateOpcode',0xced8:'HiiUpdateForm',
       0xcc24:'UpdateFormPackage',0x8f10:'UnicodeFormat',0xa2ac:'UnicodeAppend'}

class SocketVM(VM):
 def __init__(self,first_id=0x7000,slots=((0,0),(2,0),(4,0),(6,0)),disabled=(),excluded=(),string_ids=None):
  self.u=Uc(UC_ARCH_X86,UC_MODE_64)
  for p,n in [(BASE,0x122000),(BS,0x10000),(STACK,0x20000),(POOL,0x400000),
              (HOB,0x1000),(MI,0x5000),(SPD,0x30000)]:self.u.mem_map(p,n)
  self.pe_bytes=(H/'inputs/SocketSetup.efi').read_bytes();assert hashlib.sha256(self.pe_bytes).hexdigest()==ORIGINAL_SHA
  p=pefile.PE(data=self.pe_bytes);assert p.OPTIONAL_HEADER.SizeOfImage==0x122000
  p.relocate_image(BASE);mapped=p.get_memory_mapped_image();self.u.mem_write(BASE,mapped)
  textsec=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text')
  self.text_extent=(BASE+textsec.VirtualAddress,textsec.Misc_VirtualSize)
  self.native_text_before=hashlib.sha256(bytes(self.u.mem_read(*self.text_extent))).hexdigest()
  self.forms=(H/'inputs/SocketSetup.forms.bin').read_bytes();body=self.forms+b'\x04\x00\x00\xdf'
  self.package=uuid.UUID('6b6fd380-2c55-42c6-98bf-cbbc5a9aa666').bytes_le+D(20+len(body))+body
  self.handlers={};self.next=POOL;self.live={};self.calls=collections.Counter();self.trace=[];self.updates=[];self.strings=[];self.allocations=[];self.error=None;self.first_id=first_id;self.next_id=first_id
  self.supplied_ids=None if string_ids is None else list(string_ids)
  self.native_calls=collections.Counter();self.model_reads=collections.Counter()
  for offset in range(0x18,0x180,8):self.wq(BS+offset,self.stub('unknown-bs-'+hex(offset),self.unknown))
  for offset in range(0,0x40,8):self.wq(STR+offset,self.stub('unknown-string-'+hex(offset),self.unknown))
  for offset in range(0,0x60,8):self.wq(DB+offset,self.stub('unknown-db-'+hex(offset),self.unknown))
  for offset,name,fn in [(0x40,'AllocatePool',self.allocate),(0x48,'FreePool',self.free)]:self.wq(BS+offset,self.stub(name,fn))
  for offset,name,fn in [(0,'NewString',self.new_string),(0x10,'SetString',self.set_string),(0x18,'GetLanguages',self.languages)]:self.wq(STR+offset,self.stub(name,fn))
  for offset,name,fn in [(0x20,'ExportPackageLists',self.export),(0x10,'UpdatePackageList',self.update)]:self.wq(DB+offset,self.stub(name,fn))
  for rva,val in [(0x14d40,BS),(0x14df8,STR),(0x14e18,DB),(0x14d20,HANDLE),
                  (0x14d58,HOB),(0x14d60,SPD_PTR)]:self.wq(BASE+rva,val)
  guid=bytes(self.u.mem_read(BASE+0xf0d0,16))
  self.hob=struct.pack('<HHI',4,32,0)+guid+Q(MI)+struct.pack('<HHI',0xffff,8,0)
  self.u.mem_write(HOB,self.hob);self.wq(SPD_PTR,SPD)
  self.slots=[list(v)for v in slots];self.disabled=list(disabled);self.excluded=[list(v)for v in excluded]
  assert all(0<=c<8 and 0<=d<2 for c,d in slots)
  for c,d in slots:
   # Synthetic DDR5 RDIMM attributes. They change generated string text, while
   # the forms carry only the explicitly supplied runtime NewString IDs.
   ch=c*0x104;ofs=ch+d*0x79
   self.u.mem_write(MI+0x405e+ch,bytes([0 if c in disabled else 1]))
   for off,val in [(0x4071,1),(0x4072,int((c,d)in excluded)),(0x4074,4),
                   (0x4076,1),(0x4077,0x12),(0x4078,1)]:self.u.mem_write(MI+off+ofs,bytes([val]))
   self.u.mem_write(MI+0x407f+ofs,struct.pack('<H',32<<4))
   self.u.mem_write(MI+0x4081+ofs,struct.pack('<H',0xffff))
  # SPD selector bytes at +27BC4 + channel*A04 are zero: original 7C58 takes
  # the ordinary non-3DS path and does not call E0A4 or 7CAC.
  self.model_objects=[('GuidHobAndEnd',HOB,len(self.hob)),('SPDGlobalPointer',SPD_PTR,8),
                      ('SyntheticMemoryInfo',MI,0x5000),('SyntheticSPDInfo',SPD,0x30000)]
  self.model_inputs={'hob_guid_from_original_rva_f0d0':str(uuid.UUID(bytes_le=guid)),
    'cached_hob_global_rva':'0x14d58','memory_info_pointer_payload_offset':'0x18',
    'slots_present':self.slots,'disabled_channels':self.disabled,'excluded_slots':self.excluded,
    'new_string_first_id':first_id,'new_string_ids_are_modeled':True,
    'explicit_new_string_return_ids':self.supplied_ids,
    'SPD_selector':'zero at SPD+0x27bc4+channel*0xa04; original non-3DS branch',
    'string_attributes':'synthetic 1-rank x4 32GB DDR5 RDIMM, manufacturer 0xffff',
    'HII_database':'one original forms package plus END; no original string package installed',
    'all_other_fields_in_modeled_objects':'zero; not observed from hardware'}
  self.u.hook_add(UC_HOOK_CODE,self.code,begin=STUB,end=STOP)
  self.u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
  for rva in CHAIN:self.u.hook_add(UC_HOOK_CODE,self.native_entry,begin=BASE+rva,end=BASE+rva)
  for p,n in [(HOB,0x1000),(MI,0x5000),(SPD,0x30000)]:
   self.u.hook_add(UC_HOOK_MEM_READ,self.read_model,begin=p,end=p+n-1)
  self.u.hook_add(UC_HOOK_MEM_WRITE,self.reject_code_write,begin=self.text_extent[0],end=sum(self.text_extent)-1)
 def new_string(self,a):
  if self.supplied_ids is not None:
   index=sum(x['operation']=='NewString'for x in self.strings)
   assert index<len(self.supplied_ids),'original builder requested more IDs than supplied'
   self.next_id=self.supplied_ids[index]
  return super().new_string(a)
 def native_entry(self,u,p,n,_):self.native_calls[CHAIN[p-BASE]]+=1
 def read_model(self,u,access,p,size,value,_):
  for name,start,length in self.model_objects:
   if start<=p and p+size<=start+length:self.model_reads[name]+=1;return
  self.error={'out_of_model_object_read':hex(p),'size':size};u.emu_stop()
 def reject_code_write(self,u,access,p,size,value,_):self.error={'native_code_write':hex(p),'size':size};u.emu_stop()
 def run(self):
  sp=STACK+0x18000-8;self.wq(sp,STOP);self.u.reg_write(UC_X86_REG_RSP,sp)
  for r in REGS:self.u.reg_write(r,0)
  try:self.u.emu_start(BASE+0x61b0,STOP+1,count=10000000)
  except Exception as e:
   if not self.error:self.error=str(e)
  if self.error or self.u.reg_read(UC_X86_REG_RIP)!=STOP:raise RuntimeError(str(self.error))
  assert hashlib.sha256(bytes(self.u.mem_read(*self.text_extent))).hexdigest()==self.native_text_before
  return self.updates

def experiment(name,slots,disabled=(),excluded=(),first_id=0x7000):
 v=SocketVM(first_id,slots,disabled,excluded)
 r={'case':name,'scope':__doc__,'target_rva':'0x61b0','original_pe_sha256':ORIGINAL_SHA,
    'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'service_base_source_sha256':hashlib.sha256((H/'replay_nvme.py').read_bytes()).hexdigest(),
    'model_inputs':v.model_inputs,'code_patches':0,'firmware_or_hardware_actions':0,
    'authorization':False,'status':'RUNNING'}
 try:
  forms=v.run();assert len(forms)==1;out=forms[0];expected=sum(c not in disabled and (c,d)not in excluded for c,d in slots)
  assert len(out)==len(v.forms)+expected*7,(len(out),expected)
  r['status']='PASS_ORIGINAL_NATIVE_UPDATE_WITH_MODELED_SERVICES'
  r['generated_forms']={'bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),
    'physical_sha256_match':hashlib.sha256(out).hexdigest()==PHYSICAL_SHA,
    'original_forms_equal':out==v.forms,'modeled_subtitles':expected}
  (H/(name+'.forms.bin')).write_bytes(out)
 except Exception as e:r['status']='FAIL_MODEL_BOUNDARY';r['error']=str(e)
 r.update(services=dict(v.calls),native_entries=dict(v.native_calls),modeled_memory_reads=dict(v.model_reads),
          strings=v.strings,live_allocations=v.live)
 (H/(name+'.json')).write_text(json.dumps(r,indent=2)+'\n');return r

if __name__=='__main__':
 cases=[('socket_model_zero',()),('socket_model_four',((0,0),(2,0),(4,0),(6,0))),
        ('socket_model_disabled_channel',((0,0),(2,0),(4,0),(6,0)),(2,)),
        ('socket_model_excluded_slot',((0,0),(2,0),(4,0),(6,0)),(),((4,0),))]
 for case in cases:
  r=experiment(*case);print(json.dumps({k:r[k]for k in ('case','status','generated_forms','error')if k in r}))
