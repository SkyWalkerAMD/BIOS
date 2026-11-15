"""Execute the actual read-only EFI with original W890 modules and modeled services."""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys,datetime
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build'
LEGACY=ROOT/'analysis/aitweaker_lock/probe_p3_kvm'
for name in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/name))
sys.path.insert(0,str(LEGACY))
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
fixture=load('native_sample_p3_fixture',LEGACY/'verify_inventory.py');fixture.OUT=OUT
from unicorn.x86_const import UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RAX,UC_X86_REG_RSP,UC_X86_REG_RIP
class Machine(fixture.Machine):
 def __init__(self,mode):
  super().__init__('W890_SAGE_0603','unknown_build' if mode=='wrong_text' else 'normal')
  self.mode=mode;self.stub(self.bs+0x38,'GetMemoryMap');base,data=self.module_images['AMITSE'];self.tse=base
  self.app=0x720000;self.table=0x721000;self.page=0x722000
  self.w64(base+0xafdd0,0 if mode=='inactive' else self.app)
  self.w64(base+0xafcb0,1);self.w64(base+0xafbc8,self.bs);self.w64(base+0xbabe8,0x5555)
  self.u.mem_write(base+0xafddc,bytes(8));self.w64(base+0xafde8,0);self.u.mem_write(base+0xafe00,bytes(4))
  self.u.mem_write(self.app,bytes(0x60));self.u.mem_write(self.app+0x28,struct.pack('<IIQ',0,1,self.table))
  self.w64(self.table,self.page);self.u.mem_write(self.page,bytes(0x68));self.w64(self.page+0x20,0x5555)
  self.u.mem_write(self.page+0x2a,struct.pack('<H',0x2712))
  if mode=='bad_page_count':self.u.mem_write(self.app+0x2c,struct.pack('<I',4097))
  if mode=='bad_page_pointer':self.w64(self.table,0xeeeeeeee)
  self.module_images['AMITSE']=(base,bytes(self.u.mem_read(base,len(data))))
 def hook(self,u,address,size,user):
  if self.stubs.get(address)!='GetMemoryMap':return super().hook(u,address,size,user)
  self.calls.append('GetMemoryMap');sp=u.reg_read(UC_X86_REG_RSP);assert sp%16==8
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=self.r64(sp+40)
  if self.mode=='map_error':u.reg_write(UC_X86_REG_RAX,(1<<63)|7);return
  records=[]
  for start,end,protection in u.mem_regions():
   if self.mode=='missing_app_region' and start==0x600000:continue
   attr=0x2000 if self.mode=='text_read_protected' and start==self.tse else 0
   records.append(struct.pack('<IIQQQQ',4,0,start,0,(end-start+1)//4096,attr))
  raw=b''.join(records);assert len(raw)<=self.r64(a);u.mem_write(b,raw);self.w64(a,len(raw));self.w64(c,1);self.w64(d,40)
  u.mem_write(e,struct.pack('<I',2 if self.mode=='wrong_map_version' else 1));u.reg_write(UC_X86_REG_RAX,0)
 def run(self,expected):
  self.u.reg_write(UC_X86_REG_RSP,0xefff08);self.w64(0xefff08,0x8ff000)
  self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(self.entry,0x8ff000,count=400000000)
  assert self.u.reg_read(UC_X86_REG_RIP)==0x8ff000 and self.u.reg_read(UC_X86_REG_RAX)==0
  for base,data in self.module_images.values():assert bytes(self.u.mem_read(base,len(data)))==data
  assert not self.created and not self.log
  assert all(not name.startswith('FORBIDDEN') for name in self.calls)
  log=self.output.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode('ascii')
  assert ('NATIVE_SAMPLE_STATUS='+expected+'\r\n').encode() in log,(self.mode,log)
  assert (b'COLLECTION_STATUS=COMPLETE' if self.mode=='active' else b'COLLECTION_STATUS=PARTIAL') in log
  (OUT/'efi_cases'/f'{self.mode}.txt').write_bytes(b'MODELED SERVICES AND NATIVE STATE; NOT A PHYSICAL LOG\r\n'+log)
  return {'case':self.mode,'passed':True,'sample_status':expected,'module_memory_unchanged':True,'filesystem_calls':0,'runtime_service_calls':0}
def main():
 (OUT/'efi_cases').mkdir(exist_ok=True);results=[]
 for mode,expected in [('active','STABLE_DOUBLE_SAMPLE'),('inactive','INACTIVE'),('wrong_text','UNAVAILABLE'),('map_error','MEMORY_MAP_UNAVAILABLE'),('wrong_map_version','TEXT_RANGE_REFUSED'),('text_read_protected','TEXT_RANGE_REFUSED'),('missing_app_region','REFUSED'),('bad_page_count','REFUSED'),('bad_page_pointer','REFUSED')]:
  results.append(Machine(mode).run(expected));print(mode,'PASS',flush=True)
 report={'passed':True,'cases':results,'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),'scope':'Actual EFI bytes and original W890 module text; services and live native state are explicit fixtures.'}
 (OUT/'efi_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 vm=load('w890_native_sample_vm',LEGACY/'verify_vm.py');vm.OUT=OUT;vm.ISO=OUT/'W890-NATIVE-SAMPLE01-NOFLASH.iso'
 result=vm.run('sata',800,600,0);assert result['passed']
 print(json.dumps({'efi_cases':len(results),'ovmf_passed':True}),flush=True)
if __name__=='__main__':main()
