"""Actual HII06 EFI with original modules + 13 model HII instances.
CPU register observations and SHA calls are explicit oracles; actual C SHA is
separately exercised by verify_core, and actual CPU walker/UI by the OVMF runs.
"""
from pathlib import Path
import hashlib,importlib.util,json,re,struct,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build';LEGACY=ROOT/'analysis/aitweaker_lock/probe_p3_kvm'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
sys.path.insert(0,str(LEGACY))
spec=importlib.util.spec_from_file_location('hii06_p3_fixture',LEGACY/'verify_inventory.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture);fixture.OUT=OUT
import pefile
from unicorn import UC_HOOK_CODE,UC_PROT_READ
from unicorn.x86_const import *
ERR=lambda n:(1<<63)|n
def p64(n):return struct.pack('<Q',n)
symbols={m.group(1):int(m.group(2),16)-0x140000000+0x100000 for m in re.finditer(r'\s[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})', (OUT/'probe.map').read_text())}
catalog=json.loads((HERE.parent/'foreign_hii05/catalog.json').read_text());profiles=json.loads((OUT/'profiles.json').read_text())
class Machine(fixture.Machine):
 def __init__(self,mode):
  super().__init__('W890_SAGE_0603','normal');self.mode=mode;self.configs={};self.packages={};self.drivers={};self.handles_by_guid={};self.module_bases={};self.sha_calls=0;self.cpu_calls=0
  self.stub(self.bs+0x38,'GetMemoryMap')
  existing={'AMITSE':0x1111,'Setup':0x2222};nextbase=0x3000000
  for n,p in enumerate(profiles):
   if p['name'] in existing:
    handle=existing[p['name']];base=self.module_images[p['name']][0]
   else:
    base=nextbase;nextbase+=0x400000;handle=0x6000+n
    pe=pefile.PE(p['path']);pe.relocate_image(base);data=pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0')
    self.u.mem_map(base,(len(data)+4095)&~4095);self.u.mem_write(base,data);self.u.mem_protect(base,(len(data)+4095)&~4095,UC_PROT_READ)
    path=bytes([4,6,20,0])+uuid.UUID(p['guid']).bytes_le+bytes([127,255,4,0]);li=bytearray(96);struct.pack_into('<Q',li,32,self.alloc(path));struct.pack_into('<QQ',li,64,base,len(data));self.loaded[handle]=self.alloc(li);self.module_images[p['name']]=(base,data)
   self.module_bases[p['name']]=base;self.handles_by_guid[p['guid']]=handle
  # Explicit unknown producer model, based on Ip6 bytes only for range/hash tests.
  ip6=next(p for p in profiles if p['name']=='Ip6Dxe');pe=pefile.PE(ip6['path']);base=0x5800000;pe.relocate_image(base);data=pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0');self.u.mem_map(base,(len(data)+4095)&~4095);self.u.mem_write(base,data);self.u.mem_protect(base,(len(data)+4095)&~4095,UC_PROT_READ);self.module_images['NONFV_MODEL']=(base,data)
  li=bytearray(96);struct.pack_into('<Q',li,32,self.alloc(bytes([4,4,8,0])+b'A\0\0\0'+bytes([127,255,4,0])));struct.pack_into('<QQ',li,64,base,len(data));unknown=0x6888;self.loaded[unknown]=self.alloc(li)
  def unknown_forms():
   fset=b'\x0e\x97'+uuid.UUID('25fd9f0b-a3ef-4788-a40c-81849d178a6c').bytes_le+b'\0'*5
   body=fset+b''.join(b'\x01\x86'+struct.pack('<HH',0x3000+i,1)+b'\x29\x02' for i in range(4))+b'\x29\x02'
   return struct.pack('<I',(len(body)+4)|(2<<24))+body
  for package in catalog['packages']:
   form=b''.join((ROOT/f['blob_path']).read_bytes() for f in package['forms_packages']) if package['forms_packages'] else unknown_forms()
   blob=uuid.UUID(package['package_list_guid']).bytes_le+struct.pack('<I',24+len(form))+form+b'\4\0\0\xdf'
   for instance in package['hardware_instances']:
    h=0x900000+len(self.packages)*16;self.packages[h]=blob
    producer=package['producer_modules'][0] if package['producer_modules'] else None
    driver=self.handles_by_guid[producer['ffs_guid']] if producer else unknown
    if producer and producer['module_name']=='GetCpuInfo':
     self.cpu_hii=h;self.drivers[h]=0;self.w64(self.module_bases['GetCpuInfo']+0x3538,h)
    else:
     self.drivers[h]=driver
     if driver not in self.configs:
      callbacks=instance['callbacks'];module_base=self.r64(self.loaded[driver]+64);config=self.alloc(b''.join(p64(module_base+c['rva']) for c in callbacks));self.configs[driver]=config
  # Only source memory fixture setup above is allowed to change original data.
  if mode=='bad_foreign_text':self.u.mem_write(self.module_bases['SocketSetup']+0x1003,b'\xcc')
  if mode=='bad_reloc':
   p=next(p for p in profiles if p['name']=='SocketSetup');self.u.mem_write(self.module_bases['SocketSetup']+p['reloc_rva']+9,b'\xff')
  if mode=='cpu_handle_mismatch':self.w64(self.module_bases['GetCpuInfo']+0x3538,0xdddd)
  if mode=='overlapping_image':self.loaded[0x6999]=self.loaded[unknown]
  if mode=='bad_loaded_pointer':self.loaded[0x6999]=0xdead0000
  if mode=='fingerprint_budget':
   source=next(h for h in self.packages if self.drivers[h])
   for i in range(45):self.packages[0xa00000+i*16]=self.packages[source];self.drivers[0xa00000+i*16]=self.drivers[source]
  self.module_images={n:(a,bytes(self.u.mem_read(a,len(b)))) for n,(a,b) in self.module_images.items()}
  self.u.mem_map(0x5000000,0x10000);self.w64(0x5000000,0x5001003);self.w64(0x5001000,0x5002003)
  for i in range(512):self.w64(0x5002000+i*8,i*0x200000|0x83)
  if mode in ('page_not_present','page_not_identity'):
   index=self.module_bases['SocketSetup']//0x200000
   self.w64(0x5002000+index*8,(index*0x200000|0x82) if mode=='page_not_present' else ((index+1)*0x200000|0x83))
  self.u.hook_add(UC_HOOK_CODE,self.oracle,begin=symbols['i04_cpu'],end=symbols['i04_cpu'])
  self.u.hook_add(UC_HOOK_CODE,self.oracle,begin=symbols['ap_sha256'],end=symbols['ap_sha256'])
 def oracle(self,u,address,size,user):
  sp=u.reg_read(UC_X86_REG_RSP);a,b,c=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8)]
  if address==symbols['i04_cpu']:
   self.cpu_calls+=1;u.mem_write(a,struct.pack('<QQQQQII',0x80010001,0x5000000,0x20,0xc00,0x0007040600070406,48,0));u.reg_write(UC_X86_REG_RAX,1)
  else:
   self.sha_calls+=1;u.mem_write(c,hashlib.sha256(bytes(u.mem_read(a,b))).digest())
  u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,self.r64(sp))
 def hook(self,u,address,size,user):
  name=self.stubs.get(address)
  if name not in ('GetMemoryMap','LocateHandles','HandleProtocol','ListPackages','ExportPackages','GetHiiDriver'):return super().hook(u,address,size,user)
  self.calls.append(name);sp=u.reg_read(UC_X86_REG_RSP);assert sp%16==8
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=self.r64(sp+40);ret=0
  if name=='GetMemoryMap':
   if self.mode=='map_error':u.reg_write(UC_X86_REG_RAX,ERR(7));return
   records=[]
   for start,end,protection in u.mem_regions():
    attrs=0x2000 if self.mode=='read_protected' and start==self.module_bases['SocketSetup'] else 0
    records.append(struct.pack('<IIQQQQ',4,0,start,0,(end-start+1)//4096,attrs))
   raw=b''.join(records);assert len(raw)<=self.r64(a);u.mem_write(b,raw);self.w64(a,len(raw));self.w64(c,1);self.w64(d,40);u.mem_write(e,struct.pack('<I',1))
  elif name=='LocateHandles':self.w64(d,len(self.loaded));self.w64(e,self.alloc(b''.join(p64(h) for h in self.loaded)))
  elif name=='HandleProtocol':
   g=self.guid(b);ptr=self.loaded.get(a,0) if g==fixture.ref.LOADED else self.configs.get(a,0) if g==fixture.ref.CONFIG else 0
   if ptr:self.w64(c,ptr)
   else:ret=ERR(14)
  elif name=='ListPackages':
   needed=len(self.packages)*8
   if self.r64(d)<needed:self.w64(d,needed);ret=ERR(5)
   else:u.mem_write(e,b''.join(p64(h) for h in self.packages));self.w64(d,needed)
  elif name=='ExportPackages':
   blob=self.packages[b]
   if self.mode=='oversized_export':self.w64(c,32*1024*1024);ret=ERR(5)
   elif self.r64(c)<len(blob):self.w64(c,len(blob));ret=ERR(9)
   else:u.mem_write(d,blob);self.w64(c,len(blob))
  elif name=='GetHiiDriver':
   self.w64(c,self.drivers[b])
   if self.mode=='warning_driver_status':ret=1
  u.reg_write(UC_X86_REG_RAX,ret)
 def run(self):
  self.u.reg_write(UC_X86_REG_RSP,0xefff08);self.w64(0xefff08,0x8ff000);self.u.reg_write(UC_X86_REG_RCX,0x3333);self.u.reg_write(UC_X86_REG_RDX,self.st)
  self.u.emu_start(self.entry,0x8ff000,count=450000000);assert self.u.reg_read(UC_X86_REG_RIP)==0x8ff000,'instruction limit';assert self.u.reg_read(UC_X86_REG_RAX)==0
  for base,data in self.module_images.values():assert bytes(self.u.mem_read(base,len(data)))==data
  assert not self.created and not self.log and not any(n.startswith('FORBIDDEN') for n in self.calls)
  log=self.output.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode('ascii')
  expected={'map_error':b'H6.MAP=REFUSED','read_protected':b'C=RANGE','bad_foreign_text':b'C=MISMATCH','bad_reloc':b'C=RELOC_TABLE','cpu_handle_mismatch':b'DRIVER=NULL_ORIGINAL S=UNKNOWN','overlapping_image':b'OWNER_UNKNOWN','oversized_export':b'HII export_size','bad_loaded_pointer':b'L6 I=0000000000006999 E=POINTER_RANGE','warning_driver_status':b'HII.driver=0x0000000000000001','fingerprint_budget':b'H6.EXTRA=OVER_BUDGET_PARTIAL','page_not_present':b'C=RANGE','page_not_identity':b'C=RANGE'}.get(self.mode,b'C=MATCH')
  assert expected in log,(self.mode,log[-2500:])
  if self.mode=='normal':
   lines=log.splitlines();f=[x for x in lines if x.startswith(b'F6 ')];m=[x for x in lines if x.startswith(b'M6 ')];assert len(f)==13,(len(f),log)
   assert sum(b'25FD9F0B' in x for x in f)==2;assert sum(b'C=MATCH' in x for x in m)==10 and sum(b'C=UNKNOWN' in x for x in m)==1
   assert b'DRIVER=NULL_ORIGINAL S=SAVED_HANDLE_MATCH' in log
   for line in f:
    h=int(re.search(rb'H=([0-9A-F]+)',line)[1],16);blob=self.packages[h];form=blob[20:-4];assert hashlib.sha256(form).hexdigest().upper().encode() in line
   added=sum(len(x)+2 for x in lines if x.startswith((b'M6 ',b'F6 ',b'C6 ',b'D6 ')));assert added<=8192,added
  else:
   added=sum(len(x)+2 for x in log.splitlines() if x.startswith((b'M6 ',b'F6 ',b'C6 ',b'D6 ',b'L6 ')));assert added<=8192,added
  (OUT/'efi_cases').mkdir(exist_ok=True);(OUT/'efi_cases'/f'{self.mode}.txt').write_bytes(log)
  return {'case':self.mode,'passed':True,'bytes':len(log),'pages':(len(log)+767)//768,'additional_fingerprint_bytes':added,'foreign_memory_unchanged':True,'filesystem_calls':0,'variable_calls':0,'business_callbacks':0,'cpu_observation_oracle_calls':self.cpu_calls,'sha_oracle_calls':self.sha_calls}
def main():
 cases=sys.argv[1:] or ['normal','map_error','read_protected','bad_foreign_text','bad_reloc','cpu_handle_mismatch','overlapping_image','oversized_export','bad_loaded_pointer','warning_driver_status','fingerprint_budget','page_not_present','page_not_identity'];results=[]
 for mode in cases:
  r=Machine(mode).run();results.append(r);print(json.dumps(r),flush=True)
 (OUT/('efi_tests.json' if len(cases)>1 else 'efi_test_'+cases[0]+'.json')).write_text(json.dumps({'passed':True,'count':len(results),'cases':results,'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),'scope':'Actual collector PE, original module bytes, original forms plus two explicitly synthetic unknown 4-form packages. Synthetic page tables execute the real walker; CPU observations and SHA are oracle calls. No physical board accessed.'},indent=2)+'\n')
if __name__=='__main__':main()
