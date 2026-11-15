"""D7 actual EFI tests. Firmware services/page tables are modeled explicitly.
The shipping selection is never relaxed: synthetic positives use a separate
LAB-only binary/configuration whose digest and source label differ.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,re,struct,subprocess,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];H6=HERE.parent/'diagnostic_hii06'
for part in ('pydeps','vm-pydeps','kvm-pydeps'):sys.path.insert(0,str(ROOT/'tools'/part))
from prepare_selection import canonical
from decode_packet import CPU,NVME,SOCKET,UNKNOWN,BASELINES,validate_forms
from transport import parse
import pefile
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
BASE={g:(HERE.parent/'foreign_hii05/blobs'/f'{name}_0.forms.bin').read_bytes() for g,name in ((CPU,'GetCpuInfo'),(NVME,'NvmeDynamicSetup'),(SOCKET,'SocketSetup'))}
def insert_before_form_end(base,records):
 at=4;depth=0
 while at<len(base):
  op=base[at];n=base[at+1]&127;sc=base[at+1]>>7
  if op==1:form_depth=depth+1
  if op==41:
   if depth==locals().get('form_depth',-1):
    body=base[4:at]+records+base[at:];return struct.pack('<I',len(body)+4|(2<<24))+body
   depth-=1
  elif sc:depth+=1
  at+=n
 raise AssertionError('No form end')
def contents(huge=False):
 cpu=BASE[CPU];body=cpu[4:132]+b''.join(struct.pack('<BBHHH',3,8,0x100+i,0,0) for i in range(168))+cpu[132:]
 result={CPU:struct.pack('<I',len(body)+4|(2<<24))+body,NVME:insert_before_form_end(BASE[NVME],struct.pack('<BBHHB',2,7,0x30,0x1c,0)),SOCKET:insert_before_form_end(BASE[SOCKET],struct.pack('<BBHHB',2,7,0x30,0,0)*4)}
 fset=b'\x0e\x97'+uuid.UUID(UNKNOWN).bytes_le+b'\0'*5
 records=struct.pack('<BBHHB',2,7,0x30,0,0)*333+struct.pack('<BBHHH',3,8,0x31,0,0)
 body=fset+b''.join(b'\x01\x86'+struct.pack('<HH',0x3100+i,1)+(records if i==0 else b'')+b'\x29\x02' for i in range(4))+b'\x29\x02'
 result[UNKNOWN]=struct.pack('<I',len(body)+4|(2<<24))+body;assert len(result[UNKNOWN])==2400
 if huge:
  data=bytearray(result[SOCKET]);at=4;changed=[]
  while at<len(data):
   n=data[at+1]&127
   if data[at]==1 and n==6:changed.append(at+4)
   at+=n
  assert len(changed)>2
  for at in (changed[0],changed[-1]):data[at]^=1
  result[SOCKET]=bytes(data)
 for data in result.values():validate_forms(data)
 return result
def lab_selection(path,huge=False):
 selection=json.loads((HERE/'selection_hardware02.json').read_text());payload=selection['payload'];payload['lab_only']=True;payload['source_log_sha256']=hashlib.sha256(b'LAB synthetic HII06 source, not physical evidence').hexdigest();forms=contents(huge)
 for t in payload['targets']:t['result_bytes']=len(forms[t['package_list_guid']]);t['result_sha256']=hashlib.sha256(forms[t['package_list_guid']]).hexdigest()
 profiles=json.loads((H6/'build/profiles.json').read_text());p=next(p for p in profiles if p['name']=='Ip6Dxe');pe=pefile.PE(p['path']);pe.relocate_image(0x5800000);mapped=pe.get_memory_mapped_image();text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');raw=hashlib.sha256(mapped[text.VirtualAddress:text.VirtualAddress+text.Misc_VirtualSize]).hexdigest()
 pathsha=hashlib.sha256(bytes([4,4,8,0])+b'A\0\0\0'+bytes([127,255,4,0])).hexdigest().upper()
 for m in payload['source_module_observations']:
  if m['reported_ffs_guid']=='NONFV':m.update(image_bytes=pe.OPTIONAL_HEADER.SizeOfImage,text_rva=text.VirtualAddress,text_bytes=text.Misc_VirtualSize,raw_sha256=raw)
 payload['source_nonfv_path_observations']=[line.split(' P=')[0]+' P='+pathsha for line in payload['source_nonfv_path_observations']]
 selection['selection_sha256']=hashlib.sha256(canonical(payload)).hexdigest();selection['status']='SYNTHETIC_LAB_ONLY_NOT_FOR_HARDWARE';path.parent.mkdir(exist_ok=True,parents=True);path.write_text(json.dumps(selection,indent=2)+'\n');return selection
def load_fixture(out):
 spec=importlib.util.spec_from_file_location('delta07_h6_fixture',H6/'verify_efi.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 module.OUT=out;module.fixture.OUT=out
 module.symbols={m.group(1):int(m.group(2),16)-0x140000000+0x100000 for m in re.finditer(r'\s[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})',(out/'probe.map').read_text())}
 return module
def run_case(out,selection,mode,huge=False,shipping=False):
 fixture=load_fixture(out);forms=contents(huge)
 class Machine(fixture.Machine):
  def __init__(self):
   parent_mode={'bad_producer_text':'bad_foreign_text','bad_reloc':'bad_reloc','cpu_saved_mismatch':'cpu_handle_mismatch','map_error':'map_error','duplicate_owner':'overlapping_image','warning_driver':'warning_driver_status'}.get(mode,'normal')
   super().__init__(parent_mode)
   for h,blob in list(self.packages.items()):
    guid=str(uuid.UUID(bytes_le=blob[:16]))
    if guid in forms:
     form=forms[guid]
     self.packages[h]=blob[:16]+struct.pack('<I',24+len(form))+form+b'\x04\0\0\xdf'
   if mode=='forms_changed':
    h=next(h for h,b in self.packages.items() if b[:16]==uuid.UUID(NVME).bytes_le);b=bytearray(self.packages[h]);b[-9]^=1;self.packages[h]=bytes(b)
   if mode=='extra_unknown':
    h=next(h for h,b in self.packages.items() if b[:16]==uuid.UUID(UNKNOWN).bytes_le);self.packages[0xd00000]=self.packages[h];self.drivers[0xd00000]=self.drivers[h]
   if mode=='wrong_callback':
    h=next(h for h,b in self.packages.items() if b[:16]==uuid.UUID(NVME).bytes_le);c=self.configs[self.drivers[h]];self.w64(c+16,self.r64(c+16)+1)
   if mode=='unknown_path_changed':
    path=self.r64(self.loaded[0x6888]+32);self.u.mem_write(path+4,b'B')
   self.spf_reads=[];self.spf_started=False
   if mode.startswith('spf_'):
    record=json.loads((HERE.parent/'parser_review06/original_inventory.json').read_text());raw=Path(record['original_source']).read_bytes();assert hashlib.sha256(raw).hexdigest()==record['original_sha256'];self.spf_base=0x7000000
    self.u.mem_map(self.spf_base,(len(raw)+4095)&~4095);self.u.mem_write(self.spf_base,raw)
    self.module_images['SOURCE_SPF']=(self.spf_base,raw)
    tse=self.module_bases['AMITSE']
    for off,val in zip((0xbab20,0xbab10,0xbab18,0xbabc0,0xbaaf0),(self.spf_base,self.spf_base+0x60,self.spf_base+0xf2394,0x90000000,0x90001000)):self.w64(tse+off,val)
    if mode=='spf_unmapped_source':self.w64(tse+0xbab20,0xdead0000)
    def observe(u,address,size,user):
     if address==fixture.symbols['s7_capture_pair']:self.spf_started=True
     elif address==fixture.symbols['host_copy']:
      a=u.reg_read(UC_X86_REG_RDX);n=u.reg_read(UC_X86_REG_R9)
      if self.spf_base<=a<self.spf_base+0x100000:self.spf_reads.append((a-self.spf_base,n))
    for symbol in ('s7_capture_pair','host_copy'):self.u.hook_add(UC_HOOK_CODE,observe,begin=fixture.symbols[symbol],end=fixture.symbols[symbol])
   self.module_images={n:(a,bytes(self.u.mem_read(a,len(b)))) for n,(a,b) in self.module_images.items()}
  def hook(self,u,address,size,user):
   name=self.stubs.get(address)
   if mode=='spf_loaded_changed' and self.spf_started and name=='HandleProtocol' and u.reg_read(UC_X86_REG_RCX)==0x1111:
    self.w64(self.loaded[0x1111]+72,0xdf000)
   if mode=='duplicate_hii' and name=='ListPackages' and self.r64(u.reg_read(UC_X86_REG_R9))>=len(self.packages)*8:
    super().hook(u,address,size,user);sp=u.reg_read(UC_X86_REG_RSP);outp=self.r64(sp+40);self.w64(outp+8,self.r64(outp));return
   return super().hook(u,address,size,user)
 m=Machine();m.u.reg_write(UC_X86_REG_RSP,0xefff08);m.w64(0xefff08,0x8ff000);m.u.reg_write(UC_X86_REG_RCX,0x3333);m.u.reg_write(UC_X86_REG_RDX,m.st)
 m.u.emu_start(m.entry,0x8ff000,count=450000000);assert m.u.reg_read(UC_X86_REG_RIP)==0x8ff000,'instruction limit';assert m.u.reg_read(UC_X86_REG_RAX)==0
 for a,b in m.module_images.values():assert bytes(m.u.mem_read(a,len(b)))==b
 for a,n in m.allocations.items():assert bytes(m.u.mem_read(a-16,16))==b'\xa5'*16 and bytes(m.u.mem_read(a+n,16))==b'\xa5'*16
 assert not m.created and not m.log and not any(n.startswith('FORBIDDEN') for n in m.calls)
 log=m.output.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode('ascii');payload=selection['payload'];decoded=parse(log,payload['targets'],bytes.fromhex(payload['source_log_sha256']),bytes.fromhex(selection['selection_sha256']),BASE,15360)
 if mode=='normal':assert decoded['complete'] and len(decoded['objects'])==5
 if mode.startswith('spf_'):
  if shipping:assert decoded['refused']==[1,2,3,4,5]
  else:assert decoded['complete']
  allowed={(0x44,4),(0,4),(0x2c,4),(0x30,4),(0x40,4),(0x60,4),(0x64,4),(0x64+378*4,4),(0xf2364,4),(0xf2368,4),(0x650,8),(0x12,2),(0x08,2),(0x0a,2)}
  assert all(read in allowed for read in m.spf_reads),m.spf_reads
  if mode=='spf_complete':assert decoded['spf']['both_reads_complete'] and decoded['spf']['carrier_state']=='COMPLETE_OBSERVATION' and len(m.spf_reads)==28
  elif mode=='spf_unmapped_source':assert not decoded['spf']['both_reads_complete'] and not m.spf_reads
  elif mode=='spf_loaded_changed':assert decoded['spf']['carrier_state']=='MODULE_CHANGED' and not decoded['spf']['both_reads_complete'] and decoded['spf']['a']['fields']['source'] is None
 if mode=='huge_socket':assert decoded['omitted']==[5] and len(decoded['objects'])==4
 if mode=='shipping_refuses_synthetic':assert decoded['refused']==[1,2,3,4,5]
 expected={'forms_changed':[2],'bad_producer_text':[5],'bad_reloc':[5],'cpu_saved_mismatch':[1],'duplicate_owner':[3,4],'extra_unknown':[3,4],'wrong_callback':[2],'unknown_path_changed':[3,4],'warning_driver':[1,2,3,4,5],'map_error':[1,2,3,4,5],'duplicate_hii':[1,2,3,4,5]}
 if mode in expected:assert decoded['refused']==expected[mode],(mode,decoded['refused'],log.decode())
 for obj in decoded['objects'].values():assert obj['forms']==forms[obj['metadata']['package_list_guid']]
 case_name=('shipping_' if shipping else '')+mode;case_dir=out/'efi_cases';case_dir.mkdir(exist_ok=True);(case_dir/(case_name+'.txt')).write_bytes(log)
 return {'case':case_name,'passed':True,'efi_sha256':sha(out/'BOOTX64.EFI'),'selection_sha256':selection['selection_sha256'],'bytes':len(log),'pages':(len(log)+767)//768,'exported':len(decoded['objects']),'omitted':decoded['omitted'],'refused':decoded['refused'],'spf':decoded['spf'],'spf_reads':m.spf_reads,'foreign_memory_unchanged':True,'variable_calls':0,'filesystem_calls':0,'business_calls':0,'sha_oracle_calls':m.sha_calls,'cpu_observation_oracle_calls':m.cpu_calls}
def main():
 p=argparse.ArgumentParser();p.add_argument('--skip-build',action='store_true');p.add_argument('--case',action='append');a=p.parse_args();out=HERE/'build';lab=out/'lab';selpath=lab/'SYNTHETIC-selection.json';selection=lab_selection(selpath)
 if not a.skip_build:subprocess.run([sys.executable,'-X','utf8',str(HERE/'build.py'),'--selection',str(selpath),'--out',str(lab)],check=True)
 results=[]
 for mode in (a.case or ['normal','forms_changed','bad_producer_text','bad_reloc','cpu_saved_mismatch','duplicate_owner','extra_unknown','wrong_callback','unknown_path_changed','warning_driver','map_error','duplicate_hii','spf_complete','spf_unmapped_source','spf_loaded_changed']):
  r=run_case(lab,selection,mode);results.append(r);print(json.dumps({k:r[k] for k in ('case','passed','bytes','exported','omitted','refused')}),flush=True)
 shipping=json.loads((HERE/'selection_hardware02.json').read_text());r=run_case(out,shipping,'shipping_refuses_synthetic');results.append(r);print(json.dumps({k:r[k] for k in ('case','passed','bytes','exported','omitted','refused')}),flush=True)
 r=run_case(out,shipping,'spf_complete',shipping=True);results.append(r);print(json.dumps({k:r[k] for k in ('case','passed','bytes','exported','omitted','refused')}),flush=True)
 if not a.case:
  huge=out/'lab_huge';hp=huge/'SYNTHETIC-selection.json';hs=lab_selection(hp,True)
  if not a.skip_build:subprocess.run([sys.executable,'-X','utf8',str(HERE/'build.py'),'--selection',str(hp),'--out',str(huge)],check=True)
  r=run_case(huge,hs,'huge_socket',True);results.append(r);print(json.dumps({k:r[k] for k in ('case','passed','bytes','exported','omitted','refused')}),flush=True)
 report={'passed':True,'count':len(results),'cases':results,'shipping_efi_sha256':sha(out/'BOOTX64.EFI'),'scope':'Actual EFI instructions and original producer PE bytes. Synthetic services/identity page tables/CPU observations/SHA oracle. Successful content cases use separately compiled LAB selection, never the hardware selection. No device access.'}
 (out/'efi_tests.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
