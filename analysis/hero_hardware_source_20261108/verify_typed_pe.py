"""Run the new PE using the frozen I4 service doubles; no additional IO permitted."""
from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,re,struct,sys,zlib
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
spec=importlib.util.spec_from_file_location('i4_pe',ROOT/'analysis/hero_pcie_collect_i4_20261108/verify_i4_pe.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);base.APP=P/'HHS-TEST-CARRIER.EFI'
from unicorn.x86_const import *
from abi_types import Record,Result,Visitor,Sink,HpcRecord,Capture

class Machine(base.Machine):
 def __init__(self,scenario='normal'):
  super().__init__(scenario)
  self.snapshots=[];self.workspace_size=json.loads((P/'build.json').read_text())['workspace_bytes']
  self.workspace=self.alloc(bytes(self.workspace_size));self.result=self.alloc(bytes(C.sizeof(Result)))
  self.visitor_fn=self.new_stub('TypedVisit');self.visitor=self.alloc(struct.pack('<IIQQ',1,C.sizeof(Visitor),0,self.visitor_fn))
  self.sink=self.alloc(bytes(C.sizeof(Sink)));self.hpc_records=self.alloc(bytes(C.sizeof(HpcRecord)*128));self.capture=self.alloc(bytes(C.sizeof(Capture)))
 def address(self,name):
  text=(P/'source.map').read_text();m=re.search(r'\b'+re.escape(name)+r'\s+([0-9a-fA-F]{16})',text);assert m,name;return int(m[1],16)
 def call(self,name,args):
  stack=0x70ffef8;self.w64(stack,self.stop);self.u.reg_write(UC_X86_REG_RSP,stack)
  for reg,value in zip((UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9),args):self.u.reg_write(reg,value)
  for i,value in enumerate(args[4:]):self.w64(stack+40+8*i,value)
  address=self.base+self.pe.OPTIONAL_HEADER.AddressOfEntryPoint if name=='entry' else self.address(name)
  self.u.emu_start(address,self.stop,count=90_000_000);assert self.u.reg_read(UC_X86_REG_RIP)==self.stop
  return self.u.reg_read(UC_X86_REG_RAX)
 def hook(self,u,address,size,user):
  if self.stubs.get(address)!='TypedVisit':return super().hook(u,address,size,user)
  self.calls.append('TypedVisit');a=u.reg_read(UC_X86_REG_RCX);ptr=u.reg_read(UC_X86_REG_RDX);assert a==0
  r=Record.from_buffer_copy(bytes(u.mem_read(ptr,C.sizeof(Record))));assert r.version==1 and r.bytes==C.sizeof(Record)
  item=dict(kind=r.kind,index=r.source_index,valid=r.valid,incomplete=r.incomplete,issues=r.issues,handle=r.source_handle,
    path_valid=r.path.valid,path_stable=r.path.stable,path_first_bytes=r.path.first_bytes,path_second_bytes=r.path.second_bytes,
    path_first=bytes(u.mem_read(r.path.first,r.path.first_bytes)).hex() if r.path.first_bytes else '')
  if r.kind==1:
   v=r.data.pci;item.update(flags=v.flags,bdf=[v.segment,v.bus,v.device,v.function],config=bytes(u.mem_read(v.config,v.config_bytes)).hex() if v.config_bytes else '',config_crc32=v.config_crc32)
  elif r.kind==2:
   v=r.data.block;item.update(media_stable=v.stable,media_bytes=v.media_bytes,media=bytes(u.mem_read(v.first,v.media_bytes)).hex() if v.readable else '')
  else:
   v=r.data.disk;item.update(identify_status=v.identify_status,identify_bytes=v.captured_bytes,identify=bytes(u.mem_read(v.identify,v.captured_bytes)).hex() if v.captured_bytes else '',skip=v.skip,guards=v.buffer_guards_ok,format_size=v.format_size_match)
  self.snapshots.append(item)
  status=1 if self.scenario=='visitor_abort' else 0;u.reg_write(UC_X86_REG_RAX,status)
  for reg in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(reg,0xcccccccccccccccc)
 def collect(self):
  assert self.call('HeroHardwareSourceWorkspaceSize',[])==self.workspace_size
  assert self.call('HeroHardwareSourceInit',[self.workspace,self.workspace_size])==0
  status=self.call('HeroHardwareSourceCollect',[self.st,self.workspace,self.workspace_size,self.visitor,self.result]);assert not self.owned
  result=Result.from_buffer_copy(bytes(self.u.mem_read(self.result,C.sizeof(Result))));assert result.version==1 and result.bytes==C.sizeof(Result) and result.status==status
  return status,result

def main():
 rows=[]
 cases=['normal','ata','unknown_disk','identify_error','identify_too_large','short_identify','identify_overrun','no_devices','map_error','mmio_map','count_cap','path_missing','path_outside_map','protocol_outside_map','malformed_path','media_changes','location_error','config_error','enum_error_with_buffer','free_fail','visitor_abort']
 for case in cases:
  m=Machine(case);status,result=m.collect()
  expected=0 if case in ('normal','ata','unknown_disk','no_devices') else base.ERR(21) if case=='visitor_abort' else base.ERR(7) if case=='free_fail' else base.ERR(6)
  assert status==expected,(case,hex(status))
  assert result.complete==(expected==0) and result.incomplete==(expected!=0)
  if case in ('normal','ata'):assert len(m.snapshots)==3 and all(x['valid'] for x in m.snapshots)
  if case=='unknown_disk':assert m.identify_calls==0 and m.snapshots[-1]['skip']==1 and result.groups[2].complete
  if case in ('identify_error','identify_too_large','short_identify','identify_overrun'):
   assert result.groups[0].complete and result.groups[1].complete and not result.groups[2].complete
  if case in ('identify_error','identify_too_large','identify_overrun'):assert m.snapshots[-1]['identify_bytes']==0
  if case=='identify_too_large':assert m.identify_calls==1
  if case=='media_changes':assert not result.groups[1].stable and not result.groups[1].complete and result.groups[0].complete
  if case=='visitor_abort':assert result.visitor_aborted and len(m.frees)==1 and not result.groups[0].complete and result.groups[0].captured==0
  if case=='count_cap':assert result.groups[0].declared==129 and result.groups[0].captured==128 and result.groups[0].truncated
  if case in ('map_error','mmio_map','protocol_outside_map'):assert m.config_calls==0 and m.identify_calls==0
  assert not any(n.startswith('Forbidden') for n in m.calls)
  groups=[{f:getattr(g,f) for f in ['kind','declared','captured','complete','stable','truncated','issues','source_bytes','source_crc32']} for g in result.groups]
  if case=='normal':(P/'actual-pe-typed-records.json').write_text(json.dumps(dict(groups=groups,records=m.snapshots),indent=2)+'\n')
  rows.append(dict(case=case,passed=True,status=f'{status:016X}',groups=groups,calls=sorted(set(m.calls))))
  print(case+' PASS',flush=True)
 # Exercise real compiled PCI copy/capture adapter as the native visitor.
 for case in ('normal','identify_error','free_fail','location_error','count_cap'):
  m=Machine(case);assert m.call('HeroHardwareSourceInit',[m.workspace,m.workspace_size])==0
  assert m.call('HeroHardwarePciSinkInit',[m.sink,m.hpc_records,128])==0
  m.w64(m.visitor+8,m.sink);m.w64(m.visitor+16,m.address('HeroHardwarePciVisit'))
  status=m.call('HeroHardwareSourceCollect',[m.st,m.workspace,m.workspace_size,m.visitor,m.result]);assert not m.owned
  result=m.call('HeroHardwarePciCapture',[m.sink,m.result,m.capture])
  assert (result==0)==(case in ('normal','identify_error')),(case,result)
  if result==0:
   rec=HpcRecord.from_buffer_copy(bytes(m.u.mem_read(m.hpc_records,C.sizeof(HpcRecord))))
   cap=Capture.from_buffer_copy(bytes(m.u.mem_read(m.capture,C.sizeof(Capture))))
   assert rec.flags==7 and rec.segment==0 and rec.bus==1 and rec.path_bytes==10 and zlib.crc32(bytes(rec.config))==rec.config_crc32
   assert cap.pci_complete==1 and cap.pci_declared==cap.pci_captured==1 and cap.cleanup_status==0
  rows.append(dict(case='compiled_adapter_'+case,passed=True,source_status=f'{status:016X}',capture_result=result,calls=sorted(set(m.calls))))
  print('compiled_adapter_'+case+' PASS',flush=True)
 m=Machine();assert m.call('entry',[])==base.ERR(3) and not m.calls;rows.append(dict(case='test_carrier_entry_no_actions',passed=True))
 allowed={'Handles','GetMap','Handle','Config','Location','Identify','FreePool','TypedVisit'}
 assert all(set(row.get('calls',[]))<=allowed for row in rows)
 report=dict(passed=True,scope='Exact new EFI PE with frozen I4 service doubles; typed visitor and adapter, no hardware',pe_sha256=hashlib.sha256(base.APP.read_bytes()).hexdigest(),workspace_bytes=m.workspace_size,record_bytes=C.sizeof(Record),result_bytes=C.sizeof(Result),new_hardware_methods_added=False,allowed_UEFI_methods=sorted(allowed-{'TypedVisit'}),cases=rows)
 (P/'pe-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows)}))
if __name__=='__main__':main()
