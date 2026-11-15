"""Actual I5-C PE: standard DriverBinding entry + real current-SMBIOS builder.
UEFI ConnectController is a small x64 fixture that calls actual Supported and
Start methods; only network preparation and TLS are synthetic responses.
"""
from pe_fixture import *
OriginalMachine=Machine
class BindingMachine(OriginalMachine):
 def __init__(self,case):
  super().__init__(case);self.binding=0;self.trigger=0
  old=set(self.stubs)
  for off,name in ((0x118,'Open'),(0x120,'Close'),(0x90,'Uninstall')):self.stub(self.bs+off,name)
  connect=self.st+0x3e0000;self.stubs[connect]='Connect';self.w64(self.bs+0x108,connect);self.u.mem_write(connect,b'\xc3')
  self.stubs[symbols['i5_observe_bmc_usb']]='ObserveUsb'
  for address in self.stubs.keys()-old:self.u.hook_add(unicorn.UC_HOOK_CODE,self.hook,begin=address,end=address)
 def api(self):return struct.unpack('<IIIIQQQQQQQII',self.u.mem_read(self.published,80))
 def callback(self,address):
  stack=self.st+0xf0008;stop=self.st+0x3ff000;self.w64(stack,stop);self.u.reg_write(UC_X86_REG_RSP,stack)
  self.u.emu_start(address,stop,count=10000000);assert self.u.reg_read(UC_X86_REG_RIP)==stop;return self.u.reg_read(UC_X86_REG_RAX)
 def hook(self,u,at,size,ctx):
  name=self.stubs[at]
  if name not in ('Install','ObserveUsb','Connect','Open','Close','Uninstall'):return super().hook(u,at,size,ctx)
  self.calls.append(name);sp=u.reg_read(UC_X86_REG_RSP);a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];e=0
  if name=='Install':
   guid=str(uuid.UUID(bytes_le=bytes(u.mem_read(b,16))))
   if guid=='7e06fa9a-532e-44c6-928a-cf19d2718e4b':
    if self.case=='install_failure':e=ERR(9)
    else:self.published=d;self.w64(a,0x6000)
   elif guid=='18a031ab-b443-4d1a-a5c0-0c09261e9f71':
    assert self.r64(a)==0x77
    if self.case=='binding_install_failure':e=ERR(9)
    else:
     self.binding=d
     # Native ABI: save controller across real Supported and Start calls.
     code=bytes.fromhex('4883ec3848894c2420')+b'\x48\xb9'+struct.pack('<Q',d)+bytes.fromhex('488b5424204531c0488b01ffd04885c07515')+b'\x48\xb9'+struct.pack('<Q',d)+bytes.fromhex('488b5424204531c0ff51084883c438c3')
     target=next(k for k,v in self.stubs.items() if v=='Connect');u.mem_write(target,code)
   elif guid=='9412c522-5b86-4cae-8799-82ee194b9fa5':
    assert self.r64(a)==0x100 and d==self.published
    if self.case=='marker_install_failure':e=ERR(9)
    else:self.trigger=d
   else:raise AssertionError(guid)
  elif name=='ObserveUsb':
   self.w64(a,0x100);self.w64(a+8,0x101);e=0 if self.case=='no_usb' else 1
  elif name=='Connect':
   assert a==0x100 and self.r64(b)==0x77 and self.r64(b+8)==0 and c==0 and d==0
   return # Execute fixture code, not a shortcut to the work function.
  elif name=='Open':
   assert a==0x100 and d==0x77 and self.r64(sp+0x28)==0x100 and self.r64(sp+0x30)==0x10
   self.w64(c,self.trigger);e=ERR(7) if self.case=='marker_open_failure' else 0
  elif name=='Uninstall':assert a==0x100 and c==self.published;self.trigger=0
  elif name=='Close':assert a==0x100 and c==0x77 and d==0x100
  u.reg_write(UC_X86_REG_RAX,e);u.reg_write(UC_X86_REG_RIP,self.r64(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
rows=[]
badsource=('bad_uuid','zero_uuid','board','bios','truncated','duplicate','checksum','missing','memory_map_failure','mmio','current_capture_bad_cpu')
for case in ('success','changed_dimm','current_capture','no_usb','network_failure','tls_pin_changed','timeout','http401','cleanup_failure','source_changed_after_root','marker_install_failure','marker_open_failure','binding_install_failure',*badsource):
 m=BindingMachine(case);assert m.run()==0
 before=m.api();assert before[0]==0x42354e49 and before[1]==2 and before[2]==80
 assert 'i5_prepare_network' not in m.calls and 'GET0' not in m.calls # DriverEntry does no I/O.
 if not before[3]:m.callback(before[9])
 info=m.api();good=case in ('success','changed_dimm','current_capture');assert info[3]==(2 if good else 3),(case,info)
 assert (info[4]==0)==good and info[5]==4
 triggered=case not in ('no_usb','marker_install_failure','marker_open_failure','binding_install_failure')
 assert info[11]==int(triggered) and info[12]==int(triggered),(case,info)
 if case in badsource or not triggered:assert 'i5_prepare_network' not in m.calls and 'GET0' not in m.calls
 if case=='network_failure':assert 'GET0' not in m.calls
 if case in ('tls_pin_changed','timeout','http401','source_changed_after_root'):assert 'GET0' in m.calls and 'GET1' not in m.calls
 if good:assert m.calls.count('GET0')==1 and m.calls.count('GET1')==1
 before=list(m.calls);assert m.callback(info[9])==ERR(20);assert m.calls==before
 assert m.run()==ERR(20);assert m.calls.count('i5_prepare_network')<=1 and m.calls.count('GET0')<=1
 if triggered:assert b'I5_BINDING_START_TPL=0x0000000000000004' in m.log()
 if case=='changed_dimm':assert b'16384' in bytes(m.u.mem_read(info[8],34608))
 if case=='current_capture':assert b'I5_SOURCE_CRC32=0x000000008B120398' in m.log()
 if case=='current_capture_bad_cpu':assert b'I5_CATALOG_ERROR_TYPE=0x0000000000000004' in m.log()
 rows.append({'case':case,'state':info[3],'result':hex(info[4]),'binding_starts':info[11],'core_runs':info[12],'passed':True})
for case in ('install_failure','high_tpl'):
 m=BindingMachine(case);assert m.run()==(ERR(9) if case=='install_failure' else ERR(3));assert 'i5_prepare_network' not in m.calls;rows.append({'case':case,'passed':True})
m=BindingMachine('success');assert m.run()==0;m.tpl=8;m.callback(m.api()[9]);assert m.api()[3]==3 and m.api()[11]==m.api()[12]==0;rows.append({'case':'high_tpl_trigger_refused','passed':True})
for forbidden in (b'POST ',b'PATCH ',b'DELETE ',b'/Bios/Settings',b'/Bios/SD'):assert forbidden not in data,forbidden
report={'passed':True,'count':len(rows),'cases':rows,'pe_sha256':hashlib.sha256(data).hexdigest(),'scope':'Actual DriverEntry/DriverBinding.Supported/Start at TPL4 and current-host parser; fake UEFI transport/USB descriptor lookup, no hardware or native BDS timing claim'}
(BASE/'tests/binding-driver-pe.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='cases'}))
