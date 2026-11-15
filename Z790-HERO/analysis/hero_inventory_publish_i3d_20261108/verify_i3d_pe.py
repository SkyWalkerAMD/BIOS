"""Execute the delivered I3d PE against captured SMBIOS and strict EFI doubles."""
from pathlib import Path
import hashlib,json,re,struct,sys,types,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from unicorn.x86_const import *
base=types.ModuleType('p6_test_base');base.__file__=str(ROOT/'analysis/hero_ipmi_p6_20261104/collector/verify_app.py')
code=Path(base.__file__).read_text()
code=code.replace('self.u.mem_map(0x100000,0xf00000)','self.u.mem_map(0x100000,0xf00000);self.u.mem_map(0x10000000,0x1000000)')
code=code.replace('relocate_image(0x100000)','relocate_image(0x10000000)').replace('self.u.mem_write(0x100000,self.pe','self.u.mem_write(0x10000000,self.pe').replace('self.entry=0x100000+','self.entry=0x10000000+')
code=code.replace('self.u.hook_add(UC_HOOK_CODE,self.hook)','self.initial_code_hook=self.u.hook_add(UC_HOOK_CODE,self.hook)')
exec(compile(code,base.__file__,'exec'),base.__dict__);base.P=HERE
capture=(ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_text(encoding='utf-8')
original=bytes.fromhex(capture.split('TABLE_HEX_BEGIN\n')[1].split('TABLE_HEX_END')[0])
entries=[];at=0
while at<len(original):
 t,n=original[at:at+2];end=original.index(b'\0\0',at+n)+2;entries.append((t,at,end));at=end
 if t==127:break
symbols={}
for line in (HERE/'BOOTX64.EFI.map').read_text().splitlines():
 m=re.match(r'\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+(\S+)\s+([0-9A-Fa-f]{16})\s',line)
 if m:symbols[m[1]]=int(m[2],16)-0x140000000+0x10000000
class Machine(base.Machine):
 def __init__(self,keys,case='correct',volume=False,writable=False,bad_marker=False):
  self.case=case;self.volume=volume
  super().__init__(keys=keys,resident=False,p6_resident=False,writable=writable,bad_marker=bad_marker)
  raw=bytearray(original);one=next(a for t,a,b in entries if t==1)
  if case=='uuid':raw[one+8]^=1
  if case=='board':raw[raw.index(b'ROG MAXIMUS Z790 HERO')]=ord('X')
  if case=='bios':raw[raw.index(b'3107')+3]=ord('8')
  if case=='cpu':raw[next(a for t,a,b in entries if t==4)+6]^=1
  if case=='dimm':raw[next(a for t,a,b in entries if t==17)+6]^=1
  if case=='duplicate_type1':
   start,end=next((a,b) for t,a,b in entries if t==1);raw=raw[:-6]+raw[start:end]+raw[-6:]
  if case=='truncated':raw=raw[:-1]
  addr=self.alloc(bytes(raw));ep=bytearray(b'_SM3_\0'+bytes([24,3,5,0,1,0])+struct.pack('<IQ',len(raw),addr));ep[5]=(-sum(ep))&255
  if case=='checksum':ep[5]^=1
  eptr=self.alloc(bytes(ep));table=self.alloc(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',eptr))
  self.w64(self.st+0x68,0 if case=='missing' else 1);self.w64(self.st+0x70,table)
  self.stub(self.rt+0x48,'ReadVariable');self.stub(self.bs+0x100,'DisableAppWatchdog');self.stub(self.bs+0x38,'ReadMemoryMap')
  self.u.hook_del(self.initial_code_hook)
  for address in self.stubs:self.u.hook_add(base.UC_HOOK_CODE,self.hook,begin=address,end=address)
 def hook(self,u,address,size,data):
  name=self.stubs.get(address)
  if name and (name.startswith('R2') or name.startswith('P6')):raise AssertionError('No resident core calls')
  if name not in ('Handle','Locate','ReadVariable','ReadMemoryMap','DisableAppWatchdog','FileOpen','FileRead'):return super().hook(u,address,size,data)
  self.calls.append(name);rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)];result=base.ERR(14)
  if name=='Handle':
   self.w64(c,0);g=self.guid(b)
   if self.volume and a==base.IMAGE and g=='5b1b31a1-9562-11d2-8e3f-00a0c969723b':self.w64(c,self.loaded);result=0
   elif self.volume and a==0x7777 and g=='964e5b22-6459-11d2-8e39-00a0c969723b':self.w64(c,self.fs);result=0
  elif name=='Locate':
   assert self.guid(a) in ('952cb795-ff36-48cf-a249-4df486d6ab8d','9042a9de-23dc-4a38-96fb-7aded080516a','30cfe3e7-3de1-4586-be20-deaba1b3b793','6441f818-6362-4e44-b570-7dba31dd2453','ef9fc172-a1b2-4693-b327-6d32fc416042','0fd96974-23aa-4cdc-b9cb-98d17750322a','6a1ee763-d47a-43b4-aabe-ef1de2ab56fc','40823e46-8089-43f6-aa64-a6334212bb12')
   self.w64(c,0)
   if self.guid(a)=='40823e46-8089-43f6-aa64-a6334212bb12' and self.case=='old_r2_present':result=0
  elif name=='ReadVariable':
   if self.wide(a)=='TlsCaCertificate':assert self.r64(d)==0
   else:assert self.wide(a)=='NetworkStackVar' and self.r64(d)==64 and self.guid(b)=='d1405d16-7afc-4695-bb12-41459d3695a2'
  elif name=='ReadMemoryMap':
   assert self.r64(a)==65536
  elif name=='DisableAppWatchdog':
   assert (a,b,c,d)==(0,0,0,0);result=base.ERR(3) if self.case=='watchdog_failure' else 0
  elif name=='FileRead':
   assert a==self.marker;v=b'WRONG\n' if self.bad_marker else b'HERO-INVENTORY-I3D\n';assert self.r64(b)>=len(v);self.w64(b,len(v));u.mem_write(c,v);result=0
  else:
   path=self.wide(c)
   if path=='\\HERO_I3D.TAG':assert d==1;self.w64(b,self.marker);result=0
   elif re.fullmatch(r'\\I3D[0-9]{3}\.TXT',path):
    if d==1:
     if path in self.files:self.w64(b,self.file);result=0
    else:
     assert d==0x8000000000000003 and path not in self.files;result=base.ERR(8)
     if self.writable:self.created=True;self.files[path]=bytearray();self.file_name=path;self.pos=0;self.w64(b,self.file);result=0
   else:raise AssertionError(path)
  u.reg_write(UC_X86_REG_RAX,result)
  for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(r,0xcccccccccccccccc)
 def audit_bytes(self):
  n=self.r64(symbols['audit_len']);assert n<2097152;return bytes(self.u.mem_read(symbols['audit'],n))
rows=[]
for case in ('correct','uuid','board','bios','cpu','dimm','duplicate_type1','truncated','checksum','missing','watchdog_failure','old_r2_present'):
 m=Machine('\r\x1bdunpbwiwhssrq\rqq',case);status,output=m.run();assert status==0 and not m.keys
 assert 'HERO Inventory I3d - INVENTORY CONTINUATION' in output
 good=case in ('correct','cpu','dimm','watchdog_failure','old_r2_present')
 expected='I3_TARGET_71_VERIFIED=0x'+('0000000000000001' if good else '0000000000000000');assert expected in output
 assert 'HERO Inventory I3d RETURNING TO FIRMWARE' in output and m.calls.count('DisableAppWatchdog')==1
 log=m.audit_bytes()
 if not good:assert 'Handles' not in m.calls and 'Locate' not in m.calls and 'ReadVariable' not in m.calls
 else:
  assert 'Handles' in m.calls and 'ReadVariable' in m.calls and b'HERO_DEPEX_READONLY_D1_BEGIN' in log
  exact=b'I3D_INVENTORY_SOURCE_EXACT=0x'+(b'0000000000000000' if case in ('cpu','dimm') else b'0000000000000001');assert exact in log
  assert m.calls.count('ReadMemoryMap')==1 and b'DX_MAP_STATUS=800000000000000E' in log
  assert b'I3D_OLD_R2_METHODS_NOT_CALLED' in log
  if case=='old_r2_present':assert b'I3D_OLD_R2_PRESENT_AT_CAPTURE=0x0000000000000001' in log
 if case=='watchdog_failure':assert 'watchdog could not be disabled' in output
 rows.append({'case':'actual_pe_identity_'+case,'passed':True,'no_network_or_driver_start':True})
m=Machine('cv\x1b\x1bqq');status,output=m.run();assert status==0 and 'KVM_LOG_BEGIN' not in output and 'TEXT PAGE 1/' in output
log=m.audit_bytes();assert log.startswith(b'HERO-INVENTORY-I3D\r\nBUILD=I3D-71-CONTINUATION\r\nRUN=')
(HERE/'synthetic-identity-capture.TXT').write_bytes(log)
rows.append({'case':'actual_pe_capture_direct_paging_and_exit_keys','passed':True})
for volume,writable,bad in ((False,False,False),(True,False,False),(True,True,True),(True,True,False)):
 m=Machine('llqq',volume=volume,writable=writable,bad_marker=bad);status,output=m.run();assert status==0
 if volume and writable and not bad:
  assert set(m.files)=={'\\I3D000.TXT','\\I3D001.TXT'}
  for v in m.files.values():assert v.startswith(b'HERO-INVENTORY-I3D\r\n') and b'I3D_UEFI_APPLICATION_WATCHDOG_DISABLE=0x0000000000000000' in v
 else:assert not m.files
 rows.append({'case':f'actual_pe_file_marker_{volume}_{writable}_{bad}','passed':True})
binary=(HERE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
for forbidden in (b'DELETE ',b'/Registries',b'/BiosStaticFiles',b'/Bios/SD',b'/Bios/Settings'):assert forbidden not in binary,forbidden
assert b'HERO-INVENTORY-I3D-QR1\n' in binary and b'PATCH ' in binary and b'POST ' in binary
cert=(ROOT/'analysis/hero_ipmi_continued_live_20261108/assets/bmc-71-public-leaf.der').read_bytes();assert cert in binary
rows.append({'case':'binary_no_bios_routes_and_exact_public_certificate','passed':True})
report={'all_passed':True,'count':len(rows),'cases':rows,'app_sha256':hashlib.sha256(binary).hexdigest(),
 'capture_sha256':hashlib.sha256((ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_bytes()).hexdigest(),
 'limits':['Actual PE with captured SMBIOS and synthetic EFI; no live .71 USB/TLS or publication.']}
(HERE/'pe-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(rows),'app_sha256':report['app_sha256']}))
