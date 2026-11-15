"""Execute the exact I3 app with captured .71 SMBIOS and deny all network writes."""
from pathlib import Path
import hashlib,importlib.util,json,re,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from unicorn.x86_const import *
spec=importlib.util.spec_from_file_location('p6_app_harness',ROOT/'analysis/hero_ipmi_p6_20261104/collector/verify_app.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base);base.P=HERE
capture=(ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_text(encoding='utf-8')
original=bytes.fromhex(capture.split('TABLE_HEX_BEGIN\n')[1].split('TABLE_HEX_END')[0])
entries=[];at=0
while at<len(original):
 t,n=original[at:at+2];end=original.index(b'\0\0',at+n)+2;entries.append((t,at,end));at=end
 if t==127:break
class Machine(base.Machine):
 def __init__(self,keys,case='correct'):
  super().__init__(keys=keys,resident=False,p6_resident=False)
  raw=bytearray(original)
  one=next(a for t,a,b in entries if t==1)
  if case=='uuid':raw[one+8]^=1
  if case=='board':raw[raw.index(b'ROG MAXIMUS Z790 HERO')]=ord('X')
  if case=='bios':raw[raw.index(b'3107')+3]=ord('8')
  if case=='duplicate_type1':
   start,end=next((a,b) for t,a,b in entries if t==1)
   raw=raw[:-6]+raw[start:end]+raw[-6:]
  if case=='truncated':raw=raw[:-1]
  addr=self.alloc(bytes(raw));ep=bytearray(b'_SM3_\0'+bytes([24,3,5,0,1,0])+struct.pack('<IQ',len(raw),addr));ep[5]=(-sum(ep))&255
  if case=='checksum':ep[5]^=1
  eptr=self.alloc(bytes(ep));table=self.alloc(uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+struct.pack('<Q',eptr))
  self.w64(self.st+0x68,0 if case=='missing' else 1);self.w64(self.st+0x70,table)
  self.stub(self.rt+0x48,'TlsCaSizeQuery')
 def hook(self,u,address,size,data):
  name=self.stubs.get(address)
  if name and (name.startswith('R2') or name.startswith('P6')):raise AssertionError('No resident core calls')
  if name not in ('Handle','Locate','TlsCaSizeQuery'):return super().hook(u,address,size,data)
  self.calls.append(name);rsp=u.reg_read(UC_X86_REG_RSP);assert rsp%16==8
  a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
  if name=='Handle':
   # No boot FS/USB NIC/GOP is exposed; this test must not try driver load.
   self.w64(c,0)
  elif name=='Locate':
   assert self.guid(a) in ('952cb795-ff36-48cf-a249-4df486d6ab8d','9042a9de-23dc-4a38-96fb-7aded080516a')
   self.w64(c,0)
  else:
   assert self.wide(a)=='TlsCaCertificate' and self.r64(d)==0
  u.reg_write(UC_X86_REG_RAX,base.ERR(14))
  for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11):u.reg_write(r,0xcccccccccccccccc)
rows=[]
for case in ('correct','uuid','board','bios','duplicate_type1','truncated','checksum','missing'):
 m=Machine('\r\x1bdunpbwhrq\rqq',case);status,output=m.run()
 assert status==0 and not m.keys
 assert 'HERO Inventory I3 - READ-ONLY INTERNAL USB/TLS' in output
 expected='I3_TARGET_71_VERIFIED=0x'+('0000000000000001' if case=='correct' else '0000000000000000')
 assert expected in output
 assert 'HERO Inventory I3 RETURNING TO FIRMWARE' in output
 if case!='correct':assert 'Handles' not in m.calls and 'Locate' not in m.calls and 'TlsCaSizeQuery' not in m.calls
 else:assert 'Handles' in m.calls and 'TlsCaSizeQuery' in m.calls
 rows.append({'case':'actual_pe_identity_'+case,'passed':True,'no_network_or_driver_start':True})
m=Machine('cv\x1b\x1bqq')
# First C uses text fallback; V within viewer is ignored, Esc returns. Extra Esc
# in main must not exit. This captures the actual app's snapshot header.
status,output=m.run();assert status==0 and 'KVM_LOG_BEGIN' in output
log=output.split('KVM_LOG_BEGIN\r\n',1)[1].split('KVM_LOG_END\r\n',1)[0].encode()
assert log.startswith(b'HERO-INVENTORY-I3\r\nBUILD=I3-71-PINNED-GET-ONLY\r\nRUN=')
(HERE/'synthetic-identity-capture.TXT').write_bytes(log)
rows.append({'case':'actual_pe_capture_header_and_exit_keys','passed':True})
binary=(HERE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
for forbidden in (b'POST /',b'PATCH /',b'/Registries',b'/BiosStaticFiles',b'/Bios/SD',b'/Bios/Settings'):
 assert forbidden not in binary,forbidden
assert b'HERO-INVENTORY-I3-QR1\n' in binary
cert=(ROOT/'analysis/hero_ipmi_continued_live_20261108/assets/bmc-71-public-leaf.der').read_bytes()
assert cert in binary
rows.append({'case':'binary_get_only_routes_and_exact_public_certificate','passed':True})
report={'all_passed':True,'count':len(rows),'cases':rows,'app_sha256':hashlib.sha256(binary).hexdigest(),
 'capture_sha256':hashlib.sha256((ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_bytes()).hexdigest(),
 'limits':['Captured SMBIOS is replayed in synthetic UEFI services; no live .71 execution or USB/TLS connection.']}
(HERE/'pe-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'count':len(rows),'app_sha256':report['app_sha256']}))
