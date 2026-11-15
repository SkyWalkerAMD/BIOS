"""Real host DMI bytes through the actual new launcher PE; services mocked."""
from pathlib import Path
import hashlib,json,struct
BASE=Path(__file__).resolve().parents[1];ROOT=BASE.parents[1]
namespace={'__file__':str(BASE/'tests/test_launcher_pe.py'),'__name__':'fixture_definitions'}
code=(BASE/'tests/test_launcher_pe.py').read_text().split('\nrows=[]')[0]
exec(compile(code,str(BASE/'tests/test_launcher_pe.py'),'exec'),namespace)
Machine=namespace['Machine'];ERR=namespace['ERR'];DEFAULT=namespace['DEFAULT']
evidence=ROOT/'analysis/hero15_rc5_live_20261108';raw=(evidence/'host-DMI.bin').read_bytes();epraw=(evidence/'host-smbios_entry_point.bin').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='9831e487a7a77ea5ff841e53ab36ff3474b56aa8a328d2a467c578a7a2859637'
rows=[]
for mode in ('exact_actual_table','wrong_uuid_byte','former_71_uuid','wrong_bios'):
 data=bytearray(raw);p=0
 while p<len(data):
  typ,n=data[p],data[p+1];end=data.index(b'\0\0',p+n)+2
  if typ==1:
   if mode=='wrong_uuid_byte':data[p+8]^=1
   if mode=='former_71_uuid':data[p+8:p+24]=bytes.fromhex('9565299beb5589e65fd208bfb8eeda44')
  if typ==0 and mode=='wrong_bios':
   at=data.index(b'3107',p+n,end);data[at:at+4]=b'9999'
  p=end
  if typ==127:break
 m=Machine(DEFAULT[:21]);m.u.mem_write(m.base+0x7000,bytes(data));ep=bytearray(epraw)
 assert ep[:5]==b'_SM3_' and len(ep)==24 and sum(ep)%256==0
 struct.pack_into('<IQ',ep,12,len(data),m.base+0x7000);ep[5]=0;ep[5]=(-sum(ep))&255;m.u.mem_write(m.base+0x6100,bytes(ep))
 text=m.run();assert m.calls.count('Load')==(1 if mode=='exact_actual_table' else 0),(mode,text)
 rows.append(mode)
report={'passed':True,'cases':4,'rows':rows,'launcher_sha256':hashlib.sha256((BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),'actual_DMI_sha256':hashlib.sha256(raw).hexdigest(),'scope':'Full raw host DMI and entry-point bytes rebased in emulated UEFI readable RAM, actual launcher execution; no hardware'}
(BASE/'tests/actual-host-identity.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
