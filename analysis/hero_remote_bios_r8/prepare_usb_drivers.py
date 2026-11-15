"""Prepare RAM-load-only network modules from the user's Creator image.

The only code change removes the Creator Setup[0xBF5] feature-option gate.
It does not change password, signature, variable-lock or recovery checks.
The application must independently require HERO 3107 and the observed BMC USB
VID/PID before loading either file. This script does not load or flash anything.
"""
from pathlib import Path
import hashlib,json,sys,zlib
OUT=Path(__file__).resolve().parent; ROOT=OUT.parents[1]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
origin=json.loads((OUT/'reference/usb-driver-origin.json').read_text())
rows=[]
for row in origin:
 source=OUT/'reference'/(row['guid']+'.efi');raw=source.read_bytes()
 assert hashlib.sha256(raw).hexdigest()==row['sha256']
 pe=pefile.PE(data=raw);data=bytearray(raw);patches=[]
 if row['guid'].startswith('11E32C34'):
  offset=pe.get_offset_from_rva(0x512)
  before=bytes.fromhex('80bd350b000001754b')
  assert data[offset:offset+len(before)]==before
  data[offset:offset+len(before)]=b'\x90'*len(before)
  patches=[{'rva':'0x512','file_offset':offset,'old':before.hex(),'new':(b'\x90'*len(before)).hex(),'reason':'remove only donor Setup[0xBF5] == 1 gate; retain GetVariable success and boot-mode checks'}]
  name='H6RNDIS.EFI'
 else:name='H6USBLAN.EFI'
 if patches:
  p=pefile.PE(data=bytes(data));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();data=p.write()
  patches.append({'field':'PE.OptionalHeader.CheckSum','reason':'recompute PE checksum after the feature-gate edit'})
 else:data=raw
 target=OUT/'staged-drivers'/name;target.parent.mkdir(exist_ok=True);target.write_bytes(data)
 rows.append({'name':name,'source_sha256':row['sha256'],'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'crc32':f'{zlib.crc32(data):08X}','patches':patches,'executed':False})
(OUT/'staged-drivers/manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows,indent=2))
