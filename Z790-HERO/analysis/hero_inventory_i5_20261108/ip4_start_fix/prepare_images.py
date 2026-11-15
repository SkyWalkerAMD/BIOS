"""Prepare hash-bound private RAM copies only; original firmware is untouched."""
from pathlib import Path
import hashlib,json,sys,zlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone

PLAN=[
 ('DpcDxe','4b63a9174d92b913bd765b2b49b57db4b714070e7678e152deabb5d0026f2dfa',None,None),
 ('SnpDxe','b186518817547c71ab0818f1bc0872c2d21e7f78ec42028498fba4247a263474',0x613,0x619),
 ('MnpDxe','690fddefa6de980d76137422c5dc1a8a92b62a451da8cfb9e9abdb46eb0bf3e5',0x637,0x63d),
 ('ArpDxe','c3cf643cb938463e55d4b47cf330871967680a57ace6dc8362536ee5ddcbebea',0x637,0x63d),
 ('Ip4Dxe','c3152865b50e5426511de8ee376cff2fb2c67eabaa2fdd4a774d4a995bb5e601',0x6fb,0x705),
 ('TcpDxe','ebb1897f10fd37fbe3a42518ac7a7c7b1fc0f04e33086bc4bc5fb973a467608c',0x68e,0x697),
]
rows=[]
for name,digest,start,end in PLAN:
 raw=(OUT/'reference'/(name+'.efi')).read_bytes();assert hashlib.sha256(raw).hexdigest()==digest
 pe=pefile.PE(data=raw);patches=[];data=bytearray(raw)
 if start is not None:
  offset=pe.get_offset_from_rva(start);old=raw[offset:offset+end-start]
  expected={'SnpDxe':'384424607462','MnpDxe':'384424607462','ArpDxe':'384424607462',
            'Ip4Dxe':'384424600f8483000000','TcpDxe':'3845200f8440010000'}[name]
  assert old.hex()==expected,(name,old.hex())
  ins=list(capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(old,start))
  assert len(ins)==2 and ins[0].mnemonic=='cmp' and ins[1].mnemonic=='je'
  data[offset:offset+len(old)]=b'\x90'*len(old)
  patches.append({'rva':hex(start),'file_offset':offset,'old':old.hex(),'new':'90'*len(old),
                  'purpose':'Private BMC-only RAM instance; bypass only successful NetworkStackVar enable flag check. Preserve failed GetVariable branch.'})
 if name=='Ip4Dxe':
  # REA confirms initialization calls these two MAC-named NVR configuration
  # helpers. A private RAM network instance uses only its own default state:
  # read returns NOT_FOUND, persistence reports success without NVR access.
  # No original firmware module or runtime services table is modified.
  for rva,expected,replacement,purpose in (
   (0x5bbc,'48895c2408488974241055','48b80e00000000000080c3','Private Ip4Config2 read: return EFI_NOT_FOUND; do not import saved interface configuration'),
   (0x5d88,'48895c','31c0c3','Private Ip4Config2 save: return EFI_SUCCESS; no SetVariable or flash persistence'),
   (0xec5,'e8f24c0000','31c0909090','Private Start only: use completed Ip4Config2Init defaults; skip the second saved-configuration read. First read remains NOT_FOUND, save remains no-op. No error branch or configuration initialization is bypassed')):
   at=pe.get_offset_from_rva(rva);old=bytes.fromhex(expected);new=bytes.fromhex(replacement)
   assert len(old)==len(new) and raw[at:at+len(old)]==old
   data[at:at+len(old)]=new
   patches.append({'rva':hex(rva),'file_offset':at,'old':expected,'new':replacement,'purpose':purpose})
 p=pefile.PE(data=bytes(data));p.OPTIONAL_HEADER.CheckSum=p.generate_checksum();data=p.write()
 file=OUT/'staged-drivers'/('I5'+name.upper()+'.EFI');file.write_bytes(data)
 rows.append({'name':name,'file':file.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
              'source_sha256':digest,'crc32':f'{zlib.crc32(data):08X}','patches':patches})
for name,sha in [('H6RNDIS.EFI','e265ab2e07ee0f477f8fc1da1d1f968740c8896be6b3caeb20f07bb258ece22b'),
                 ('H6USBLAN.EFI','bb55f635bfe0e4cf428f1a6b16700f7e250ddeed4c4a462ffb83e4c36bac99f0')]:
 data=(OUT/'staged-drivers'/name).read_bytes();assert hashlib.sha256(data).hexdigest()==sha
 rows.append({'name':name.split('.')[0],'file':name,'bytes':len(data),'sha256':sha,
              'crc32':f'{zlib.crc32(data):08X}','patches':'Unchanged frozen I3d driver; see base manifest'})
(OUT/'staged-drivers/manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
with (OUT/'source/driver_images.h').open('w') as f:
 f.write('/* Generated pinned RAM images. Not original firmware replacements. */\n')
 for row in rows:
  data=(OUT/'staged-drivers'/row['file']).read_bytes()
  f.write('static const uint8_t image_'+row['name']+'[]={\n')
  for off in range(0,len(data),24):f.write(','.join('0x%02x'%v for v in data[off:off+24])+',\n')
  f.write('};\n')
 f.write('typedef struct {const char *name;const uint8_t *bytes;UN length;uint32_t crc;} I5_IMAGE;\n')
 f.write('static const I5_IMAGE images[]={\n')
 for row in rows:f.write('{"%s",image_%s,sizeof(image_%s),0x%su},\n'%(row['name'],row['name'],row['name'],row['crc32']))
 f.write('};\n')
print('Pinned private RAM images',len(rows),'total bytes',sum(r['bytes'] for r in rows))
