from pathlib import Path
import hashlib,json,re,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
capture=ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT'
text=capture.read_text();raw=bytes.fromhex(text.split('TABLE_HEX_BEGIN\n')[1].split('TABLE_HEX_END')[0])
assert len(raw)==5957 and zlib.crc32(raw)==0x97f9e765
selected=bytearray();at=0;records=[]
while at<len(raw):
 typ,size=raw[at:at+2];end=raw.index(b'\0\0',at+size)+2
 if typ in (0,1,2,4,17):
  block=raw[at:end];selected+=block;records.append({'type':typ,'handle':int.from_bytes(raw[at+2:at+4],'little'),'length':len(block),'sha256':hashlib.sha256(block).hexdigest()})
 at=end
 if typ==127:break
assert at==len(raw)
(HERE/'source/inventory_source.h').write_text('/* Exact complete SMBIOS types 0/1/2/4/17 from the .71 I1 capture. */\nstatic const uint8_t inventory_source_records[]={\n'+''.join(','.join('0x%02x'%b for b in selected[i:i+16])+',\n' for i in range(0,len(selected),16))+'};\n')
(HERE/'identity-source.json').write_text(json.dumps({'capture_sha256':hashlib.sha256(capture.read_bytes()).hexdigest(),'table_sha256':hashlib.sha256(raw).hexdigest(),'selected_sha256':hashlib.sha256(selected).hexdigest(),'selected_bytes':len(selected),'records':records,'comparison':'Exact raw records including formatted section, handles, complete strings, original ordering. Entry version3.5; source identity fixed by I3 gate.'},indent=2)+'\n')
print('Selected exact SMBIOS bytes',len(selected))
