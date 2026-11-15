from pathlib import Path
import json,struct,hashlib,uuid
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
src=P/'artifacts/Creator-PeiSelStatusCode.efi';b=src.read_bytes()
base=struct.unpack_from('<Q',b,16)[0];adjust=struct.unpack_from('<H',b,6)[0]-40
sections=[]
for i in range(b[4]):
 o=40+i*40;vs,va,size,raw=struct.unpack_from('<4I',b,o+8)
 sections.append((va,size,raw-adjust))
def offset(addr):
 rva=addr-base
 for va,size,raw in sections:
  if va<=rva<va+size:return raw+rva-va
 raise ValueError(hex(addr))
origin=0xfff832c8;size=0x2c4;off=offset(origin);table=b[off:off+size]
assert len(table)==59*12
rows=[]
for i in range(59):
 data=table[i*12:i*12+12];value,kind,sensor,d1,d2,d3=struct.unpack('<IIBBBB',data)
 rows.append({'index':i,'address':hex(origin+12*i),'status_value':hex(value),'status_type_low8':kind,
 'sensor_type':hex(sensor),'event_data':[hex(d1),hex(d2),hex(d3)],'bytes':data.hex()})
names={}
for line in (ROOT/'analysis/uefitool_guids.csv').read_text(encoding='utf-8-sig').splitlines():
 if ',' in line:
  g,n=line.split(',',1);names[g.upper()]=n
inv=json.loads((ROOT/'analysis/inventory.json').read_text(encoding='utf-8'))
matches=[];statusmods=[]
needle=table[:48]
for m in inv['ProArt-Z790-CREATOR-WIFI-ASUS-IPMI-3002.CAP']:
 name=names.get(m['guid'],'')
 if 'StatusCode' in name:statusmods.append({'guid':m['guid'],'name':name,'path':m['path']})
 for f in (ROOT/m['path']).rglob('body.bin'):
  if not('PE32 image' in f.parent.name or 'TE image' in f.parent.name):continue
  data=f.read_bytes();pos=data.find(needle)
  if pos>=0:matches.append({'guid':m['guid'],'name':name,'path':str(f.relative_to(ROOT)),
  'offset':hex(pos),'whole_table_matches':data[pos:pos+size]==table,'sha256':hashlib.sha256(data).hexdigest()})
result={'source':str(src.relative_to(ROOT)),'sha256':hashlib.sha256(b).hexdigest(),'table_address':hex(origin),
 'table_file_offset':hex(off),'entry_size':12,'count':59,'lookup_function':'0xfff82ef2',
 'type_filter':'Handler reduces EFI_STATUS_CODE_TYPE to low 8 bits; only 1 (progress) and 2 (error) eligible.',
 'record_format':'16 bytes: RecordID=0, RecordType=2, Timestamp=0, GeneratorID=1, EvMRevision=4, SensorType=table[8], SensorNumber=0, EventType=0x6F, EventData1..3=table[9..11].',
 'referenced_guids':[{ 'address':hex(addr), 'guid':str(uuid.UUID(bytes_le=b[offset(addr):offset(addr)+16]))} for addr in [0xfff83248,0xfff83258,0xfff83268,0xfff83288,0xfff83298,0xfff832a8]],
 'rows':rows,'same_table_in_creator':matches,'status_named_modules':statusmods}
(P/'creator-post-status-mapping.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'entries':len(rows),'matches':matches,'statusmodules':statusmods},indent=2))
for row in rows[:12]:print(row)
