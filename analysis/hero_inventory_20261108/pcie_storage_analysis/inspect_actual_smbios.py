"""Inspect already captured HERO SMBIOS slot/onboard records; no machine I/O."""
from pathlib import Path
import collections,hashlib,json,sys
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
sys.path.insert(0,str(OUT.parent))
from smbios_inventory import parse_capture,string
source=ROOT/'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT'
records,meta=parse_capture(source.read_text(encoding='utf-8'))
rows=[]
for r in records:
 if r['type'] not in (9,41):continue
 d=r['data']; row=dict(type=r['type'],handle=f'{r["handle"]:04X}',formatted_hex=d.hex().upper(),strings=r['strings'])
 if r['type']==9:
  row.update(designation=string(r,4),slot_type_raw=d[5],slot_width_raw=d[6],current_usage_raw=d[7],slot_length_raw=d[8],slot_id=int.from_bytes(d[9:11],'little'))
  if len(d)>=17:
   segment=int.from_bytes(d[13:15],'little');bus=d[15];df=d[16]
   row.update(segment_raw=segment,bus_raw=bus,device_function_raw=df,
              address_known=segment!=0xffff and bus!=0xff and df!=0xff)
   if row['address_known']:row['bdf']=f'{segment:04X}:{bus:02X}:{df>>3:02X}.{df&7}'
  if len(d)>=19:row.update(data_bus_width_raw=d[17],peer_group_count=d[18])
 elif len(d)>=11:
  segment=int.from_bytes(d[7:9],'little');bus=d[9];df=d[10]
  row.update(designation=string(r,4),enabled=bool(d[5]&0x80),device_type_raw=d[5]&0x7f,instance=d[6],segment_raw=segment,bus_raw=bus,device_function_raw=df,address_known=segment!=0xffff and bus!=0xff and df!=0xff)
  if row['address_known']:row['bdf']=f'{segment:04X}:{bus:02X}:{df>>3:02X}.{df&7}'
 rows.append(row)
result=dict(source=source.relative_to(ROOT).as_posix(),source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),metadata=meta,type_counts=dict(collections.Counter(r['type'] for r in records)),slots_and_onboard=rows,interpretation='Historical SMBIOS declarations, not a current PCIe enumeration or proof that a device is installed in any slot.')
(OUT/'hero71-smbios-pcie.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2,ensure_ascii=False))
