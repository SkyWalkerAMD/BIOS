"""Inspect original extracted files and record dispatch/event candidates only."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import json, hashlib, uuid
HERE=Path(__file__).resolve().parent
BASE=HERE.parents[2]
meta=json.loads((BASE/'analysis/module_metadata.json').read_text(encoding='utf-8'))
sf=Path(meta['Setup']['source_path']).parents[1]
af=Path(meta['AMITSE']['source_path']).parents[2]
fv=sf.parent
dump=next(p for p in sf.parents if p.name.endswith('.CAP.dump'))
guids={
 'EndOfDxe':'02ce967a-dd7e-4ffc-9ee7-810cf0470880',
 'TseBootManager':'8a91b1e1-56c7-4adc-abeb-1c2ca1729eff',
 'BdsArch':'665e3ff6-46cc-11d4-9a38-0090273fc14d',
 'FormBrowser2':'b9d4c360-bcfb-4f9b-9298-53c136982258',
}
patterns={k:uuid.UUID(v).bytes_le for k,v in guids.items()}
hits=[];n=0
for p in dump.rglob('body.bin'):
 if 'PE32 image section' not in p.parent.name: continue
 n+=1; b=p.read_bytes(); h={}
 for name,pattern in patterns.items():
  offsets=[]; pos=0
  while True:
   pos=b.find(pattern,pos)
   if pos<0:break
   offsets.append(hex(pos));pos+=1
  if offsets:h[name]=offsets
 if h:
  hits.append({'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'guid_file_offsets':h})
depex={}
for name,p in [('Setup',sf),('AMITSE',af)]:
 depex[name]={'file_info':(p/'info.txt').read_text(),'sections':[]}
 for d in p.rglob('info.txt'):
  if 'dependency' in d.parent.name:
   depex[name]['sections'].append({'path':str(d),'info':d.read_text(),'body_hex':(d.parent/'body.bin').read_bytes().hex()})
ap=fv/'0 DXE apriori file/0 Raw section/body.bin';b=ap.read_bytes()
report={'scope':'Read-only original CAP extracted PE files; GUID presence is a candidate, not an observed call or dynamic sequence.',
 'guid_definitions':guids,'scanned_pe32_files':n,'hits':hits,'depex':depex,
 'apriori':{'path':str(ap),'sha256':hashlib.sha256(b).hexdigest(),'guids':[str(uuid.UUID(bytes_le=b[i:i+16])) for i in range(0,len(b),16)]}}
(HERE/'dxe_order_inventory.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print('PE files',n,'hits',len(hits))
for h in hits:print(h['guid_file_offsets'],h['path'].split(str(fv))[-1])
