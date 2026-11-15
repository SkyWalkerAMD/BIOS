"""Read-only extraction of unchanged target UEFI providers for hang review."""
from pathlib import Path
import hashlib,importlib.util,json,sys,re
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
spec=importlib.util.spec_from_file_location('prior_independent_cap',ROOT/'analysis/hero_rc5_independent_review_20261108/audit_rc5.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
parsed=a.image(a.BASELINE);rows=[]
for layer in ('outer','inner'):
 for guid,entry in parsed[layer]['files'].items():
  if entry['type'] in (1,0xf0):continue
  try:s=a.sections(entry['data'][24:])
  except ValueError:continue
  names=[(x['body'] if x['type']==0x15 else x['body'][2:]).decode('utf-16le').rstrip('\0') for x in s if x['type'] in (0x14,0x15)]
  images=[x['body'] for x in s if x['type']==0x10]
  if len(images)!=1:continue
  raw=images[0]
  pdbs=re.findall(rb'[ -~]{4,}\.pdb',raw)
  match={'348c4d62-bfbd-4882-9ece-c80bb1c4783b':'HiiDatabase','d6a2cb7f-6a18-4e2f-b43b-9920a733700a':'DxeCore'}.get(guid)
  if hashlib.sha256(raw).hexdigest()=='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c':match='AMITSE'
  if not match:continue
  name=match;(OUT/(name+'.efi')).write_bytes(raw)
  rows.append(dict(name=name,guid=guid,layer=layer,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
(OUT/'subjects.json').write_text(json.dumps(dict(baseline=str(a.BASELINE),sha256=hashlib.sha256(parsed['cap']).hexdigest(),subjects=rows),indent=2)+'\n')
print(json.dumps(rows,indent=2))
