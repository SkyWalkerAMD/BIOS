from pathlib import Path
import json,hashlib
p=Path(__file__).resolve().parent
out=p/'edk2_hii_reference';out.mkdir(exist_ok=True)
rows=[]
for x in json.loads((p/'edk2_hii_inputs.json').read_text(encoding='utf-8')):
    name=x['display_title'];assert name in ('UefiInternalFormRepresentation.h','HiiDatabase.h')
    b=x['content'].encode('utf-8');blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest();assert blob==x['sha']
    f=out/name;f.write_bytes(b)
    rows.append({'path':str(f),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob_sha':blob,'url':x['display_url']})
(out/'provenance.json').write_text(json.dumps({'source':'Official tianocore/edk2 default branch via GitHub plugin, fetched 2026-11-03; reference only, not ASUS runtime','artifacts':rows},indent=2)+'\n',encoding='utf-8')
print(json.dumps(rows))
