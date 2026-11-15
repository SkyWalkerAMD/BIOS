from pathlib import Path
import json, hashlib
here=Path(__file__).resolve().parent
data=json.loads((here/'edk2_reference_inputs.json').read_text(encoding='utf-8'))
out=here/'edk2_reference';out.mkdir(exist_ok=True)
rows=[]
for item in data['files']:
    assert item['name'] in ('Cpu.h','CpuDxe.c','CpuPageTable.c','MemoryAttribute.h')
    content=item['content'].encode('utf-8')
    actual=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
    assert actual==item['sha'], (item['name'],actual,item['sha'])
    dest=out/item['name'];dest.write_bytes(content)
    rows.append({'path':str(dest),'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest(),'git_blob_sha':actual,'url':item['display_url']})
(out/'provenance.json').write_text(json.dumps({'source':data['source'],'artifacts':rows},indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':'PASS','files':rows}))
