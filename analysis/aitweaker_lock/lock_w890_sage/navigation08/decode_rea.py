from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent
def texts(o):
 if isinstance(o,dict):
  for k,v in o.items():
   if k in ['pseudocode','decompiled_code']and isinstance(v,str):yield v
   else:yield from texts(v)
 elif isinstance(o,list):
  for v in o:yield from texts(v)
index=[]
for p in sorted((H/'rea02').glob('n08-*.json')):
 r=json.loads(p.read_text())
 if r.get('isError'):continue
 e=json.loads(r['content'][0]['text'])
 if 'evidence_id'not in e:continue
 name=p.stem[4:];ps=list(dict.fromkeys(texts(e)));out=H/(name+'.c');out.write_text('\n\n'.join(ps))
 index.append({'response':p.relative_to(H).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'evidence_id':e['evidence_id'],'pseudocode':out.name})
(H/'rea02_index.json').write_text(json.dumps(index,indent=2)+'\n');print(json.dumps(index,indent=2))
