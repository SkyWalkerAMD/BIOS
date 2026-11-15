"""New local immutable-target REA session; prior evidence is read, not rerun."""
from pathlib import Path
import json,hashlib
H=Path(__file__).resolve().parent;B=H.parent
(H/'rea_session.mjs').write_bytes((B/'navigation/rea_session.mjs').read_bytes())
seeds=(B/'navigation/seeds.tsv').read_text()
seeds+='\n# Exact original callee entries from BrowserLoop tail and method tables.\n'
items=[('0xfd18','Original_OemDispatch'),('0xfcb4','Original_OemSelectorLookup'),('0x64b2c','Original_RenderCleanup'),('0x1d6e8','Original_AppDestructor')]
seeds+=''.join(f'{a}\tfunction\t{name}\n'for a,name in items)
(H/'seeds.tsv').write_text(seeds)
steps=[{'name':'open_binary','arguments':{'provider_id':'ghidra','path':str(B/'navigation/modules/AMITSE.efi')},'label':'n08-open'}]
steps +=[{'name':'analyze_function','arguments':{'procedure':a,'detail':'complete'},'label':'n08-'+a[2:]}for a,_ in items]
(H/'plan-tail.json').write_text(json.dumps(steps,indent=2)+'\n')
prior=json.loads((B/'navigation06_actions/rea_index.json').read_text())
paths={0x190f4:B/'navigation/rea/W890-seeded-loop190f4.json'}
for d in prior['dossiers']:
 if d['module']=='AMITSE.efi'and int(d['rva'],16)in [0x748c,0x189a4,0x3f5cc,0x3f414]:paths[int(d['rva'],16)]=B/'navigation06_actions'/d['response']
index=[];out=H/'existing';out.mkdir(exist_ok=True)
def texts(o):
 if isinstance(o,dict):
  for k,v in o.items():
   if k in ['pseudocode','decompiled_code']and isinstance(v,str):yield v
   else:yield from texts(v)
 elif isinstance(o,list):
  for v in o:yield from texts(v)
for rva,p in paths.items():
 result=json.loads(p.read_text());ev=json.loads(result['content'][0]['text'])
 ps=list(dict.fromkeys(texts(ev)))
 (out/(f'{rva:x}.c')).write_text('\n\n'.join(ps))
 index.append({'rva':rva,'source':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'evidence_id':ev['evidence_id'],'pseudocode_count':len(ps)})
(H/'existing_evidence.json').write_text(json.dumps(index,indent=2)+'\n')
print(json.dumps(index,indent=2))
