from pathlib import Path
import urllib.request,hashlib,json,re
D=Path(__file__).resolve().parent
s=(D/'sources/model-manual.html').read_text(encoding='utf-8')
paths=sorted(set(re.findall(r'(/pub/ASUS/[^"\\\s]+(?:E26993|C26993)[^"\\\s]+\.pdf)',s)))
assert len(paths)==2,paths
results=[]
for p in paths:
    url='https://dlcdnets.asus.com'+p
    row={'url':url,'discovered_in':'sources/model-manual.html'}
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(req,timeout=45) as r:
            b=r.read();row.update(status=r.status,final_url=r.url,headers=dict(r.headers))
        assert b.startswith(b'%PDF-')
        target=D/'sources'/p.rsplit('/',1)[-1];target.write_bytes(b)
        row.update(path=str(target.relative_to(D)),size=len(b),sha256=hashlib.sha256(b).hexdigest())
    except Exception as e:row['error']=repr(e)
    results.append(row)
    print(row.get('status'),url,row.get('size'),row.get('error'))
(D/'manual_retrieval.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
