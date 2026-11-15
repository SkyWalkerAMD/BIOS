"""Read original ZIP and public ASUS support pages; no native utility execution."""
from pathlib import Path
import hashlib,json,re,urllib.request,zipfile
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[3]
OUT=BASE/'sources'
OUT.mkdir(exist_ok=True)
def sha(b): return hashlib.sha256(b).hexdigest()
zpath=ROOT/'Pro-WS-W890E-SAGE-SE-ASUS-0603.zip'
out={'original_zip':{'path':str(zpath.relative_to(ROOT)),'size':zpath.stat().st_size,'sha256':sha(zpath.read_bytes())},'members':[],'retrievals':[]}
with zipfile.ZipFile(zpath) as z:
    for name in z.namelist():
        b=z.read(name)
        row={'name':name,'size':len(b),'sha256':sha(b)}
        if name.lower().endswith(('.exe','.cfg')):
            p=OUT/Path(name).name;p.write_bytes(b);row['extracted']=str(p.relative_to(ROOT))
        out['members'].append(row)
urls={
 'model-manual.html':'https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w890e-sage-se/helpdesk_manual?model2Name=Pro-WS-W890E-SAGE-SE',
 'flashback-faq.html':'https://www.asus.com/support/faq/1038568/',
 'model-bios.html':'https://www.asus.com/motherboards-components/motherboards/workstation/pro-ws-w890e-sage-se/helpdesk_bios?model2Name=Pro-WS-W890E-SAGE-SE'
}
for name,url in urls.items():
    req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req,timeout=45) as r:
            b=r.read();status=r.status;final=r.url;headers=dict(r.headers)
        p=OUT/name;p.write_bytes(b)
        row={'url':url,'final_url':final,'status':status,'path':str(p.relative_to(ROOT)),'size':len(b),'sha256':sha(b),'headers':headers}
        text=b.decode('utf-8','replace').replace('\\u002F','/').replace('\\/','/')
        links=sorted(set(re.findall(r'https?[^\s<>"\x27]+',text)))
        row['relevant_links']=[x for x in links if any(y in x.lower() for y in ['.pdf','.cap','.zip','manual','dlcdn','download'])]
    except Exception as e: row={'url':url,'error':repr(e)}
    out['retrievals'].append(row)
(BASE/'source_retrieval.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
for r in out['retrievals']:
    print(r.get('status'),r['url'],r.get('size'),r.get('error'))
    for x in r.get('relevant_links',[]):
        if '.pdf' in x.lower() or '.zip' in x.lower(): print(x[:500])
b=(OUT/'BIOSRenamer.exe').read_bytes()
strings=[{'offset':m.start(),'text':m.group().decode('ascii')} for m in re.finditer(rb'[\x20-\x7e]{6,}',b)]
(BASE/'renamer_ascii_strings.json').write_text(json.dumps(strings,indent=2),encoding='utf-8')
print('RENAMER',[(x['offset'],x['text']) for x in strings if any(v in x['text'].lower() for v in ['w890','cap','rename','usbflash'])])
