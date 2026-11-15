"""Issue one JSON command to the private, authorized BMC browser."""
from pathlib import Path
import json,sys,time
sys.stdout.reconfigure(encoding='utf-8')
P=Path(__file__).resolve().parent
c=json.loads(sys.argv[1]);n=1+max([int(f.name[:3]) for f in (P/'commands').glob('[0-9][0-9][0-9]-*.json')],default=0)
name=f'{n:03d}-{c["action"]}.json'
with (P/'commands'/name).open('x',encoding='utf-8') as f:json.dump(c,f)
r=P/'responses'/name
for _ in range(100):
    if r.exists():
        try:
            d=json.loads(r.read_text(encoding='utf-8'));print(name)
            if d.get('ok') and isinstance(d.get('result'),dict) and 'fields' in d['result']:
                result=d['result'];print(json.dumps({k:result.get(k) for k in ('url','title','text','pages')},ensure_ascii=False,indent=2))
            else:print(json.dumps(d,ensure_ascii=False,indent=2))
            break
        except json.JSONDecodeError:pass
    time.sleep(.25)
else:print(name,'pending')
