"""Issue one JSON command to the private, authorized BMC browser."""
from pathlib import Path
import json,re,sys,time
sys.stdout.reconfigure(encoding='utf-8')
P=Path(__file__).resolve().parent
c=json.loads(sys.argv[1])
def sequence(name):
    extended=re.fullmatch(r'999-([0-9]{6})-[-\w]+\.json',name)
    if extended:return int(extended[1])
    legacy=re.fullmatch(r'([0-9]{3})-[-\w]+\.json',name)
    return int(legacy[1]) if legacy else 0
n=1+max((sequence(f.name) for f in (P/'commands').glob('*.json')),default=0)
# The already-running controller accepts a three-digit prefix followed by word
# characters. Keep that contract when a long QR session passes command 999.
assert n<1_000_000
name=f'{n:03d}-{c["action"]}.json' if n<1000 else f'999-{n:06d}-{c["action"]}.json'
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
