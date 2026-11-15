"""Observed KVM key using the browser's native key path; no power actions."""
from pathlib import Path
import argparse,json,subprocess,sys
sys.stdout.reconfigure(encoding='utf-8')
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('action',choices=['key','capture']);p.add_argument('value');p.add_argument('--page',type=int,default=2);p.add_argument('--wait-ms',type=int,default=1200)
a=p.parse_args();assert 0<=a.wait_ms<=5000
if a.action=='capture': c=dict(action='capture',page=a.page,name=a.value)
else:
    keys={'ESC':'Escape','ENTER':'Enter','UP':'ArrowUp','DOWN':'ArrowDown','LEFT':'ArrowLeft','RIGHT':'ArrowRight','F1':'F1','F8':'F8','HOME':'Home','END':'End'}
    key=keys.get(a.value.upper())
    if key is None:
        assert len(a.value)==1 and a.value.isascii() and a.value.isalpha()
        key=a.value.lower()
    c=dict(action='press',page=a.page,selector='#kvm_textbox',key=key,waitMs=a.wait_ms)
r=subprocess.run([sys.executable,'-X','utf8',str(HERE/'command.py'),json.dumps(c)],capture_output=True,text=True,encoding='utf-8',check=True)
name=r.stdout.splitlines()[0]
response=json.loads((HERE/'responses'/name).read_text(encoding='utf-8'))
assert response.get('ok'),response
print(name)
print(json.dumps({'ok':True,'action':a.action,'value':a.value}))
