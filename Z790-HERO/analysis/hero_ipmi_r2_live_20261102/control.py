"""Send one explicit KVM key or capture and retain the resulting native PNG."""
from pathlib import Path
import argparse,base64,json,time
OUT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('operation',choices=['key','capture']);p.add_argument('key',nargs='?');p.add_argument('--wait-ms',type=int,default=1200);p.add_argument('--page',type=int,default=1);a=p.parse_args()
assert 0<=a.wait_ms<=20000
capture="return {image:document.getElementById('kvm').toDataURL('image/png'),frameCount:window.frames_received};"
if a.operation=='key':
    named={'F8':('F8','F8',119),'Delete':('Delete','Delete',46),'Escape':('Escape','Escape',27),'Enter':('Enter','Enter',13),'ArrowDown':('ArrowDown','ArrowDown',40),'ArrowUp':('ArrowUp','ArrowUp',38),'ArrowLeft':('ArrowLeft','ArrowLeft',37),'ArrowRight':('ArrowRight','ArrowRight',39)}
    if a.key in named:key,code,num=named[a.key]
    elif a.key and len(a.key)==1 and a.key.isascii() and a.key.isalnum():
        key=a.key.lower();code=('Key'+a.key.upper()) if a.key.isalpha() else 'Digit'+a.key;num=ord(a.key.upper())
    else:raise ValueError('Unsupported key')
    data=json.dumps(dict(key=key,code=code,keyCode=num,which=num,bubbles=True,cancelable=True))
    expression="(async()=>{const e=document.getElementById('kvm_textbox'),a="+data+";e.focus();e.dispatchEvent(new KeyboardEvent('keydown',a));try{await new Promise(r=>setTimeout(r,180));}finally{e.dispatchEvent(new KeyboardEvent('keyup',a));}await new Promise(r=>setTimeout(r,"+str(a.wait_ms)+"));"+capture+"})()"
else:expression="(()=>{"+capture+"})()"
number=1+max([int(f.name[:3]) for f in (OUT/'commands').glob('[0-9][0-9][0-9]-*.json')],default=0)
name=f'{number:03d}-'+('key-'+a.key if a.operation=='key' else 'capture')+'.json'
with (OUT/'commands'/name).open('x',encoding='utf-8') as f:json.dump(dict(action='evaluate',page=a.page,expression=expression),f)
deadline=time.monotonic()+a.wait_ms/1000+8
response=OUT/'responses'/name
while not response.exists() and time.monotonic()<deadline:time.sleep(.2)
if not response.exists():print(json.dumps(dict(command=name,pending=True)));raise SystemExit(0)
for i in range(10):
    try:d=json.loads(response.read_text(encoding='utf-8'));break
    except json.JSONDecodeError:time.sleep(.1)
if not d['ok']:print(json.dumps(d));raise SystemExit(1)
result=d['result'];image=base64.b64decode(result['image'].split(',',1)[1],validate=True)
dest=OUT/'screens'/(response.stem+'.png');dest.write_bytes(image)
print(json.dumps(dict(command=name,image=dest.as_posix(),bytes=len(image),frames=result.get('frameCount'))))
