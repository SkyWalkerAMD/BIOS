"""Bounded observed KVM key/capture commands; never reset or change configuration."""
from pathlib import Path
import argparse,json,subprocess,sys
OUT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('action',choices=['key','capture']);p.add_argument('value');p.add_argument('--page',type=int,default=1);p.add_argument('--wait-ms',type=int,default=1200)
a=p.parse_args();assert 0<=a.wait_ms<=5000
if a.action=='capture':
    c=dict(action='capture',page=a.page,name=a.value)
else:
    special={'ESC':('Escape','Escape',27),'ENTER':('Enter','Enter',13),'UP':('ArrowUp','ArrowUp',38),'DOWN':('ArrowDown','ArrowDown',40),'LEFT':('ArrowLeft','ArrowLeft',37),'RIGHT':('ArrowRight','ArrowRight',39),'F1':('F1','F1',112),'F8':('F8','F8',119)}
    if a.value.upper() in special:key,code,k=special[a.value.upper()]
    else:
        assert len(a.value)==1 and a.value.isascii() and a.value.isalpha()
        key=a.value.lower();code='Key'+a.value.upper();k=ord(a.value.upper())
    attrs=json.dumps(dict(key=key,code=code,keyCode=k,which=k,bubbles=True,cancelable=True))
    expression="(async()=>{const e=document.getElementById('kvm_textbox'),a="+attrs+";e.focus();e.dispatchEvent(new KeyboardEvent('keydown',a));try{await new Promise(r=>setTimeout(r,120));}finally{e.dispatchEvent(new KeyboardEvent('keyup',a));}await new Promise(r=>setTimeout(r,"+str(a.wait_ms)+"));return {key:a.key};})()"
    c=dict(action='evaluate',page=a.page,expression=expression)
r=subprocess.run([sys.executable,'-X','utf8',str(OUT/'command.py'),json.dumps(c)],capture_output=True,text=True,encoding='utf-8',check=True)
print(r.stdout,end='')
