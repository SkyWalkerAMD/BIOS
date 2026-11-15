"""One explicit power-on of the observed-off host, followed by DEL keys."""
from pathlib import Path
import json
P=Path(__file__).resolve().parent
LIVE=P.parent/'hero_ipmi_flash_live_20261104'
observed=json.loads((LIVE/'responses/013-evaluate.json').read_text(encoding='utf-8'))
assert observed['ok'] and observed['result']['executed'] is False
message=observed['result']['message']
assert message.endswith('Do you want to perform Power On operation?')
script="""(async()=>{
if(document.getElementById('power_ctrl_btn').title!=='Server is Powered Off')throw new Error('Host is not in observed powered-off state');
const expected=EXPECTED, old=window.confirm;let seen=null;
window.confirm=m=>{seen=m;if(m!==expected)throw new Error('Unexpected confirmation');return true;};
try{document.getElementById('power_on').click();}finally{window.confirm=old;}
if(seen!==expected)throw new Error('Power-on confirmation not observed');
const e=document.getElementById('kvm_textbox'),a={key:'Delete',code:'Delete',keyCode:46,which:46,bubbles:true,cancelable:true};
for(let i=0;i<55;i++){e.focus();e.dispatchEvent(new KeyboardEvent('keydown',a));try{await new Promise(r=>setTimeout(r,80));}finally{e.dispatchEvent(new KeyboardEvent('keyup',a));}await new Promise(r=>setTimeout(r,700));}
return {powerOnRequested:true,deleteKeys:55};})()""".replace('EXPECTED',json.dumps(message))
n=1+max(int(p.name[:3]) for p in (LIVE/'commands').glob('[0-9][0-9][0-9]-*.json'))
path=LIVE/'commands'/f'{n:03d}-power-on-setup.json'
with path.open('x',encoding='utf-8') as f:json.dump(dict(action='evaluate',page=1,expression=script),f)
print(path)
