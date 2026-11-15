from pathlib import Path
import json,sys
p=Path(sys.argv[1]);d=json.loads(p.read_text(encoding='utf-8'))
def walk(x):
 if isinstance(x,dict):
  if isinstance(x.get('normalized_result'),str):
   yield x.get('parameters',{}),x['normalized_result']
  if isinstance(x.get('pseudocode'),str):
   yield x.get('procedure',{}),x['pseudocode']
  for k,v in x.items():
   if k=='text' and isinstance(v,str):
    try:yield from walk(json.loads(v))
    except ValueError:pass
   else:yield from walk(v)
 elif isinstance(x,list):
  for v in x:yield from walk(v)
seen=set();blocks=[]
for proc,code in walk(d):
 if code in seen:continue
 seen.add(code);blocks.append('/* '+json.dumps(proc)+' */\n'+code)
text='\n\n'.join(blocks)
p.with_suffix('.c').write_text(text,encoding='utf-8')
print(text)
