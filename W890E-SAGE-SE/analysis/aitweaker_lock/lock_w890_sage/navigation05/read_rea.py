from pathlib import Path
import json
H=Path(__file__).resolve().parent
for p in sorted((H/'rea').glob('*.json')):
 x=json.loads(p.read_text()).get('structuredContent',{});code=x.get('normalized_result',{}).get('pseudocode')
 if code:
  (H/(p.stem+'.c.txt')).write_text(code.replace('\r\n','\n'))
  if any(s in p.stem for s in ['allocation','reallocation','savecontext','restorecontext']):print(p.stem+'\n'+code[:18000])
