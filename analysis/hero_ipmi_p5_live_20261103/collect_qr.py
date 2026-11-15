"""Collect a bounded QR log using page-next keys; verify every page and full CRC."""
from pathlib import Path
import json,subprocess,sys
P=Path(__file__).resolve().parent
sys.path.insert(0,str(P.parent/'hero_ipmi_p5'))
from decode_captures import read_image,parse_frame,assemble
first=Path(sys.argv[1]);dest=P/sys.argv[2]
frames=[read_image(first)];meta=parse_frame(frames[0]);assert meta['page']==1 and meta['pages']<=80
print('QR pages',meta['pages'],flush=True)
for page in range(2,meta['pages']+1):
 r=subprocess.run([sys.executable,'-X','utf8',str(P/'control.py'),'key','N','--wait-ms','1400','--page','2'],check=True,capture_output=True,text=True)
 data=json.loads(r.stdout);assert not data.get('pending')
 raw=read_image(Path(data['image']));m=parse_frame(raw)
 assert m['page']==page and (m['total'],m['crc'])==(meta['total'],meta['crc'])
 frames.append(raw)
data,summary=assemble(frames)
with dest.open('xb') as f:f.write(data)
dest.with_suffix('.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
