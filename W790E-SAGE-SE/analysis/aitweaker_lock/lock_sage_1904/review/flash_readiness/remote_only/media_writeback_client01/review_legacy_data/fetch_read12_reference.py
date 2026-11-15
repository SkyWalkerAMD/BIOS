"""Single fixed public Linux source GET, no target access."""
from pathlib import Path
import hashlib,json,urllib.request
p=Path(__file__).resolve().parent/'reference/target_core_sbc.c'
url='https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/target/target_core_sbc.c'
data=urllib.request.urlopen(url,timeout=30).read();p.write_bytes(data)
v=dict(path=p.name,url=url,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
p.with_suffix('.json').write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8');print(json.dumps(v))
