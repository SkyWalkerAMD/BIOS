"""Fetch only two pinned public EDK II reference files. No target address."""
from pathlib import Path
import hashlib,json,urllib.request
HERE=Path(__file__).resolve().parent
OUT=HERE/'reference';OUT.mkdir(exist_ok=True)
manifest=[]
for tail in ['MdePkg/Library/UefiScsiLib/UefiScsiLib.c','MdePkg/Include/IndustryStandard/Scsi.h']:
    url='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/'+tail
    data=urllib.request.urlopen(url,timeout=30).read()
    p=OUT/Path(tail).name;p.write_bytes(data)
    manifest.append(dict(path=p.name,url=url,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
(OUT/'sources.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
print(json.dumps(manifest,indent=2))
