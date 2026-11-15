"""Fetch the exact public EDK2 ABI headers; no machine/BMC endpoints."""
from pathlib import Path
import hashlib,json,urllib.request
out=Path(__file__).resolve().parent/'reference'
paths=['MdePkg/Include/Protocol/BlockIo.h','MdePkg/Include/Protocol/DiskInfo.h',
       'MdePkg/Include/Protocol/PciIo.h','MdePkg/Include/Protocol/DevicePath.h',
       'MdePkg/Include/Uefi/UefiSpec.h','MdePkg/Include/Uefi/UefiMultiPhase.h']
items=[]
for path in paths:
    url='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/'+path
    data=urllib.request.urlopen(url,timeout=20).read()
    name=Path(path).name
    (out/name).write_bytes(data)
    items.append(dict(file=name,url=url,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
(out/'sources.json').write_text(json.dumps(items,indent=2)+'\n',encoding='utf8')
print(json.dumps(items,indent=2))
