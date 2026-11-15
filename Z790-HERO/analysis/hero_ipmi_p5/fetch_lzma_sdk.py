"""Pinned EDK II LZMA SDK sources; no third-party binary execution."""
from pathlib import Path
import urllib.request,hashlib,json,time
P=Path(__file__).resolve().parent/'host-lzma';P.mkdir(exist_ok=True)
base='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/BaseTools/Source/C/LzmaCompress/Sdk/C/'
names=['7zTypes.h','Compiler.h','Precomp.h','CpuArch.h','LzFind.h','LzFind.c','LzHash.h','LzmaEnc.h','LzmaEnc.c','LzmaDec.h','LzmaDec.c']
manifest=[]
for name in names:
    if (P/name).exists():data=(P/name).read_bytes()
    else:
        for attempt in range(3):
            try:data=urllib.request.urlopen(base+name,timeout=15).read();break
            except Exception:
                if attempt==2:raise
                time.sleep(1)
        (P/name).write_bytes(data)
    print(name,len(data),flush=True)
    manifest.append(dict(name=name,url=base+name,sha256=hashlib.sha256(data).hexdigest()))
(P/'sources.json').write_text(json.dumps(manifest,indent=2)+'\n');print('Downloaded',len(manifest),'pinned source files')
