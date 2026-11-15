"""Fetch pinned primary UEFI declarations for the M1 ABI and IFR review."""
from pathlib import Path
import hashlib,json,urllib.request
OUT=Path(__file__).resolve().parent/'source/reference'
BASE='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/'
PATHS=['MdePkg/Include/Protocol/HiiDatabase.h','MdePkg/Include/Protocol/HiiString.h',
 'MdePkg/Include/Protocol/HiiConfigAccess.h','MdePkg/Include/Protocol/HiiConfigRouting.h',
 'MdePkg/Include/Protocol/FormBrowser2.h','MdePkg/Include/Uefi/UefiInternalFormRepresentation.h',
 'MdePkg/Include/Uefi/UefiSpec.h','MdeModulePkg/Library/UefiHiiLib/HiiLib.c']
def main():
    OUT.mkdir(parents=True,exist_ok=True);rows=[]
    for name in PATHS:
        path=OUT/Path(name).name;url=BASE+name
        if not path.exists():
            with urllib.request.urlopen(url,timeout=30) as response:path.write_bytes(response.read())
        rows.append(dict(path=name,url=url,sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    (OUT/'sources.json').write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
    print('Pinned primary references:',len(rows))
if __name__=='__main__':main()
