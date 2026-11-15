from pathlib import Path
import urllib.request,json,hashlib
base=Path(__file__).resolve().parent/'reference'
files={'TlsConfig.h':'MdePkg/Include/Protocol/TlsConfig.h','TlsProtocol.c':'NetworkPkg/TlsDxe/TlsProtocol.c','TlsConfigProtocol.c':'NetworkPkg/TlsDxe/TlsConfigProtocol.c','TlsInit.c':'CryptoPkg/Library/TlsLib/TlsInit.c','TlsConfig.c':'CryptoPkg/Library/TlsLib/TlsConfig.c'}
rows=[]
for name,path in files.items():
 url='https://raw.githubusercontent.com/tianocore/edk2/edk2-stable202502/'+path
 data=urllib.request.urlopen(url,timeout=20).read();(base/name).write_bytes(data)
 rows.append({'name':name,'url':url,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
(base/'tls-private-sources.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows,indent=2))
