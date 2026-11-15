"""Freeze a compact I3 GET-only delivery; no R8/RC4 artifact is modified."""
from pathlib import Path
import hashlib,json,zipfile
HERE=Path(__file__).resolve().parent
build=json.loads((HERE/'build.json').read_text(encoding='utf-8'))
for name,digest in build['sources'].items():
 assert hashlib.sha256((HERE/'source'/name).read_bytes()).hexdigest()==digest,name
files=[HERE/p for p in ('HERO-INVENTORY-I3-READONLY.iso','使用说明-I3.txt','decode_captures.py','build.json','provenance.json',
 'network-tests.json','tcp-tests.json','tls-client-tests.json','pe-verification.json','vm-verification.json',
 'prepare_readonly.py','prepare_tests.py','build.py','test_network.c','test_network.py','test_tcp.c','test_tcp.py',
 'test_tls_client.c','test_tls_client.py','verify_pe.py','run_vm.py')]
files += [p for folder in ('USB','source','staged-drivers') for p in (HERE/folder).rglob('*') if p.is_file()]
manifest={str(p.relative_to(HERE)).replace('\\','/'):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files}
(HERE/'package-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
path=HERE/'HERO-INVENTORY-I3-READONLY.zip'
with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in files+[HERE/'package-manifest.json']:z.write(p,str(p.relative_to(HERE)))
print(json.dumps({'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}))
