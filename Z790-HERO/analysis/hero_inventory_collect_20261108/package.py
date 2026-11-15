"""Create a compact inventory-tool delivery without caches or synthetic firmware vars."""
from pathlib import Path
import hashlib
import json
import zipfile
HERE=Path(__file__).resolve().parent
files=[HERE/p for p in ('HERO-SMBIOS-I1-READONLY.iso','使用说明.txt','decode_captures.py','build.json',
                       'verification.json','vm-verification.json','source-provenance.json',
                       'prepare_sources.py','build.py','verify_inventory.py','run_vm.py')]
files+=sorted(p for base in ('USB','source') for p in (HERE/base).rglob('*') if p.is_file())
manifest={str(p.relative_to(HERE)).replace('\\','/'):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files}
(HERE/'package-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
package=HERE/'HERO-SMBIOS-I1-READONLY.zip'
with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in files+[HERE/'package-manifest.json']:z.write(p,str(p.relative_to(HERE)))
print(json.dumps({'path':str(package),'bytes':package.stat().st_size,'sha256':hashlib.sha256(package.read_bytes()).hexdigest()}))
