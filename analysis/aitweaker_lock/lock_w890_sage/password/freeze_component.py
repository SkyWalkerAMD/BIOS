"""Bind current W890 component sources/tests without promoting release status."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
paths=[]
for pattern in ['*.py','*.c','*.h','*.txt','*.json','*.pack','core/*.py','core/*.c','core/*.h','core/*.json',
                'core/build/*.dll','build/*.json','build/*.dll','build/*.pack','build/*.forms',
                'provider/*.c','provider/*.h','provider/*.py','provider/build/*.json','provider/build/*.efi']:
    paths.extend(HERE.glob(pattern))
paths=sorted({p for p in paths if p.name!='component_manifest.json'})
items={str(p.relative_to(HERE)).replace('\\','/'):{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}for p in paths}
for name in ['core/test_report.json','build/adaptation_test.json','provider/build/provider_pe_test.json','build/hii_test.json']:
    r=json.loads((HERE/name).read_text());assert r['status'].startswith('PASS'),name
build=json.loads((HERE/'provider/build/build.json').read_text());assert items['provider/build/'+build['file']]['sha256']==build['sha256']
report={'status':'FROZEN_COMPONENT_FOR_REVIEW_NOT_FLASH_READY','release_ready':False,'hardware_operations':0,'firmware_writes':0,
        'target':'ASUS Pro WS W890E-SAGE SE BIOS0603','bindings':items,'binding_count':len(items)}
(HERE/'component_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'bindings':len(items),'manifest_sha256':hashlib.sha256((HERE/'component_manifest.json').read_bytes()).hexdigest()}))
