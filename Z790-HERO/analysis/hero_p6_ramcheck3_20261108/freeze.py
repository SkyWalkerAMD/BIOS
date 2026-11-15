from pathlib import Path
import hashlib,json,zipfile
BASE=Path(__file__).resolve().parent
build=json.loads((BASE/'build.json').read_text());tests=json.loads((BASE/'tests/launcher-pe.json').read_text());driver=json.loads((BASE/'tests/exact-driver-defaults.json').read_text());vm=json.loads((BASE/'vm-verification.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert tests['passed'] and tests['cases']==112 and driver['passed'] and driver['cases']==6 and vm['passed']
assert tests['actual_launcher_sha256']==build['launcher_sha256']==vm['launcher_sha256']==sha(BASE/'USB/EFI/BOOT/BOOTX64.EFI')
assert build['iso_sha256']==vm['iso_sha256']==sha(BASE/'HERO-P6-RAMCHECK-3.iso')
assert build['original_driver_sha256']==driver['driver_sha256']==sha(BASE/'USB/EFI/BOOT/HEROP6.EFI')
for name,value in build['sources'].items():assert sha(BASE/'source'/name)==value,name
paths=[BASE/n for n in ('HERO-P6-RAMCHECK-3.iso','操作说明.txt','decode_captures.py','build.json','vm-verification.json','tests/launcher-pe.json','tests/exact-driver-defaults.json','vm/OVMF-P6-RAMCHECK.TXT')]
manifest={'status':'Frozen, awaiting real HERO native SetupEnter/AfterBoot/HII test','scope':'IPMI native menu read check with S21R return-to-Setup refresh. No inventory or flash.','expected_nv_change':'Only absent HeroIpmiSettings may be seeded by new P6: 32B attrs3 defaults. Existing21/32 safe defaults are not modified.','files':{p.relative_to(BASE).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in paths},'verified':{'actual_launcher_pe_cases':112,'exact_driver_default_lifecycles':6,'OVMF_qr_pages':vm['qr_exact_roundtrip']['pages'],'OVMF_return':True}}
(BASE/'FROZEN-ARTIFACTS.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');paths.append(BASE/'FROZEN-ARTIFACTS.json')
output=BASE/'HERO-P6-RAMCHECK-3-PACKAGE.zip'
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in paths:z.write(p,p.relative_to(BASE).as_posix())
with zipfile.ZipFile(output) as z:
 assert z.testzip() is None
 for p in paths:assert z.read(p.relative_to(BASE).as_posix())==p.read_bytes()
print(json.dumps({'package':str(output),'sha256':sha(output),'bytes':output.stat().st_size,'iso_sha256':build['iso_sha256']},indent=2))
