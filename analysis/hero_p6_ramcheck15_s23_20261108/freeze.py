from pathlib import Path
import hashlib,json,zipfile
BASE=Path(__file__).resolve().parent
build=json.loads((BASE/'build.json').read_text());tests=json.loads((BASE/'tests/launcher-pe.json').read_text());driver=json.loads((BASE/'tests/exact-driver-defaults.json').read_text());vm=json.loads((BASE/'vm-verification.json').read_text());host=json.loads((BASE/'tests/actual-host-identity.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert tests['passed'] and tests['cases']==112 and driver['passed'] and driver['cases']==6 and vm['passed']
assert host['passed'] and host['cases']==4 and host['launcher_sha256']==build['launcher_sha256']
assert tests['actual_launcher_sha256']==build['launcher_sha256']==vm['launcher_sha256']==sha(BASE/'USB/EFI/BOOT/BOOTX64.EFI')
assert build['iso_sha256']==vm['iso_sha256']==sha(BASE/'HERO-P6-HOST15-S23.iso')
assert build['original_driver_sha256']==driver['driver_sha256']==sha(BASE/'USB/EFI/BOOT/HEROP6.EFI')
for name,value in build['sources'].items():assert sha(BASE/'source'/name)==value,name
paths=[BASE/n for n in ('HERO-P6-HOST15-S23.iso','USB/EFI/BOOT/BOOTX64.EFI','USB/EFI/BOOT/HEROP6.EFI','操作说明.txt','decode_captures.py','build.json','vm-verification.json','tests/launcher-pe.json','tests/exact-driver-defaults.json','tests/actual-host-identity.json','origin.json','vm/OVMF-P6-RAMCHECK.TXT')]
manifest={'status':'Frozen RAM candidate, awaiting real HERO synchronous AfterBoot/HII test; not a flash package','scope':'IPMI native menu read check with S23 exact P5 readonly + P6 / synchronous AfterBoot refresh. No inventory or flash.','exact_core_sha256':build['original_driver_sha256'],'early_setup_timer_unchanged_not_hardware_validated':True,'expected_nv_change':'Only absent HeroIpmiSettings may be seeded by new P6: 32B attrs3 defaults. Existing21/32 safe defaults are not modified.','files':{p.relative_to(BASE).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in paths},'verified':{'actual_launcher_pe_cases':112,'exact_driver_default_lifecycles':6,'OVMF_qr_pages':vm['qr_exact_roundtrip']['pages'],'OVMF_return':True}}
manifest.update(scope='Exact known P5 readonly or P6 native resource status check with S23. No HII injection, inventory or flash.',known_P5_is_readonly_and_does_not_validate_configuration_controls=True,actual_host_DMI_identity_cases=4)
(BASE/'FROZEN-ARTIFACTS.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');paths.append(BASE/'FROZEN-ARTIFACTS.json')
output=BASE/'HERO-P6-HOST15-S23-PACKAGE.zip'
with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in paths:z.write(p,p.relative_to(BASE).as_posix())
with zipfile.ZipFile(output) as z:
 assert z.testzip() is None
 for p in paths:assert z.read(p.relative_to(BASE).as_posix())==p.read_bytes()
report={'package':str(output),'sha256':sha(output),'bytes':output.stat().st_size,'iso_sha256':build['iso_sha256'],'zip_readback_all_files':True}
(BASE/'PACKAGE-HASH.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
