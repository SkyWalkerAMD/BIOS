from pathlib import Path
import hashlib,json,shutil
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
OLD=ROOT/'analysis/hero_p6_ramcheck15_s22_20261108';NEW=ROOT/'analysis/hero_p6_ramcheck15_s23_20261108'
expected='1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc'
assert hashlib.sha256((BASE/'HeroIpmiP6.efi').read_bytes()).hexdigest()==expected
assert not NEW.exists(),'Do not overwrite frozen launcher'
NEW.mkdir();shutil.copytree(OLD/'source',NEW/'source');(NEW/'tests').mkdir();(NEW/'build').mkdir();(NEW/'USB/EFI/BOOT').mkdir(parents=True)
for name in ('build.py','decode_captures.py','run_vm.py','freeze.py'):shutil.copyfile(OLD/name,NEW/name)
for name in ('test_launcher_pe.py','test_exact_driver_defaults.py','test_actual_host_identity.py'):shutil.copyfile(OLD/'tests'/name,NEW/'tests'/name)
shutil.copyfile(BASE/'HeroIpmiP6.efi',NEW/'USB/EFI/BOOT/HEROP6.EFI')
replacements={'S22':'S23','s22':'s23','abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75':expected,'portable PCI / synchronous AfterBoot':'exact P5 readonly + P6 / synchronous AfterBoot'}
for path in [NEW/n for n in ('build.py','decode_captures.py','run_vm.py','freeze.py','source/app.c','source/kvm.c','tests/test_launcher_pe.py','tests/test_exact_driver_defaults.py')]:
 text=path.read_text()
 for a,b in replacements.items():text=text.replace(a,b)
 path.write_text(text,encoding='utf-8')
report=json.loads((OLD/'origin.json').read_text())
report['source']='Frozen .15 S22 RAM launcher copied; same UUID, memory checks and safe-default preflight; embedded new exact S23'
report['parent_launcher_sha256']=hashlib.sha256((OLD/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest()
report['changes']=['embedded exact S23 driver and SHA256 pin','S23 title and QR marker; same .15 identity and unchanged loading/preflight logic']
report['limitations']=['Linux variable enumeration is not proof of absence; original UEFI preflight remains mandatory.','S23 recognizes full byte-equal known P5 readonly and P6 resources, requiring one accepted resource across a complete readable enumeration.','Old P5 remains readonly without editable configuration questions. This test cannot validate F10 writes on that resource.','New S23 RAM test, not C03/C04 exact core and not a firmware flash package.']
(NEW/'origin.json').write_text(json.dumps(report,indent=2)+'\n')
print(NEW)
