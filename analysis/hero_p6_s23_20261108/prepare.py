"""Copy frozen S22 for exact known-P5 read-only resource compatibility."""
from pathlib import Path
import hashlib,json,shutil
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1];OLD=ROOT/'analysis/hero_p6_s22_20261108'
assert hashlib.sha256((OLD/'HeroIpmiP6.efi').read_bytes()).hexdigest()=='abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75'
for directory in ('source','backend','native'):shutil.copytree(OLD/directory,OUT/directory)
for name in ('build_runtime.py','verify_runtime.py'):shutil.copyfile(OLD/name,OUT/name)
(OUT/'tests').mkdir()
for name in ('test_settings21.py','test_sync_lifecycle.py','test_pci_discovery.py'):shutil.copyfile(OLD/'tests'/name,OUT/'tests'/name)
shutil.copyfile(ROOT/'analysis/hero_ipmi_p5/Setup-forms-P5.bin',OUT/'native/Setup-forms-P5.bin')
driver=OUT/'source/driver.c';s=driver.read_text().replace('HERO-IPMI-P6-S22 / dynamic PCI discovery / S21S lifecycle unchanged','HERO-IPMI-P6-S23 / exact P5 readonly + P6 resources / S22 transport');driver.write_text(s)
test=OUT/'tests/test_sync_lifecycle.py';s=test.read_text().replace('S22','S23');test.write_text(s)
record={'baseline':str(OLD.relative_to(ROOT)),'baseline_PE_sha256':'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75','scope':'Add byte-equal known P5 readonly resource alongside exact P6; no lifecycle, settings, PCI or BMC command changes','baseline_sources':{p.relative_to(OLD).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for d in ('source','backend','native') for p in (OLD/d).rglob('*') if p.is_file()}}
(OUT/'origin.json').write_text(json.dumps(record,indent=2)+'\n')
