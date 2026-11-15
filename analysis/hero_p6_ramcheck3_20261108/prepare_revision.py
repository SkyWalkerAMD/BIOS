"""Prepare the standalone RAMCHECK3 fork; never modifies frozen RAMCHECK2."""
from pathlib import Path
BASE=Path(__file__).resolve().parent
assert BASE.name=='hero_p6_ramcheck3_20261108'
files=['build.py','run_vm.py','decode_captures.py','freeze.py','source/app.c','source/kvm.c','tests/test_launcher_pe.py','tests/test_exact_driver_defaults.py','操作说明.txt']
old='6a5e2c86f9e49ceefa47d8765cf45c585805f7ac164f07be07df6505100d8ffb'
new='5adbebb682b957a7877d87918286f7a1cbf297bbf7e2c14d7632c7d1afa3d685'
for name in files:
 p=BASE/name;s=p.read_text(encoding='utf-8')
 s=s.replace(old,new).replace('hero_p6_settings21_20261108','hero_p6_settings21r_20261108')
 s=s.replace('HERO-P6-RAMCHECK-2','HERO-P6-RAMCHECK-3').replace('HERO-P6-RAMCHECK2-QR1','HERO-P6-RAMCHECK3-QR1').replace('HERO_P6_RAMCHECK_2','HERO_P6_RAMCHECK_3')
 s=s.replace('HERO P6 RAM CHECK 2','HERO P6 RAM CHECK 3').replace('HERO P6 RAM check 2','HERO P6 RAM check 3')
 s=s.replace('S21-compatible core','S21R return-to-Setup refresh')
 p.write_text(s,encoding='utf-8')
