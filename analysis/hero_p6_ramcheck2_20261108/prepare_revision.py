from pathlib import Path
BASE=Path(__file__).resolve().parent
files=['build.py','run_vm.py','decode_captures.py','freeze.py','source/app.c','source/kvm.c','tests/test_launcher_pe.py','tests/test_exact_driver_defaults.py','操作说明.txt']
old='71dd9b0956f3e3f1dab3893b2106f01aba0745ba6d5ecf7b172a82f8914bfba0'
new='6a5e2c86f9e49ceefa47d8765cf45c585805f7ac164f07be07df6505100d8ffb'
for name in files:
 p=BASE/name;s=p.read_text(encoding='utf-8')
 s=s.replace(old,new).replace('hero_ipmi_p6_20261104','hero_p6_settings21_20261108')
 s=s.replace('HERO-P6-RAMCHECK-1','HERO-P6-RAMCHECK-2').replace('HERO-P6-RAMCHECK1-QR1','HERO-P6-RAMCHECK2-QR1').replace('HERO_P6_RAMCHECK_1','HERO_P6_RAMCHECK_2')
 s=s.replace('HERO P6 RAM CHECK 1','HERO P6 RAM CHECK 2').replace('HERO P6 RAM check 1','HERO P6 RAM check 2')
 p.write_text(s,encoding='utf-8')
