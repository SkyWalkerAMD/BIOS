"""Refresh only the un-frozen draft after adding requested cached stage trace."""
from pathlib import Path
import hashlib,shutil
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];APP=ROOT/'analysis/hero_p6_ramcheck15_s23_20261108'
OLD='9b543396a646929356166ae6af10aed4b071e83bdd39b051211632a43cb36153'
NEW='1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc'
assert not (APP/'FROZEN-ARTIFACTS.json').exists()
assert hashlib.sha256((BASE/'HeroIpmiP6.efi').read_bytes()).hexdigest()==NEW
for name in ('build.py','tests/test_launcher_pe.py','tests/test_exact_driver_defaults.py'):
 path=APP/name;s=path.read_text();assert OLD in s;path.write_text(s.replace(OLD,NEW))
shutil.copyfile(BASE/'HeroIpmiP6.efi',APP/'USB/EFI/BOOT/HEROP6.EFI')
