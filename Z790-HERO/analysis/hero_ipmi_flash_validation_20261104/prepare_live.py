"""Prepare an isolated review browser and a non-booting CAP check medium."""
from pathlib import Path
import hashlib, json, sys, io

P = Path(__file__).resolve().parent
ROOT = P.parents[1]
LIVE = ROOT/'analysis/hero_ipmi_flash_live_20261104'
OLD = ROOT/'analysis/hero_ipmi_p5_review_live_20261103'
LIVE.mkdir(exist_ok=True)
for name in ('start_browser.py','control.py','command.py'):
    dest = LIVE/name
    data = (OLD/name).read_bytes()
    if dest.exists():
        assert dest.read_bytes() == data
    else:
        dest.write_bytes(data)
browser = (OLD/'browser.cjs').read_text(encoding='utf-8')
browser = browser.replace('../hero_ipmi_p5/review-media.json','../hero_ipmi_flash_validation_20261104/review-media.json')
browser = browser.replace('../hero_ipmi_p5/HERO-P5-RC1-IMAGE-REVIEW.iso','../hero_ipmi_flash_validation_20261104/HERO-RC2-IMAGE-CHECK.iso')
(LIVE/'browser.cjs').write_text(browser,encoding='utf-8')

for folder in ('tools/kvm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):
    sys.path.insert(0,str(ROOT/folder))
import disk_images, pycdlib
candidate = ROOT/'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP'
official = ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
def sha(data): return hashlib.sha256(data).hexdigest()
cap = candidate.read_bytes()
orig = official.read_bytes()
assert sha(cap) == '5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
assert sha(orig) == 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
files = {'/P5RC2.CAP':cap,'/ORIG3107.CAP':orig,
         '/README.TXT':b'HERO 3107: P5RC2.CAP unsigned candidate; ORIG3107.CAP vendor control. File validation only. No boot executable or flash script.\r\n'}
disk_images.OUT = P
disk_images.VOLUME_SIZE = 96*1024*1024
fat = P/'review-media.img'
disk_images.create(fat,layout='superfloppy',fat_type=16,files=files)
with disk_images.PyFatFS(str(fat),read_only=True) as fs:
    for name,data in files.items(): assert fs.readbytes(name) == data
iso = P/'HERO-RC2-IMAGE-CHECK.iso'
image = pycdlib.PyCdlib()
image.new(interchange_level=3,vol_ident='HERO_RC2_CHECK')
image.add_file(str(fat),iso_path='/EFIBOOT.IMG;1')
image.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul',boot_load_size=0)
for name,data in files.items(): image.add_fp(io.BytesIO(data),len(data),iso_path=name+';1')
image.write(str(iso))
image.close()
check = pycdlib.PyCdlib()
check.open(str(iso))
for name,data in files.items():
    stream = io.BytesIO()
    check.get_file_from_iso_fp(stream,iso_path=name+';1')
    assert stream.getvalue() == data
check.close()
manifest = dict(candidate_sha256=sha(cap),official_sha256=sha(orig),iso_sha256=sha(iso.read_bytes()),
                iso_bytes=iso.stat().st_size,purpose='read-only EZ Flash image validation with an official control; no boot executable or auto-flash')
(P/'review-media.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
print(json.dumps(manifest,indent=2))
