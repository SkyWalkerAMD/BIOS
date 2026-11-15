"""Read-only virtual-media file for the vendor's BIOS image validation screen.
No auto-flash script or flash utility is placed on this media.
"""
from pathlib import Path
import sys,json,hashlib,io
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
for folder in ('tools/kvm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/folder))
import disk_images,pycdlib
cap=(P/'candidate/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP').read_bytes()
verified=json.loads((P/'candidate-verification.json').read_text());assert verified['passed'] and verified['candidate_sha256']==hashlib.sha256(cap).hexdigest()
original=(ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP').read_bytes()
assert hashlib.sha256(original).hexdigest()=='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
files={'/P5RC1.CAP':cap,'/ORIG3107.CAP':original,'/README.TXT':b'P5 RC1 UNSIGNED TEST CANDIDATE. ORIG3107.CAP is the unchanged vendor image. No auto-flash.\r\n'}
disk_images.OUT=P;disk_images.VOLUME_SIZE=96*1024*1024
boot=P/'review-media.img';disk_images.create(boot,layout='superfloppy',fat_type=16,files=files)
with disk_images.PyFatFS(str(boot),read_only=True) as fs:
    for name,data in files.items():assert fs.readbytes(name)==data
iso=P/'HERO-P5-RC1-IMAGE-REVIEW.iso';image=pycdlib.PyCdlib();image.new(interchange_level=3,vol_ident='P5_RC1_REVIEW')
# EDK II PartitionDxe/ElTorito.c uses count <2 for the entire image extent.
# A count of 4 exposes only a tiny partition; 64 MiB exceeds the u16 count.
image.add_file(str(boot),iso_path='/EFIBOOT.IMG;1');image.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',platform_id=0xef,efi=True,media_name='noemul',boot_load_size=0)
for name,data in files.items():image.add_fp(io.BytesIO(data),len(data),iso_path=name+';1')
image.write(str(iso));image.close()
check=pycdlib.PyCdlib();check.open(str(iso))
for name,expected in files.items():
    data=io.BytesIO();check.get_file_from_iso_fp(data,iso_path=name+';1');assert data.getvalue()==expected
check.close()
manifest=dict(candidate_sha256=hashlib.sha256(cap).hexdigest(),official_sha256=hashlib.sha256(original).hexdigest(),iso_sha256=hashlib.sha256(iso.read_bytes()).hexdigest(),iso_bytes=iso.stat().st_size,purpose='vendor image validation with unchanged official control; no automatic flashing or boot executable')
(P/'review-media.json').write_text(json.dumps(manifest,indent=2)+'\n');print(manifest)
