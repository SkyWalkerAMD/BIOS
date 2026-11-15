"""Independent final .15 R5 loader/ISO gate review; no hardware execution."""
from pathlib import Path
import hashlib, importlib.util, io, json, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
BASE=ROOT/'analysis/hero_sensor_r5_20261108/autoboot15'
PE='b1b280e5d75e81ffae313c5f8ae4aa8fe422a08d6a44f83fa5888a5dce719d73'
ISO='29b384da3ee6f87794898a0f78f363e1dbaaa731d72b3d1c87c9151fc4976594'
CORE='81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(BASE/'USB/EFI/BOOT/BOOTX64.EFI')==PE
assert sha(BASE/'HERO15-R5-AUTO-BDS-TEST.iso')==ISO
assert sha(BASE.parent/'USB/EFI/HERO/HeroIpmiR5.efi')==CORE
build=json.loads((BASE/'build.json').read_text())
for name,digest in build['sources'].items():assert sha(BASE/'source'/name)==digest,name
sys.path.insert(0,str(BASE))
spec=importlib.util.spec_from_file_location('review_guarded_r5',BASE/'verify_guarded_launcher.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
rows=[]
for case,loads,starts in [
 ('first',1,1),('diagnostic_only',0,0),('existing_ready',0,0),('existing_old_r4',0,0),
 ('existing_manual',0,0),('without_D',0,0),('wrong_uuid',0,0),('uuid_changed',0,0),
 ('cfg_created_same_default',0,0),('lock_appeared',0,0),('bar_changed',0,0),('count_changed',0,0),
 ('loaded_options_pointer',1,0),('watchdog_error',0,0),('crc_bypass_bad_sha',0,0),('mmio_map',0,0)]:
    m=fixture.Machine(case);status=m.execute()
    assert m.calls.count('LoadImage')==loads and m.calls.count('StartImage')==starts,(case,status,m.output)
    assert not any(x=='FORBIDDEN' for x in m.calls)
    if case=='first':assert 'FIRST_PASS_NO_BMC_QUERY' in m.output
    if case=='existing_ready':assert 'READY_TO_BOOT_OBSERVED' in m.output
    if case=='diagnostic_only':assert m.location_reads==1 and not m.loaded
    rows.append({'case':case,'passed':True,'load_calls':loads,'start_calls':starts})
for part in ('tools/pydeps','tools/kvm-pydeps','tools/vm-pydeps','analysis/aitweaker_lock/uefi_vm_20261015'):sys.path.insert(0,str(ROOT/part))
import pefile,pycdlib,disk_images
pe=pefile.PE(str(BASE/'USB/EFI/BOOT/BOOTX64.EFI'))
assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum()
assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
iso=pycdlib.PyCdlib();iso.open(str(BASE/'HERO15-R5-AUTO-BDS-TEST.iso'))
assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
for source,target in (('/EFI/BOOT/BOOTX64.EFI;1','USB/EFI/BOOT/BOOTX64.EFI'),('/HERO_R5A.TAG;1','USB/HERO_R5A.TAG'),('/EFIBOOT.IMG;1','efi-boot.img')):
    b=io.BytesIO();iso.get_file_from_iso_fp(b,iso_path=source);assert b.getvalue()==(BASE/target).read_bytes()
iso.close()
with disk_images.PyFatFS(str(BASE/'efi-boot.img'),read_only=True) as fat:
    assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI')==(BASE/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()
    assert fat.readbytes('/HERO_R5A.TAG')==b'HERO-R5AUTO\r\n'
result={'passed':True,'cases':len(rows),'results':rows,'launcher_sha256':PE,'iso_sha256':ISO,'core_sha256':CORE,
        'source_hashes_match_build':True,'iso_visible_and_el_torito_fat_match':True,
        'firstpass':'D only performs bounded identity/PCI configuration/variable reads; L repeats exact snapshot and pin verification then loads resident driver with untouched empty LoadOptions.',
        'secondpass':'Identity-gated cached observation only. No manual run or synthetic ReadyToBoot signal.',
        'owner_lifetime':'Callback/code/context belong to separately loaded R5, not the exiting application. No app callback is registered.',
        'scope':'Permits controlled two-pass RAM BDS experiment on identified .15. No hardware results established by this offline report.',
        'trusted_fixture_limit':'UEFI services and API status are doubles; actual driver bytes checked at LoadImage, but child execution is not supplied by this loader fixture.',
        'no_hardware_actions':True}
dest=HERE/'host15-r5-loader-review.json';dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'cases':len(rows),'iso_sha256':ISO,'report_sha256':sha(dest)},indent=2))
