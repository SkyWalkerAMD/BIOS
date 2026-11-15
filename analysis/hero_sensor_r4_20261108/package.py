"""Freeze both R4 RAM images with source, evidence and verified byte manifest."""
from pathlib import Path
import hashlib,json,zipfile
OUT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
core=OUT/'USB/EFI/HERO/HeroIpmiR4.efi';core_sha=sha(core)
tests=['verification.json','entry-verification.json','r3-verification.json','r4-verification.json',
       'write-boundary-verification.json','capture-verification.json','autoboot/capture-verification.json','autoboot/launcher-verification.json']
for name in tests:
    t=read(OUT/name);assert t['all_passed']
    if 'driver_sha256' in t:assert t['driver_sha256']==core_sha
assert read(OUT/'ffs-verification.json')['native_HERO_DxeCore_accepts']
assert read(OUT/'ffs-verification.json')['driver_sha256']==core_sha
assert read(OUT/'build.json')['outputs'][0]['sha256']==core_sha
assert read(OUT/'autoboot/build.json')['core_sha256']==core_sha
files=set()
for directory in ('source','USB','fixtures','autoboot/source','autoboot/USB'):
    files.update(p for p in (OUT/directory).rglob('*') if p.is_file())
for name in ['操作与验证说明.txt','origin.json','live-map-evidence.json','build.json','ffs-verification.json',
             'HeroIpmiCoreR4.ffs','HERO-IPMI-R4-CORE-TEST.iso','autoboot/HERO-R4-AUTO-BDS-TEST.iso',
             'autoboot/build.json','OFFLINE-r4-success.txt','OFFLINE-r4-preserve_other14.txt','OFFLINE-r4-fan_unavailable.txt',*tests]:files.add(OUT/name)
files.update(OUT.glob('*.py'));files.update((OUT/'autoboot').glob('*.py'))
manual=read(OUT/'vm/results.json');assert manual['all_passed'];files.add(OUT/'vm/results.json')
for c in manual['cases']:
    assert c['iso_sha256']==sha(OUT/'HERO-IPMI-R4-CORE-TEST.iso') and c['driver_sha256']==core_sha
    directory=OUT/'vm'/c['case']
    files.update(p for p in directory.iterdir() if p.suffix in ('.json','.TXT','.png'))
auto=[]
for prefix in ('vm-final','vm-usb'):
    matches=[]
    for p in (OUT/'autoboot').glob(prefix+'*/result.json'):
        t=read(p)
        if t['passed'] and t['iso_sha256']==sha(OUT/'autoboot/HERO-R4-AUTO-BDS-TEST.iso') and t['core_sha256']==core_sha:matches.append((p,t))
    assert matches
    p,t=sorted(matches,key=lambda x:x[0].stat().st_mtime)[-1];auto.append(t)
    if prefix=='vm-usb':assert t['usb_logs_exactly_match_full_qr']
    files.update(p for p in p.parent.iterdir() if p.suffix in ('.json','.TXT','.png'))
for p in files:assert p.is_file()
manifest={p.relative_to(OUT).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(files)}
(OUT/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2)+'\n')
files.add(OUT/'SHA256SUMS.json')
dest=OUT/'HERO-IPMI-R4-RAM-VALIDATION-20261108.zip'
with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in sorted(files):z.write(p,p.relative_to(OUT).as_posix())
with zipfile.ZipFile(dest) as z:
    assert z.testzip() is None and len(z.namelist())==len(files)
    for p in files:
        raw=z.read(p.relative_to(OUT).as_posix());assert raw==p.read_bytes()
        if p.name!='SHA256SUMS.json':assert hashlib.sha256(raw).hexdigest()==manifest[p.relative_to(OUT).as_posix()]['sha256']
handoff={'schema':'hero-ipmi-r4-ram-validation-1','zip':dest.name,'bytes':dest.stat().st_size,'sha256':sha(dest),'members':len(files),
 'manual_iso':{'path':'HERO-IPMI-R4-CORE-TEST.iso','bytes':(OUT/'HERO-IPMI-R4-CORE-TEST.iso').stat().st_size,'sha256':sha(OUT/'HERO-IPMI-R4-CORE-TEST.iso')},
 'auto_iso':{'path':'autoboot/HERO-R4-AUTO-BDS-TEST.iso','bytes':(OUT/'autoboot/HERO-R4-AUTO-BDS-TEST.iso').stat().st_size,'sha256':sha(OUT/'autoboot/HERO-R4-AUTO-BDS-TEST.iso')},
 'core_sha256':core_sha,'ffs_sha256':sha(OUT/'HeroIpmiCoreR4.ffs'),'ffs_guid':'89924765-f984-4ad3-839b-51fdce378d88',
 'offline_cases':sum(read(OUT/name)['count'] for name in tests),'ovmf_manual_optical_and_USB':True,'ovmf_real_BDS_optical_and_USB':True,
 'R4_fresh_BMC_hardware_tested':False,'single_map_live_hardware_verified':True,'CAP_included':False,
 'max_new_RPM_SET_per_fresh_initialization':1,'preserves_other14_mappings':True,'no_extra_hide_unhide':True,'no_PWM_type_mode_EC_SET':True,
 'no_inventory':True,'api_compatibility':'R2 v2 and R3 v3 GUIDs/report layouts unchanged; log identity requires R4.',
 'zip_readback_all_SHA_verified':True}
(OUT/'handoff.json').write_text(json.dumps(handoff,indent=2)+'\n');print(json.dumps(handoff,indent=2))
