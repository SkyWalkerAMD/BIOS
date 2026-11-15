from pathlib import Path
import hashlib,json,uuid
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OLD=ROOT/'analysis/hero_p6_s22_20261108'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
PE='1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc'
FFS='15c1e38b0693105a3f2abad917f375cc0d36285d9e4d8402013e5088244766fa'
assert sha(BASE/'HeroIpmiP6.efi')==PE and sha(BASE/'HeroIpmiNativeP6.ffs')==FFS
assert sha(OLD/'HeroIpmiP6.efi')=='abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75'
changed=[]
for p in (BASE/'source').rglob('*'):
 if p.is_file():
  old=OLD/'source'/p.relative_to(BASE/'source')
  if not old.exists() or p.read_bytes()!=old.read_bytes():changed.append(p.relative_to(BASE/'source').as_posix())
assert sorted(changed)==['driver.c','expected_p5.h','p5.h','publisher.c'],changed
banner_old='HERO-IPMI-P6-S22 / dynamic PCI discovery / S21S lifecycle unchanged'
banner_new='HERO-IPMI-P6-S23 / exact P5 readonly + P6 resources / S22 transport'
assert (BASE/'source/driver.c').read_text().replace(banner_new,banner_old)==(OLD/'source/driver.c').read_text()
for name in ('p6_backend.c','p6_backend.h'):assert (BASE/'backend'/name).read_bytes()==(OLD/'backend'/name).read_bytes()
for name in ('Setup-forms-P6.bin','native-payload.json'):assert (BASE/'native'/name).read_bytes()==(OLD/'native'/name).read_bytes()
assert sha(BASE/'native/Setup-forms-P5.bin')=='b295f8ce9b5f38f366f3cf8c9c8895f218bd009c2a9c9144ea2ff6c5ff3f98c8'
def sections(path):
 b=path.read_bytes();assert str(uuid.UUID(bytes_le=b[:16]))=='261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
 assert int.from_bytes(b[20:23],'little')==len(b) and b[18]==7 and b[17]==0xaa
 h=bytearray(b[:24]);h[17]=h[23]=0;assert sum(h)%256==0
 at=24;result=[]
 while at<len(b):
  n=int.from_bytes(b[at:at+3],'little');assert n>=4 and at+n<=len(b)
  result.append((b[at+3],b[at+4:at+n]));at+=n
  if at!=len(b):pad=(-at)%4;assert b[at:at+pad]==bytes(pad);at+=pad
 assert at==len(b) and [x[0] for x in result]==[0x13,0x10,0x15]
 return result
before=sections(OLD/'HeroIpmiNativeP6.ffs');after=sections(BASE/'HeroIpmiNativeP6.ffs')
assert after[0]==before[0] and after[2]==before[2] and after[1][1]==(BASE/'HeroIpmiP6.efi').read_bytes()
checks={}
for name,key,count in [('runtime-verification.json','count',53),('tests/settings21-pe.json','cases',35),('tests/sync-lifecycle-pe.json','cases',17),('tests/pci-discovery-pe.json','cases',52),('tests/resource-compatibility-pe.json','cases',47)]:
 r=json.loads((BASE/name).read_text());assert r['passed'] and r[key]==count and r['driver_sha256']==PE;checks[name]=count
files=['HeroIpmiP6.efi','HeroIpmiNativeP6.ffs','runtime-build.json','runtime-verification.json','tests/settings21-pe.json','tests/sync-lifecycle-pe.json','tests/pci-discovery-pe.json','tests/resource-compatibility-pe.json','tests/OFFLINE-S23-AFTERBOOT.txt','设计与验证边界.txt']
report={'status':'Frozen S23 exact known-P5-readonly/P6 resource RAM candidate; .15 hardware validation pending; no CAP generated','driver_sha256':PE,'ffs_sha256':FFS,'api_version':6,'api_size':24,'ffs_guid':'261135b0-7b73-49c0-bcc8-2f9cf4eef19e','production_files_changed_from_S22':changed,'driver_c_banner_only':True,'settings_journal_transport_and_lifecycle_unchanged':True,'native_forms_sha256':sha(BASE/'native/Setup-forms-P6.bin'),'known_P5_readonly_forms_sha256':sha(BASE/'native/Setup-forms-P5.bin'),'depex_unchanged':True,'early_setup_timer_unchanged_not_hardware_validated':True,'strict_ffs_sections':[{'type':k,'bytes':len(b)} for k,b in after],'actual_pe_checks':checks,'files':{n:{'sha256':sha(BASE/n),'bytes':(BASE/n).stat().st_size} for n in files},'sources':{p.relative_to(BASE).as_posix():sha(p) for p in (BASE/'source').rglob('*') if p.is_file()},'test_sources':{p.relative_to(BASE).as_posix():sha(p) for p in (BASE/'tests').glob('test_*.py')},'notes':['Known P5 accepts only exact complete frozen Forms and publishes existing40 values. Known P6 retains exact complete Forms and41 values.','Every Forms handle must be exported and structurally readable before unique-known-target acceptance; failures are terminal.','Publish repins the same kind and prechecks every language/value ID before first SetString. Unknown or mixed resources are not accepted.','Resource kind, known SHA/bytes, enumeration counts and failure stage/ID/status are RAM-audited.','P5 compatibility is readonly display, not creation of21 configuration controls or F10 verification.','No HII injection, inventory or firmware write in the RAM launcher.']}
(BASE/'FROZEN-CORE-UTF8.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k not in ('sources','files','test_sources')},indent=2))
