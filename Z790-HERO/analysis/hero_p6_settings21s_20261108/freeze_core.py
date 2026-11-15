from pathlib import Path
import hashlib,json,uuid
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OLD=ROOT/'analysis/hero_p6_settings21r_20261108'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
PE='401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66'
FFS='75f2f92feaaeccc1eadccf2beda02d7f2d3dc34ffa9058a62928d16009b7a63b'
assert sha(BASE/'HeroIpmiP6.efi')==PE and sha(BASE/'HeroIpmiNativeP6.ffs')==FFS
assert sha(OLD/'HeroIpmiP6.efi')=='5adbebb682b957a7877d87918286f7a1cbf297bbf7e2c14d7632c7d1afa3d685'
changed=[]
for p in (BASE/'source').rglob('*'):
 if p.is_file() and p.read_bytes()!=(OLD/'source'/p.relative_to(BASE/'source')).read_bytes():changed.append(p.relative_to(BASE/'source').as_posix())
assert changed==['driver.c'],changed
for name in ('p6_backend.c','p6_backend.h'):assert (BASE/'backend'/name).read_bytes()==(OLD/'backend'/name).read_bytes()
assert (BASE/'native/Setup-forms-P6.bin').read_bytes()==(OLD/'native/Setup-forms-P6.bin').read_bytes()
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
for name,key,count in [('runtime-verification.json','count',53),('tests/settings21-pe.json','cases',35),('tests/sync-lifecycle-pe.json','cases',17)]:
 r=json.loads((BASE/name).read_text());assert r['passed'] and r[key]==count and r['driver_sha256']==PE;checks[name]=count
files=['HeroIpmiP6.efi','HeroIpmiNativeP6.ffs','runtime-build.json','runtime-verification.json','tests/settings21-pe.json','tests/sync-lifecycle-pe.json','tests/OFFLINE-S21S-AFTERBOOT.txt']
report={'status':'Frozen S21S RAM candidate; real AfterBoot validation pending; no CAP generated','driver_sha256':PE,'ffs_sha256':FFS,'api_version':6,'api_size':24,'ffs_guid':'261135b0-7b73-49c0-bcc8-2f9cf4eef19e','production_files_changed_from_S21R':changed,'settings_and_journal_unchanged':True,'native_forms_sha256':sha(BASE/'native/Setup-forms-P6.bin'),'depex_unchanged':True,'early_setup_timer_unchanged_not_hardware_validated':True,'strict_ffs_sections':[{'type':k,'bytes':len(b)} for k,b in after],'actual_pe_checks':checks,'files':{n:{'sha256':sha(BASE/n),'bytes':(BASE/n).stat().st_size} for n in files},'sources':{p.relative_to(BASE).as_posix():sha(p) for p in (BASE/'source').rglob('*') if p.is_file()}}
(BASE/'FROZEN-CORE-UTF8.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k not in ('sources','files')},indent=2))
