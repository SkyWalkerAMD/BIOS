from pathlib import Path
import hashlib,json,struct,uuid
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OLD=ROOT/'analysis/hero_ipmi_p6_20261104'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
expected='6a5e2c86f9e49ceefa47d8765cf45c585805f7ac164f07be07df6505100d8ffb'
assert sha(BASE/'HeroIpmiP6.efi')==expected
assert sha(OLD/'HeroIpmiP6.efi')=='71dd9b0956f3e3f1dab3893b2106f01aba0745ba6d5ecf7b172a82f8914bfba0'
changed=[]
for p in (BASE/'source').rglob('*'):
 if p.is_file() and p.read_bytes()!=(OLD/'source'/p.relative_to(BASE/'source')).read_bytes():changed.append(p.relative_to(BASE/'source').as_posix())
assert sorted(changed)==['driver.c','settings.c'],changed
for n in ('p6_backend.c','p6_backend.h'):assert (BASE/'backend'/n).read_bytes()==(OLD/'backend'/n).read_bytes()
forms=(BASE/'native/Setup-forms-P6.bin').read_bytes();assert forms==(OLD/'native/Setup-forms-P6.bin').read_bytes()
ops=[];at=4
while at<len(forms):
 n=forms[at+1]&127;assert n>=2 and at+n<=len(forms);ops.append((at,forms[at:at+n]));at+=n
assert at==len(forms)
stores=[(at,b) for at,b in ops if b[0]==0x26 and b[4:20]==uuid.UUID('bef09fe1-8540-4be1-9082-e6624328f435').bytes_le]
assert len(stores)==1;offset,store=stores[0];assert struct.unpack_from('<I',store,20)[0]==3 and struct.unpack_from('<H',store,24)[0]==32
questions=[b for _,b in ops if b[0] in (5,7) and len(b)>=17 and struct.unpack_from('<H',b,8)[0]==0x3f00]
defined=sorted(struct.unpack_from('<H',b,10)[0] for b in questions);assert defined==list(range(21))
ffs=(BASE/'HeroIpmiNativeP6.ffs').read_bytes();assert str(uuid.UUID(bytes_le=ffs[:16]))=='261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
assert int.from_bytes(ffs[20:23],'little')==len(ffs) and ffs[18]==7 and ffs[17]==0xaa
h=bytearray(ffs[:24]);h[17]=h[23]=0;assert sum(h)%256==0
at=24;sections=[]
while at<len(ffs):
 n=int.from_bytes(ffs[at:at+3],'little');assert n>=4 and at+n<=len(ffs);sections.append((ffs[at+3],ffs[at+4:at+n]));at+=n
 if at!=len(ffs):at=(at+3)&~3
assert at==len(ffs) and [k for k,_ in sections]==[0x13,0x10,0x15]
assert sections[1][1]==(BASE/'HeroIpmiP6.efi').read_bytes()
assert ffs.endswith(sections[-1][1]) # No trailing alignment bytes.
runtime=json.loads((BASE/'runtime-verification.json').read_text());special=json.loads((BASE/'tests/settings21-pe.json').read_text())
assert runtime['passed'] and runtime['count']==53 and special['passed'] and special['cases']==35
assert runtime['driver_sha256']==special['driver_sha256']==expected
files=['HeroIpmiP6.efi','HeroIpmiNativeP6.ffs','runtime-build.json','runtime-verification.json','tests/settings21-pe.json','兼容性说明.txt']
report={'status':'Frozen core; awaiting real P6-S21 RAM test','driver_sha256':expected,'api_version':6,'api_size':24,'ffs_guid':'261135b0-7b73-49c0-bcc8-2f9cf4eef19e','production_files_changed':changed,'settings_storage_lengths':[21,32],'settings_internal_bytes':32,'state_bytes':144,'native_ifr':{'offset':offset,'declared_size':32,'defined_offsets':defined,'forms_sha256':hashlib.sha256(forms).hexdigest()},'strict_ffs_sections':[{'type':k,'bytes':len(b)} for k,b in sections],'files':{n:{'sha256':sha(BASE/n),'bytes':(BASE/n).stat().st_size} for n in files},'sources':{p.relative_to(BASE).as_posix():sha(p) for p in (BASE/'source').rglob('*') if p.is_file()}}
(BASE/'FROZEN-CORE-UTF8.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in report.items() if k!='sources'},indent=2))
