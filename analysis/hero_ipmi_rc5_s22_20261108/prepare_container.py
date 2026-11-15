"""Prepare a new candidate build workspace; never overwrite the C03 release."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
OLD=ROOT/'analysis/hero_ipmi_rc5_s21s_20261108'
R5=ROOT/'analysis/hero_sensor_r5_20261108/HeroIpmiCoreR5.ffs'
P6=ROOT/'analysis/hero_p6_s22_20261108/HeroIpmiNativeP6.ffs'
R5_FFS='be0d4f23272f8c98266629a9e10b1f36f47c35477eb997b3ce44525d230fc792'
R5_PE='81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4'
P6_FFS='554e210cca3de3bc337f944e7126f244d1ffcd67bb81089662f6d3ae78f2ad1b'
P6_PE='abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75'
def sha(b):return hashlib.sha256(b).hexdigest()
assert sha(R5.read_bytes())==R5_FFS and sha(P6.read_bytes())==P6_FFS
assert sha((R5.parent/'USB/EFI/HERO/HeroIpmiR5.efi').read_bytes())==R5_PE
assert sha((P6.parent/'HeroIpmiP6.efi').read_bytes())==P6_PE
frozen=json.loads((OLD/'FROZEN-CANDIDATE03.json').read_text(encoding='utf-8'))
pins={x['path'].replace('\\','/'):x['sha256'] for x in frozen['own_files']}
replacements={
 '3b3665040f28e374b0056fd98a7b1b283f6baaeb77067f34e3d701564fb04ed3':R5_FFS,
 'a3036261c18bd66b158844a6818cf828b54af002dbb9ecf45d8dbc97a5317b2f':R5_PE,
 '75f2f92feaaeccc1eadccf2beda02d7f2d3dc34ffa9058a62928d16009b7a63b':P6_FFS,
 '401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66':P6_PE,
 'analysis/hero_sensor_r4_20261108/HeroIpmiCoreR4.ffs':'analysis/hero_sensor_r5_20261108/HeroIpmiCoreR5.ffs',
 'analysis/hero_p6_settings21s_20261108/HeroIpmiNativeP6.ffs':'analysis/hero_p6_s22_20261108/HeroIpmiNativeP6.ffs',
 'builder-guard-tests-ipmi-only-s21s.json':'builder-guard-tests-ipmi-only-s22.json',
 'R4 sensors/Dashboard':'R5 sensors/Dashboard','R4 sensors':'R5 sensors',
 'R4 and native-P6':'R5 and native-P6','R4 + native P6':'R5 + native P6',
 '# Frozen native21B S21S: FROZEN-CORE-UTF8.json; 53+35+17 author PE checks.':'# S22 preserves S21S lifecycle; adds unique PCI bus discovery. Hardware evidence is separate.',
}
rows=[]
for name in ('build_candidate.py','verify_candidate.py','test_builder_guards.py'):
 src=OLD/name;b=src.read_bytes();assert sha(b)==pins[src.relative_to(ROOT).as_posix()]
 t=b.decode('utf-8')
 for old,new in replacements.items():t=t.replace(old,new)
 dest=HERE/name;assert not dest.exists();dest.write_text(t,encoding='utf-8',newline='\n')
 rows.append({'source':src.relative_to(ROOT).as_posix(),'source_sha256':sha(b),'output':dest.relative_to(ROOT).as_posix(),'sha256':sha(dest.read_bytes())})
manifest={'build_id':'RC5-IPMI-ONLY-R5-S22-CANDIDATE04','modules':[
 {'role':'sensors_dashboard','guid':'89924765-f984-4ad3-839b-51fdce378d88','path':R5.relative_to(ROOT).as_posix(),'sha256':R5_FFS,'pe_sha256':R5_PE},
 {'role':'native_ipmi','guid':'261135b0-7b73-49c0-bcc8-2f9cf4eef19e','path':P6.relative_to(ROOT).as_posix(),'sha256':P6_FFS,'pe_sha256':P6_PE}]}
(HERE/'integration-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(HERE/'builder-source-provenance.json').write_text(json.dumps({'base':'frozen C03 builder/checker/guard tests','changes':'only explicitly listed release pins, source paths and wording','replacements':replacements,'files':rows},indent=2)+'\n')
print('Prepared C04 container sources; hardware/final-release approval not inferred.')
