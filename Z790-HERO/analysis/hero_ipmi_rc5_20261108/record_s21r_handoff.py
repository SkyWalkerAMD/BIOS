"""Record immutable candidate02 pins; no firmware/flash operations."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
folder=HERE/'RC5-IPMI-ONLY-R4-S21R-CANDIDATE02'
build=json.loads((folder/'build-report.json').read_text())
check=json.loads((folder/'independent-container-verification.json').read_text())
guard=json.loads((HERE/'builder-guard-tests-ipmi-only-s21r.json').read_text())
cap=ROOT/build['candidate']
assert sha(cap)==build['candidate_sha256']==check['candidate_sha256']=='a10c22412e0f1388915b14c3c297121cc9d9b976ce10143652b4b15b9cc4f5c1'
assert cap.stat().st_size==33558528 and check['passed'] and guard['passed'] and guard['tests']==30
old=HERE/'RC5-IPMI-ONLY-R4-S21-CANDIDATE01/HERO-3107-IPMI-RC5-IPMI-ONLY-R4-S21-CANDIDATE01-UNSIGNED.CAP'
assert sha(old)=='0f755eb739d83e40b289c2835d44e29f97f6c106a6820e57c4397ba648a4beaa'
oldpins={'build_candidate.py':'d3e5e17b321dc36a5a2747146b0dee5fe3efae16ae5b87a36103b1e87f54fbe4','verify_candidate.py':'a66e657eea875b7f2cbea53868625d09620d0c316bd92ebde32ad7a2cf273b3e','test_builder_guards.py':'9783f194e87e5dfc232eacfadb5b7d26295ad12a199d7214a1585cb6d2db8efb'}
for n,d in oldpins.items():assert sha(HERE/'builder-source-s21-candidate01'/n)==d
core=ROOT/'analysis/hero_p6_settings21r_20261108/FROZEN-CORE-UTF8.json'
ram=ROOT/'analysis/hero_p6_ramcheck3_20261108'
record={'status':'Offline candidate02, awaiting real RAM/native and flash results','candidate':cap.relative_to(ROOT).as_posix(),'sha256':sha(cap),'bytes':cap.stat().st_size,'baseline_sha256':build['baseline_sha256'],'modules':build['modules'],'exactly_two_existing_replacements':True,'inventory_included':False,'other_FFS_and_platform_preserved':True,'core_freeze_sha256':sha(core),'guard_cases':30,'candidate01_preserved':True,'candidate01_source_snapshot':oldpins,'current_sources':{n:sha(HERE/n) for n in oldpins},'reports':{n:sha(folder/n) for n in ('build-report.json','independent-container-verification.json','integration-manifest.json')},'ramcheck3':{n:{'sha256':sha(ram/n),'bytes':(ram/n).stat().st_size} for n in ('HERO-P6-RAMCHECK-3.iso','HERO-P6-RAMCHECK-3-PACKAGE.zip','FROZEN-ARTIFACTS.json')},'field_guide_note':'Existing delivery-draft guide is tied to candidate01. Root must update its fixed CAP name/hash and live-result markers before any final package.','hardware_actions':False}
(HERE/'ipmi-only-s21r-build-handoff.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in record.items() if k in ('candidate','sha256','bytes','status','field_guide_note')},indent=2))
