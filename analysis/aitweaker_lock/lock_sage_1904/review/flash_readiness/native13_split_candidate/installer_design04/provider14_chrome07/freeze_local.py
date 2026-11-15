"""Freeze P14 exact classifier07 binding, without transferring hardware results."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;ROOT=D04.parents[6]
CORE=D04/'static_chrome_candidate07';OLD=D04/'provider13'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mp=HERE/'local_candidate_manifest.json'
if '--verify' in sys.argv:
 m=json.loads(mp.read_text())
 for r in m['artifacts']:
  p=D04/r['path'];assert p.stat().st_size==r['bytes'] and sha(p)==r['sha256'],r['path']
 print(json.dumps({'status':'PASS_P14_FROZEN_BINDINGS','artifacts':len(m['artifacts']),'manifest_sha256':sha(mp)}));sys.exit(0)
assert not mp.exists(),'Already frozen; use --verify'
cm=json.loads((CORE/'candidate_manifest.json').read_text())
for row in cm['artifacts']:
 p=ROOT/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['path']
b=json.loads((HERE/'build/build.json').read_text());efi=HERE/'build/AiTweakerSplitProvider14.UNSIGNED.local.efi'
assert sha(efi)==b['efi_sha256']
for name,h in b['sources'].items():assert sha(HERE/'source'/name)==h,name
for name,h in b['objects'].items():assert sha(HERE/'build'/name)==h,name
profile=json.loads((HERE/'split_profile.json').read_text())
assert profile['guard_template_sha256']=='2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'
assert sha(HERE/'build/management.pack')==sha(OLD/'build/management.pack')
unchanged={}
for p in (HERE/'source').iterdir():
 if p.name!='split_profile.h':assert sha(p)==sha(OLD/'source'/p.name),p.name;unchanged[p.name]=sha(p)
reports=[]
for p,n in [(CORE/'build/split_guard_regression.json',198),(CORE/'build/chrome_verification.json',106),(HERE/'build/owner_verification.json',31)]:
 r=json.loads(p.read_text());assert r['checks']==n and r['status'].startswith('PASS'),p
 if p.parent.parent==HERE:assert r['provider_sha256']==sha(efi) and r['split_build_sha256']==sha(CORE/'build/split_build.json')
 reports.append({'path':str(p.relative_to(D04)),'sha256':sha(p),'checks':n,'scope':r['status']})
review={'status':'FROZEN_P14_EXACT_CHROME07_REBIND_LOCAL_ONLY_NOT_RELEASE_READY','provider_sha256':sha(efi),'provider_bytes':efi.stat().st_size,'guard_template_sha256':profile['guard_template_sha256'],'classifier_manifest_sha256':sha(CORE/'candidate_manifest.json'),'public_abi_unchanged':{'guid':'87e3c6fa-11fb-4e77-af2d-ea50b640fa13','provider_bytes':56,'frame_bytes':48,'context_bytes':96,'binding_bytes':160,'state_page':4096,'state_used':32},'all_other_p13_sources_byte_identical':unchanged,'tests':reports,'test_count':335,'limits':['Actual P14 owner plus new guard is tested with explicit UEFI/callee models; not native ASUS GUI acceptance.','Earlier P13 OVMF and physical attach results do not transfer across P14 hash. Password crypto/UI source is unchanged but final P14 entry/HII/UI still needs bound testing.','07 retains the known no-safe-page denial/input-suppression limitation; no forced native exit or unknown-page exception.','The same public GUID does not permit interchangeable artifacts: full detached template, exact installed12 targets and original OEM text are pinned.','No permanent firmware integration, modified CAP or signature/flash acceptance.']}
(HERE/'local_candidate_review.json').write_text(json.dumps(review,indent=2)+'\n')
files=set(HERE.glob('*.py'))|set(HERE.glob('*.json'))
files.update(p for p in (HERE/'source').iterdir()if p.is_file())
files.update(p for p in (HERE/'build').iterdir()if p.is_file())
files.update([CORE/'candidate_manifest.json',CORE/'candidate_review.json',CORE/'build/split_build.json',CORE/'build/guard_template.bin',CORE/'build/split_guard_regression.json',CORE/'build/chrome_verification.json'])
files.update(p for p in (CORE/'source').iterdir()if p.is_file())
files.discard(mp)
m={'status':review['status'],'path_base':'installer_design04','artifacts':[{'path':str(p.relative_to(D04)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)]}
mp.write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({'status':review['status'],'provider_sha256':sha(efi),'artifacts':len(m['artifacts']),'manifest_sha256':sha(mp)}))
