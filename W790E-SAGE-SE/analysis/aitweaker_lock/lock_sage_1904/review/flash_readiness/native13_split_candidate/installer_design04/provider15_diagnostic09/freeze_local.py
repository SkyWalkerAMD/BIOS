"""Freeze diagnostic-only P15 source/guard binding; later lab evidence is separate."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;CORE=D04/'diagnostic_guard09';OLD=D04/'provider14_chrome07'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
mp=HERE/'local_candidate_manifest.json'
if '--verify' in sys.argv:
 m=json.loads(mp.read_text())
 for r in m['artifacts']:
  p=D04/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256'],r['path']
 print(json.dumps({'status':'PASS_P15_FROZEN_BINDINGS','artifacts':len(m['artifacts']),'sha256':sha(mp)}));raise SystemExit
assert not mp.exists(),'Already frozen; use --verify'
cm=json.loads((CORE/'candidate_manifest.json').read_text())
for r in cm['artifacts']:
 p=D04/r['path'];assert p.stat().st_size==r['bytes']and sha(p)==r['sha256']
b=json.loads((HERE/'build/build.json').read_text());efi=HERE/'build/AiTweakerSplitProvider15.UNSIGNED.local.efi'
assert sha(efi)==b['efi_sha256']
for n,h in b['sources'].items():assert sha(HERE/'source'/n)==h,n
for n,h in b['objects'].items():assert sha(HERE/'build'/n)==h,n
profile=json.loads((HERE/'split_profile.json').read_text())
assert profile['guard_template_sha256']==sha(CORE/'build/guard_template.bin')
assert sha(HERE/'build/management.pack')==sha(OLD/'build/management.pack')
for n in ['diagnostic09.h','diagnostic_store.h']:assert sha(HERE/'source'/n)==sha(CORE/'source'/n)
unchanged={}
changed={'owner.c','hii.c','ui.c','split_profile.h'}
for p in(OLD/'source').iterdir():
 if p.name not in changed:assert sha(p)==sha(HERE/'source'/p.name),p.name;unchanged[p.name]=sha(p)
owner=json.loads((HERE/'build/owner_verification.json').read_text())
assert owner['checks']==31 and owner['status'].startswith('PASS')and owner['provider_sha256']==sha(efi)and owner['split_build_sha256']==sha(CORE/'build/split_build.json')
review={
 'status':'FROZEN_P15_DIAGNOSTIC_ONLY_LOCAL_CANDIDATE_NOT_RELEASE_READY',
 'provider_sha256':sha(efi),'provider_bytes':efi.stat().st_size,'guard_template_sha256':profile['guard_template_sha256'],
 'guard_manifest_sha256':sha(CORE/'candidate_manifest.json'),
 'public_abi_unchanged':{'guid':'87e3c6fa-11fb-4e77-af2d-ea50b640fa13','provider_bytes':56,'frame_bytes':48,'context_bytes':96,'binding_bytes':160,'state_page':4096,'state_prefix':32},
 'private_trace':{'offset':64,'bytes':576,'header_sha256':sha(HERE/'source/diagnostic09.h'),'store_sha256':sha(HERE/'source/diagnostic_store.h')},
 'unchanged_original_p14_sources':unchanged,
 'changes':{'owner.c':'New private bounded state-region accessor; no change to owner/grant checks.','hii.c':'Direct FFE2 verify wraps existing request with independent diagnostic origin; does not use an old classification.','ui.c':'Existing UNCONFIGURED screen shows six diagnostic lines; its successful acknowledgement increments diagnostic-only counter. Password enrollment/unlock/crypto behavior unchanged.','split_profile.h':'Full new detached template identity and exact native Begin/End return offsets.','diagnostic.c':'Non-secret display scalar conversion/CRC and six ConOut lines; every next line checks ending. No variable/input operations.'},
 'tests':[{'path':str((HERE/'build/owner_verification.json').relative_to(D04)),'sha256':sha(HERE/'build/owner_verification.json'),'checks':31,'scope':owner['status']}],
 'external_evidence_policy':'Independent exact-PE display/storage and new OVMF lab reports are separately frozen supplements. Earlier P14 physical/OVMF results are not transferred across hashes.',
 'limits':['This EFI is a provider, not a standalone installer or flashable BIOS.','No-safe-page denial/input suppression remains; diagnostics do not force a safe exit.','New diagnostic display does not establish ASUS root cause or prove native management works.','Current physical diagnostic scope must not create a password; cross-boot recovery after an interrupted password write is a separate unresolved workflow.','No real password/record is logged or included in artifacts. No hardware actions occurred here.']}
(HERE/'local_candidate_review.json').write_text(json.dumps(review,indent=2)+'\n')
files=set(HERE.glob('*.py'))|set(HERE.glob('*.json'))
files.update(p for sub in ['source','build']for p in(HERE/sub).iterdir()if p.is_file())
files.update([CORE/'candidate_manifest.json',CORE/'candidate_review.json',CORE/'integration_contract.json',CORE/'build/split_build.json',CORE/'build/guard_template.bin',CORE/'build/diagnostic_verification.json',OLD/'local_candidate_manifest.json'])
files.update(p for p in(CORE/'source').iterdir()if p.is_file())
files.discard(mp)
m={'status':review['status'],'path_base':'installer_design04','artifacts':[{'path':str(p.relative_to(D04)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)]}
mp.write_text(json.dumps(m,indent=2)+'\n')
print(json.dumps({'status':review['status'],'provider_sha256':sha(efi),'artifacts':len(m['artifacts']),'manifest_sha256':sha(mp),'review_sha256':sha(HERE/'local_candidate_review.json')}))
