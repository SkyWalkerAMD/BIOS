"""Freeze local classifier evidence only, not a provider or hardware package."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[7];PROOF=HERE.parent/'guard_blackout_review01'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
if '--verify' in sys.argv:
 manifest=json.loads((HERE/'candidate_manifest.json').read_text())
 for row in manifest['artifacts']:
  p=ROOT/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['path']
 print(json.dumps({'status':'PASS_LOCAL_CLASSIFIER_BINDINGS','artifacts':len(manifest['artifacts'])}));raise SystemExit
build=json.loads((HERE/'build/split_build.json').read_text())
test=json.loads((HERE/'build/chrome_verification.json').read_text())
old=json.loads((HERE/'build/split_guard_regression.json').read_text())
assert test['checks']==106 and test['status'].startswith('PASS_')
assert old['checks']==198 and old['reused_policy_checks']==139 and old['status'].startswith('PASS_')
assert test['new_build_sha256']==old['split_build_sha256']==sha(HERE/'build/split_build.json')
assert test['new_source_sha256']==build['sources']['gate.c']==sha(HERE/'source/gate.c')
for name,digest in build['sources'].items():assert sha(HERE/'source'/name)==digest
for name,row in build['module_fixtures'].items():assert sha(HERE/'build'/(name+'.split-guard.bin'))==row['guard_sha256']==test['new_guard_sha256'][name]
review={
 'status':'FROZEN_LOCAL_STATIC_CHROME_CLASSIFIER_NOT_DEPLOYABLE',
 'problem':'Frozen original guard asks HII ownership for static native SUBTITLE controls that original16354/33634 intentionally construct with source=-1 before the first page render.',
 'behavior':'Recognize only exact original static chrome frames/control methods/descriptor semantics and source association. Other protected forms/questions and unknown structures remain denied.',
 'strictness':['Native frame kinds1/2/3/5, singleton, exact frame/control vtables','All10 frame and12 control method slots pinned; original method body ranges CRC-checked and current FrameInput detour matched to this guard','Generic object callbacks, Question metadata and expression pointer absent','Type8/7B SUBTITLE, original slots for kinds1/2/3 and native dynamic footer token3 for kind5','Frame/control/IFR writable; source NULL or unknown association refused','Known static marker with any failed invariant returns UNKNOWN directly, including after native renderer changes source to validHII; no fallback to ordinary non-Question classifier'],
 'source_cases':['Native -1 string sentinel','Existing validated Setup/foreign HII ownership','Exact AMITSE93970 slot resolved through HII.GetPackageListHandle to a LoadedImage with the original AMITSE base/size'],
 'same_policy':['Protected form IDs','Protected Setup Question and varstore29/selected33 offsets','Password begin/end/query/request/manage ABI','Local commit/default/save-feedback gates','No-safe-page redirect/exit behavior remains unchanged and incomplete'],
 'template_sha256':build['template_sha256'],
 'template_bytes':build['template_bytes'],
 'module_fixtures':build['module_fixtures'],
 'author_checks':{
  'new_constructor_and_negative_cases':{'checks':106,'sha256':sha(HERE/'build/chrome_verification.json')},
  'old_policy_and_split_state_regression':{'checks':198,'inherited_policy_checks':139,'sha256':sha(HERE/'build/split_guard_regression.json')}
 },
 'original_byte_analysis':{'manifest_sha256':sha(PROOF/'review_manifest.json'),'review_sha256':sha(PROOF/'diagnostic_design.json')},
 'retained_superseded_local_revisions':['251219b67d0eeb2b:initial67+198 before writable-boundary refinement','00f0a64aaccf5a5c:70+198 before strict claimed-static failure and full frame table pin'],
 'limits':['This is compiled detached guard code plus synthetic memory fixtures; no complete EFI installer, ISO or flashable BIOS was produced.','FrozenP13 binds the old guard and cannot bind this new guard. Any future provider/app requires new exact template/hash/call-return binding and its own regression/manifest.','Original constructors/populator execute with modeled allocation/CopyMem/color services; new guard actual bytes execute. Full original renderer/browser/password GUI and physical state are untested by these author cases.','AMITSE string-driver association has independent original-byte evidence, but is not a captured post-render physical HII topology.','The physical black-screen root cause remains unproven; baseline06 and a bounded new native test are distinct required evidence.','No-safe-page safe unwind remains unproven. No native reset flag, RuntimeServices table or unknown-page permission was changed.'],
 'no_hardware_network_or_firmware_operation':True,
 'frozen_N12_P12_N13_P13_TX05_modified':False
}
(HERE/'candidate_review.json').write_text(json.dumps(review,indent=2)+'\n')
paths=[p for p in HERE.iterdir()if p.is_file()and p.name!='candidate_manifest.json']
paths += [p for p in (HERE/'source').iterdir()if p.is_file()]
paths += [p for p in (HERE/'build').iterdir()if p.is_file()]
paths += [p for p in (HERE/'revisions').rglob('*')if p.is_file()]
proof=json.loads((PROOF/'review_manifest.json').read_text())
paths += [ROOT/x['path']for x in proof['artifacts']]+[PROOF/'review_manifest.json']
manifest={'status':'FROZEN_CLASSIFIER_ONLY_NO_PROVIDER_INSTALLER_OR_HARDWARE_DELIVERY','artifacts':[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(set(paths))]}
(HERE/'candidate_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'artifacts':len(manifest['artifacts']),'review_sha256':sha(HERE/'candidate_review.json'),'manifest_sha256':sha(HERE/'candidate_manifest.json'),'template_sha256':build['template_sha256']}))
