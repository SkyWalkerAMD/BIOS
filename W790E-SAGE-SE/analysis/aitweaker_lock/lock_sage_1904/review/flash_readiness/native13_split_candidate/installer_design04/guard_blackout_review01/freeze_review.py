"""Freeze only this new diagnostic review, never frozen candidates."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;N13=D04.parent;ROOT=HERE.parents[7]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
if '--verify' in sys.argv:
 manifest=json.loads((HERE/'review_manifest.json').read_text())
 for row in manifest['artifacts']:
  p=ROOT/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['path']
 print(json.dumps({'status':'PASS_FROZEN_REVIEW_BINDINGS','artifacts':len(manifest['artifacts'])}));raise SystemExit
reports={name:{'sha256':sha(HERE/name),'checks':json.loads((HERE/name).read_text())['checks']}for name in ['counterexample.json','native_exit_counterexample.json','native_static_control_counterexample.json','static_populator_input_review.json']}
report={
 'status':'CONFIRMED_LOCAL_COMPATIBILITY_AND_NO_SAFE_EXIT_DEFECTS_PHYSICAL_ROOT_CAUSE_UNPROVEN',
 'frozen_tested_app_sha256':'9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3',
 'frozen_tested_iso_sha256':'aca8533281df2d2432881a28441143baf104bc3655bc3309620c76055251ae78',
 'physical_observations':[
  'Mode1 install/remove and Mode2 pre-M provider attach succeeded in captured snapshots; no post-M application snapshot was captured.',
  'M produced an800x600 all-black KVM viewport; one ESC did not visibly return. This alone does not discriminate native rendering, guard refusal, CPU hold, exception or KVM transport.',
  'Root subsequently verified original BIOS renders and a fresh read-only startup sees original module identities/private credential absence. This does not reconstruct all pre-power-off activity.'
 ],
 'local_evidence':reports,
 'confirmed_defects':[
  {'id':'NO_SAFE_PAGE_LOOP','evidence':'counterexample.json','result':'A denied/unknown sole page with no verified redirect suppresses original rendering/input/poll and leaves app+5A zero. Actual E91E branches back to E6BD. This is an implementation liveness defect, not accepted safe denial behavior.'},
  {'id':'STATIC_CHROME_LIFECYCLE','evidence':'native_static_control_counterexample.json','result':'Original16354/33634 initialize standard static subtitle controls with HII=-1. The frozen guard asks HII ownership before non-question classification, rejecting them before original171D4 can assign a valid string source.'},
  {'id':'ACTION_REQUEST_OUT_INITIALIZATION','evidence':'native_exit_counterexample.json','result':'Original21415 leaves ActionRequest untouched when reset-action83678 is zero. A caller initializing~0 and requiring0 falsely rejects a normal return. This is separate from the observed failure to return.'}
 ],
 'source_and_table_correction':'The first NULL-HII/TEXT03 fixture was a synthetic generic counterexample. Real native evidence is SUBTITLE02/7B, control type8, HII sentinelFFFFFFFFFFFFFFFF; neither is an actual hardware structure dump.',
 'candidate_direction':{
  'directory':'../static_chrome_candidate07',
  'scope':'Separately compiled exact-native static subtitle classifier only; no old firmware/driver/provider/installer changes.',
  'conditions':['Pinned original module/header/unchanged method code and vtables','Singleton known native frame kinds1/2/3/5 and exact subtitle class','No object callback, Question metadata or expression pointer','Known original subtitle descriptor slots or exact native kind5 dynamic7B footer','NULL or unknown source/structure remain rejected; AMITSE string association must be exact'],
  'limits':['New provider template/return-address rebinding remains necessary. FrozenP13 cannot bind the changed guard.','Candidate results never transfer to final9115/N12 or an unbuilt future EFI/ISO.','No-safe-page exit is unchanged and must remain an explicit limitation.']
 },
 'safe_exit_assessment':{
  'unconditional_app_5a_write':'REJECTED_UNPROVEN',
  'reason':'Original E52D can reset with pending83580 and null93028. Even with93028 nonzero, outer SendForm213B5 independently resets when83580 is nonzero and93038 is null. Returning ACCESS_DENIED/ABORTED does not suppress those branches.',
  'not_allowed_shortcuts':['Do not clear pending-reset flags or parent pointers','Do not replace RuntimeServices.ResetSystem/SetVariable tables','Do not allow unknown/protected pages to escape the loop','Do not manufacture stack unwinding or callback return addresses'],
  'remaining_proof':'Complete native E52D/122C cleanup, eventFFFF002B registered callbacks, outer SendForm cleanup and relevant BootManager caller behavior must be checked before claiming a non-reset/no-save unwind. Testing only the direct reset condition is insufficient.',
  'implementation':'NONE; no exit patch produced.'
 },
 'diagnostic_order':[
  'Use the separate unhooked original-SendForm baseline06 to distinguish a native browser/context/display failure from guard behavior. No provider/password/detours in that baseline.',
  'Validate the narrow static classifier against exact original constructors and negative mutations before any new provider/app rebinding.',
  'A future guard trace should record first failure stage, native frame/control kind, HII classification result, source sentinel category, IFR opcode/length, begin/status/depth and safe-redirect result in an owned bounded buffer. Do not record secrets or credential records.',
  'Trace delivery still needs a proven returning path. A buffer alone cannot diagnose a black screen after power loss; do not claim an unavailable post-mortem dump exists. No new blind timer, callback, unsafe unwind or unreviewed installer is authorized by this design.'
 ],
 'not_proven':['Physical black-screen root cause','Native full ASUS password UI acceptance','Complete protected entry coverage on hardware','No unrelated OEM NVRAM write during SendForm','Safe no-page unwind','Permanent signed/flashable release readiness'],
 'hardware_or_network_actions':False,
 'frozen_artifacts_modified':False
}
(HERE/'diagnostic_design.json').write_text(json.dumps(report,indent=2)+'\n')
paths=[p for p in HERE.iterdir()if p.is_file() and p.name!='review_manifest.json']
core=D04/'split_core';old=N13.parent/'native12_safety_review/implementation';driver=N13.parents[2]/'driver'
paths += [N13/'boot_context/AMITSE.original.efi',N13/'boot_context/Setup.original.efi',core/'source/gate.c',core/'verify_split.py']
paths += [core/'build'/n for n in ['split_build.json','AMITSE.split-guard.bin','Setup.split-guard.bin','AMITSE.memory-fixture.bin','Setup.memory-fixture.bin','owned-state-fixture.bin']]
paths += [old/'verify_guard.py',old/'build/build.json',old/'build/AMITSE.native-gate.UNSIGNED.review.efi',old/'build/Setup.native-gate.UNSIGNED.review.efi']
paths += [driver/n for n in ['verify_adapter.py','policy.json','build/driver.map','build/AiTweakerLock1904.efi']]
manifest={'status':'FROZEN_DIAGNOSTIC_REVIEW_NOT_EXECUTABLE_DELIVERY','artifacts':[{'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(set(paths))]}
(HERE/'review_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'artifacts':len(paths),'review_sha256':sha(HERE/'diagnostic_design.json'),'manifest_sha256':sha(HERE/'review_manifest.json')}))
