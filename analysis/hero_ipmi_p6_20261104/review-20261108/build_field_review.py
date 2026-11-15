"""Bind the independent review conclusion to the exact RC4 release candidate."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;ROOT=HERE.parents[2]
CAP_SHA='44256d23a952234e99bb81743bdcca28a5472a6406eceb18a82a82667b7dcff5'
PE_SHA='71dd9b0956f3e3f1dab3893b2106f01aba0745ba6d5ecf7b172a82f8914bfba0'
CAP=BASE/'firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
assert sha(CAP)==CAP_SHA and sha(BASE/'HeroIpmiP6.efi')==PE_SHA
container=read(HERE/('container-'+CAP_SHA[:12])/'independent-container-review.json')
recovery=read(HERE/('fixed-'+PE_SHA[:12])/'independent-recovery-review.json')
runtime=read(BASE/'runtime-verification.json');backend=read(BASE/'backend/test_report.json')
assert container['passed'] and container['sha256']==CAP_SHA
assert recovery['passed'] and recovery['driver_sha256']==PE_SHA and len(recovery['cases'])==8
assert runtime['passed'] and runtime['driver_sha256']==PE_SHA and runtime['count']==53
assert backend['successful'] and backend['tests']==47 and backend['subcases']==313
for rel,h in recovery['source_sha256'].items():assert sha(BASE/rel)==h
paths=[
 HERE/'pending-watchdog-replay.json',HERE/'setupenter-lifecycle.json',HERE/'afterboot-lifecycle.json',
 HERE/'special-beforeboot-helper.json',
 HERE/('container-'+CAP_SHA[:12])/'independent-container-review.json',
 HERE/('fixed-'+PE_SHA[:12])/'independent-recovery-review.json',
 BASE/'runtime-verification.json',BASE/'backend/test_report.json',
 BASE/'native/independent-verification.json',BASE/'native/native-variable-emulation.json',
 BASE/'creator-review/creator-behavior-review.json',BASE/'creator-review/p6-lifecycle-differences.json']
report={
 'review_date':'2026-11-08','scope':'Independent local firmware review. No network access, real BMC writes, reboots or flashing by this reviewer.',
 'candidate':str(CAP.relative_to(ROOT)),'candidate_sha256':CAP_SHA,'driver_sha256':PE_SHA,
 'release_ready_for_field_test':True,'hardware_validated':False,'production_release_validated':False,
 'remaining_known_release_blockers':[],
 'resolved_findings':[
  {'id':'P6-REVIEW-01','title':'Interrupted watchdog start survived host reset but pending journal blocked the stop path',
   'original_driver_sha256':'67c843e1c3c33f5dd27d86fd352d8050880feaeb95f3616ca027c445d2b6932a',
   'original_reproduced':True,'fix_verified_on_driver_sha256':PE_SHA,
   'verification':'Actual PE instructions after a simulated reset immediately following successful BMC Reset Watchdog. Matching purpose/action/count is stopped with one Set Watchdog; phase 6 and blocked 1 remain; foreign/mismatched running timers receive zero writes; later callbacks do not retry.'},
  {'id':'P6-REVIEW-02','title':'SetupEnter is guarded per AMITSE image and does not reliably republish on returned UEFI apps',
   'original_reproduced':True,'fix_verified_on_driver_sha256':PE_SHA,
   'verification':'Exact AMITSE 0xD090 replay proves BeforeBoot then AfterBoot for returning StartImage success/failure and selected LoadImage failure. Actual new PE registered AfterBoot handler stops the timer, permits a later launch, and does not repeat once-per-boot SEL erasure.'}
 ],
 'evidence_summary':{
  'independent_whole_capsule_inventory':{'official_files':717,'rc3_files':719,'rc4_files':719,'byte_identical_to_rc3':715,'changed_files':4,'new_uefiextract_warning_lines':0,'fresh_extractions_of_review_copies':True},
  'r2_driver_retained_exactly':True,'outside_dxe_and_capsule_wrapper_unchanged':True,
  'setup_code_data_and_relocation_entries_identical_to_official':True,
  'setup_resource_growth_reloc_section_moved_and_directory_adjusted':True,
  'independent_actual_pe_regression_cases':8,'main_actual_pe_runtime_cases_reused':53,
  'portable_backend_cases_reused':47,'portable_backend_subcases_reused':313,
  'rea_reused_ids':['ev_0f583fe537b40032180c3345316145baf6487b87f1000c2f246f4230b8e20ad8','ev_f6d453bc35455677f87532f6acafe7c6ee8bbe4ca69fc18dad423c267d99a872']
 },
 'precise_watchdog_return_scope':{
  'normal_boot_launcher':'AMITSE 0xD090, StartImage 0xDA68, AfterBoot publish 0xDAEC; selected failure publish 0xDBF1; protocol 8c12a959-70bc-4362-b437-b80514a1916e.',
  'special_helper':'0x4E93C is a callback-table target in selector FFFF000B. It requires protocol 473a2909-ed0e-4a61-8792-dc3383c8c01a and assembles EFI\\...\\Boot\\bootmgfw.efi. It publishes BeforeBoot at 0x4EB9C and starts an image at 0x4EBB2, with no local AfterBoot publication.',
  'scope_boundary':'The reviewed D090 flow calls that callback group synchronously and eventually publishes the outer AfterBoot when its boot attempt returns. No guarantee is made for unrelated direct StartImage callers, other firmware/legacy launch paths, or nested applications which never return.',
  'ownership_boundary':'IPMI watchdog metadata identifies purpose/action/timeout, not the originating program. Matching another program using identical metadata cannot be excluded.'
 },
 'startup_latency_scope':{
  'readiness_samples':31,'maximum_readiness_stall_ms':30000,'normally_idle_readiness_stall_ms':2000,
  'transport_delayed_poll_budget_ms_per_operation':45000,'io_attempt_budget_per_operation':200000,
  'boundary':'Limits are per transport session and bound explicit delayed polling, not total wall-clock boot time or firmware service latency. Multiple enabled configuration operations may add their waits. No global boot-time limit or live 31-second timing validation is claimed.'
 },
 'creator_parity_limits':[
  'SEL logging control changes BMC global event logging; it does not implement Creator PEI/DXE status-code event production or Log EFI Status Codes filtering.',
  'SEL full action is evaluated at boot against available space; it is not a continuous BMC policy service and does not clear solely because historical overflow remains set.',
  'Native F10 edits persist desired settings for the next boot; writing settings while the same AMITSE session is cached is deferred until that later boot.',
  'LAN covers channel/source/IP/mask/gateway; it does not clone Creator gateway-MAC editing, IPv6, or every OEM callback.',
  'MLED/BMC_LED and in-band driver/ACPI adaptation are not completed by this candidate.',
  'OS watchdog starts at the reviewed firmware boot boundary, including UEFI applications; the OS or management software must service or stop it.'
 ],
 'field_validation_still_required':[
  'RC4 FlashBack acceptance and cold/warm boot on the intended HERO board; prior RC3 success does not validate these RC4 bytes.',
  'Native BIOS F10 save/discard behavior and next-boot verified BMC application for each exposed setting.',
  'LAN changes with independent access available; live BMC sessions may move or disconnect.',
  'Watchdog return-to-BIOS, OS servicing and controlled timeout behavior on real hardware.',
  'Explicit SEL clear/delete request effects on real device, without assuming simulator acceptance proves BMC behavior.'
 ],
 'release_identity_note':'Modified payload is not ASUS re-signed. This is a field-test candidate, not a vendor-approved production BIOS.',
 'artifacts':{str(p.relative_to(ROOT)):{'sha256':sha(p),'bytes':p.stat().st_size} for p in paths}
}
(HERE/'field-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
text=f'''HERO P6 RC4 independent review - 2026-11-08
Candidate SHA256: {CAP_SHA}
Driver SHA256: {PE_SHA}

Result: ready for controlled field testing; hardware_validated=false.
No remaining demonstrated release blocker was found in this local review.

Two concrete defects were reproduced in the previous driver and verified fixed:
1. Host reset after BMC Reset Watchdog but before final journal could leave a running timer with no recovery stop. New stop-only recovery preserves the blocked journal and refuses differing watchdog metadata.
2. SetupEnter publication is guarded per AMITSE image. New AfterBoot notification stops the timer after the reviewed normal UEFI launch path returns or fails.

Validation: fresh immutable-copy extraction of all three capsules; 719 RC4 files,
715 byte-identical to RC3 and 4 intended changes. R2 retained. No new extractor
warning lines versus official/RC3. Setup non-resource bytes and relocation entries
unchanged; .reloc moves after the larger resource with its directory adjusted.
8 independent actual-PE regressions passed; main 53 runtime cases and portable
47 cases / 313 subcases were reused with matching current identities.

Return coverage: normal AMITSE 0xD090 is covered. Special callback 0x4E93C emits
BeforeBoot but no local AfterBoot; its reviewed synchronous parent eventually
emits AfterBoot. Arbitrary direct StartImage callers and all nested/legacy paths
are not claimed to be covered. OS must service or stop the OS Load watchdog.

Readiness: 31 samples/30 seconds explicit stall maximum per open, normally 2 seconds.
45 seconds delayed polling and 200000 I/O attempts per transport session are not
a whole-boot wall-clock guarantee. Multiple configured operations add latency.

Creator parity is partial: no Creator PEI status-code logging, continuous SEL-full
service, MLED/BMC_LED callbacks, or in-band ACPI adaptation. F10 requests apply on
the following boot. The exact RC4 bytes still need FlashBack, native save/apply,
network change, watchdog and SEL validation on the intended machine.
'''
(HERE/'field-review.txt').write_text(text)
print(json.dumps({k:report[k] for k in ('candidate_sha256','driver_sha256','release_ready_for_field_test','hardware_validated','remaining_known_release_blockers')},indent=2))
