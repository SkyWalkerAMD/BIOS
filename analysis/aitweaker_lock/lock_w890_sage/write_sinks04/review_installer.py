"""Record independent source review and verify exact final lab evidence bindings.
This does not rerun or broaden the root agent's completed VM experiments.
"""
from pathlib import Path
import json,hashlib,re
H=Path(__file__).resolve().parent;R=H.parents[3];I=H.parent/'installer04'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
bound={};checks=[]
def bind(p):p=p.resolve();bound[str(p.relative_to(R))]={'bytes':p.stat().st_size,'sha256':sha(p)};return p
for m in [I/'build/build_manifest.json',I/'watch_build/build_manifest.json']:
 j=read(bind(m))
 for path,want in j['inputs'].items():
  p=Path(path);assert p.stat().st_size==want['bytes'] and sha(p)==want['sha256'],path;bind(p)
 outputs=[j['output']]if'output'in j else list(j['outputs'].values())
 for out in outputs:
  p=Path(out['path']);assert p.stat().st_size==out['bytes'] and sha(p)==out['sha256'];bind(p)
 checks.append({'check':'all build inputs and outputs byte exact','manifest':str(m.relative_to(R)),'passed':True})
runs=['20261108_023557','20261108_023349_watch0','20261108_023349_watch1','20261108_023434_watch2','20261108_023434_watch3']
expected=[96,9,4,10,9];run_records=[];outputs=[I/'build/W890-Installer04.TCG-ONLY.efi']+[I/f'watch_build/W890-ColdWatch04-{i}.TCG-ONLY.efi'for i in range(4)]
for name,count,efi in zip(runs,expected,outputs):
 p=I/'runs'/name/'result.json';j=read(bind(p));log=bind(p.with_name('debug.log'));s=log.read_text(errors='replace')
 assert j['status'].startswith('PASS_') and j['checks']==count and j['exit_code']==33 and j['iso_before']==j['iso_after']
 assert sha(log)==j['debug_sha256'] and sha(efi)==j['efi_sha256'];assert len(re.findall(r'^PASS ',s,re.M))==count
 assert not re.search(r'^FAIL ',s,re.M)
 run_records.append(dict(path=str(p.relative_to(R)),efi_sha256=sha(efi),checks=count,scope=j['scope'],fault_injection=j.get('fault_injection')))
guards=[I/'build/entry_guard_tests.json']+[I/f'watch_build/W890-ColdWatch04-{i}.TCG-ONLY.guard.json'for i in range(4)]
for path,efi in zip(guards,outputs):
 j=read(bind(path));assert j['efi_sha256']==sha(efi) and len(j['cases'])==2
 assert all(c['passed']and not c['firmware_services_accessed']and c['image_unchanged']for c in j['cases'])
checks.append({'check':'5 final actual EFI entry guards, 2 modeled non-TCG CPUID cases each','passed':True})
sources={str(p.relative_to(R)):sha(p)for p in [I/'source/transaction.c',I/'source/transaction.h',I/'source/memory.c',I/'source/memory.h',I/'source/cold_watch.c',I/'source/cold_watch.h']}
findings=[
 {'id':'F1','severity':'high','problem':'finish called RestoreTPL before checking terminal EBS flags when second raised-TPL validation revoked the transaction.','status':'FIXED_SOURCE_AND_REAL_OVMF_INJECTION','resolution':'Pre-call ended/VM/context checks prevent any RestoreTPL after revocation; retains resident HOLD/ENDED state.','evidence':'20261108_023557: terminal notification during second validation; current TPL16 proves no RestoreTPL.'},
 {'id':'F2','severity':'high','problem':'validate and repeated memory capture dereferenced cached ST/BS before checking current mappings.','status':'FIXED_SOURCE_AND_REAL_OVMF_RP_PAGES','resolution':'service_tables validates both spans before field loads; repeated i04_capture validates previous mapped tables and captured memory_map function before calling it. First EFI-entry table remains the documented bootstrap trust anchor.','evidence':'20261108_023557: private ST and BS copies marked read-protected; validate/resnapshot refuse without fault.'},
 {'id':'F3','severity':'high','problem':'prepare could still read BS raise/restore fields before the later validate page checks.','status':'FIXED_SOURCE_AND_REAL_OVMF_RP_PAGES','resolution':'service_tables runs at prepare entry and immediately before capturing raise/restore methods.','evidence':'20261108_023557: prepare is tested while private ST/BS pages are protected, before failed resnapshot.'},
 {'id':'F4','severity':'medium','problem':'Outer accepted cold-watch consumer could overwrite a FAULT raised by a nested notification.','status':'FIXED_SOURCE_AND_EXPLICIT_TEST_SHIM_IN_REAL_OVMF','resolution':'Consumer return requires phase to remain exactly CW_WINDOW; nested FAULT is preserved.','evidence':'20261108_023434_watch2; direct nested-notify test shim is accurately identified, not a naturally recursive firmware notification.'},
 {'id':'F5','severity':'medium','problem':'Cold-watch service/table reads lacked current mapping checks and captured method pinning.','status':'FIXED_SOURCE_AND_PRIVATE_TABLE_FAULT_INJECTION','resolution':'alive verifies ST/BS spans and seven pinned methods with executable mappings; service change invalidates the accepted consumer.','evidence':'20261108_023434_watch3 changes a private Boot Services copy, not the firmware global table.'},
 {'id':'F6','severity':'informational','problem':'attempted mask actually recorded confirmed replacement sites; an interrupted current write was not represented.','status':'CLARIFIED_AND_FAILURE_STATE_RECORDED','resolution':'Header defines confirmed mask; touched and unknown_site record attempted/ambiguous current writes. HOLD never authorizes unload or blind rollback.'},
]
limits=[
 'No unresolved issue from this bounded installer source review remains after the listed fixes. This is not a security certification or approval for physical installation.',
 'Caller-provided context, plan and lease callback are trusted internal objects in this lab component. Real loader ownership, callback lifetime and immutable consumer binding remain root integration prerequisites.',
 'The actual transaction operates on lab-owned original-image copies and return stubs. It has no actual native observer/password/write-sink deployment binding.',
 'Raised TPL only excludes normal callbacks on the same processor. AP/SMM quiescence and physical original-page writability are not demonstrated.',
 'Cold-watch observes standard OVMF LoadImage timing and refuses a pre-existing target. It never calls original AMITSE StartImage and installs no hook. Two-stage firmware bootstrap and physical DXE ordering remain unverified.',
 'Memory walker assumes startup identity mapping and trusted resident code/context; it changes no foreign protections, control registers or page tables.',
 'No firmware signature, supported modified-image acceptance, flash or no-POST recovery evidence is supplied by these tests.',
]
report={'reviewer':'/root/w890_release','status':'REVIEW_FINDINGS_FIXED_FOR_BOUNDED_LAB_COMPONENT_NOT_DEPLOYABLE','findings':findings,'checks':checks,'final_sources':sources,'runs':run_records,'entry_guard_cases':10,'limits':limits,'bindings':bound,'release_ready':False,'physically_installed':False}
(H/'installer_review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'findings_fixed':len(findings),'vm_checks':[r['checks']for r in run_records],'bindings':len(bound),'sha256':sha(H/'installer_review.json')}))
