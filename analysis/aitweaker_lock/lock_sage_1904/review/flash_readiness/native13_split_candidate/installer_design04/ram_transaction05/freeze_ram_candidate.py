"""Freeze reviewable volatile test artifacts; never flash or access hardware."""
from pathlib import Path
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parent;BUILD=HERE/'app_build'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
efi=BUILD/'SageNative13RamTest05.efi';expected='9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3'
manifest_path=HERE/'ram_candidate_manifest.json';review_path=HERE/'ram_candidate_review.json'
if '--verify' in sys.argv:
 m=json.loads(manifest_path.read_text())
 for row in m['artifacts']:
  p=D04/row['path'];assert p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],row['path']
 print(json.dumps({'status':'PASS_FROZEN_ARTIFACTS','artifacts':len(m['artifacts']),'manifest_sha256':sha(manifest_path)}));sys.exit(0)
assert not manifest_path.exists(),'Already frozen: use --verify, do not overwrite'
assert sha(efi)==expected
b=json.loads((BUILD/'app_build.json').read_text());assert b['efi_sha256']==expected
for row in b['sources']:assert sha(HERE/row['path'])==row['sha256'],row['path']
for name,value in b['objects'].items():assert sha(BUILD/name)==value,name
tests=[]
for name,count,key in [('integrated_core_verification.json',75,'transaction_efi_sha256'),('platform_verification.json',43,'efi_sha256'),('platform_edges.json',37,'efi_sha256')]:
 path=BUILD/name;r=json.loads(path.read_text());assert r[key]==expected and r['checks']==count
 tests.append({'path':str(path.relative_to(D04)),'sha256':sha(path),'checks':count,'scope':r['status']})
package_dir=D04/'ram_test05_delivery/packages/9115f1afbab01b62';package=json.loads((package_dir/'package.json').read_text());assert package['efi_sha256']==expected
iso=Path(package['iso']);assert sha(iso)==package['iso_sha256']=='aca8533281df2d2432881a28441143baf104bc3655bc3309620c76055251ae78'
smoke=D04/'ram_test05_delivery/ovmf/20261103_212825/result.json';r=json.loads(smoke.read_text());assert r['efi_sha256']==expected and r['iso_sha256']==sha(iso) and r['status'].startswith('PASS_')
independent=D04/'ram_transaction05_independent_review'
entry_report=independent/'final_app_edges_9115f1afbab01b62/result.json';assert entry_report.is_file()
entry=json.loads(entry_report.read_text());assert entry['efi_sha256']==expected and entry['cases']==20 and entry['status'].startswith('PASS_')
extra=[Path(x).resolve()for x in sys.argv[1:]]
assert len(extra)>=2,'Pass final complete-app UI and actual OVMF provider-validator reports'
for p in extra:assert p.is_relative_to(D04.resolve()) and p.is_file(),p
extras=[json.loads(p.read_text())for p in extra]
assert any(r.get('actual_app_sha256')==expected and r.get('cases')==122 and r.get('status','').startswith('PASS_')for r in extras)
assert any(r.get('result',{}).get('actual_app_sha256')==expected and r.get('result',{}).get('checks')==85 and r.get('result',{}).get('status','').startswith('PASS_')for r in extras)
review={
 'status':'FROZEN_REVIEWABLE_VOLATILE_NATIVE_TEST_CANDIDATE_NOT_FIRMWARE_RELEASE',
 'target':'ASUS Pro WS W790E-SAGE SE / BIOS 1904 only',
 'efi_sha256':expected,'iso_sha256':sha(iso),'hardware_execution_by_author':False,'firmware_release_ready':False,
 'architecture':{
  'original_modules':'Original LoadedImage sizes/headers stay unchanged; exact full .text and 12 original windows pinned before publication.',
  'separate_bases':'Two standard AllocatePages-owned code allocations, an owned RW/NX state page; immutable 160-byte bindings specify both original and guard bases. No adjacent foreign expansion pages are used.',
  'code_binding':'Same frozen P13 policy payload; five complete instruction prologues with register-preserving FF25 absolute continuations, exact rel32 targets and aligned DIR64 stores. Runtime constructed bytes independently equal frozen builder fixtures, then accepted by actual frozen P13 owner.',
  'provider':'Exact embedded caa80df1 P13 EFI, ordinary LoadImage/StartImage once. Before entry, pin declared PE headers/sections/BSS and 17 exact relocations. Legal ImageBase relocation normalized; undefined alignment holes/raw padding not read. Published object and five method RVAs are fixed, initial query must be READY only.',
  'identity':'Exact SMBIOS board/version; unique AMITSE/Setup LoadedImages, original fulltext; Core normalized fulltext and bounded captured entry stack; observed AMITSE outer returns 2D7D or 960C to exact 9F78 launch only. Stage7/app0 is never an idle proof.',
  'transaction':'BSP TPL31 has only pure map-bounded CPU page walks, hashes, exact stores/readback and serialization. No map/attribute/allocation/variable/protocol/output calls inside transaction. Original eight pages must still be identity supervisor RWX; no foreign attribute setter.',
  'rollback':'Restore only current exact replacement bytes; unknown bytes never overwritten. Failed proof, ending or unexpected state is terminal CPU-only hold. BUSY retains all pointers and allocations. No RestoreTPL or console/QR/reboot service after terminal high-TPL hold.',
  'lifetime':'App never returns after registering events. Every published or retained allocation and P13 context survives until BMC power off; no UnloadImage/free of published resources. StartImage error may destroy its metadata; later rollback only uses the app-owned cached span.',
  'tpl_contract':'Entry gates validate TPL4 before wrapper map/loader work; SendForm and provider-query returns are checked before later service/menu work. Fixed original Core StartImage saves caller TPL and calls original RestoreTPL on return (separate original-byte evidence). Other trusted standard UEFI service contracts are explicit premises.',
 },
 'operator_sequence':[
  'Boot this exact ISO by the already reviewed CD-only maintenance procedure. Verify candidate header/menu and complete initial log; preflight refusal permits no transaction.',
  'Press 1 once for install/check/rollback with no provider start or private credential writes. Capture Q snapshot and independently confirm all12 original sites restored before selecting mode2.',
  'Press 2 once only after mode1 review. Private credential must initially be absent; otherwise mode2 refuses to modify it. All allocations and any attempted P13 instance are retained; no retry creates another provider.',
  'M opens separate test management form through real original SendForm. B opens default original Setup formset (FormId0); browse only and ESC to return. Do not save BIOS or select a boot override. Separate M is not final OEM integrated-password UI acceptance.',
  'R compares OC/MEM snapshots, deletes only the exact legal128B private credential last observed during this session and verifies NOT_FOUND, then restores original hooks. Unknown credential or changed original settings are preserved and reported; OC/MEM are never written back.',
  'Q creates immutable monotonic SNAPSHOT_ID logs; T switches QR/text. Capture complete header/footer/CRC. App remains resident; root uses BMC power off and media cleanup. A terminal hold has no recovery output: use BMC power off; a temporary credential may remain and must not be blindly deleted on the next run.'
 ],
 'logging':{'maximum_bytes':24575,'header':'AITWK-P3-KVM\\r\\nSAGE_NATIVE13_RAM_TEST05\\r\\n','end':'SAGE_NATIVE13_RAM_TEST05_END','one_snapshot_id':True,'secret_payload_or_hash_logged':False,'overflow':'explicit LOG_OVERFLOW=YES / LOG_COMPLETE=NO; bounded reserved footer; further test actions stop'},
 'exact_app_author_tests':tests,'exact_app_author_test_count':155,
 'independent_reports':[{'path':str(p.relative_to(D04)),'sha256':sha(p)}for p in [entry_report,smoke,*extra]],
 'limitations':[
  'No native installation or ASUS password GUI was executed on hardware by this author. Physical acceptance remains separate from these offline artifacts.',
  'Initial production inventory collector is not fully emulated as an ASUS machine: author transaction fixture seeds exact module identities; unsupported-platform real OVMF refusal and earlier read-only ASUS probes are distinct evidence.',
  'Author fault matrices model CPU register reads and UEFI services; exact SHA requested bytes use Python hashlib for speed. Actual P13 joint owner and real OVMF loaded-app validator execute native SHA. No modeled success is called ASUS GUI acceptance.',
  'TPL excludes ordinary BSP callbacks, not arbitrary AP/SMM/adversarial same-privilege mutation. A CPU fault does not turn into a recoverable TX status; current effective permissions are required before stores.',
  'A pair of full OC/MEM snapshots does not prove absence of all OEM-internal NVRAM changes. Only the private password variable is deliberately written by password management/cleanup; no global RT table hook exists.',
  'This ISO changes RAM and an explicitly temporary private password variable, not the BIOS firmware image. It is not a signed flashable release, not permanent integration, and not evidence the existing BMC accepts modified firmware.',
  'N12/P12 and all frozen earlier candidates are unchanged. N13 RAM bytes/provider GUID are a separate candidate and must not be substituted into older firmware or treated as identical permanent firmware bytes.'
 ]
}
review_path.write_text(json.dumps(review,indent=2)+'\n')
files=set(p for p in (HERE/'source').rglob('*')if p.is_file())
files.update(HERE/n for n in ['build_app.py','generate_platform_assets.py','platform_assets.json','app_source_seed.json','seed_app_sources.py','verify_transaction.py','verify_integrated_core.py','verify_platform.py','verify_platform_edges.py','freeze_ram_candidate.py','physical_prerequisite_review.json','ram_candidate_review.json'])
files.update(BUILD/n for n in ['SageNative13RamTest05.efi','app.map','app_build.json','integrated_core_verification.json','platform_verification.json','platform_edges.json',*b['objects'].keys()])
files.update([entry_report,smoke,*extra,D04/'provider13/local_candidate_manifest.json',D04/'provider13/local_candidate_review.json',D04/'split_core/build/split_build.json',D04/'ram_test05_delivery/BasePeCoff.official.c',D04/'ram_test05_delivery/transport_boundary_result.json'])
files.update(package_dir/n for n in ['package.json','SageNative13RamTest05.efi','SAGE-N13-RAMTEST05-NOFLASH.iso','readonly-efiboot.img'])
files.update(independent/n for n in ['original_startimage_error_cleanup.json','original_startimage_tpl_restore.json','verify_original_startimage_tpl.py','original_startimage_tpl_restore.asm.txt'])
rows=[]
for p in sorted(files):assert p.is_file(),str(p);rows.append({'path':str(p.relative_to(D04)),'bytes':p.stat().st_size,'sha256':sha(p)})
manifest={'status':review['status'],'path_base':'installer_design04','efi_sha256':expected,'iso_sha256':sha(iso),'artifacts':rows,'review_sha256':sha(review_path),'hardware_execution':False,'firmware_release_ready':False}
manifest_path.write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'status':'FROZEN_RAM_TEST_ONLY','artifacts':len(rows),'review_sha256':sha(review_path),'manifest_sha256':sha(manifest_path),'efi_sha256':expected,'iso_sha256':sha(iso)}))
