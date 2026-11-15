"""Freeze the exact owned-RAM prerequisite, separate from all earlier probes."""
from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;N13=HERE.parents[1];FR=N13.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
sys.path.insert(0,str(HERE));from decode_probe import decode
efi=HERE/'build/SageNative13Prerequisite04.efi';iso=HERE/'build/SAGE-N13-OWNED-PREREQUISITE04.iso'
assert sha(efi)=='a8a828427a412eaffb36bc244a91175507a940238ae30c51c3e64d0520fea800'
assert sha(iso)=='852ed9fdbf39cad8764bf0b1cf21c2b3fb1b95f939c9536e13ad22dbf943307c'
tests=HERE/'tests/verification.json';tr=json.loads(tests.read_text());assert tr['efi_sha256']==sha(efi)and tr['case_count']==66 and all(c['passed']for c in tr['cases'])
ovmf=json.loads((HERE/'ovmf_report.json').read_text());assert ovmf['status']=='PASS_ACTUAL_EFI_ISO_OVMF_BOOT_TRANSPORT'and ovmf['efi_sha256']==sha(efi)and ovmf['iso_sha256']==sha(iso)
run=Path(ovmf['run']);assert run.name=='20261103_193613'
raw,transport=decode(sorted(run.glob('qr-*.png')));assert raw==(run/'probe.log').read_bytes()
assert raw.count(b'PASS owned allocation cycle complete\r\n')==2
for line in [b'OwnedCodeReturn=000000004E313304\r\n',b'RetainedOwnedPages=0000000000000000\r\n',b'EBSObserved=0000000000000000\r\n',b'ResidentHoldRequired=0000000000000000\r\n']:
 assert line in raw,line
assert raw.count(b'NO_FLASH_NO_HOOKS_NO_VARIABLE_WRITES_NO_DISK_WRITES\r\n')==2
assert b'SAGE N13 - PREREQUISITE04'in efi.read_bytes()
# Clang inlines the constant text conversion into stores; the text title need
# not survive as a contiguous ASCII/UTF16 blob. Its actual frame is separately
# captured and independently inspected, and the compiled source is bound here.
assert 'SAGE N13 prereq04 - OWNED RAM ONLY'in(HERE/'source/transport/kvm.c').read_text()
(run/'qr-decoded.log').write_bytes(raw)
ep3=N13/'entry_probe03/entry_context03_manifest.json';ep3data=json.loads(ep3.read_text());assert len(ep3data['artifacts'])==110
for artifact in ep3data['artifacts']:assert sha(N13/artifact['path'])==artifact['sha256'],artifact['path']
refs=FR/'remote_only/continuation08/edk2_reference'
reference=[{'path':str(p),'sha256':sha(p)}for p in sorted(refs.iterdir())if p.is_file()]
review={
 'status':'FROZEN_OWNED_RAM_PREREQUISITE_ONLY_NOT_NATIVE_INSTALLER',
 'efi_sha256':sha(efi),'iso_sha256':sha(iso),'efi_bytes':efi.stat().st_size,
 'actual_efi_synthetic_cases':66,'tests_sha256':sha(tests),
 'exact_iso_ovmf':{'report_path':str(HERE/'ovmf_report.json'),'report_sha256':sha(HERE/'ovmf_report.json'),'run':str(run),'qr_transport':transport,'owned_code_and_data_cycles':2,'fixed_owned_code_return':'0x4e313304','owned_allocations_released':True,'resident_hold_required':False,'ASUS_modules_present':False},
 'mutations_permitted_by_this_artifact':['AllocatePages and FreePages for its own fresh three-page allocations','Write six fixed code bytes or one marker byte only to the verified owned middle page','CPU Arch SetMemoryAttributes only for that owned middle page, with semantic restoration','Register and close its own temporary ExitBootServices event'],
 'mutations_not_implemented':['Original module bytes or metadata','Original page-permission changes','HII package changes','Native Setup or SendForm invocation','RuntimeServices replacement','Variable writes','Flash or disk writes','Direct control-register, MSR, or PTE writes'],
 'readiness_limits':['Prerequisite service and owned-allocation result only; native N13 transaction remains unimplemented.','Page-table walk assumes the x64 pre-virtual-map firmware identity-mapping model, checking EFI-map bounds at each table read.','SMEP/SMAP/PKE/CET/PKS configurations are conservatively unsupported.','RO bits with CR0.WP disabled do not prove supervisor write enforcement.','Successful standard service plus PTE readback does not independently establish every TLB or AP state.','No full native ASUS browser, management UI, credential or flash acceptance is provided.'],
 'scope_labels_corrected':['QR banner PREREQUISITE04','Text banner OWNED RAM ONLY','Exit message explicitly no flash/native hooks/variable writes'],
 'official_reference_files':reference,
 'frozen_ep3_manifest_sha256':sha(ep3),'frozen_ep3_artifacts_verified_unchanged':110,
 'remote_or_device_actions_by_builder':False,'source_script_sha256':sha(Path(__file__)),
}
report=HERE/'prerequisite04_review.json';report.write_text(json.dumps(review,indent=2)+'\n')
files=set()
for folder in ['source','tests']:
 for p in(HERE/folder).rglob('*'):
  if p.is_file()and'__pycache__'not in p.parts:files.add(p)
for p in(HERE/'build').iterdir():
 if p.is_file()and p.suffix in['.efi','.iso','.img','.json','.map','.obj']:files.add(p)
for p in run.iterdir():
 if p.is_file()and p.suffix in['.png','.json','.log']:files.add(p)
for name in['README.txt','source_origins.json','identity_binding.json','build_probe.py','run_ovmf_probe.py','decode_probe.py','verify_prerequisite.py','finalize_prerequisite.py','ovmf_report.json','prerequisite04_review.json']:files.add(HERE/name)
manifest={'status':review['status'],'path_base':'prerequisite_probe04','artifacts':[{'path':str(p.relative_to(HERE)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)],'entrypoint_iso_sha256':sha(iso),'review_sha256':sha(report)}
dest=HERE/'prerequisite04_manifest.json';dest.write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'review_sha256':sha(report),'manifest_sha256':sha(dest),'artifacts':len(files),'efi_sha256':sha(efi),'iso_sha256':sha(iso),'ovmf_qr':transport}))
