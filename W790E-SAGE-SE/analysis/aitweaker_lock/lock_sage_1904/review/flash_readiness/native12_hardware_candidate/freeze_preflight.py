from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((HERE/'build/build.json').read_text());tests=json.loads((HERE/'tests/verification.json').read_text());vm=json.loads((HERE/'ovmf_report.json').read_text());run=Path(vm['run'])
assert tests['status']=='PASS_ACTUAL_EFI_BYTES_SYNTHETIC_UEFI' and tests['case_count']==20
assert vm['status']=='PASS_ACTUAL_EFI_ISO_OVMF_BOOT_TRANSPORT'
assert tests['efi_sha256']==vm['efi_sha256']==build['efi_sha256']==sha(Path(build['efi']))
assert vm['iso_sha256']==build['iso_sha256']==sha(Path(build['iso']))
assert (run/'decoded.log').read_bytes()==(run/'probe.log').read_bytes()
report={'status':'FROZEN_READ_ONLY_PREFLIGHT_ONLY','installation_authorized':False,'efi_sha256':build['efi_sha256'],'iso_sha256':build['iso_sha256'],'native_guard_or_provider_started':False,'machine_code_synthetic_cases':20,'ovmf_checks':vm['checks'],'actual_ovmf_qr_roundtrip':{'bytes':(run/'decoded.log').stat().st_size,'sha256':sha(run/'decoded.log'),'identical_to_actual_debug_log':True},'tests_sha256':sha(HERE/'tests/verification.json'),'ovmf_report_sha256':sha(HERE/'ovmf_report.json'),'identity_binding_sha256':sha(HERE/'identity_binding.json'),'hardware_results':None,'pending':['Physical-board identity and exact page layout','Independent transactional loader feasibility/ownership/metadata/rollback review','OEM native GUI and password behavior with exact NATIVE12/provider12','Authorized permanent deployment and recovery path']}
(HERE/'preflight_review.json').write_text(json.dumps(report,indent=2)+'\n')
paths=list((HERE/'source').rglob('*'))+list((HERE/'tests').glob('*'))+[HERE/x for x in ['prepare_probe.py','build_probe.py','verify_probe.py','run_ovmf_probe.py','decode_probe.py','freeze_preflight.py','README.md','identity_binding.json','preflight_review.json','ovmf_report.json','build/build.json','build/probe.map','build/SageNative12ReadOnlyPreflight.efi','build/SAGE-NATIVE12-READONLY-PREFLIGHT.iso','build/readonly-efiboot.img']]+[p for p in run.iterdir()if p.suffix in ['.png','.ppm','.json','.log']]
manifest={'status':'FROZEN_READ_ONLY_PREFLIGHT_ONLY','artifacts':[{'path':str(p.relative_to(HERE)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(set(paths))if p.is_file()]}
(HERE/'preflight_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'manifest_sha256':sha(HERE/'preflight_manifest.json'),'review_sha256':sha(HERE/'preflight_review.json'),'artifacts':len(manifest['artifacts'])}))
