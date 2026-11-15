"""Bind final INV03 artifacts/tests; no build, device or deployment operation."""
from pathlib import Path
import hashlib,json,sys,zipfile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
load=lambda p:json.loads(p.read_text(encoding='utf8'))
build=load(OUT/'build.json');native=load(OUT/'local_verification.json');vm=load(OUT/'ovmf_verification.json')
efi=OUT/'BOOTX64.EFI';iso=OUT/'SAGE1904-SPI-INVENTORY03.iso'
assert sha(efi)==build['efi_sha256']==native['efi_sha256']==vm['efi_sha256']=='ffff289eb6e2b52ba8a53c66ffd70ff4e181443b23a1ef0b5ba60c445c50efba'
assert sha(iso)==build['iso_sha256']==vm['iso_sha256']=='cafd2b99a276897afa9bff0d330e2fecc58fecb5554c546e07fbdf7ef78f34e3'
assert native['status']=='PASS_LOCAL_SIMULATION_ONLY' and native['case_count']==157 and native['inv02_baseline_cases']==89 and native['inv03_additional_cases']==68
assert vm['status']=='PASS_LOCAL_OVMF_ONLY' and all(c['owned_process_finished'] for c in vm['cases'])
assert sha(OUT/'build.json')==native['build_sha256']
assert sha(HERE/'source/inventory.c')==native['source_sha256']=='2f6856531adbb98403aeb4e455531c6d03149e0d426c10c62b1932bde97a442a'
assert sha(HERE/'verify_candidate.py')==native['test_source_sha256'] and sha(HERE/'verify_ovmf.py')==vm['test_source_sha256']
assert all(sha(HERE/name)==digest for name,digest in build['source_files'].items())
assert all(sha(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'/name)==entry['original_sha256'] for name,entry in build['reused_p3'].items())
prior={}
for folder,efi_pin,iso_name,iso_pin in [
 ('spi_inventory_candidate','7950e97739264a395b71aea450c33274a01b0ec5411ed9ec705a5b08bfa973e0','SAGE1904-SPI-INVENTORY01.iso','7e023055a8c4e874d0e9d87a544ea948083705164b82eeafb439b1b46d8b3d8b'),
 ('spi_inventory_candidate02','9530c440c74ba13ad5294319b0e6aba647e348a4cb17122a2b8829bb0e2fbe8e','SAGE1904-SPI-INVENTORY02.iso','e8f09b8665c18c1681b8ae123f9b384427bc6bce5d5052ec77654aa19d2c42f9')]:
    p=HERE.with_name(folder);assert sha(p/'build/BOOTX64.EFI')==efi_pin and sha(p/'build'/iso_name)==iso_pin
    prior[folder]={'efi_sha256':efi_pin,'iso_sha256':iso_pin,'source_sha256':sha(p/'source/inventory.c')}
assert prior['spi_inventory_candidate']['source_sha256']=='6d7ecec192b814ffd85805a3ea16ecf44f745e4b3d4a1674f8ad91468fe2f3df'
assert prior['spi_inventory_candidate02']['source_sha256']=='20747e5fa983c34993059e052aafaae100be57a6fe7b534f3fddcd4da874a403'
prod=sha(ROOT/'analysis/aitweaker_lock/lock_sage_1904/driver/build/AiTweakerLock1904.efi');assert prod=='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'

pe=pefile.PE(str(efi));section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);instructions=list(cs.disasm(section.get_data()[:section.Misc_VirtualSize],section.VirtualAddress))
forbidden=[(i.address,i.mnemonic,i.op_str) for i in instructions if i.mnemonic in ['in','insb','insw','insd','out','outsb','outsw','outsd','wrmsr','wrpkru','syscall','sysenter'] or (i.mnemonic=='mov' and i.op_str.startswith(('cr','dr')))]
assert not forbidden
files=[p for p in (HERE/'source').rglob('*') if p.is_file()]+[HERE/n for n in ['build_candidate.py','verify_candidate.py','verify_ovmf.py','verify_root_bridge_evidence.py','extend_verification.py','prepare_candidate03.py','finalize_report.py','sources.json','layout_evidence.json','root_bridge_evidence.json','inventory02-to-03.patch','baseline_binding.json']]+[OUT/n for n in ['build.json','local_verification.json','ovmf_verification.json','synthetic-positive-log.txt']]
archive=OUT/'review-snapshot.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for p in files:z.write(p,p.relative_to(HERE).as_posix())
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert all(hashlib.sha256(z.read(p.relative_to(HERE).as_posix())).hexdigest()==sha(p) for p in files)
bindings={p.relative_to(HERE).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in files+[efi,iso,archive,OUT/'source-snapshot.zip']}
report={
 'status':'READY_FOR_REVIEW_LOCAL_TESTS_ONLY','hardware_tested':False,'application':'SPI-INVENTORY-03','board':'ASUS Pro WS W790E-SAGE SE','bios':'1904','artifact_bindings':bindings,
 'native_cases':157,'inv02_baseline_cases':89,'root_bridge_additional_cases':68,'ovmf_boots':2,'ovmf_checks_total':sum(len(c['checks']) for c in vm['cases']),
 'static_instruction_check':{'decoded':len(instructions),'forbidden_direct_IO_or_privileged_write':forbidden},
 'fallback_gate':['All14 PCI_IO.Mem.Read return EFI_UNSUPPORTED; mixed successes or other failures do not trigger fallback.','Observed7AA4, 0000:00:1F.5, revision/class0C800011, enabled memory decode, BAR FE010000; rechecked before and after root selection.','Unique segment0 root with bus0 resource coverage; unknown potentially-relevant root prevents uniqueness.','Exactly one memory resource covers FE010000..FE010097; producer, positive decode, no translation or reserved flags.','Only bounded RAM QWORD descriptors/EndTag are parsed; invalid pointers/lengths/checksum/duplicates/coverage refuse.'],
 'read_scope':{'PCI_MMIO':'Unchanged14 PciIo BAR0-relative reads','RootBridge_MMIO':'Same14 fixed absolute addresses, 32-bit width and Count1, only after all gates','SPI_cycles':0,'flash_bytes':0,'application_PCI_MMIO_write_calls':0,'RuntimeServices_calls':0,'CPU_IO2_calls':0,'actual_density':'unknown'},
 'additional_metadata':'Existing GetMemoryMap descriptors covering BAR: type/start/end/attributes only; CPU_IO2 LocateProtocol presence only. Neither permits bypassing root-resource checks.',
 'resource_ownership':'RootBridge Configuration buffer is borrowed and never freed; only LocateHandleBuffer lists are freed.',
 'transport':{'mode':'QR/text only; existing P2 file output and P3 QR tools remain unchanged','frame_header':'AITWK-P3-KVM','log_header':'SPI-INVENTORY-03 LOCAL-CANDIDATE','chunk_bytes':768,'synthetic_fallback_log_bytes':native['qr_log_bytes'],'synthetic_fallback_QR_pages':native['qr_pages'],'decoder':'Existing decode_captures.py assemble(frames, require_inventory=False)','watchdog':'SetWatchdogTimer(0) records success/failure; if it fails, timeout resets remain possible','exit':'Esc returns to firmware; no app-triggered shutdown/reboot. Follow maintenance control plan.'},
 'limitations':['No hardware operation or deployment was performed by this agent; INV03 hardware acceptance has not occurred.','Root resource windows may legitimately omit the integrated SPI range. Refusal proves insufficient route evidence, not unreadable hardware or flash protection.','All positive RootBridge reads are Unicorn callback fixtures. OVMF tests boot/identity/absent-SPI refusal/QR and exit, not physical W790 or successful real RootBridge reads.','Protocol providers may have implementation details beyond application call boundaries; the app never invokes their write, attribute, map or CPU_IO2 methods.','Register status is not a complete SPI dump, actual capacity measurement or recovery guarantee. No FGO, FDOC, JEDEC/SFDP or flash read/program cycles.','Unsigned EFI; no Secure Boot variable, CAP, password-driver or prior inventory artifact modified.'],
 'prior_inventory_preserved':prior,'production_driver_preserved_sha256':prod
}
(HERE/'candidate_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'manifest_sha256':sha(HERE/'candidate_manifest.json'),'review_archive_sha256':sha(archive),'efi_sha256':sha(efi),'iso_sha256':sha(iso),'native_cases':157,'ovmf_checks':report['ovmf_checks_total']},indent=2))
