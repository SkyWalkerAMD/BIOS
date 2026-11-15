"""Bind final INV04 sources, isolated artifacts and local verification reports."""
from pathlib import Path
import hashlib,json,sys,zipfile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import capstone,pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
load=lambda p:json.loads(p.read_text(encoding='utf8'))
build=load(OUT/'build.json');native=load(OUT/'local_verification.json');vm=load(OUT/'ovmf_verification.json')
efi=OUT/'BOOTX64.EFI';iso=OUT/'SAGE1904-SPI-INVENTORY04.iso'
assert sha(efi)==build['efi_sha256']==native['efi_sha256']==vm['efi_sha256']=='d64b934a06668b777b78663a786ff2287b8e062abdb883624071eb3e3451e3a0'
assert sha(iso)==build['iso_sha256']==vm['iso_sha256']=='fd3a3f691c2a1823823ae8829f27729294451b123f9cc651efb06ccce5939a00'
assert sha(HERE/'source/inventory.c')==native['source_sha256']=='cdee28b549b0d99939425e08021860b71ab826d9fa0048a131e28bc763910c54'
assert native['status']=='PASS_LOCAL_SIMULATION_ONLY' and native['case_count']==223 and native['inv03_baseline_cases']==157 and native['inv04_additional_cases']==66
assert vm['status']=='PASS_LOCAL_OVMF_ONLY' and all(c['owned_process_finished'] for c in vm['cases'])
assert sha(OUT/'build.json')==native['build_sha256']
assert sha(HERE/'verify_candidate.py')==native['test_source_sha256'] and sha(HERE/'verify_ovmf.py')==vm['test_source_sha256']
assert all(sha(HERE/name)==v for name,v in build['source_files'].items())
assert all(sha(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'/name)==v['original_sha256'] for name,v in build['reused_p3'].items())
prior={}
for folder,sid,source_pin,efi_pin,iso_pin in [
 ('spi_inventory_candidate','01','6d7ecec192b814ffd85805a3ea16ecf44f745e4b3d4a1674f8ad91468fe2f3df','7950e97739264a395b71aea450c33274a01b0ec5411ed9ec705a5b08bfa973e0','7e023055a8c4e874d0e9d87a544ea948083705164b82eeafb439b1b46d8b3d8b'),
 ('spi_inventory_candidate02','02','20747e5fa983c34993059e052aafaae100be57a6fe7b534f3fddcd4da874a403','9530c440c74ba13ad5294319b0e6aba647e348a4cb17122a2b8829bb0e2fbe8e','e8f09b8665c18c1681b8ae123f9b384427bc6bce5d5052ec77654aa19d2c42f9'),
 ('spi_inventory_candidate03','03','2f6856531adbb98403aeb4e455531c6d03149e0d426c10c62b1932bde97a442a','ffff289eb6e2b52ba8a53c66ffd70ff4e181443b23a1ef0b5ba60c445c50efba','cafd2b99a276897afa9bff0d330e2fecc58fecb5554c546e07fbdf7ef78f34e3')]:
    old=HERE.with_name(folder)
    assert sha(old/'source/inventory.c')==source_pin and sha(old/'build/BOOTX64.EFI')==efi_pin and sha(old/'build'/f'SAGE1904-SPI-INVENTORY{sid}.iso')==iso_pin
    prior[sid]={'source_sha256':source_pin,'efi_sha256':efi_pin,'iso_sha256':iso_pin}
production=sha(ROOT/'analysis/aitweaker_lock/lock_sage_1904/driver/build/AiTweakerLock1904.efi');assert production=='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
original=HERE.parent/'cpuio2_native/native_review.json';assert sha(original)=='528503ed795ba75848ec968eff18d3dceb816f9a8bff5cb839dd81995aa6f145'
pe=pefile.PE(str(efi));text=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text');cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
ins=list(cs.disasm(text.get_data()[:text.Misc_VirtualSize],text.VirtualAddress))
bad=[(i.address,i.mnemonic,i.op_str) for i in ins if i.mnemonic in ['in','insb','insw','insd','out','outsb','outsw','outsd','wrmsr','wrpkru','syscall','sysenter'] or (i.mnemonic=='mov' and i.op_str.startswith(('cr','dr')))];assert not bad
files=[p for p in (HERE/'source').rglob('*') if p.is_file()]+[HERE/n for n in ['build_candidate.py','verify_candidate.py','verify_ovmf.py','verify_cpu_evidence.py','extend_verification.py','prepare_candidate04.py','finalize_report.py','sources.json','layout_evidence.json','root_bridge_evidence.json','cpu_io_evidence.json','inventory03-to-04.patch','baseline_binding.json']]+[OUT/n for n in ['build.json','local_verification.json','ovmf_verification.json','synthetic-positive-log.txt']]
archive=OUT/'review-snapshot.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for p in files:z.write(p,p.relative_to(HERE).as_posix())
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None and all(hashlib.sha256(z.read(p.relative_to(HERE).as_posix())).hexdigest()==sha(p) for p in files)
bindings={p.relative_to(HERE).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in files+[efi,iso,archive,OUT/'source-snapshot.zip']}
report={
 'status':'READY_FOR_REVIEW_LOCAL_TESTS_ONLY','hardware_tested':False,'application':'SPI-INVENTORY-04','board':'ASUS Pro WS W790E-SAGE SE','bios':'1904','artifact_bindings':bindings,
 'latest_native_total':223,'new_CPU_cases':66,'baseline_cases_included_in_total':157,'ovmf_boots':2,'ovmf_checks_total':sum(len(c['checks']) for c in vm['cases']),
 'static_instruction_check':{'instructions_decoded':len(ins),'forbidden_direct_IO_or_privileged_write':bad},
 'CPU_route_trigger':['All14 original PCI_IO.Mem.Read return EFI_UNSUPPORTED.','Root resource selection fails before any RootBridge.Mem.Read call. Root read errors never trigger CPU fallback.'],
 'CPU_gates':['Fresh GetMemoryMap before and after CPU protocol selection; size/stride/version and all descriptor ranges valid.','Exactly one descriptor overlaps FE010000..FE010FFF; type11, startFE010000, one4KiB page, exact observed attributes8000000000000001.','SMBIOS SAGE1904 plus PCI7AA4/BDF0000:00:1F.5/rev-class0C800011/memory-decode/BARFE010000 rechecked around selection.','Exactly one CPU_IO2 handle; interface is readable RAM, method is nonnull within exactly one Boot/RuntimeServicesCode mapping with no RP/XP reported.','Only fixed14 addresses, Width32/Count1; first failed EFI status, all-ones, invalid FDV or busy SCIP stops the CPU path.'],
 'attribute_semantics':'UC/RUNTIME and absent RP are reported descriptor capability bits, not proof of current cache settings or physical read permission. Exact matching binds the previously observed resource and changes no attributes.',
 'read_scope':{'SPI_cycles':0,'flash_bytes':0,'application_PCI_MMIO_write_calls':0,'SetVariable_calls':0,'CPU_IO2_Mem_Read_maximum':14,'CPU_IO2_Mem_Write_calls':0,'CPU_IO2_Io_calls':0,'raw_pointer_MMIO_reads':0,'actual_density':'unknown'},
 'root_change':'Original strict root gate retained. Added GRAN and explicit rejection reason for evidence; no relaxed matching.',
 'transport':{'mode':'KVM QR/text; original file-output and P3 transports remain available unchanged','frame_header':'AITWK-P3-KVM','log_header':'SPI-INVENTORY-04 LOCAL-CANDIDATE','CPU_data_prefix':'CPU <REGISTER> OFFSET=... RAW=...','CPU_blocks':['CPU_OBSERVATIONS_BEGIN','CPU_OBSERVATIONS_END','CPU_OBSERVATIONS_STOPPED_ON_ERROR'],'CPU_discovery_label':'CPU_IO2_DISCOVERY=PRESENT','synthetic_CPU_log_bytes':native['qr_log_bytes'],'synthetic_CPU_QR_pages':native['qr_pages'],'decoder':'Existing decode_captures.py assemble(frames, require_inventory=False)','watchdog':'SetWatchdogTimer(0) outcome recorded; failure leaves possible firmware timeout resets.','exit':'Esc returns to firmware; application does not shut down or reboot.'},
 'original_CPU_IO2_supporting_evidence':{'path':str(original.relative_to(HERE.parent)),'sha256':sha(original),'scope':'Independent original1904 driver identification and21 isolated native read cases; separate evidence, not added to223 candidate test count.'},
 'limitations':['INV04 has no hardware acceptance yet. No device action or deployment was performed by this agent.','223 cases execute the exact application EFI with explicit synthetic firmware/protocol callbacks; successful CPU MMIO values are simulated.','Two OVMF boots verify optical boot, identity/absent-SPI refusal, QR/text and exit; they do not prove physical W790 MMIO access.','Original CPU_IO2 code does not implement a register allowlist; this application provides fixed-address and resource restrictions.','Memory-map capability matching does not promise access; any read failure is reported without protection changes or further read route.','Register observations are not a whole-chip dump, capacity measurement, complete backup or recovery guarantee.','Unsigned EFI; no Secure Boot variable, firmware CAP, production password driver or earlier inventory artifacts were modified.'],
 'preserved_inventory_versions':prior,'preserved_production_driver_sha256':production
}
(HERE/'candidate_manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'manifest_sha256':sha(HERE/'candidate_manifest.json'),'review_archive_sha256':sha(archive),'latest_native_total':223,'new_CPU_cases':66,'ovmf_checks':report['ovmf_checks_total'],'efi_sha256':sha(efi),'iso_sha256':sha(iso)},indent=2))
