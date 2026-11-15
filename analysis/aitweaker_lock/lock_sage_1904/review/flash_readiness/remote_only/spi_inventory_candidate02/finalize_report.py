"""Bind already built/tested local artifacts; never rebuild or access hardware."""
from pathlib import Path
import hashlib,json,sys,zipfile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((OUT/'build.json').read_text(encoding='utf8'))
native=json.loads((OUT/'local_verification.json').read_text(encoding='utf8'))
vm=json.loads((OUT/'ovmf_verification.json').read_text(encoding='utf8'))
assert native['status']=='PASS_LOCAL_SIMULATION_ONLY' and native['case_count']==89
assert native['inv01_baseline_cases']==62 and native['inv02_additional_cases']==27
assert vm['status']=='PASS_LOCAL_OVMF_ONLY' and all(c['owned_process_finished'] for c in vm['cases'])
efi=OUT/'BOOTX64.EFI';iso=OUT/'SAGE1904-SPI-INVENTORY02.iso'
assert sha(efi)==build['efi_sha256']==native['efi_sha256']==vm['efi_sha256']=='9530c440c74ba13ad5294319b0e6aba647e348a4cb17122a2b8829bb0e2fbe8e'
assert sha(iso)==build['iso_sha256']==vm['iso_sha256']=='e8f09b8665c18c1681b8ae123f9b384427bc6bce5d5052ec77654aa19d2c42f9'
assert sha(OUT/'build.json')==native['build_sha256']
assert sha(HERE/'source/inventory.c')==native['source_sha256']
assert sha(HERE/'verify_candidate.py')==native['test_source_sha256']
assert sha(HERE/'verify_ovmf.py')==vm['test_source_sha256']
assert all(sha(HERE/name)==v for name,v in build['source_files'].items())
assert all(sha(ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'/name)==v['original_sha256'] for name,v in build['reused_p3'].items())

# Static supplement: no direct port I/O, MSR/control-register writes or syscall.
# Dynamic protocol write slots were independently traps in Unicorn. This scan
# does not certify what the firmware's own PciIo/GOP/Watchdog implementations do.
pe=pefile.PE(str(efi));text_section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.text')
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
ins=list(cs.disasm(text_section.get_data()[:text_section.Misc_VirtualSize],text_section.VirtualAddress))
bad=[(i.address,i.mnemonic,i.op_str) for i in ins if i.mnemonic in ['in','insb','insw','insd','out','outsb','outsw','outsd','wrmsr','wrpkru','syscall','sysenter'] or (i.mnemonic=='mov' and i.op_str.startswith(('cr','dr')))]
assert not bad,bad
files=[efi,iso,OUT/'source-snapshot.zip',OUT/'build.json',OUT/'local_verification.json',OUT/'ovmf_verification.json',HERE/'source/inventory.c',HERE/'build_candidate.py',HERE/'verify_candidate.py',HERE/'verify_ovmf.py',HERE/'sources.json',HERE/'layout_evidence.json',HERE/'verify_layout_evidence.py',HERE/'inventory01-to-02.patch',HERE/'preparation.json',HERE/'prepare_candidate02.py',Path(__file__)]
bindings={p.relative_to(HERE).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in files}
review=OUT/'review-snapshot.zip'
with zipfile.ZipFile(review,'w',zipfile.ZIP_DEFLATED) as z:
    for p in list((HERE/'source').rglob('*'))+[HERE/n for n in ['build_candidate.py','verify_candidate.py','verify_ovmf.py','finalize_report.py','sources.json','layout_evidence.json','verify_layout_evidence.py','inventory01-to-02.patch','preparation.json','prepare_candidate02.py']]+[OUT/n for n in ['build.json','local_verification.json','ovmf_verification.json','synthetic-positive-log.txt']]:
        if p.is_file():z.write(p,p.relative_to(HERE).as_posix())
with zipfile.ZipFile(review) as z:assert z.testzip() is None
report={
 'status':'READY_FOR_REVIEW_LOCAL_TESTS_ONLY','hardware_tested':False,
 'board':'ASUS Pro WS W790E-SAGE SE','bios':'1904',
 'application':'SPI-INVENTORY-02','artifact_bindings':bindings,
 'review_archive':{'path':str(review.relative_to(HERE)),'sha256':sha(review)},
 'native_cases':89,'inv01_baseline_cases':62,'inv02_added_cases':27,'baseline_case_adjustment':'The unsupported-ID example changed from newly supported 7AA4 to still-unsupported 7AA5; all other baseline cases retained.','ovmf_boots':2,'ovmf_checks_total':sum(len(c['checks']) for c in vm['cases']),
 'static_instruction_check':{'instructions_decoded':len(ins),'forbidden_direct_io_or_privileged_write_found':bad},
 'spi_access_scope':{'pci':'PciIo.Pci.Read only, 32-bit reads at offsets 0/4/8/10h/DCh','mmio':'PciIo.Mem.Read only, BAR0-relative 14 allowlisted status registers','spi_cycles':0,'flash_bytes':0,'actual_capacity':'unknown','runtime_services_calls':0,'pcicfg_mmio_write_interfaces':'not callable; opaque placeholders','other_boot_service_effect':'SetWatchdogTimer(0), allocation/free and console/GOP display; no claim about internal implementation of firmware services'},
 'gates':['Valid bounded RAM memory map and matching SMBIOS2/3 board/version','Exactly one Intel 8086:7A24 or 7AA4 at 0000:00:1F.5; 7AA4 additionally requires observed revision/class 0x0C800011','Re-read device ID must exactly match the selected enumeration ID; switching between two allowed IDs is rejected','Existing enabled Memory Space decode and nonzero 32-bit 4KiB-aligned BAR','PciIo read method present; read failures/all-ones and busy/invalid descriptor marked partial'],
 'transport':{'mode':'KVM QR/text only in this new application','frame_header':'AITWK-P3-KVM','log_header':'SPI-INVENTORY-02 LOCAL-CANDIDATE','chunk_bytes':768,'checksums':'per-page CRC32 plus whole-log CRC32 and total/offset/page consistency','decoder':'Existing probe_p3_kvm/decode_captures.py assemble(frames, require_inventory=False)','not_replacement':'Existing P2 file-output and P3 KVM tools are unchanged; this scoped collector adds no file export.','exit':'Esc returns to firmware. Physical operator should follow parent maintenance plan; the app does not shut down or reboot the host.','watchdog':'Successful disable recorded. If it fails the log warns and marks partial; firmware watchdog may reset while displayed.'},
 'limitations':['No BMC connection, physical power action, PCI/MMIO/flash target access or deployment was performed by this agent.','INV01 hardware log proves visible 7AA4/revision11/class0C8000 only. New INV02 MMIO operation remains untested on hardware; no previous acceptance inherited.','FREG0..5 and 8-bit FRAP fields cannot establish every extension region; slot9 is deliberately not inferred.','Read-only status inventory cannot establish actual chip density, whole-chip read access or a complete/restorable backup.','Positive SPI cases use explicit synthetic callbacks in Unicorn; OVMF positive identity case only proves safe refusal of a missing controller.','Unsigned EFI; no Secure Boot variables, host disks, firmware CAPs or password-driver objects changed.'],
 'preserved_production_efi_sha256':sha(ROOT/'analysis/aitweaker_lock/lock_sage_1904/driver/build/AiTweakerLock1904.efi')
}
assert report['preserved_production_efi_sha256']=='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
old=HERE.with_name('spi_inventory_candidate')
assert sha(old/'source/inventory.c')=='6d7ecec192b814ffd85805a3ea16ecf44f745e4b3d4a1674f8ad91468fe2f3df'
assert sha(old/'build/BOOTX64.EFI')=='7950e97739264a395b71aea450c33274a01b0ec5411ed9ec705a5b08bfa973e0'
assert sha(old/'build/SAGE1904-SPI-INVENTORY01.iso')=='7e023055a8c4e874d0e9d87a544ea948083705164b82eeafb439b1b46d8b3d8b'
report['preserved_inv01']={'source_sha256':sha(old/'source/inventory.c'),'efi_sha256':sha(old/'build/BOOTX64.EFI'),'iso_sha256':sha(old/'build/SAGE1904-SPI-INVENTORY01.iso')}
(HERE/'candidate_manifest.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'manifest_sha256':sha(HERE/'candidate_manifest.json'),'review_archive_sha256':sha(review),'native_cases':89,'ovmf_checks':report['ovmf_checks_total'],'source_sha256':sha(HERE/'source/inventory.c')},indent=2))
