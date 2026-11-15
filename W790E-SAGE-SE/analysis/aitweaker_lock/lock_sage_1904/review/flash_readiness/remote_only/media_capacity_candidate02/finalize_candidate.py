"""Freeze hashes and locally observed validation; no target/network actions."""
from pathlib import Path
import datetime,hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());OUT=HERE/'build'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
load=lambda p:json.loads(Path(p).read_text(encoding='utf8'))
save=lambda p,v:Path(p).write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
build=load(OUT/'build.json');native=load(OUT/'native_verification.json');qr=load(OUT/'transport_verification.json');parser=load(OUT/'parser_verification.json');vm=load(OUT/'ovmf_verification.json')
efi=sha(OUT/'BOOTX64.EFI');iso=sha(OUT/'SAGE1904-MEDIA-CAPACITY02.iso')
assert efi=='32dc160872be34fba92caba733995d447c37bb2c9c38210467fd433c909fd199'
assert iso=='f7c7986bad443beae44a53b12266e95704d8ca04dbea09ade7c1225ee35333fe'
for r in [build,native,qr,vm]:assert r['efi_sha256']==efi
assert build['iso_sha256']==vm['iso_sha256']==iso
assert native['status']==qr['status']==parser['status']=='PASS' and vm['status']=='PASS_LOCAL_OVMF_ONLY'
assert native['test_sha256']==sha(HERE/'verify_native.py') and qr['test_sha256']==sha(HERE/'verify_transport.py')
assert vm['test_sha256']==sha(HERE/'verify_ovmf.py') and parser['test_sha256']==sha(HERE/'verify_parser.py')
assert parser['parser_sha256']==sha(HERE/'decode_capacity_log.py')
assert all(sha(HERE/name)==h for name,h in build['source_files'].items())
assert all(sha(HERE/'review/native_logs'/(r['name']+'.txt'))==r['log_sha256'] for r in native['cases'])
assert all(c['efi_sha256']==efi and c['owned_process_finished'] and c['qr_matches_console'] and c['all_data_and_iso_images_unchanged'] for c in vm['cases'])
pristine=HERE.parent/'media_writeback_review/blank_test/WRITEBACK02.img'
assert sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
external=[
 ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162/hardware-usbinv01-1793687929667/hardware-log.txt',
 HERE.parent/'media_usb_inventory01/candidate_manifest.json',
 HERE.parent/'media_oem_usb_review04/oem_geometry_review.json',
 HERE.parent/'media_geometry_review03/geometry_review.json',pristine,
 ROOT/'analysis/uefitool_guids.csv']
inputs=[{'path':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in external]
assert inputs[0]['sha256']=='789aca35a5a208e67da6506f63710031e2c181cc7565f136355a28d2bb6e5612'
report={
 'status':'LOCAL_VALIDATED_SCSI_ONLY_CANDIDATE','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'hardware_tested_by_this_task':False,'bmc_network_access_by_this_task':False,
 'candidate':{'efi':'build/BOOTX64.EFI','efi_sha256':efi,'efi_bytes':(OUT/'BOOTX64.EFI').stat().st_size,
              'iso':'build/SAGE1904-MEDIA-CAPACITY02.iso','iso_sha256':iso,'iso_bytes':(OUT/'SAGE1904-MEDIA-CAPACITY02.iso').stat().st_size},
 'observed_input':{'source':inputs[0],'vid_pid':'046B:FF31','interface':'08/06/50; number0 alt0 endpoints2','path_hex':'02010C00D041030A00000000010106000014030506000C000305060001007FFF0400','block_io_cached_block_bytes':1024,'block_io_cached_last_block':262144,'media_present':True,'media_readonly':False,'sfs_published':False,'scope':'Prior USBINV01 metadata, not a raw capacity command.'},
 'decision':{
  'raw_bot':'NOT_IMPLEMENTED. USB_IO bulk calls would bypass the existing AMI USB storage producer transaction ownership; neither RaiseTPL nor opening USB_IO proves exclusivity against producer/SMM. EXCLUSIVE open can disconnect a bound driver and is outside this diagnostic.',
  'standard_owner':'Use only an already installed SCSI_IO on the exact target path or its sole Device Logical Unit LUN0 child. Unknown/multi-instance SCSI paths cause uncertainty and zero commands.',
  'ext_scsi_and_ata':'Presence and bounded exact/ancestor/descendant/unrelated path association are logged. No methods dereferenced or executed.',
  'no_owner':'Return NO_STANDARD_SCSI_IO with RC10_COMMANDS=0. Do not retry or fall back to raw USB.',
  'selector':'Exactly one VID/PID + mass-storage interface match across complete inventory, fixed full hardware path, interface0/alt0/2endpoints, and exactly one eligible owner; recheck identity/path/owner/cached media immediately before command.',
  'command':'One application-level ExecuteScsiCommand(CDB=25000000000000000000, in8/out0, EventNULL, timeout20000000x100ns). Direct-access device type0 and LUN0 required.',
  'response':'EFI success + host0 + target0 + exact8 bytes + untouched packet inputs/CDB + data/CDB guard integrity. No old/failed response accepted. RC16 sentinel and zero block size stop without another command.',
  'driver_boundary':'Transport framing, physical USB commands/retries, and CSW validation remain inside the existing driver. The app makes one standard protocol dispatch and requests a 2-second timeout; it cannot externally cancel a noncompliant firmware implementation.'},
 'forbidden_application_operations':['raw USB transfer','ConnectController/DisconnectController','OpenProtocol EXCLUSIVE/BY_DRIVER','BlockIO ReadBlocks/WriteBlocks/Reset/Flush','file Open/Read/Create/Write','Ext SCSI/ATA pass-through execution','SCSI write/reset/request sense/retry','PCI/SPI/flash/NVRAM/RuntimeServices','BMC access'],
 'permitted_environment_effects':['Disable the inherited UEFI watchdog for QR capture','Allocate/free console metadata/graphics buffers','Console/GOP display and keyboard polling','One standard SCSI command only when all target gates pass'],
 'validation':{
  'native':{'file':'build/native_verification.json','actual_compiled_efi':True,'case_count':native['case_count'],'all_forbidden_service_pointers_trap':True,'max_application_commands':1},
  'parser':{'file':'build/parser_verification.json','native_logs':len(parser['native_logs']),'corruptions_rejected':len(parser['rejected_mutations'])},
  'qr':{'file':'build/transport_verification.json','compiled_encoder':True,'unchanged_p3_decoder':True,'cases':len(qr['cases']),'pages':qr['total_pages'],'roundtrip_identical':True,'missing_and_corrupt_page_rejected':True},
  'ovmf':{'file':'build/ovmf_verification.json','cases':len(vm['cases']),'real_qemu_non_target_cases':[c['case'] for c in vm['cases'] if not c['synthetic_provider']],
          'synthetic_provider_cases':[c['case'] for c in vm['cases'] if c['synthetic_provider']],
          'synthetic_limit':'The two test-only loaders publish mock USB/BlockIO/SCSI protocols and run the unchanged final EFI. They verify UEFI dispatch/QR/timeout handling, not physical USB or SAGE SCSI availability.',
          'all_input_disks_and_isos_unchanged':True,'all_owned_qemu_processes_finished':True},
  'fixed_before_freeze':'A small-path/no-BlockIO log-overflow fixture exposed overcounting an incompletely printed HANDLE. Fixed reported++ to occur only after complete HANDLE_END output; the 70-handle reproducer now decodes as explicit partial/zero-command, and all final tests were rerun.'},
 'log_contract':{'first_line':'MEDIA-CAPACITY-02 STANDARD SCSI OWNER ONLY','max_bytes_exclusive':32768,'max_handles':128,'max_path_bytes':2048,'max_path_nodes':64,
   'parser':'decode_capacity_log.py:parse(bytes)','success_field':'rc10_success','valid_response_is_not_overall_success':True,
   'separate_fields':['complete','target_count','command_count','rc10_valid_response','rc10_success','blocked_reason','test_status'],
   'overflow':'Explicit LOG_OVERFLOW and OBSERVATION_PARTIAL; zero command; footer reserved; no silent handle count truncation.'},
 'minimum_hardware_observation':{
  'runs':1,'proposal_only':'Parent may reuse its already audited fixed-image HD session and boot the production CAP02 ISO once, collect every QR page, validate P3 CRC then parse. This child has not performed it.',
  'if_unique_scsi_present':'One run provides cached BlockIO before, returned RC10 bytes, and cached BlockIO after. No second query is needed for this comparison.',
  'normal_rc10_wrong_cache':'512-byte sectors and lastLBA32767 from RC10 against cached1024/262144 establishes interface disagreement at this observation; it does not identify every earlier initialization cause.',
  'same_wrong_geometry':'Matching1024/262144 establishes present agreement only; cannot distinguish gadget/backend behavior from OEM transport/provider interpretation without further evidence.',
  'no_scsi':'An intact full capability inventory with no associated SCSI_IO is a useful negative result, not a capacity-read pass. Stop, no BOT fallback.',
  'potential_next_route':'A minimal RAM-only Linux with no automount/network could own the USB MSC transport and issue SG_IO RC10 to unique046B:FF31. This is a future design only; not downloaded, built, or validated here.'},
 'limits':['SCSI protocol availability on the actual SAGE firmware remains unmeasured. Existing AMI direct USB-to-BlockIO static evidence suggests absence is plausible, not proved.','The path pin may reject a changed enumeration path; that is intentional.','No guarantee against malicious protocol providers or arbitrary invalid firmware pointers. Guards detect bounded overwrites only.','No direct USB-wire capture; capacity is the standard SCSI provider response.','No source BIOS, password driver, existing HD client, writeback geometry guard or frozen prior artifact was changed.'],
 'reference_access':'An attempted public-header download was blocked and escalation rejected by automatic approval as outside the offline task scope. No workaround download was used. Exact ABI field order/signatures came from official UEFI2.11 text already independently read and supplied by parent; local UefiScsiLib.c cross-check and compile-time offsets are documented in abi_review.json.',
 'not_for_target':['test_only_fixtures/build/TEST-ONLY-SYNTHETIC-success.iso','test_only_fixtures/build/TEST-ONLY-SYNTHETIC-timeout.iso'],
 'input_artifacts':inputs
}
save(HERE/'capacity_review.json',report)
files=[]
for p in sorted(HERE.rglob('*')):
    if p.is_file() and p.name!='candidate_manifest.json' and '__pycache__' not in p.parts:
        files.append({'path':p.relative_to(HERE).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)})
manifest={'status':'FROZEN_LOCAL_CANDIDATE','created_utc':report['created_utc'],'hardware_tested':False,
 'efi_sha256':efi,'iso_sha256':iso,'review_sha256':sha(HERE/'capacity_review.json'),'artifacts':files,'inputs':inputs}
save(HERE/'candidate_manifest.json',manifest)
assert all(sha(HERE/r['path'])==r['sha256'] for r in files)
assert all(sha(ROOT/r['path'])==r['sha256'] for r in inputs)
print(json.dumps({'status':manifest['status'],'artifacts':len(files),'inputs':len(inputs),'efi_sha256':efi,'iso_sha256':iso,'review_sha256':manifest['review_sha256'],'manifest_sha256':sha(HERE/'candidate_manifest.json'),'native_cases':native['case_count'],'qr_pages':qr['total_pages'],'ovmf_cases':len(vm['cases'])},indent=2))
