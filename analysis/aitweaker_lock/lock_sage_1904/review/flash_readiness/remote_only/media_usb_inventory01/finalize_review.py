"""Freeze already-tested metadata-only inventory, without changing EFI/ISO."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,io,json,sys,zipfile
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pefile,pycdlib
from pyfatfs.PyFatFS import PyFatFS
from decode_inventory_log import parse
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
def bind(p):return {'path':str(p.resolve()),'bytes':p.stat().st_size,'sha256':sha(p)}
def main():
    native=json.loads((OUT/'native_verification.json').read_text());vm=json.loads((OUT/'ovmf_verification.json').read_text());qr=json.loads((OUT/'transport_verification.json').read_text());parser=json.loads((OUT/'parser_verification.json').read_text());build=json.loads((OUT/'build.json').read_text())
    assert native['status']==qr['status']==parser['status']=='PASS' and native['case_count']==52 and qr['total_pages']==48
    assert vm['status']=='PASS_LOCAL_OVMF_ONLY' and len(vm['cases'])==9
    efi=OUT/'BOOTX64.EFI';iso=OUT/'SAGE1904-MEDIA-USB-INVENTORY01.iso'
    assert sha(efi)==build['efi_sha256']==vm['efi_sha256']==native['efi_sha256']==qr['efi_sha256']=='25157e8c9a562676bc79fe4eb76bf25073ce872d1d9f6adf1987a2d2c33bd51b'
    assert sha(iso)==build['iso_sha256']==vm['iso_sha256']=='4bf3b75b2ee3d4fa6a865fec9f104751424bd969a2fdd002b074916eb687898a'
    assert sha(HERE/'verify_native.py')==native['test_sha256'] and sha(HERE/'verify_ovmf.py')==vm['test_sha256']
    assert sha(HERE/'verify_transport.py')==qr['test_sha256'] and sha(HERE/'decode_inventory_log.py')==parser['parser_sha256']
    for n,s in build['source_files'].items():assert sha(HERE/n)==s
    pe=pefile.PE(str(efi));assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10 and pe.FILE_HEADER.Machine==0x8664
    assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
    cd=pycdlib.PyCdlib();cd.open(str(iso));buf=io.BytesIO();cd.get_file_from_iso_fp(buf,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert buf.getvalue()==efi.read_bytes()
    buf=io.BytesIO();cd.get_file_from_iso_fp(buf,iso_path='/EFIBOOT.IMG;1');assert buf.getvalue()==(OUT/'eltorito.img').read_bytes();assert cd.eltorito_boot_catalog.validation_entry.platform_id==0xef;cd.close()
    with PyFatFS(str(OUT/'eltorito.img'),read_only=True,utc=True) as fs:assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()
    old=HERE.parent/'media_writeback_uefi01';hd=HERE.parent/'media_writeback_client01/review_legacy_data/bounded_legacy.py';pristine=HERE.parent/'media_writeback_review/blank_test/WRITEBACK02.img'
    preserved={old/'build/BOOTX64.EFI':'1469c7ae5b39859ff22a96a335d24bc029a3490bf892e45f3d478e43abd8b092',old/'build/SAGE1904-MEDIA-WRITEBACK01.iso':'eda0104fc05847b825ae9fbf16eae62674016509afb76c53188666011fb2f3d1',old/'candidate_manifest.json':'923b2e9aa7d1eefadfda8d506e0fe3595689daa9f3b93b5a3e48877811c2dd25',hd:'163bca4e30aec052d0604a47077a436f2fa2931115d35d76c741cc4d27fcdab5',pristine:'df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'}
    assert all(sha(p)==s for p,s in preserved.items())
    for case in vm['cases']:
        assert case['status']=='PASS_LOCAL_OVMF_ONLY' and case['all_data_and_iso_images_unchanged'] and case['owned_process_finished']
        p=HERE/case['folder']/'RESTORED-LOG.TXT';assert sha(p)==case['restored_log_sha256'];assert parse(p.read_bytes())['complete']
    notes={'status':'TEST_FIXTURE_EXPECTATIONS_CORRECTED_EFI_UNCHANGED',
           'initial_report':bind(HERE/'review/ovmf_initial_failures.json'),'initial_test_source':bind(HERE/'review/verify_ovmf_initial.py'),
           'facts':['Initial assertions incorrectly required every attached but non-boot HD to have BlockIO. OVMF only published USB_IO for that disk; the diagnostic correctly recorded missingBlockIO/SFS.',
                    'The empty raw disk QEMU fixture failed to start because no file backend was supplied. It is preserved as a setup failure, never counted as a diagnostic pass.',
                    'Final5CD-boot cases explicitly check the existing protocol state. Additional4normal boot-from-data-disk fixtures let firmware publishBlockIO normally before the unchanged app; no ConnectController was added.',
                    'No-media present=0 behavior is covered by actual EFI native fixture; absence of any extra disk is separately covered in OVMF. Empty-HDD physical behavior is not claimed.']}
    save(HERE/'review/fixture_adjustments.json',notes)
    report={'status':'READY_FOR_PARENT_REVIEW_OFFLINE_ONLY','utc':datetime.now(timezone.utc).isoformat(),'hardware_tested':False,
      'efi':bind(efi),'iso':bind(iso),'application_source':bind(HERE/'source/inventory.c'),
      'behavior':['Enumerate existing USB_IO,BlockIO,SFS handle lists independently, merge into at most128uniquehandles and retain source-mask/per-handle protocol association.',
                  'Record all providers, including nonUSB,unknownVID/PID,unusualgeometry,readOnly,noMedia and missingSFS; there is no target-selection filter.',
                  'Read only standardUSB device/interface descriptors, descriptorhex,VID/PID,class/subclass/protocol.046B:FF31 is an informational marker, not an access gate.',
                  'Record complete generic well-formed devicepaths up to2048bytes/64nodes, including multi-instance paths. Malformed/out-of-bound paths are explicitly marked uncertain and not represented as completepaths.',
                  'Record BlockIO revision and current mediaid/present/removable/readOnly/logical/writeCaching/blockSize/alignment/lastLBA. No BlockIO method is invoked.',
                  'Record SFS protocol availability without OpenVolume or any file method.',
                  'No ConnectController,USB rawTransfer,deviceReset,PCI/SPI,RuntimeServices,variable,filesystem or storage-data methods are called by the app.',
                  'Disable theUEFI watchdog; display exact logs through originalP3QR/text protocol. At32768-byte cap, reserve512bytes for explicitLOG_OVERFLOW/INVENTORY_PARTIAL/error/footer; never silently claim a truncated completeinventory.'],
      'verification':{'native_cases':52,'native_report':bind(OUT/'native_verification.json'),'OVMF_cases':9,'OVMF_report':bind(OUT/'ovmf_verification.json'),
                      'OVMF_QR_pages':sum(c['qr_pages'] for c in vm['cases']),'compiled_QR_stress_pages':48,'QR_report':bind(OUT/'transport_verification.json'),
                      'parsed_fixture_logs':49,'parser_rejections':14,'parser_report':bind(OUT/'parser_verification.json'),
                      'ISO_and_ElTorito_exact_EFI_verified':True,'all_existing_WB_HD_and_pristine_artifacts_unchanged':True},
      'primary_reference':{'file':bind(HERE/'source/reference/UsbIo.h'),'source_url':'https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/UsbIo.h','abi':'x64UsbGetDeviceDescriptor slot6/offset0x30; UsbGetInterfaceDescriptor slot8/offset0x40'},
      'next_interpretation':['If no vendorHDUSB descriptor appears, lower USB enumeration/back-endgadget binding remains unobserved; noConnectController is attempted.',
                             'If vendorHD USB_IO exists but BlockIO is missing, storage-driver binding remains distinct from absentUSBdevice.',
                             'If BlockIO exists, inspectMediaPresent/readOnly/geometry and correlate completeDevicePath prefixes with SFS providers.',
                             'A successful diagnostic means metadata was recorded. It does not meanHD filewriteback,fullSPIbackup,firmwarepassworddeployment or flashrecovery succeeded.'],
      'limits':['Only currently published protocols are observable. Firmware may not connect non-boot storage; no implicit refresh/connect is performed.',
                'Metadata reflects one scan; no media locking or cross-protocol snapshot guarantee. Firmware protocol pointers must satisfy the UEFIABI.',
                'DP_VALID means bounded genericnode structure, not semantic validation of every vendor/devicepath subtype. Fullrawbytes are retained for independent review.',
                'Standard descriptor methods may be implemented internally by firmware USB code; this is not a claim of zero controller activity. GOP/console/keyboard UI also uses normalUEFI services.',
                'The diagnostic reports read-only flags exactly; firmware metadata flags can differ from underlying emulator/backend write protection.',
                'The128handle/32KiB limits can yield explicit partial/error output on large systems. Such output must not be accepted as completeinventory.',
                'No physicalBMC/ASUS test or network operation was performed by this task. ExistingV3HDsocket/boot orchestration remains parent-owned.'],
      'preserved_artifacts':[bind(p) for p in preserved]}
    save(HERE/'inventory_review.json',report)
    sources=[p for p in (HERE/'source').rglob('*') if p.is_file()]+[HERE/n for n in ['build_candidate.py','verify_native.py','verify_ovmf.py','verify_transport.py','verify_parser.py','decode_inventory_log.py','finalize_review.py','sources.json']]
    with zipfile.ZipFile(OUT/'source-snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
        for p in sources:z.write(p,p.relative_to(HERE).as_posix())
    with zipfile.ZipFile(OUT/'source-snapshot.zip') as z:
        assert z.testzip() is None and all(hashlib.sha256(z.read(p.relative_to(HERE).as_posix())).hexdigest()==sha(p) for p in sources)
    build.update(status='PASS_OFFLINE_NATIVE52_OVMF9_QR90_ONLY',source_files={p.relative_to(HERE).as_posix():sha(p) for p in sources},source_archive_sha256=sha(OUT/'source-snapshot.zip'),packaging_note='Source/evidence archive refreshed after tests; EFI and ISO unchanged.');save(OUT/'build.json',build)
    paths=sources+[HERE/'inventory_review.json',OUT/'BOOTX64.EFI',iso,OUT/'eltorito.img',OUT/'source-snapshot.zip',OUT/'build.json',OUT/'inventory.map',OUT/'qr_test.dll',OUT/'native_verification.json',OUT/'ovmf_verification.json',OUT/'parser_verification.json',OUT/'transport_verification.json',HERE/'review/fixture_adjustments.json',HERE/'review/ovmf_initial_failures.json',HERE/'review/verify_ovmf_initial.py']
    paths+=list((HERE/'review/native_logs').glob('*.txt'))
    for c in vm['cases']:
        d=HERE/c['folder'];paths += [d/n for n in ['result.json','command.json','RESTORED-LOG.TXT','parsed_inventory.json','serial.log']]+list(d.glob('qr-*.png'))
    paths+=list((OUT/'synthetic-qr').rglob('*.png'))
    manifest={'status':'FROZEN_OFFLINE_REVIEW_NOT_HARDWARE_ACCEPTED','efi_sha256':sha(efi),'iso_sha256':sha(iso),'artifacts':[bind(p) for p in sorted(set(paths),key=str)]}
    save(HERE/'candidate_manifest.json',manifest)
    print(json.dumps({'efi_sha256':sha(efi),'iso_sha256':sha(iso),'review_sha256':sha(HERE/'inventory_review.json'),'manifest_sha256':sha(HERE/'candidate_manifest.json'),'bound_artifacts':len(manifest['artifacts']),'native':52,'OVMF':9,'QR_pages':sum(c['qr_pages'] for c in vm['cases'])+48},indent=2))
if __name__=='__main__':main()
