"""Bind completed offline checks; never rebuild or alter the tested EFI/ISO."""
from pathlib import Path
import datetime, hashlib, io, json, shutil, struct, sys, warnings, zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[6]
OUT=HERE/'build'
REVIEW=HERE/'review'
REVIEW.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def evidence(p):
    return dict(path=str(p),bytes=p.stat().st_size,sha256=sha(p))

native=json.loads((OUT/'native_verification.json').read_text(encoding='utf-8'))
ovmf=json.loads((OUT/'ovmf_verification.json').read_text(encoding='utf-8'))
build=json.loads((OUT/'build.json').read_text(encoding='utf-8'))
assert native['status']=='PASS_SYNTHETIC_UEFI_NATIVE_CODE_ONLY' and native['cases_count']==102
assert ovmf['status']=='PASS_LOCAL_OVMF_ONLY' and len(ovmf['cases'])==7
assert all(v['status']=='PASS_LOCAL_OVMF_ONLY' for v in ovmf['cases'])
efi=OUT/'BOOTX64.EFI';iso=OUT/'SAGE1904-MEDIA-WRITEBACK01.iso'
assert sha(efi)==native['efi_sha256']==ovmf['efi_sha256']==build['efi_sha256']=='1469c7ae5b39859ff22a96a335d24bc029a3490bf892e45f3d478e43abd8b092'
assert sha(iso)==ovmf['iso_sha256']==build['iso_sha256']=='eda0104fc05847b825ae9fbf16eae62674016509afb76c53188666011fb2f3d1'
assert sha(HERE/'verify_native.py')==native['test_sha256']
assert sha(HERE/'source/writeback.c')==native['source_sha256']
assert sha(HERE/'verify_ovmf.py')==ovmf['test_source_sha256']
assert all(sha(HERE/p)==s for p,s in build['source_files'].items() if p!='sources.json'),'Pre-finalization application source snapshot differs'

refs=REVIEW/'reference';refs.mkdir(exist_ok=True)
copied=[]
for src,name,url,detail in [
 (ROOT/'analysis/hero_remote_bios_r7/reference/UsbIo.h','UsbIo.h','https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Protocol/UsbIo.h','Protocol struct has UsbGetInterfaceDescriptor at slot8, x64 offset0x40; only that cached descriptor method is used.'),
 (HERE.parent/'spi_inventory_candidate04/source/reference_documents/UefiSpec.h','UefiSpec.h','https://github.com/tianocore/edk2/blob/edk2-stable202502/MdePkg/Include/Uefi/UefiSpec.h','EFI_CONNECT_CONTROLLER: Recursive FALSE expands one controller level; TRUE expands the subtree below that specific handle. Existing BootServices.ConnectController slot0x108.')]:
    dst=refs/name;shutil.copyfile(src,dst)
    assert sha(src)==sha(dst)
    copied.append(dict(**evidence(dst),copied_from=str(src),reference_url=url,supports=detail))

pristine=HERE.parent/'media_writeback_review/blank_test/WRITEBACK02.img'
assert pristine.stat().st_size==16777216 and sha(pristine)=='df7fa016a0f4be496d3d446db558e8de15f537aa9953faff20b4ae0c6132b4b6'
with pristine.open('rb') as f:bpb=f.read(512)
u16=lambda n:struct.unpack_from('<H',bpb,n)[0]
u32=lambda n:struct.unpack_from('<I',bpb,n)[0]
bps,spc,reserved,fats,roots,total,spf=u16(11),bpb[13],u16(14),bpb[16],u16(17),u16(19) or u32(32),u16(22)
root_sectors=(roots*32+bps-1)//bps
data_sectors=total-reserved-fats*spf-root_sectors
clusters=data_sectors//spc
bpb_report=dict(bytes_per_sector=bps,sectors_per_cluster=spc,reserved_sectors=reserved,fat_count=fats,root_entries=roots,total_sectors=total,sectors_per_fat=spf,root_sectors=root_sectors,data_sectors=data_sectors,full_data_clusters=clusters,allocation_bytes=bps*spc,filesystem_managed_bytes=clusters*bps*spc,raw_device_bytes=total*bps)
assert bpb_report['allocation_bytes']==2048 and bpb_report['filesystem_managed_bytes']==16726016
downloads=json.loads((HERE/'source/reference/download_manifest.json').read_text(encoding='utf-8'))
for item in downloads:assert sha(HERE/item['path'])==item['sha256']
sources=json.loads((HERE/'sources.json').read_text(encoding='utf-8'))
sources['scope']='Disposable marker-matched USB virtual-HD file write only. Scoped standard ConnectController calls can run existing USB/storage/filesystem drivers; no direct SPI, PCI, RuntimeServices, raw BlockIO write or USB transfer methods are called by the test application.'
sources['primary_references']=downloads+copied
sources['pinned_FAT16_BPB']=bpb_report
save(HERE/'sources.json',sources)

warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/vm-pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pycdlib,pefile
from pyfatfs.PyFatFS import PyFatFS
pe=pefile.PE(str(efi))
assert pe.verify_checksum() and pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
cd=pycdlib.PyCdlib();cd.open(str(iso));buf=io.BytesIO()
cd.get_file_from_iso_fp(buf,iso_path='/EFI/BOOT/BOOTX64.EFI;1');assert buf.getvalue()==efi.read_bytes()
buf=io.BytesIO();cd.get_file_from_iso_fp(buf,iso_path='/EFIBOOT.IMG;1')
assert buf.getvalue()==(OUT/'eltorito.img').read_bytes()
assert cd.eltorito_boot_catalog.validation_entry.platform_id==0xef;cd.close()
with PyFatFS(str(OUT/'eltorito.img'),read_only=True,utc=True) as fs:
    assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()

# Only source/evidence packaging changes after tests; tested binaries untouched.
source_files={p.relative_to(HERE).as_posix():sha(p) for p in (HERE/'source').rglob('*') if p.is_file()}
for p in [HERE/'build_candidate.py',HERE/'verify_native.py',HERE/'verify_ovmf.py',Path(__file__),HERE/'sources.json',HERE/'expected-result.bin']+list(refs.glob('*')):
    source_files[p.relative_to(HERE).as_posix()]=sha(p)
with zipfile.ZipFile(OUT/'source-snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
    for n in source_files:z.write(HERE/n,n)
with zipfile.ZipFile(OUT/'source-snapshot.zip') as z:
    assert z.testzip() is None and all(hashlib.sha256(z.read(n)).hexdigest()==s for n,s in source_files.items())
build.update(status='PASS_OFFLINE_NATIVE102_OVMF7_ONLY',source_files=source_files,source_archive_sha256=sha(OUT/'source-snapshot.zip'),packaging_note='Source/evidence archive refreshed after offline tests; EFI and ISO bytes were not rebuilt or changed.',native_verification_sha256=sha(OUT/'native_verification.json'),ovmf_verification_sha256=sha(OUT/'ovmf_verification.json'))
build['scope']=sources['scope'];save(OUT/'build.json',build)

report=dict(status='READY_FOR_PARENT_REVIEW_OFFLINE_ONLY',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    hardware_tested=False,efi=evidence(efi),iso=evidence(iso),
    pristine_image=evidence(pristine),pristine_unchanged=True,pinned_FAT16_BPB=bpb_report,
    application_source=evidence(HERE/'source/writeback.c'),
    selection_and_connection=[
        'Enumerate only existing USB_IO then BlockIO handles (each <=128); no all-handle or PCI/hub/controller ConnectAll.',
        'USB_IO branch: valid USB path, exact interface class08/subclass06/protocol50/BOT and two endpoints; no existing BlockIO or SFS; ConnectController(handle,NULL,NULL,FALSE).',
        'BlockIO branch: valid USB path, media present, writable, 512-byte sectors and lastLBA32767; no SFS; ConnectController(handle,NULL,NULL,TRUE).',
        'At most32 connection calls; connection, protocol, descriptor or enumeration uncertainty aborts. There is no connection retry.',
        'Fresh SFS enumeration; exact raw geometry, WBTEST02 label, 2048 allocation bytes, 16726016 managed bytes, sufficient free space and exact IDENTIFY.TXT content/size/EOF.',
        'Exactly one match and no uncertain eligible volume required. Recheck USB path, raw geometry, MediaId, label and marker immediately before mutation.'
    ],
    file_transaction=[
        'Open WRBACK.TXT read-only must yield EFI_NOT_FOUND with null handle; existing empty or nonempty file is refused.',
        'One CREATE|READ|WRITE open only. Require new handle methods, empty file and neither directory nor read-only attribute before Write.',
        'Exactly one120-byte Write, exact byte count, successful Flush and Close.',
        'Reopen read-only and verify metadata length, exact content and EOF; close root and file; any reported failure makes test status fail.',
        'No Delete, SetInfo, SetPosition/truncate, raw BlockIO write, raw USB transfer, PCI, SPI, RuntimeServices or device reset methods are called by the app.'
    ],
    evidence=[
        dict(test='Actual tested EFI native bytecode in Unicorn',cases=native['cases_count'],report=evidence(OUT/'native_verification.json'),scope='UEFI services are synthetic, QR presenter skipped; all application decisions/selection/file transaction run from actual EFI bytes; all unapproved service and port-I/O calls trap.'),
        dict(test='QEMU/OVMF actual USB/filesystem integration',cases=len(ovmf['cases']),report=evidence(OUT/'ovmf_verification.json'),scope='Readonly boot CD plus disposable regular-file USB HD copies; no target hardware or network; positive file reopen verified on host; six negative image hashes unchanged.'),
        dict(test='VM QR transport',pages=sum(c['qr_pages'] for c in ovmf['cases']),scope='Each case complete QR pages reconstructed byte-for-byte against console log/CRC; Home/text/QR return/Escape checked.'),
        dict(test='Packaging',scope='PE x64 EFI application, checksum/relocation/import/signature fields checked; ISO and El Torito FAT both contain the exact tested EFI; source archive entries/hash checked.')
    ],
    limitations=[
        'No BMC, physical ASUS motherboard, remote virtual-HD persistence or recovery path has passed through this offline task.',
        'ConnectController invokes existing firmware drivers under selected USB storage. The app itself makes no raw write call, but this is not a claim of zero USB/controller/device I/O.',
        'Firmware must already expose either USB_IO for the selected storage interface or suitable USB BlockIO; missing lower-level enumeration remains a refusal. No root-controller blanket connection is attempted.',
        'The exact FS_INFO values follow the pinned image BPB and EDK II semantics. An ASUS filesystem reporting different values is refused until independently explained; there is no fallback broadening.',
        'After CREATE, write/flush/close/readback faults may leave an empty or partially written disposable file. No cleanup delete or retry occurs.',
        'UEFI has no exclusive CREATE mode; a concurrent empty file created between absence check and CREATE cannot be distinguished. The later test must exclusively own the disposable image/session.',
        'UEFI selection uses exact geometry/label/marker rather than a whole-image hash. Parent-controlled backend must independently pin and bound WRITEBACK02.img and prevent arbitrary paths/device backends.',
        'Before claiming real writeback, stop/unmount/close the owned backend and reopen the local image read-only to verify WRBACK.TXT content, image size, marker, filesystem integrity and relevant before/after hashes.',
        'This tool only writes the stated temporary120-byte diagnostic file. It reads no flash contents and establishes neither a complete SPI backup nor a safe flash-recovery path.'
    ])
save(HERE/'writeback_review.json',report)
paths=[efi,iso,OUT/'eltorito.img',OUT/'source-snapshot.zip',OUT/'build.json',OUT/'inventory.map',OUT/'native_verification.json',OUT/'ovmf_verification.json',HERE/'writeback_review.json']
paths += [HERE/n for n in source_files]
for c in ovmf['cases']:
    folder=HERE/c['folder']
    assert sha(folder/'RESTORED-LOG.TXT')==c['restored_log_sha256']
    paths += [folder/'result.json',folder/'RESTORED-LOG.TXT',folder/'command.json']
manifest=dict(status='OFFLINE_CHECKED_NOT_HARDWARE_ACCEPTED',efi_sha256=sha(efi),iso_sha256=sha(iso),artifacts=[evidence(p) for p in sorted(set(paths),key=str)],pristine_image_unchanged_sha256=sha(pristine))
save(HERE/'candidate_manifest.json',manifest)
assert sha(efi)==native['efi_sha256'] and sha(iso)==ovmf['iso_sha256']
print(json.dumps(dict(efi_sha256=sha(efi),iso_sha256=sha(iso),review_sha256=sha(HERE/'writeback_review.json'),manifest_sha256=sha(HERE/'candidate_manifest.json'),bound_artifacts=len(manifest['artifacts']),native_cases=native['cases_count'],OVMF_cases=len(ovmf['cases'])),indent=2))
