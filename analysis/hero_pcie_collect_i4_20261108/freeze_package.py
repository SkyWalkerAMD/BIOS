"""Freeze the I4 media, exact sources and completed local verification."""
from pathlib import Path
import hashlib,json,zipfile
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
app=P/'USB/EFI/BOOT/BOOTX64.EFI';iso=P/'HERO-PCIE-I4-READONLY.iso'
assert sha(app)=='f83b176cc4e14aee10233596c1290ae8f883c48d323b87bc1e597a18605d6e51'
assert sha(iso)=='f9f40da3f315f92aeec9d73d302ca12dedea52eaec1577d858fca25bdb9518d5'
build=json.loads((P/'build.json').read_text())
for name,value in build['source_hashes'].items():assert sha(P/'source'/name)==value,name
checks={name:json.loads((P/name).read_text()) for name in ['pe-verification.json','official-abi-verification.json','guard-page-tests.json','qr-boundary-tests.json','vm-verification.json','vm-nvme-first-verification.json']}
assert all(v['passed'] for v in checks.values())
assert checks['pe-verification.json']['app_sha256']==sha(app)
assert checks['vm-verification.json']['iso_sha256']==sha(iso)==checks['vm-nvme-first-verification.json']['iso_sha256']
maximum=next(x for x in checks['pe-verification.json']['cases'] if x['case']=='maximum_records')
handoff=dict(version='I4-READONLY-1',frozen=True,physical_hardware_tested=False,
 iso=dict(file=iso.name,bytes=iso.stat().st_size,sha256=sha(iso)),efi=dict(file='USB/EFI/BOOT/BOOTX64.EFI',bytes=app.stat().st_size,sha256=sha(app)),
 api='ES pcie_storage_collect(ST*, int (*append)(void*,const char*,size_t), void*)',
 api_output='bounded structured-text raw evidence, not yet a typed-record visitor or publishable Redfish catalog',
 keys={'D':'capture once','C':'QR export','R':'text export','Esc':'leave viewer only','Q,Q':'return to firmware'},
 read_only=True,uefi_boot_watchdog_disabled=True,log_capacity=2097152,qr_chunk=512,
 limits=dict(pci=128,block=128,disk=64,device_path=1024,path_nodes=128,identify=4096,memory_map_bytes=262144,memory_map_entries=4096),
 tested_maximum_log_bytes=maximum['log_bytes'],actual_PE_test_cases=len(checks['pe-verification.json']['cases']),
 native_guard_page_cases=len(checks['guard-page-tests.json']['cases']),qr_boundary_cases=11,
 local_OVMF_full_qr_pages=[25,51],
 identity_interpretation='NVMe DiskInfo raw bytes are not assumed to be Identify Controller; EDK2 returns NamespaceData. AMI cache implementation remains unproven.',
 explicit_nonoperations=['PCI writes','BAR probing','BlockIo methods','PassThru','DiskInfo Inquiry/Sense/WhichIde','LoadImage/StartImage/ConnectController','NVRAM/SPI/BIOS writes','BMC/network/filesystem access'],
 provenance=[dict(path='analysis/hero_fw_i2c_20261108',role='startup conventions, EFI ABI, common helpers, build/OVMF packaging'),dict(path='analysis/hero_inventory_publish_i3d_20261108',role='2MiB QR/text viewer and full-size QR decoder/test pattern'),dict(path='reference/sources.json',role='official pinned edk2-stable202502 ABI headers')],
 reusable_collection_files={n:sha(P/'source'/n) for n in ['i4_collect.c','i4_collect.h','collector.h','common.c','efi_min.h']},
 no_live_sessions_or_background_processes_owned=True)
(P/'handoff.json').write_text(json.dumps(handoff,indent=2)+'\n')
names=[iso.name,'USB/EFI/BOOT/BOOTX64.EFI','操作与范围说明-I4.txt','采集接口与字段-I4.txt','handoff.json',
 'build.json','build.py','decode_captures.py','run_vm.py','verify_i4_pe.py','test_guard_pages.py','test_qr_bounds.py','test_official_abi.c',
 'freeze_package.py','fetch_reference.py','mock-catalog.TXT',*checks]
names += [p.relative_to(P).as_posix() for folder in ('source','reference') for p in (P/folder).rglob('*') if p.is_file()]
for folder in ('vm','vm-nvme-first'):
 names += [folder+'/'+n for n in ['OVMF-PCIE-I4.TXT','qr-manifest.json']]
 names += [p.relative_to(P).as_posix() for p in (P/folder).glob('page-*.png')]
assert len(names)==len(set(names))
manifest={n:dict(bytes=(P/n).stat().st_size,sha256=sha(P/n)) for n in sorted(names)}
(P/'package-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
zip_path=P/'HERO-PCIE-I4-READONLY-PACKAGE.zip'
with zipfile.ZipFile(zip_path,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for n in sorted(names+['package-manifest.json']):z.write(P/n,n)
with zipfile.ZipFile(zip_path) as z:
 assert z.testzip() is None
 for n,meta in manifest.items():
  data=z.read(n);assert len(data)==meta['bytes'] and hashlib.sha256(data).hexdigest()==meta['sha256'],n
report=dict(zip=zip_path.name,bytes=zip_path.stat().st_size,sha256=sha(zip_path),members=len(manifest)+1,zip_roundtrip_and_manifest_passed=True,iso=handoff['iso'],efi=handoff['efi'])
(P/'package-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
