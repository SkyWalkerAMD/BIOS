"""Freeze a source handoff without changing frozen I4 or PCI catalogue."""
from pathlib import Path
import hashlib,json,subprocess,zipfile
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()
sources=json.loads((P/'reference/sources.json').read_text())
for x in sources:
 b=(P/'reference'/x['file']).read_bytes();assert len(b)==x['bytes'] and sha(b)==x['sha256']
cmd=[str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ROOT/'tools/zig-x86_64-windows-0.14.1/lib/include'),'-std=c11','-ffreestanding','-fno-builtin','-Werror','-fsyntax-only',str(P/'test_official_abi.c')]
subprocess.run(cmd,check=True)
abi=dict(passed=True,pinned_revision='edk2-stable202502',official_fields_compiled=25,official_headers_sha_verified=len(sources),command=cmd)
(P/'official-abi-verification.json').write_text(json.dumps(abi,indent=2)+'\n')
for f in ('build.json','pe-verification.json','native-verification.json','helper-guard-page-tests.json','live-fixture-verification.json'):
 d=json.loads((P/f).read_text());assert d.get('passed') or d.get('all_passed'),f
header=P/'source/hero_pcie_catalog.h';frozen=ROOT/'analysis/hero_pcie_catalog_20261108/source/hero_pcie_catalog.h';assert header.read_bytes()==frozen.read_bytes()
handoff=dict(schema='HHS-HANDOFF-1',frozen_source=True,workspace_bytes=269216,workspace_alignment=16,global_status={'0':'All source groups complete','EFI_NOT_READY':'One or more source groups incomplete; independent groups remain usable','EFI_ABORTED':'Visitor rejected a record; do not publish truncated source','EFI_ALREADY_STARTED':'Same workspace is busy'},visitor_success=0,borrowed_record_lifetime='Until visitor returns only',firmware_sources=['hero_hardware_source.c','hhs_read_helpers.c','hero_hardware_pcie_adapter.c'],firmware_headers=['hero_hardware_source.h','hhs_read_abi.h','hhs_common.h','efi_min.h','hero_hardware_pcie_adapter.h','hero_pcie_catalog.h'],helper_symbols=['memcpy','memset','eq','probe_crc32'],no_automatic_publication=True,no_deletions=True,firmware_source_interface_whitelist=['LocateHandleBuffer','GetMemoryMap','HandleProtocol','PciIo.GetLocation','PciIo.Pci.Read(width=Uint8,offset=0,count=256)','DiskInfo.Identify(only IDE/AHCI/NVMe GUID,512/4096 bytes)','FreePool(handle enumeration arrays)'],source_limits={'pci':128,'block':128,'disk':64,'path_bytes':1024,'memory_map_bytes':262144,'identify_bytes':4096},hpc_header_sha256=sha(header.read_bytes()),actual_pe_tests=27,native_tests=23,helper_guard_tests=38,live_replay={'records':44,'source':'Parent-acquired I4 raw snapshot','hhs_hardware_run':False},test_carrier={'file':'HHS-TEST-CARRIER.EFI','entry_returns':'EFI_UNSUPPORTED','does_not_collect':True,'not_a_firmware_update':True},source_sha256={p.name:sha(p.read_bytes()) for p in sorted((P/'source').iterdir()) if p.is_file()},known_limits=['BlockIo is metadata only, not disk health or contents.','NVMe Identify remains opaque Namespace data when provided by EDK2; not Controller SN/MN/FR.','AMI DiskInfo implementation being cache-only is not established.','Unsupported DiskInfo interface is an explicitly skipped observation, not a deletion.','Current-boot BDF/path/handle associations are not persistent physical slot identity.','No whole-list deletion is authorized even for an empty complete enumeration.'])
(P/'handoff.json').write_text(json.dumps(handoff,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
include=[]
for path in sorted(P.rglob('*')):
 if not path.is_file() or any(v in path.parts for v in ('__pycache__','zig-local','zig-global')):continue
 if path.suffix in ('.obj','.lib','.zip') or path.name in ('SHA256SUMS.txt','package-verification.json'):continue
 include.append(path)
manifest=''.join(sha(p.read_bytes())+'  '+p.relative_to(P).as_posix()+'\n' for p in include)
(P/'SHA256SUMS.txt').write_text(manifest,encoding='utf-8',newline='\n');include.append(P/'SHA256SUMS.txt')
zip_path=P/'HERO-HARDWARE-SOURCE-20261108.zip'
with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for path in include:z.write(path,path.relative_to(P).as_posix())
with zipfile.ZipFile(zip_path) as z:
 assert z.testzip() is None
 for path in include:assert z.read(path.relative_to(P).as_posix())==path.read_bytes()
 lines=z.read('SHA256SUMS.txt').decode().splitlines()
 for line in lines:
  digest,name=line.split('  ',1);assert sha(z.read(name))==digest
report=dict(passed=True,file=zip_path.name,bytes=zip_path.stat().st_size,sha256=sha(zip_path.read_bytes()),zip_members=len(include),manifest_files=len(include)-1,all_members_readback_verified=True)
(P/'package-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
