"""Bind CPU_IO2 design to official ABI, original native review and INV03 log."""
from pathlib import Path
import difflib,hashlib,json,re,zlib
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];REF=HERE/'source/reference_documents'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
cpu=(REF/'CpuIo2.h').read_text(encoding='utf8');memory=(REF/'UefiSpec.h').read_text(encoding='utf8')
assert '0xad61f191, 0xae5f, 0x4c0e' in cpu and re.search(r'struct _EFI_CPU_IO2_PROTOCOL\s*\{.*?EFI_CPU_IO_PROTOCOL_ACCESS\s+Mem;.*?EFI_CPU_IO_PROTOCOL_ACCESS\s+Io;',cpu,re.S)
assert 'EfiCpuIoWidthUint32' in cpu and 'boot-services only protocol' in cpu
for name,value in [('EFI_MEMORY_UC','0x0000000000000001ULL'),('EFI_MEMORY_RP','0x0000000000002000ULL'),('EFI_MEMORY_XP','0x0000000000004000ULL'),('EFI_MEMORY_RUNTIME','0x8000000000000000ULL')]:assert re.search(r'#define\s+'+name+r'\s+'+value,memory)
log=CASE/'remote_172_20_2_162/hardware-spiinv03-1793675560232/hardware-log.txt';data=log.read_bytes()
assert sha(log)=='0561747f769d4db43c689c12071d9912d2bb4ff721aefe9897da1e5d76ed87d9'
assert len(data)==5019 and zlib.crc32(data)==0xbabc7ee1
for token in [b'CPU_IO2=PRESENT_NOT_CALLED',b'UEFI_MAP_COVERS_BAR TYPE=11 START=0x00000000FE010000 END=0x00000000FE010FFF ATTR=0x8000000000000001',b'ROOT_FALLBACK=REFUSED_RESOURCE_EVIDENCE',b'SPIBAR0_RAW=0xFE010000',b'SPI_REV_CLASS=0x0C800011']:assert token in data
native=HERE.parent/'cpuio2_native/native_review.json';review=json.loads(native.read_text(encoding='utf8'))
assert sha(native)=='528503ed795ba75848ec968eff18d3dceb816f9a8bff5cb839dd81995aa6f145'
assert review['status']=='PASS_ORIGINAL_CPU_IO2_STATIC_AND_SYNTHETIC_PATH_REVIEW'
assert review['inputs']['EFI']['sha256']=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
assert review['synthetic_execution']['case_count']==21
current=(HERE/'source/inventory.c').read_text(encoding='utf8');old=(HERE.with_name('spi_inventory_candidate03')/'source/inventory.c').read_text(encoding='utf8')
(HERE/'inventory03-to-04.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True),current.splitlines(True),fromfile='INV03/source/inventory.c',tofile='INV04/source/inventory.c')),encoding='utf8')
sources=json.loads((HERE/'sources.json').read_text(encoding='utf8'))
base='https://github.com/tianocore/edk2/blob/edk2-stable202502/'
refs={'CPU_IO2_ABI':base+'MdePkg/Include/Protocol/CpuIo2.h','memory_descriptor_and_attributes':base+'MdePkg/Include/Uefi/UefiSpec.h','memory_types':base+'MdePkg/Include/Uefi/UefiMultiPhase.h','memory_attributes_semantics':'https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-getmemorymap'}
sources['references'].update(refs)
sources['CPU_IO2_fallback']='Only all14 primary reads UNSUPPORTED and root path refused BEFORE any root read. Two fresh map/identity/target checks; unique readable CPU_IO2 with method inside code mapping; exact observed type11 single4KiB page/attribute8000000000000001 and no overlapping descriptor. Fixed14 Width32 Count1 calls; stop on first anomaly.'
sources['attribute_caveat']='Attributes describe capabilities, not necessarily current settings; exact values bind a prior-observed resource, not proof of current cache state/read permission.'
(HERE/'sources.json').write_text(json.dumps(sources,indent=2)+'\n',encoding='utf8')
report={
 'status':'PASS_OFFICIAL_ABI_PRIOR_RESOURCE_AND_ORIGINAL_IMPLEMENTATION_EVIDENCE','inv04_hardware_tested':False,
 'prior_inv03_log':{'path':str(log.relative_to(CASE)),'sha256':sha(log),'bytes':len(data),'crc32':'BABC7EE1','observations':['Exact MMIO page FE010000..FE010FFF type11, attributes8000000000000001','CPU_IO2 exists; INV03 did not call it','Root resource parser refused; INV03 did not print GRAN so cause remained incomplete']},
 'ABI':{'GUID':'ad61f191-ae5f-4c0e-b9fa-e869d288c64f','Mem.Read_offset':'0x00','Mem.Write_opaque_unused':'0x08','Io_methods_opaque_unused':['0x10','0x18'],'parameters':'This, UINT32 Width, UINT64 Address, UINTN Count, VOID *Buffer','width':2,'count':1,'phase':'Boot Services only'},
 'memory_gate':{'target_start':'FE010000','pages':1,'type':11,'attributes_exact':'8000000000000001','UC_bit':'1','RUNTIME_bit':'8000000000000000','RP_bit_not_reported':'2000','XP_bit':'4000','requirements':['Refresh map twice; size/stride/version and every descriptor range validated','Exactly one descriptor overlaps entire target page and matches all observed fields','Unique CPU_IO2 handle; interface buffer in RAM, method nonnull inside exactly one Boot/RuntimeServicesCode mapping with no RP/XP reported','SMBIOS and actual PCI identity/BDF/revision/decode/BAR rechecked before and after protocol selection'],'caveat':'Matching capability bits does not prove current cache mode or physical read permission. Protocol error is final for this path.'},
 'original_cpu_driver_review':{'path':str(native.relative_to(HERE.parent)),'sha256':sha(native),'scope':'Independent original ASUS CPU_IO2 producer identification plus 21 native read cases; no target-device operation and no automatic hardware acceptance for this candidate.'},
 'read_scope':{'addresses':[f'{0xfe010000+x:08X}' for x in [0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94]],'primary_trigger':'All14 PCI_IO reads must be EFI_UNSUPPORTED','root_boundary':'Only if no root was selected; root read errors never trigger CPU fallback','on_error':'Stop on first failed status, all-ones data, FDV-invalid or SCIP-busy; no other interface/raw pointer fallback','writes':0,'SetVariable':0,'SPI_cycles':0,'flash_bytes':0},
 'root_change':'Added GRAN and exact rejection reasons only; no root resource gate was relaxed.',
 'source_references':refs,'reference_files':{name:{'sha256':sha(REF/name),'bytes':(REF/name).stat().st_size} for name in ['CpuIo2.h','UefiSpec.h','UefiMultiPhase.h']},
 'limits':['Candidate still requires local tests and separate hardware evidence.','Original CPU_IO2 implementation has no register allowlist; the candidate supplies the fixed-register/address/resource gates.','No full SPI dump, density measurement, backup/restoration claim or protection change.']}
(HERE/'cpu_io_evidence.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'report_sha256':sha(HERE/'cpu_io_evidence.json'),'source_sha256':sha(HERE/'source/inventory.c')},indent=2))
