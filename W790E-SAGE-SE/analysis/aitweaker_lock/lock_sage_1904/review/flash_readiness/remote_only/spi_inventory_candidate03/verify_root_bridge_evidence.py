"""Bind official ABI references, fixed read scope and prior INV02 evidence."""
from pathlib import Path
import difflib,hashlib,json,re,zlib
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];REF=HERE/'source/reference_documents'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rb=(REF/'PciRootBridgeIo.h').read_text(encoding='utf8');acpi=(REF/'Acpi10.h').read_text(encoding='utf8');cpu=(REF/'CpuIo2.h').read_text(encoding='utf8')
assert '0x2f707ebb, 0x4a1a, 0x11d4' in rb and 'EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_CONFIGURATION' in rb
assert re.search(r'ParentHandle;.*?PollMem;.*?PollIo;.*?Mem;.*?Io;.*?Pci;.*?Configuration;.*?UINT32\s+SegmentNumber;',rb,re.S)
for text in ['ACPI_QWORD_ADDRESS_SPACE_DESCRIPTOR        0x8A','ACPI_END_TAG_DESCRIPTOR                 0x79','AddrRangeMin','AddrRangeMax','AddrTranslationOffset','AddrLen']:assert text in acpi
assert '0xad61f191, 0xae5f, 0x4c0e' in cpu
log=CASE/'remote_172_20_2_162/hardware-spiinv02-1793673912543/hardware-log.txt';data=log.read_bytes()
assert len(data)==1644 and zlib.crc32(data)==0x5b1ee3f2
assert data.count(b'STATUS=0x8000000000000003\r\n')==14
for value in [b'PCI_VID_DID=0x7AA48086',b'SPI_REV_CLASS=0x0C800011',b'PCI_COMMAND_STATUS=0x00000402',b'SPIBAR0_RAW=0xFE010000',b'BIOS_CNTL=0x100008AA']:assert value in data
current=(HERE/'source/inventory.c').read_text(encoding='utf8');old=(HERE.with_name('spi_inventory_candidate02')/'source/inventory.c').read_text(encoding='utf8')
(HERE/'inventory02-to-03.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True),current.splitlines(True),fromfile='INV02/source/inventory.c',tofile='INV03/source/inventory.c')),encoding='utf8')
sources=json.loads((HERE/'sources.json').read_text(encoding='utf8'))
base='https://github.com/tianocore/edk2/blob/edk2-stable202502/'
refs={'root_bridge_abi':base+'MdePkg/Include/Protocol/PciRootBridgeIo.h','resource_layout':base+'MdePkg/Include/IndustryStandard/Acpi10.h','CPU_IO2_presence_GUID':base+'MdePkg/Include/Protocol/CpuIo2.h','uefi_semantics':'https://uefi.org/specs/UEFI/2.11/14_Protocols_PCI_Bus_Support.html#efi-pci-root-bridge-io-protocol-configuration','edk2_configuration_implementation':base+'MdeModulePkg/Bus/Pci/PciHostBridgeDxe/PciRootBridgeIo.c#L1840'}
sources['references'].update(refs)
sources['root_fallback']='Only after all14 PCI_IO reads return EFI_UNSUPPORTED, only observed7AA4/BDF/revclass/exactBAR revalidated; unique segment0/bus0 root plus exactly one untranslated producer/positive-decode memory descriptor covering FE010000..FE010097. Fixed14 read addresses only.'
(HERE/'sources.json').write_text(json.dumps(sources,indent=2)+'\n',encoding='utf8')
report={
 'status':'PASS_OFFICIAL_ABI_AND_BOUNDED_FALLBACK_DESIGN','inv03_hardware_tested':False,
 'prior_inv02_log':{'path':str(log.relative_to(CASE)),'sha256':sha(log),'bytes':len(data),'crc32':'5B1EE3F2','conclusion':'PCI_IO.Mem.Read reports unsupported; this is not evidence of flash read protection. No MMIO data was acquired by INV02.'},
 'official_reference_files':{name:{'sha256':sha(REF/name),'bytes':(REF/name).stat().st_size,'normalization':'LF text from edk2-stable202502'} for name in ['PciRootBridgeIo.h','Acpi10.h','CpuIo2.h']},
 'abi':{'GUID':'2f707ebb-4a1a-11d4-9a38-0090273fc14d','ParentHandle':'0x00','Mem.Read':'0x18','Configuration':'0x88','SegmentNumber':'0x90 UINT32','Mem.Read_parameters':'This, UINT32 Width, UINT64 Address, UINTN Count, VOID *Buffer; no BAR index'},
 'resource_rules':{'descriptors':'Only QWORD tag8A payload43 total46 and EndTag79 total2; at most64 descriptors, each inside known RAM mapping','ownership':'Configuration buffer is borrowed and never freed','checksum':'Zero EndTag checksum means absent; nonzero must validate complete resource stream','routing':'Segment0, exactly one root covering bus0. Any inaccessible or malformed potentially-relevant root blocks uniqueness.','memory':'Exactly one memory descriptor covers every fixed address FE010000..FE010097','translation':'Zero AddrTranslationOffset; producer/positive decode; no memory-to-IO translation or reserved flags','refusal':'Missing memory aperture is missing evidence for this route, not proof that hardware is unreadable.'},
 'additional_metadata':{'UEFI_map':'Only report type/start/end/attributes of existing memory descriptors covering BAR range; no dereference of BAR','CPU_IO2':'LocateProtocol presence only; no method call or fallback to CPU_IO2'},
 'operation_bounds':{'target':'SAGE1904, 7AA4, 0000:00:1F.5, rev/class0C800011, MemorySpace enabled, BAR FE010000; rechecked before and after root selection','trigger':'All14 original PCI_IO.Mem.Read returned EFI_UNSUPPORTED; other failures or partial support do not trigger','addresses':[f'0x{0xfe010000+x:08X}' for x in [0,4,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x84,0x88,0x8c,0x90,0x94]],'width_bits':32,'count_per_address':1,'writes':0,'SPI_cycles':0,'flash_bytes':0,'CPU_IO2_operations':0},
 'sources':refs,'scope_limit':'Protocol-level read fallback only; no guarantee target firmware exposes usable root resources or can perform these reads. Not a flash dump, density check, or proof of flash read permissions.'}
(HERE/'root_bridge_evidence.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'report_sha256':sha(HERE/'root_bridge_evidence.json'),'source_sha256':sha(HERE/'source/inventory.c'),'diff_sha256':sha(HERE/'inventory02-to-03.patch')},indent=2))
