"""Build local source/field/progress manifests; do not contact the target."""
from pathlib import Path
import hashlib,json
OUT=Path(__file__).resolve().parent;BASE=OUT.parent;ROOT=OUT.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
reference={
 'PciIo.h':ROOT/'analysis/hero_ipmi_probe/source/reference/PciIo.h',
 'Pci22.h':ROOT/'analysis/hero_ipmi_init_b1/source/reference/Pci22.h',
 'SmBios.h':ROOT/'analysis/hero_ipmi_probe/source/reference/SmBios.h',
 'DevicePath.h':ROOT/'analysis/hero_inventory_collect_20261108/firmware_probe/reference/DevicePath.h',
 'pci_regs.h':ROOT/'tools/zig-x86_64-windows-0.14.1/lib/libc/include/any-linux-any/linux/pci_regs.h',
}
(OUT/'reference').mkdir(exist_ok=True)
refs=[]
for name,path in reference.items():
 dest=OUT/'reference'/name
 if dest.exists():assert dest.read_bytes()==path.read_bytes()
 else:dest.write_bytes(path.read_bytes())
 refs.append(dict(name=name,original=path.relative_to(ROOT).as_posix(),sha256=sha(path),role='Retained EDK2 primary header' if name!='pci_regs.h' else 'Linux UAPI primary header distributed with installed Zig; hash-pinned local copy'))
old=[]
for row in json.loads((BASE/'rea-evidence-index.json').read_text()):
 if any(x in row['file'] for x in ('rea-legacy','rea-bulk-audit','rea-provider-seeded','rea-inventory-seeded')):
  item=dict(row);item['current_file_sha256']=sha(BASE/row['file']);old.append(item)
direct=[]
for path in sorted((OUT/'ghidra-direct').glob('export*/*.c')):
 direct.append(dict(file=path.relative_to(OUT).as_posix(),sha256=sha(path),target_sha256='e1fd4b36c4bf60386b06d1b8fbe8c323735f1c1c110c2cb6ac0bf6e75df7d4b4',kind='Direct Ghidra 12.1.4 output, not REA MCP Evidence'))
save('evidence-index.json',dict(scope='Offline only; no new target-machine data or writes',reference_headers=refs,existing_rea=old,direct_provider=direct,bmc_source_manifest='source-manifest.json',historical_smbios='hero71-smbios-pcie.json',new_native_request=dict(open_binary='rea-leaves/responses/001-open.json',batch_result='No completed reply; cancellation after bridge stall. Do not cite a nonexistent REA leaf Evidence ID.')))
rows=[
 ('PCIeFunction','VendorId, DeviceId','EFI_PCI_IO_PROTOCOL.Pci.Read offsets 0x00/0x02','pciefunction-hi.lua','Values observable from current valid config snapshot; exact BDF and device-path identity required'),
 ('PCIeFunction','ClassCode, RevisionId','Config offsets 0x09..0x0b (little-endian 24-bit), 0x08','pciefunction-hi.lua','Keep raw numeric classification; do not infer product model or Health'),
 ('PCIeFunction','FunctionId','EFI_PCI_IO_PROTOCOL.GetLocation Function output','pciefunction-hi.lua','0..7 conventional function; ARI/VF support pending'),
 ('PCIeFunction','SubsystemVendorId, SubsystemId','Type-0 config offsets 0x2c/0x2e only','pciefunction-hi.lua','Type-1 offsets are not these fields; omit on unsupported headers'),
 ('PCIeFunction','FunctionType, DeviceClass','Requires verified classification and SR-IOV/ARI policy','pciefunction-hi.lua','Not required for minimal Id/Name record; omit until mapped, never default every function to Physical'),
 ('PCIeDevice','Id, Name','Agent namespace + current observed BDF grouping','pciedevice-hi.lua','Explicit generic label, not an asserted marketing model or physical-card serial; BDF may change on reboot'),
 ('PCIeDevice','DeviceType','Complete grouping of observed functions','pciedevice-hi.lua','Header multifunction bit alone insufficient; omit if group incomplete'),
 ('PCIeDevice','PCIeInterface.*','Bounded PCIe capability link registers','pciedevice-hi.lua','Do not decode link registers for RC-integrated endpoint/event collector; keep raw values until enum validated'),
 ('PCIeDevice','Model, Manufacturer, SerialNumber, PartNumber','Requires verified PCI VPD/other identity source, not numeric VendorId alone','pciedevice-hi.lua','Unavailable from ordinary PCI config header; omit'),
 ('PCIeSlots','Slots[].Location, SlotType, Lanes','SMBIOS Type9 + current topology and a unique binding','pcieslots-hi.lua','Historical HERO table has 6 slots but only 2 known BDFs; upstream-port mapping unresolved'),
 ('System','PCIeDevices, PCIeFunctions','Fresh System links plus verified new resource links','system.lua','PATCH replaces sets; merge all existing links with fresh ETag and verify, or leave pending'),
 ('Storage','Id, Name, StorageControllers[]','Current controller PCI/device-path identity plus optional verified Identify','storage-collection-hi.lua','Do not invent RAID level, ports, firmware, manufacturer, model, or health'),
 ('Drive','Model, SerialNumber, Revision','Bounded ATA/NVMe Identify or documented cached DiskInfo','drives-instance-hi.lua','No .71 capture yet; pass-through implementation and command allowlist not implemented'),
 ('Drive','CapacityBytes, BlockSizeBytes','Physical drive identity/geometry; BlockIo only proves address-space geometry','drives-instance-hi.lua','NVMe namespaces and RAID volumes can differ from physical drive; current parser never promotes BlockIo capacity to Drive'),
 ('Drive','Protocol, MediaType, PhysicalLocation','Unique device-path/controller/Identify evidence','drives-instance-hi.lua','USB virtual media and partitions excluded; unknown location omitted'),
 ('Drive','Status.Health, FailurePredicted, life/wear, encryption','Appropriate verified telemetry','drives-instance-hi.lua','Not proven by Identify/basic enumeration; omit, no fabricated OK'),
 ('SimpleStorage','Id, Name, UefiDevicePath, Devices[]','Observed controller and child device identities','simplestorage-collection-hi.lua','Handler requires nested Status table if Devices used; {} does not assert Health. Id score-type compatibility pending'),
]
save('field-matrix.json',[dict(resource=a,fields=b,source=c,bmc_handler=d,boundary=e,hardware_validated=False) for a,b,c,d,e in rows])
(OUT/'field-matrix.txt').write_text('\n\n'.join(f'{a} | {b}\n  Source: {c}\n  BMC: {d}\n  Boundary: {e}' for a,b,c,d,e in rows)+'\n',encoding='utf-8')
gaps=[
 ('pci_live_capture','Current PCIe config/GetLocation/device-path capture unavailable'),
 ('slot_binding','Historical Type9 upstream-port relationship needs proof'),
 ('disk_identity','No current .71 ATA/NVMe Identify or namespace/RAID map'),
 ('uefi_storage_abi','BlockIo/DiskInfo/PassThru official matching headers and adapters not yet reviewed'),
 ('host_routes','No .71 PCIe/Storage/Drive POST tests or Location acceptance observed'),
 ('collection_cache','Direct object, collection cache, and System/Chassis link visibility need separate proof'),
 ('persistence','New resource IDs and metadata not tested across host/BMC restart'),
 ('firmware_integration','No new firmware or EFI adapter built by this subtask'),
]
save('gap-checklist.json',dict(status='analysis_sealed_no_hardware_scheduled',gaps=[dict(id=a,description=b,state='pending') for a,b in gaps],prohibited_shortcuts=['DELETE or clear existing inventory','partial bulk InventoryData with invented group CRC','invent physical slot/model/serial/Health','auto replay uncertain writes','treat BlockIo namespace/RAID capacity as physical Drive'],offline_tests=json.loads((OUT/'decoder-tests.json').read_text())))
save('rea-session-status.json',dict(owned_controller_pid=41120,owned_rea_pid=29476,cancellation_file='rea-leaves/stop-session',provider_log='batch_decompile status=error after 199533 ms; temporary REA provider directory removed',process_check='PowerShell Get-Process at 2026-11-08 12:29:54+09:00 reported both PIDs absent',unified_exec_session=47708,unified_exec_final='Explicit interrupt returned completed exit_code=1; no running exec session remains',normal_close_binary_result=False,direct_ghidra='All three successful direct provider exports completed exit 0; no new provider is scheduled'))
files=[]
for p in sorted(OUT.rglob('*')):
 if not p.is_file() or p.name=='delivery-manifest.json' or '__pycache__' in p.parts:continue
 if 'ghidra-direct' in p.parts and not any(part.startswith('export') for part in p.parts) and p.suffix not in ('.json','.log','.txt'):continue
 if 'runtime-temp' in p.parts:continue
 files.append(dict(file=p.relative_to(OUT).as_posix(),bytes=p.stat().st_size,sha256=sha(p)))
save('delivery-manifest.json',dict(scope='Sealed offline PCIe/Storage analysis; no I3d/source firmware modifications',files=files))
print(json.dumps(dict(references=len(refs),existing_rea=len(old),direct_functions=len(direct),field_rows=len(rows),gaps=len(gaps),files=len(files))))
