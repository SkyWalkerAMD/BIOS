"""Create an isolated read-only ACE06 project from frozen inventory05 sources."""
from pathlib import Path
import hashlib
import json
import lzma
import struct
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
PREV = HERE.parent/'layout_recovery/probe'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for sub in ['source','reference_documents','native','build']:(HERE/sub).mkdir(exist_ok=True)
cap_path=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
cap=cap_path.read_bytes();assert hashlib.sha256(cap).hexdigest()=='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
sec=0x3181090;size=int.from_bytes(cap[sec:sec+3],'little');raw=lzma.decompress(cap[sec+24:sec+size],format=lzma.FORMAT_ALONE)
p=(16+struct.unpack_from('<H',raw,16+48)[0]+7)&~7
found=[]
while p+24<len(raw):
 if raw[p:p+24]==b'\xff'*24:break
 size=int.from_bytes(raw[p+20:p+23],'little');assert size>=24
 if raw[p:p+16]==uuid.UUID('a19b1fe7-c1bc-49f8-875f-54a5d542443f').bytes_le:
  ffs=raw[p:p+size];s=24
  while s+4<=len(ffs):
   n=int.from_bytes(ffs[s:s+3],'little');assert n>=4
   if ffs[s+3]==0x10:found.append((p,ffs,ffs[s+4:s+n]))
   s=(s+n+3)&~3
 p=(p+size+7)&~7
assert len(found)==1
offset,ffs,efi=found[0]
assert hashlib.sha256(efi).hexdigest()=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
(HERE/'native/OriginalCpuIo2.efi').write_bytes(efi);(HERE/'native/OriginalCpuIo2.ffs').write_bytes(ffs)
pe=pefile.PE(data=efi);assert pe.OPTIONAL_HEADER.ImageBase==0
assert struct.unpack('<QQQQ',pe.get_data(0x730,32))==(0x3d4,0x484,0x534,0x624)
header='/* Exact ACE1904 original CPU_IO2 read path; no SAGE hardware binding. */\n'
assert pe.get_data(0x750,32).hex()=='0102040800000000010204080000000001020408010204080000000000000000'
for name,start,end in [('cpu_parameters',0x30c,0x3d4),('cpu_read_code',0x3d4,0x481),('cpu_strides',0x750,0x770)]:
 data=pe.get_data(start,end-start);assert len(data)==end-start
 header+='static const uint8_t '+name+'['+str(len(data))+']={'+','.join('0x%02x'%b for b in data)+'};\n'
(HERE/'source/cpu_reference.h').write_text(header,encoding='ascii')
for name in ['inventory.c']:
 dest=HERE/'source'/name
 if not dest.exists():dest.write_bytes((PREV/'source'/name).read_bytes())
builder=(PREV/'build_probe.py').read_text(encoding='utf8')
builder=builder.replace("P3 = ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'", "P3 = HERE.parent/'layout_recovery/probe/source/p3'")
start=builder.index("        replacements = {")
end=builder.index("        for old, new in replacements.items():",start)
builder=builder[:start]+'''        replacements = {
            b'ACE1904 SPI INVENTORY05 - KVM LOG': b'ACE1904 SPI PROBE06 - KVM LOG',
            b'ACE SPI inventory05 - register snapshot only': b'ACE SPI probe06 - CPU_IO2 read-only snapshot',
            b'ACE SPI inventory ended. No flash data read or written.': b'ACE SPI probe06 ended. No flash data read or written.',
        }
'''+builder[end:]
builder=builder.replace('ACE1904-SPI-INVENTORY05','ACE1904-SPI-PROBE06').replace('ACEINV05','ACEPRB06').replace('ACE1904_SPIINV05','ACE1904_SPIPRB06')
builder=builder.replace('Existing EFI_PCI_IO only. Read preconfigured PCI identity/status and 14 SPI register offsets after exact ACE1904/CPU/controller gates. No raw MMIO, fallback/unhide, register write or flash read cycle.',
 'Exact observed ACE1904/CPUID/PCI identity. Read14 fixed register addresses through verified original EFI_CPU_IO2.Mem.Read only after fresh MMIO-map/provider/PCI gates. No PCI or SPI writes, SPI cycle, RootBridge fallback or raw application MMIO dereference.')
(HERE/'build_probe.py').write_text(builder,encoding='utf8')
vm=(PREV/'verify_ovmf.py').read_text(encoding='utf8').replace('ACE1904-SPI-INVENTORY05','ACE1904-SPI-PROBE06').replace('ACE SPI inventory ended.','ACE SPI probe06 ended.')
(HERE/'verify_ovmf.py').write_text(vm,encoding='utf8')
refs=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/spi_inventory_candidate04/source/reference_documents'
copied={}
for name in ['CpuIo2.h','UefiSpec.h','UefiMultiPhase.h','spi0.xml','spibar0.xml','spi-intel-pci.c','spi-intel.c']:
 src=refs/name;dst=HERE/'reference_documents'/name;dst.write_bytes(src.read_bytes());copied[name]={'source':str(src.relative_to(ROOT)),'sha256':sha(src)}
hw=HERE.parent/'bmc_inventory01/inventory-results/hardware-log.txt'
log=hw.read_bytes()
for token in [b'CPUID.1.REG0=0x000806F8',b'PCI.VID_DID=0x7AA48086',b'PCI.REVISION_CLASS=0x0C800011',b'PCI.COMMAND_STATUS=0x00000402',b'PCI.BAR0=0xFE010000',b'PCI.BIOS_CNTL=0x100008AA',b'PCI_KIND=KNOWN_700_SERIES_SPI_ID PCI_LOCATION=0000:00:1F.5']:
 assert token in log
report={'status':'PREPARED_FROM_FROZEN_ACE05_AND_ORIGINAL_ACE_CAP','hardware_log':{'path':str(hw.relative_to(ROOT)),'sha256':sha(hw)},
 'original_cpu_module':{'capsule_sha256':sha(cap_path),'decoded_container_sha256':hashlib.sha256(raw).hexdigest(),'ffs_offset':hex(offset),
 'ffs_sha256':hashlib.sha256(ffs).hexdigest(),'efi_sha256':hashlib.sha256(efi).hexdigest(),'identical_to_previous_SAGE_original_module':True,
 'qualification':'Whole EFI bytes match; this permits implementation comparison, never reuse of SAGE hardware identity/permission observations.'},
 'frozen05_inputs':{n:sha(PREV/n) for n in ['source/inventory.c','build_probe.py','verify_inventory.py','verify_ovmf.py','media_manifest.json']},
 'archived_primary_references':copied,'hardware_access':False,'production_changes':False}
(HERE/'preparation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps(report['original_cpu_module']))
