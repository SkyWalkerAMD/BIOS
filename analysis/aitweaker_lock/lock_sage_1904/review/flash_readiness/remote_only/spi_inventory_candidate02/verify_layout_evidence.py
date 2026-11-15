"""Check pinned primary-source layout chain and INV01 hardware-log binding."""
from pathlib import Path
import hashlib,json,re,zlib
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3]
REF=HERE/'source/reference_documents'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
PCI=REF/'spi-intel-pci.c';SPI=REF/'spi-intel.c'
p=PCI.read_text(encoding='utf8');s=SPI.read_text(encoding='utf8')
pin='6628e7d4c6b25c8d18f1345e3a20d21829aae7e4'
assert re.search(r'0x7a24\).*?&cnl_info',p) and re.search(r'0x7aa4\).*?&cnl_info',p)
assert re.search(r'cnl_info\s*=\s*\{\s*\.type\s*=\s*INTEL_SPI_CNL',p)
assert 'pcim_iomap_region(pdev, 0, KBUILD_MODNAME)' in p
assert re.search(r'#define\s+BCR\s+0xdc',p)
assert re.search(r'#define\s+BFPREG\s+0x00',s)
assert re.search(r'#define\s+HSFSTS_CTL\s+0x04',s)
assert re.search(r'#define\s+FRACC\s+0x50',s)
assert re.search(r'#define\s+FREG\(n\)\s+\(0x54 \+ \(\(n\) \* 4\)\)',s)
assert re.search(r'#define\s+CNL_PR\s+0x84',s)
assert re.search(r'#define\s+CNL_FREG_NUM\s+6',s)
assert re.search(r'#define\s+CNL_PR_NUM\s+5',s)
assert re.search(r'case INTEL_SPI_CNL:.*?ispi->pregs = ispi->base \+ CNL_PR;.*?ispi->nregions = CNL_FREG_NUM;.*?ispi->pr_num = CNL_PR_NUM;',s,re.S)
assert 'readl(ispi->base + BFPREG)' in s and 'readl(ispi->base + HSFSTS_CTL)' in s and 'readl(ispi->base + FRACC)' in s
assert 'readl(ispi->base + FREG(i))' in s and 'readl(ispi->pregs + PR(i))' in s
hardware=CASE/'remote_172_20_2_162/hardware-spiinv01-1793673288862/hardware-log.txt';raw=hardware.read_bytes()
assert len(raw)==877 and zlib.crc32(raw)==0x344bf0d5
for line in [b'IDENTITY_GATE=Pro WS W790E-SAGE SE; BIOS=1904',b'PCI_LOCATION=0000:00:1F.5',b'PCI_VID_DID=0x7AA48086',b'PCI_REV_CLASS=0x0C800011',b'PCI_VID_DID=0x7A8A8086',b'SPI_ID_GATE=REJECTED_OR_AMBIGUOUS']:assert line in raw
assert b'HSFSTS_HSFC OFFSET' not in raw
offsets=[0,4,0x50]+list(range(0x54,0x6c,4))+list(range(0x84,0x98,4))
assert len(offsets)==14
sources=json.loads((HERE/'sources.json').read_text(encoding='utf8'))
sources.update(status='PINNED_PRIMARY_LAYOUT_AND_PRIOR_HARDWARE_ID',accepted_vid_did=['8086:7A24','8086:7AA4 with revision/class 0x0C800011'],linux_commit=pin)
sources['references'].update(linux_pci=f'https://github.com/torvalds/linux/blob/{pin}/drivers/spi/spi-intel-pci.c#L38',linux_7aa4=f'https://github.com/torvalds/linux/blob/{pin}/drivers/spi/spi-intel-pci.c#L86',linux_layout=f'https://github.com/torvalds/linux/blob/{pin}/drivers/spi/spi-intel.c#L21',linux_cnl=f'https://github.com/torvalds/linux/blob/{pin}/drivers/spi/spi-intel.c#L1110')
sources['layout_scope']='Same exact CNL dispatch for 7A24 and 7AA4 covers existing 14 read offsets; Linux initialization/write paths are reference documents only and are not linked or called.'
(HERE/'sources.json').write_text(json.dumps(sources,indent=2)+'\n',encoding='utf8')
report={
 'status':'PASS_PRIMARY_SOURCE_LAYOUT_CHAIN','candidate02_hardware_tested':False,
 'hardware_inv01':{'path':str(hardware.relative_to(CASE)),'sha256':sha(hardware),'bytes':len(raw),'crc32':'344BF0D5','observations':['SAGE SE BIOS1904 identity matched','LPC 8086:7A8A','SPI 8086:7AA4 at 0000:00:1F.5, revision11/class0C8000','INV01 rejected unknown SPI ID before MMIO'],'does_not_establish':['BAR value or read availability','register contents','flash permissions or density']},
 'linux_commit':pin,'source_files':{p.name:{'sha256':sha(p),'bytes':p.stat().st_size,'normalization':'LF text, exact pinned source content'} for p in [PCI,SPI]},
 'chain':[
  {'file':'spi-intel-pci.c','lines':[38,40,61,86,87],'finding':'7A24 and 7AA4 share exact cnl_info -> INTEL_SPI_CNL, using BAR0.'},
  {'file':'spi-intel-pci.c','lines':[14,15],'finding':'BIOS Control/BCR at PCI config DC; bit0 write protect disable. No call to writeable callback in this application.'},
  {'file':'spi-intel.c','lines':[22,24,53,55,56,58],'finding':'BFPREG00, HSFSTS04, FRACC50, FREG54+4n; 15-bit base and limit masks.'},
  {'file':'spi-intel.c','lines':[109,110,111,1110,1112,1113,1114],'finding':'CNL selects protected range base84, six FREGs, five PRs.'},
  {'file':'spi-intel.c','lines':[204,206,218,220,222,223,225],'finding':'Driver reads this register set with readl; no per-ID layout change between the two supported IDs.'}],
 'allowed_mmio_offsets':[f'0x{x:02X}' for x in offsets],
 'candidate_change':'Add 7AA4 ONLY with already observed full revision/class DWORD 0x0C800011; retain SAGE1904 identity, exact BDF, existing BAR/decode checks and all 14 prior offsets. Re-read ID must equal originally selected ID.',
 'limitations':['Linux provides explicit controller layout support, not a guarantee of whole-chip access on ASUS firmware.','FRAP/BC descriptive field names retain CHIPSEC PCH family definitions; raw values are preserved. No extended FREG9 or capacity inference.','This application does not execute the Linux driver, enable PCI decode, change BCR/SMI/protection, or start a flash cycle.'],
 'references':sources['references']
}
(HERE/'layout_evidence.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'hardware_log_sha256':sha(hardware),'layout_evidence_sha256':sha(HERE/'layout_evidence.json'),'mmio_offsets':len(offsets)},indent=2))
