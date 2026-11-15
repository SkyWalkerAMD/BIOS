"""Compile a separate file-only USB test; no disk/SPI backup code is included."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
OLD=HERE.parent/'spi_descriptor_candidate02'
baseline=HERE.parent/'media_writeback_review/blank_test/baseline.json'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
contract=json.loads(baseline.read_text(encoding='utf-8'))
marker=contract['marker_ascii'].encode('ascii')
assert hashlib.sha256(marker).hexdigest()==contract['marker_sha256']
result=b'SAGE1904 UEFI VIRTUAL HD WRITEBACK TEST 01\r\nNONCE=E0713CEF-9409-4DCA-9F09-D02B05A2BC4C\r\nNo firmware data or passwords.\r\n'
(HERE/'expected-result.bin').write_bytes(result)
def array(name,b):return 'static const uint8_t '+name+'[]={'+','.join(str(x) for x in b+b'\0')+'};\n'
(HERE/'source/contract.h').write_text(array('marker_bytes',marker)+array('result_bytes',result),encoding='ascii')
sources={'scope':'Disposable marker-matched USB virtual-HD file write only; no controller or firmware access.',
         'image_baseline':{'path':str(baseline),'sha256':sha(baseline)},
         'expected_file_bytes':len(result),'expected_file_sha256':hashlib.sha256(result).hexdigest(),
         'builder_reference':{'path':str(OLD/'build_candidate.py'),'sha256':sha(OLD/'build_candidate.py')}}
(HERE/'sources.json').write_text(json.dumps(sources,indent=2)+'\n',encoding='utf-8')
builder=(OLD/'build_candidate.py').read_text(encoding='utf-8')
builder=builder.replace('Build isolated INV04 with bounded RootBridge/CPU read fallbacks; no target access.','Build bounded USB disposable-file writeback diagnostic; no target access.')
builder=builder.replace("[SRC/'inventory.c',SRC/'fd_core.c',", "[SRC/'writeback.c',")
builder=builder.replace('SPI DESCRIPTOR 02','MEDIA WRITEBACK 01').replace('SPI descriptor read - diagnostic','Virtual USB file writeback test').replace('4K DESCRIPTOR ONLY - NOT A BACKUP','DISPOSABLE FILE TEST ONLY')
builder=builder.replace('Descriptor log ended. No flash programming or erasing.','File test ended. No flash programming or erasing.')
builder=builder.replace('SPIFD02','USBWB01').replace('SAGE1904-SPI-DESCRIPTOR02.iso','SAGE1904-MEDIA-WRITEBACK01.iso')
builder=builder.replace('Descriptor 0..0xFFF READ twice. Transient DWORD MMIO writes only to FADDR and HSFSTS_CTL; no flash program/erase, unlock, PCI writes, SetVariable, file or network calls.','Create one bounded WRBACK.TXT on a unique 16MiB USB filesystem with exact marker and label. No flash, PCI or RuntimeServices calls.')
start=builder.index(" 'limitations':");end=builder.index("save(OUT/'build.json'",start)
builder=builder[:start]+" 'limitations':['No physical or remote writeback pass.','UEFI readback alone does not establish actual workstation image writeback.','Only a uniquely marked disposable USB image is eligible.']}\n"+builder[end:]
(HERE/'build_candidate.py').write_text(builder,encoding='utf-8')
print('Prepared file-only test source contract and builder.')
