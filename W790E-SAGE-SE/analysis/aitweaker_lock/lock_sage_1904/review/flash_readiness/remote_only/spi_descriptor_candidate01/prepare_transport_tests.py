from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;OLD=HERE.parent/'spi_inventory_candidate04'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=(OLD/'verify_candidate.py').read_text(encoding='utf-8')
body=old[old.index('# Exact compiled QR code'):old.index("report={'status':'PASS_LOCAL_SIMULATION_ONLY'")]
prefix='''from pathlib import Path
import ctypes,hashlib,json,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps'),str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
from PIL import Image
import pefile
from decode_captures import assemble,read_image,parse_frame
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
positive=(HERE/'frontend_logs/complete_original_CPU_IO2_path.txt').read_bytes()
assert b'DESCRIPTOR_TWO_PASSES_MATCH=YES' in positive
pe=pefile.PE(str(OUT/'qr_test.dll'))
assert pe.OPTIONAL_HEADER.AddressOfEntryPoint==0 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size
'''
suffix='''report={'status':'PASS_COMPILED_QR_TRANSPORT_SYNTHETIC_DESCRIPTOR','efi_sha256':sha(OUT/'BOOTX64.EFI'),
 'test_source_sha256':sha(Path(__file__)),'dll_sha256':sha(OUT/'qr_test.dll'),
 'input_log_sha256':hashlib.sha256(positive).hexdigest(),'log_bytes':len(positive),'qr_pages':len(frames),
 'crc32':f'{zlib.crc32(positive):08X}','roundtrip_identical':True,'missing_and_corrupt_page_rejected':True,
 'real_hardware_data':False}
(HERE/'transport_regression.json').write_text(json.dumps(report,indent=2)+'\\n',encoding='utf-8')
print(json.dumps(report))
'''
(HERE/'verify_transport.py').write_text(prefix+body+suffix,encoding='utf-8')
vm=(OLD/'verify_ovmf.py').read_text(encoding='utf-8')
before="assert b'actual_component_capacity=null' in log and b'COLLECTION_STATUS=PARTIAL_OR_REFUSED' in log"
after="assert b'DESCRIPTOR_DATA_NOT_EXPORTED' in log and b'ACTUAL_MMIO_WRITE_CALLS=0x00000000' in log and b'ACTUAL_MMIO_READ_CALLS=0x00000000' in log"
assert vm.count(before)==1;vm=vm.replace(before,after)
vm=vm.replace('SAGE1904-SPI-INVENTORY04.iso','SAGE1904-SPI-DESCRIPTOR01.iso')
vm=vm.replace('IDENTITY_GATE=REJECTED_BOARD_OR_BIOS','REFUSED_IDENTITY').replace('PCI_ENUM_STATUS','PCI_ENUM')
vm=vm.replace('IDENTITY_GATE=Pro WS W790E-SAGE SE; BIOS=1904','IDENTITY=Pro WS W790E-SAGE SE; BIOS=1904')
vm=vm.replace('SPI_ID_GATE=REJECTED_OR_AMBIGUOUS','REFUSED_PCI_BINDING').replace('HSFSTS_HSFC OFFSET','DESCRIPTOR_HEX_BEGIN')
vm=vm.replace('SPI inventory ended.','Descriptor log ended.')
(HERE/'verify_ovmf.py').write_text(vm,encoding='utf-8')
(HERE/'transport_test_binding.json').write_text(json.dumps({
 'old_qr_fixture_sha256':sha(OLD/'verify_candidate.py'),'old_OVMF_fixture_sha256':sha(OLD/'verify_ovmf.py'),
 'new_qr_fixture_sha256':sha(HERE/'verify_transport.py'),'new_OVMF_fixture_sha256':sha(HERE/'verify_ovmf.py'),
 'assertion_changes':'Only FD01 label/status expectations and source log paths changed; QR CRC/missing/corrupt/byte-match and all nine OVMF checks retained.'
},indent=2)+'\n',encoding='utf-8')
print('Prepared isolated QR and OVMF rejection/transport checks.')
