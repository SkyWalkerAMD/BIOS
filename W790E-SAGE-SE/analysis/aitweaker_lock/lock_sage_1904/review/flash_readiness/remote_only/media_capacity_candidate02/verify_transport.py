"""Own compiled QR encoder and original P3 decoder, no target/network I/O."""
from pathlib import Path
import ctypes,hashlib,json,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[6];OUT=HERE/'build'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps'),str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm')]
from PIL import Image
import pefile
from decode_captures import assemble,read_image
from decode_capacity_log import parse
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
pe=pefile.PE(str(OUT/'qr_test.dll'));assert pe.OPTIONAL_HEADER.AddressOfEntryPoint==0 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size
dll=ctypes.CDLL(str(OUT/'qr_test.dll'))
dll.kvm_make_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t];dll.kvm_make_frame.restype=ctypes.c_size_t
dll.kvm_encode_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p];dll.kvm_encode_frame.restype=ctypes.c_int
dll.qrcodegen_getSize.argtypes=[ctypes.c_void_p];dll.qrcodegen_getSize.restype=ctypes.c_int
dll.qrcodegen_getModule.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];dll.qrcodegen_getModule.restype=ctypes.c_bool
rows=[]
for name in ['positive_cached_mismatch','no_scsi','log_overflow','log_overflow_small']:
    original=(HERE/'review/native_logs'/(name+'.txt')).read_bytes();parsed=parse(original)
    qrdir=OUT/'synthetic-qr'/name;qrdir.mkdir(parents=True,exist_ok=True);frames=[]
    for page in range((len(original)+767)//768):
        buf=ctypes.create_string_buffer(1000);n=dll.kvm_make_frame(original,len(original),page,buf,1000);assert n;expected=buf.raw[:n]
        qr=ctypes.create_string_buffer(2500);scratch=ctypes.create_string_buffer(2500);assert dll.kvm_encode_frame(original,len(original),page,qr,scratch)==1
        side=dll.qrcodegen_getSize(qr);im=Image.new('L',((side+8)*4,)*2,255);pix=im.load()
        for y in range(side):
            for x in range(side):
                if dll.qrcodegen_getModule(qr,x,y):
                    for dy in range(4):
                        for dx in range(4):pix[(x+4)*4+dx,(y+4)*4+dy]=0
        path=qrdir/f'page-{page+1}.png';im.save(path);frame=read_image(path);assert frame==expected;frames.append(frame)
    restored,metadata=assemble(frames,require_inventory=False);assert restored==original and parse(restored)==parsed
    bad=bytearray(frames[0]);bad[-1]^=1
    for broken in [frames[:-1],[bytes(bad)]+frames[1:]]:
        try:assemble(broken,require_inventory=False)
        except ValueError:pass
        else:raise AssertionError('Missing/corrupt page accepted')
    rows.append({'input':name,'log_sha256':hashlib.sha256(original).hexdigest(),'bytes':len(original),'pages':len(frames),'crc32':f'{zlib.crc32(original):08X}','inventory_complete':parsed['complete'],'rc10_success':parsed['rc10_success'],'overflow_explicit':parsed['overflow']})
    print(json.dumps(rows[-1]),flush=True)
report={'status':'PASS','efi_sha256':sha(OUT/'BOOTX64.EFI'),'dll_sha256':sha(OUT/'qr_test.dll'),'test_sha256':sha(Path(__file__)),'cases':rows,'total_pages':sum(r['pages'] for r in rows),'roundtrip_identical':True,'missing_and_corrupt_page_rejected':True,'hardware_tested':False}
(OUT/'transport_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8')
