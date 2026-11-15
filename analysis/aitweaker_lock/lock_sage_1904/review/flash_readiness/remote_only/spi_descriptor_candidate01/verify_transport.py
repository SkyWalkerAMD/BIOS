from pathlib import Path
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
# Exact compiled QR code + unchanged existing P3 framing/decoder, on this log.
dll=ctypes.CDLL(str(OUT/'qr_test.dll'))
dll.kvm_make_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t];dll.kvm_make_frame.restype=ctypes.c_size_t
dll.kvm_encode_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p];dll.kvm_encode_frame.restype=ctypes.c_int
dll.qrcodegen_getSize.argtypes=[ctypes.c_void_p];dll.qrcodegen_getSize.restype=ctypes.c_int
dll.qrcodegen_getModule.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];dll.qrcodegen_getModule.restype=ctypes.c_bool
qrdir=OUT/'synthetic-qr';qrdir.mkdir(exist_ok=True);frames=[]
for page in range((len(positive)+767)//768):
    buf=ctypes.create_string_buffer(1000);n=dll.kvm_make_frame(positive,len(positive),page,buf,1000);expected=buf.raw[:n]
    qr=ctypes.create_string_buffer(2500);scratch=ctypes.create_string_buffer(2500);assert dll.kvm_encode_frame(positive,len(positive),page,qr,scratch)==1
    side=dll.qrcodegen_getSize(qr);im=Image.new('L',((side+8)*4,)*2,255);pix=im.load()
    for y in range(side):
        for x in range(side):
            if dll.qrcodegen_getModule(qr,x,y):
                for dy in range(4):
                    for dx in range(4):pix[(x+4)*4+dx,(y+4)*4+dy]=0
    path=qrdir/f'page-{page+1}.png';im.save(path);frame=read_image(path);assert frame==expected;frames.append(frame)
restored,metadata=assemble(frames,require_inventory=False);assert restored==positive
bad=bytearray(frames[0]);bad[-1]^=1
for broken in [frames[:-1],[bytes(bad)]+frames[1:]]:
    try:assemble(broken,require_inventory=False)
    except ValueError:pass
    else:raise AssertionError('Incomplete/corrupt inventory accepted')
report={'status':'PASS_COMPILED_QR_TRANSPORT_SYNTHETIC_DESCRIPTOR','efi_sha256':sha(OUT/'BOOTX64.EFI'),
 'test_source_sha256':sha(Path(__file__)),'dll_sha256':sha(OUT/'qr_test.dll'),
 'input_log_sha256':hashlib.sha256(positive).hexdigest(),'log_bytes':len(positive),'qr_pages':len(frames),
 'crc32':f'{zlib.crc32(positive):08X}','roundtrip_identical':True,'missing_and_corrupt_page_rejected':True,
 'real_hardware_data':False}
(HERE/'transport_regression.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report))
