"""Verify compiled QR frame/encoder bytes and exact reconstruction, including failures."""
from pathlib import Path
import ctypes as c,sys,json,hashlib,io
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
import decode_captures as decoder
from PIL import Image
import zxingcpp

def main():
    lib=c.CDLL(str(OUT/'capture_test.dll'))
    lib.kvm_make_frame.argtypes=[c.c_void_p,c.c_size_t,c.c_uint,c.c_void_p,c.c_size_t];lib.kvm_make_frame.restype=c.c_size_t
    lib.kvm_encode_frame.argtypes=[c.c_void_p,c.c_size_t,c.c_uint,c.c_void_p,c.c_void_p];lib.kvm_encode_frame.restype=c.c_int
    lib.qrcodegen_getSize.argtypes=[c.c_void_p];lib.qrcodegen_getSize.restype=c.c_int
    lib.qrcodegen_getModule.argtypes=[c.c_void_p,c.c_int,c.c_int];lib.qrcodegen_getModule.restype=c.c_bool
    def frame(data,page):
        source=c.create_string_buffer(data);target=c.create_string_buffer(4096)
        n=lib.kvm_make_frame(source,len(data),page,target,len(target));assert n
        return bytes(target[:n])
    rows=[]
    def passed(name):rows.append({'case':name,'passed':True})
    def reject(name,call):
        try:call()
        except ValueError:passed(name);return
        raise AssertionError('Expected rejection: '+name)
    for n in (1,511,512,513,1024,8448,65536,131072):
        data=bytes((i*13+19)%256 for i in range(n));frames=[frame(data,p) for p in range((n+511)//512)]
        assert decoder.assemble(list(reversed(frames)),require_snapshot=False)[0]==data
        passed('frame_roundtrip_'+str(n))
    data=b'HERO-IPMI-R3-SUMMARY\r\nRUN=1234567890ABCDEF\r\n'+(b'#001 EXAMPLE=0x0000000000000000\r\n'*35)+b'END SUMMARY - full raw TX/RX available with A/V/L\r\n'
    frames=[frame(data,p) for p in range((len(data)+511)//512)]
    assert decoder.assemble(frames+[frames[0]])[0]==data;passed('identical_duplicates_accepted')
    reject('missing_page',lambda:decoder.assemble(frames[:-1]))
    corrupt=frames[0][:-1]+bytes([frames[0][-1]^1]);reject('corrupt_page',lambda:decoder.assemble([corrupt]+frames[1:]))
    other=data.replace(b'1234567890ABCDEF',b'FEDCBA0987654321');reject('mixed_runs',lambda:decoder.assemble([frame(other,0)]+frames[1:]))
    reject('other_project_frame',lambda:decoder.parse_frame(frames[0].replace(b'HERO-IPMI-R3-QR1',b'AITWK-P3-KVM')))
    reject('incomplete_snapshot_footer',lambda:decoder.assemble([frame(data[:-1],p) for p in range((len(data)-1+511)//512)]))
    source=c.create_string_buffer(data);target=c.create_string_buffer(4096)
    assert lib.kvm_make_frame(source,0,0,target,4096)==0
    assert lib.kvm_make_frame(source,len(data),999,target,4096)==0
    assert lib.kvm_make_frame(source,len(data),0,target,1)==0;passed('encoder_input_bounds')
    # Decode QR modules emitted by the compiled C library, not a Python re-encoder.
    for page in range(len(frames)):
        qr=c.create_string_buffer(4096);scratch=c.create_string_buffer(4096)
        assert lib.kvm_encode_frame(source,len(data),page,qr,scratch)
        size=lib.qrcodegen_getSize(qr);assert 21<=size<=137 and size%4==1
        scale=4;im=Image.new('RGB',((size+8)*scale,)*2,'white');pix=im.load()
        for y in range(size):
            for x in range(size):
                if lib.qrcodegen_getModule(qr,x,y):
                    for dy in range(scale):
                        for dx in range(scale):pix[(x+4)*scale+dx,(y+4)*scale+dy]=(0,0,0)
        for quality in (None,70):
            sample=im
            if quality:
                buf=io.BytesIO();im.save(buf,format='JPEG',quality=quality);buf.seek(0);sample=Image.open(buf).convert('RGB')
            codes=zxingcpp.read_barcodes(sample,formats=zxingcpp.BarcodeFormat.QRCode)
            assert len(codes)==1 and bytes(codes[0].bytes)==frames[page]
        passed('compiled_QR_PNG_and_JPEG70_page_'+str(page+1))
    report={'image_sha256':hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
            'dll_sha256':hashlib.sha256((OUT/'capture_test.dll').read_bytes()).hexdigest(),
            'all_passed':True,'count':len(rows),'cases':rows,
            'limits':['CRC32 detects accidental damage; it is not an authenticity check.','Screenshot decoding depends on actual KVM image quality.']}
    (OUT/'capture-verification.json').write_text(json.dumps(report,indent=2)+'\n');print('CAPTURE ALL PASS',len(rows))
if __name__=='__main__':main()
