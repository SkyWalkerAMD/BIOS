"""Check native frame encoding and screenshot reconstruction, including bad inputs."""
from pathlib import Path
import ctypes,hashlib,json,sys,zlib
from decode_captures import OUT,ROOT,parse_frame,assemble,read_image
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from PIL import Image

def main():
    dll=ctypes.CDLL(str(OUT/'capture_test.dll'))
    dll.kvm_make_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t];dll.kvm_make_frame.restype=ctypes.c_size_t
    dll.kvm_encode_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p];dll.kvm_encode_frame.restype=ctypes.c_int
    dll.qrcodegen_getSize.argtypes=[ctypes.c_void_p];dll.qrcodegen_getSize.restype=ctypes.c_int
    dll.qrcodegen_getModule.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];dll.qrcodegen_getModule.restype=ctypes.c_bool
    testdir=OUT/'capture_tests';testdir.mkdir(exist_ok=True);checks=[]
    def frame(data,page,cap=1000):
        buf=ctypes.create_string_buffer(b'\xa5'*(cap+32),cap+32)
        n=dll.kvm_make_frame(data,len(data),page,ctypes.addressof(buf)+16,cap)
        assert buf.raw[:16]==b'\xa5'*16 and buf.raw[16+cap:]==b'\xa5'*16
        return buf.raw[16:16+n]
    for size in (1,767,768,769,1536,1537,65535,65536):
        data=bytes(32+i%95 for i in range(size));frames=[frame(data,i) for i in range((size+767)//768)]
        got,meta=assemble(frames,require_inventory=False);assert got==data
        assert assemble(list(reversed(frames))+frames[:1],require_inventory=False)[0]==data
        checks.append({'name':f'boundary_{size}_bytes','pages':len(frames),'passed':True})
    data=b'abc'*256;valid=frame(data,0)
    for cap in (0,1,len(valid)-1,len(valid),len(valid)+1):
        got=frame(data,0,cap);assert got==(valid if cap>=len(valid) else b'')
    for data,page in ((b'',0),(b'x'*65537,0),(b'x',1),(b'x',0xffffffff)):
        assert frame(data,page)==b''
    assert dll.kvm_make_frame(None,1,0,None,1000)==0
    checks.append({'name':'bounds_and_guard_bytes','passed':True})
    for size,page in ((1,0),(768,0),(769,1),(65536,85)):
        data=bytes(32+i%95 for i in range(size));length=((30*4+17)**2+7)//8+1
        q=ctypes.create_string_buffer(b'\xa5'*(length+32),length+32);temp=ctypes.create_string_buffer(b'\xa5'*(length+32),length+32)
        qp=ctypes.addressof(q)+16;tp=ctypes.addressof(temp)+16
        assert dll.kvm_encode_frame(data,size,page,qp,tp)==1
        for buf in (q,temp):assert buf.raw[:16]==b'\xa5'*16 and buf.raw[-16:]==b'\xa5'*16
        modules=dll.qrcodegen_getSize(qp);im=Image.new('L',((modules+8)*4,)*2,255);pixels=im.load()
        for y in range(modules):
            for x in range(modules):
                if dll.qrcodegen_getModule(qp,x,y):
                    for dy in range(4):
                        for dx in range(4):pixels[(x+4)*4+dx,(y+4)*4+dy]=0
        png=testdir/f'boundary-{size}-page-{page+1}.png';im.save(png)
        assert read_image(png)==frame(data,page)
        checks.append({'name':f'native_qr_decode_{size}_page_{page+1}','passed':True})
    sample=(OUT/'vm/sata_1280x800/RESTORED-LOG.TXT').read_bytes()
    frames=[frame(sample,i) for i in range((len(sample)+767)//768)]
    def reject(name,broken):
        try:assemble(broken)
        except ValueError:checks.append({'name':name,'passed':True})
        else:raise AssertionError(name+' was not rejected')
    reject('missing_page',frames[:1]+frames[2:])
    reject('truncated_frame',[frames[0][:-1]]+frames[1:])
    changed=bytearray(frames[0]);changed[-1]^=1
    reject('bad_page_crc',[bytes(changed)]+frames[1:])
    reject('mixed_sessions',[frame(sample+b'x',0)]+frames[1:])
    reject('bad_whole_log_crc',[re.sub(rb';C=[0-9A-F]{8};',b';C=00000000;',f) for f in frames])
    reject('out_of_bounds_total',[frames[0].replace(f'T={len(sample)};'.encode(),b'T=99999;')]+frames[1:])
    reject('out_of_bounds_offset',[frames[0].replace(b';O=0;',b';O=1;')]+frames[1:])
    reject('incomplete_inventory',[frame(b'not an inventory',0)])
    other=bytearray(sample);other[1]^=1;duplicate=frame(bytes(other),0)
    duplicate=re.sub(rb';C=[0-9A-F]{8};',f';C={zlib.crc32(sample):08X};'.encode(),duplicate)
    reject('conflicting_duplicate',frames+[duplicate])
    # Approximate modest KVM scaling/compression; never claim arbitrary KVM streams.
    for path in sorted((OUT/'vm/sata_1280x800').glob('qr-*.png')):
        original=read_image(path)
        with Image.open(path) as im:
            jpeg=testdir/(path.stem+'-quality75.jpg');im.convert('RGB').save(jpeg,quality=75)
            assert read_image(jpeg)==original
            resized=testdir/(path.stem+'-75percent.png');im.resize((im.width*3//4,im.height*3//4),Image.Resampling.LANCZOS).save(resized)
            assert read_image(resized)==original
        checks.append({'name':path.stem+'_jpeg75_and_scale75','passed':True})
    result={'passed':True,'checks':checks,'count':len(checks),'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),
      'native_test_dll_sha256':hashlib.sha256((OUT/'capture_test.dll').read_bytes()).hexdigest(),
      'scope':'native C framing, QR encoder, strict reconstruction and bounded screenshot transformations; not physical BMC testing'}
    (OUT/'capture_verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print('Native capture/decoder checks PASS:',len(checks))
if __name__=='__main__':
    import re
    main()
