"""Deterministic native parser mutation tests in isolated Windows processes.
Inputs are read-only, tested next to both leading and trailing NOACCESS pages.
The output structure ends at a NOACCESS page. No firmware is executed here.
"""
import argparse
import ctypes
import hashlib
import json
import random
import struct
import subprocess
import sys
import time
from verify import OUT,TAGS,get_module,stock_package,ImageInfo,HiiInfo,pefile

PAGE=4096
K=ctypes.WinDLL('kernel32',use_last_error=True)
K.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.c_uint32]
K.VirtualAlloc.restype=ctypes.c_void_p
K.VirtualProtect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)]
K.VirtualProtect.restype=ctypes.c_int
K.VirtualFree.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint32]
K.VirtualFree.restype=ctypes.c_int


class Guarded:
    def __init__(self,capacity):
        self.capacity=(capacity+PAGE-1)&~(PAGE-1)
        self.base=K.VirtualAlloc(None,self.capacity+2*PAGE,0x3000,0x01)
        if not self.base:raise ctypes.WinError(ctypes.get_last_error())
        self.start=self.base+PAGE

    def protect(self,mode):
        old=ctypes.c_uint32()
        if not K.VirtualProtect(self.start,self.capacity,mode,ctypes.byref(old)):
            raise ctypes.WinError(ctypes.get_last_error())

    def load(self,data,tail=True):
        self.protect(0x04)
        pointer=self.start+self.capacity-len(data) if tail else self.start
        if data:ctypes.memmove(pointer,data,len(data))
        self.protect(0x02)
        return pointer

    def output(self,size):
        self.protect(0x04)
        pointer=self.start+self.capacity-size
        ctypes.memset(pointer-16,0xa5,16+size)
        return pointer

    def close(self):
        if not K.VirtualFree(self.base,0,0x8000):raise ctypes.WinError(ctypes.get_last_error())


def corpus(seed,kind,pe=None,count=2000):
    rng=random.Random(0xA17EA2)
    yield 'original',seed
    yield 'empty',b''
    yield 'one-byte',seed[:1]
    yield 'header-truncated',seed[:19 if kind=='hii' else 63]
    if kind=='hii':
        points=[16,20,21,22,23]
        pos=24;end=20+(struct.unpack_from('<I',seed,20)[0]&0xffffff)
        while pos+2<=end:
            n=seed[pos+1]&127
            if n<2:break
            points.extend([pos,pos+1]);pos+=n
    else:
        e=pe.DOS_HEADER.e_lfanew;opt=e+24
        points=[0,2,0x3c,e,e+4,e+6,e+20,opt,opt+16,opt+56]
        points += [s.get_file_offset()+d for s in pe.sections for d in (0,8,12,16)]
    for i in range(count):
        family=i%8;data=bytearray(seed)
        if family==0:
            cut=rng.randrange(len(data)+1);data=data[:cut]
            if kind=='hii' and len(data)>=20:struct.pack_into('<I',data,16,len(data))
        elif family in (1,2,3):
            pos=rng.choice(points);width=rng.choice((1,2,4))
            width=min(width,len(data)-pos)
            val=rng.choice((0,1,2,3,19,20,23,24,127,128,255,len(data),0xffffffff))
            data[pos:pos+width]=(val&((1<<(8*width))-1)).to_bytes(width,'little')
        elif family==4:
            for _ in range(rng.randrange(1,9)):
                pos=rng.randrange(len(data));data[pos]^=1<<rng.randrange(8)
        elif family==5:
            pos=rng.randrange(len(data));n=rng.randrange(1,min(64,len(data)-pos)+1)
            del data[pos:pos+n]
            if kind=='hii' and len(data)>=20:struct.pack_into('<I',data,16,len(data))
        elif family==6:
            data=bytearray(rng.randbytes(rng.randrange(0,2048)))
            if kind=='hii' and len(data)>=20:struct.pack_into('<I',data,16,len(data))
        else:
            pos=rng.choice(points);data[pos:pos]=rng.randbytes(rng.randrange(1,17))
            if kind=='hii':struct.pack_into('<I',data,16,len(data))
        yield f'{i}:{family}',bytes(data)


def worker(tag,kind):
    start=time.perf_counter();pe=None
    if kind=='hii':seed=stock_package(tag);output_type=HiiInfo
    else:
        _,_,raw=get_module(tag,kind);pe=pefile.PE(data=raw)
        seed=pe.get_memory_mapped_image().ljust(pe.OPTIONAL_HEADER.SizeOfImage,b'\0')
        output_type=ImageInfo
    dll=ctypes.CDLL(str(OUT/'core_test.dll'))
    fn=dll.probe_hii if kind=='hii' else dll.probe_image
    fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p];fn.restype=ctypes.c_int
    input_mem=Guarded(len(seed)+64);output_mem=Guarded(PAGE)
    accepted=rejected=calls=0;digest=hashlib.sha256()
    try:
        for label,data in corpus(seed,kind,pe):
            digest.update(struct.pack('<I',len(data)));digest.update(data)
            for tail in (False,True):
                ptr=input_mem.load(data,tail);outptr=output_mem.output(ctypes.sizeof(output_type))
                try:ok=fn(ptr,len(data),outptr)
                except Exception:
                    (OUT/'guarded_failure.json').write_text(json.dumps({'tag':tag,'kind':kind,
                        'case':label,'tail':tail,'sha256':hashlib.sha256(data).hexdigest()}),encoding='utf8')
                    raise
                calls+=1;assert ok in (0,1)
                assert ctypes.string_at(outptr-16,16)==b'\xa5'*16
                if ok:
                    accepted+=1;info=output_type.from_address(outptr)
                    if kind=='hii':
                        assert info.packages>=1 and info.forms<=len(data)//6
                        assert info.passwords<=len(data)//17
                        assert info.f2713+info.f2714<=info.forms
                    else:
                        assert 0<info.size<=info.image_size<=len(data)
                        assert info.rva<=info.image_size-info.size and info.entry<info.image_size
                else:rejected+=1
        # Explicit NULL input cases with large lengths must be rejected without dereference.
        for n in (0,1,20,64,0x40000001,0xffffffffffffffff):
            ptr=output_mem.output(ctypes.sizeof(output_type));assert fn(None,n,ptr)==0;calls+=1;rejected+=1
    finally:input_mem.close();output_mem.close()
    result={'tag':tag,'parser':kind,'native_calls':calls,'accepted':accepted,'rejected':rejected,
        'corpus_sha256':digest.hexdigest(),'passed':True,'input_read_only':True,
        'leading_and_trailing_guard_pages':True,'output_tail_guard_and_prefix_canary':True,
        'seconds':round(time.perf_counter()-start,3)}
    path=OUT/('guarded-'+tag+'-'+kind+'.json')
    path.write_text(json.dumps(result,indent=2),encoding='utf8')
    print(tag,kind,calls,'guarded native calls PASS',flush=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--worker',nargs=2);args=p.parse_args()
    if args.worker:return worker(*args.worker)
    results=[]
    for tag in TAGS:
        for kind in ('AMITSE','Setup','hii'):
            subprocess.run([sys.executable,str(Path(__file__).resolve()),'--worker',tag,kind],check=True,timeout=180)
            results.append(json.loads((OUT/('guarded-'+tag+'-'+kind+'.json')).read_text()))
    report={'status':'NATIVE_GUARDED_MUTATION_PASS','workers':results,
            'native_calls':sum(r['native_calls'] for r in results),
            'core_test_dll_sha256':hashlib.sha256((OUT/'core_test.dll').read_bytes()).hexdigest(),
            'core_object_sha256':hashlib.sha256((OUT/'probe_core.obj').read_bytes()).hexdigest(),
            'shipped_efi_sha256':hashlib.sha256((OUT/'USB/EFI/BOOT/BOOTX64.EFI').read_bytes()).hexdigest(),
            'notes':['Test DLL and shipped EFI link the identical parser object.',
                     'Bounded deterministic mutation campaign; not a proof of absence of all bugs.',
                     'Parsers collect structure and fingerprints; they are not complete IFR/PE validators.']}
    (OUT/'guarded_verification.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print('Guard-page campaign PASS:',report['native_calls'],'calls',flush=True)


if __name__=='__main__':
    from pathlib import Path
    main()
