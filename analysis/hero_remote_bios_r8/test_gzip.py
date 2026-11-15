"""Exercise the actual freestanding decoder with Python zlib/gzip oracles."""
from pathlib import Path
import ctypes, gzip, hashlib, json, random, struct, subprocess, zlib
out=Path(__file__).resolve().parent
compile=json.loads((out/'build.json').read_text())['commands'][0]
subprocess.run(compile[:-4]+['-c',str(out/'test_gzip.c'),'-o',str(out/'test_gzip.obj')],check=True)
dll=out/'test_gzip.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:gzip_decode','/out:'+str(dll),str(out/'test_gzip.obj')],check=True)
lib=ctypes.CDLL(str(dll));fn=lib.gzip_decode
fn.restype=ctypes.c_uint64;fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64)]
checks=0
def decode(data,expected=None,capacity=32768):
    global checks
    src=ctypes.create_string_buffer(data);buf=ctypes.create_string_buffer(b'\xa5'*(capacity+32),capacity+32);used=ctypes.c_uint64(999)
    status=fn(src,len(data),ctypes.byref(buf,16),capacity,ctypes.byref(used));checks+=1
    assert buf.raw[:16]==b'\xa5'*16 and buf.raw[capacity+16:]==b'\xa5'*16
    if expected is not None:
        assert status==0 and used.value==len(expected) and buf.raw[16:16+used.value]==expected, (hex(status),len(data),len(expected),used.value)
    else:assert status!=0 and used.value==0
    return status
rng=random.Random(3107)
samples=[b'',b'a',b'{}',(out/'reference/registry.json').read_bytes(),(out/'reference/SetupData.xml').read_bytes(),b'x'*32768,bytes(range(256))*127,rng.randbytes(32000)]
for raw in samples:
    for level in range(10):
        data=gzip.compress(raw,compresslevel=level,mtime=0)
        if len(data)>32768:
            decode(data)
            continue
        decode(data,raw)
        if len(raw):decode(data,capacity=len(raw)-1 if len(raw)>1 else 1) if len(raw)>1 else None
        for offset in (-8,-4):
            bad=bytearray(data);bad[offset]^=1;decode(bytes(bad))
        decode(data+data);decode(data+b'x')
fixture=gzip.compress((out/'reference/registry.json').read_bytes(),mtime=0)
for n in range(len(fixture)):decode(fixture[:n])
for n in range(40):
    raw=rng.randbytes(n*47);decode(gzip.compress(raw,mtime=0),raw)
for strategy in (zlib.Z_DEFAULT_STRATEGY,zlib.Z_FIXED,zlib.Z_HUFFMAN_ONLY,zlib.Z_RLE):
    raw=(out/'reference/registry.json').read_bytes();c=zlib.compressobj(6,zlib.DEFLATED,-15,strategy=strategy);stream=c.compress(raw)+c.flush()
    for flags in (0,1,4,8,16,2,31):
        header=bytes([31,139,8,flags])+b'\0'*6
        if flags&4:header+=b'\3\0abc'
        if flags&8:header+=b'name.xml\0'
        if flags&16:header+=b'comment\0'
        if flags&2:header+=struct.pack('<H',zlib.crc32(header)&65535)
        data=header+stream+struct.pack('<II',zlib.crc32(raw),len(raw));decode(data,raw)
        if flags&2:
            bad=bytearray(data);bad[len(header)-1]^=1;decode(bytes(bad))
        for n in range(len(header)):decode(data[:n])
for reserved in (32,64,128):
    bad=bytearray(fixture);bad[3]|=reserved;decode(bytes(bad))
decode(gzip.compress(b'x'*32769,mtime=0))
decode(gzip.compress(rng.randbytes(32768),compresslevel=0,mtime=0))
for _ in range(250):decode(rng.randbytes(rng.randrange(0,256)))
result={'passed':True,'cases':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),
    'coverage':['zlib/gzip independent oracle','levels 0-9 and stored/fixed/dynamic Huffman','all truncated registry prefixes','CRC32 and ISIZE mismatch','optional gzip fields and FHCRC','reserved flags, concatenated members and trailing data refused','32KiB input/output bounds and output canaries','deterministic random malformed inputs']}
(out/'gzip-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
