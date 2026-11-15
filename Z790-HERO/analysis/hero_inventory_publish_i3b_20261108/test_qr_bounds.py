from pathlib import Path
import ctypes,hashlib,json,subprocess,zlib
import decode_captures as d
O=Path(__file__).resolve().parent
build=json.loads((O/'build.json').read_text());zig=build['commands'][0][0]
dll=O/'test_qr.dll'
subprocess.run([zig,'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:kvm_make_frame','/out:'+str(dll),*[str(O/(s+'.obj')) for s in ('kvm','crc','common','qrcodegen')]],check=True)
lib=ctypes.CDLL(str(dll));f=lib.kvm_make_frame;f.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t];f.restype=ctypes.c_size_t
cases=[]
for length in (1,511,512,513,999*512,1000*512,1000*512+1,1048575,1048576,2097151,2097152):
 data=(bytes(range(256))*((length+255)//256))[:length];crc=zlib.crc32(data);pages=(length+511)//512;src=ctypes.create_string_buffer(data);dest=ctypes.create_string_buffer(1024)
 raw=[]
 for page in range(pages):
  part=data[page*512:(page+1)*512];frame=f'HERO-INVENTORY-I3B-QR1\nT={length};C={crc:08X};P={page+1}/{pages};O={page*512};N={len(part)};D={zlib.crc32(part):08X}\n\n'.encode()+part
  if page in (0,998,999,1000,pages-1):
   n=f(src,length,page,dest,1024);assert n==len(frame) and dest.raw[:n]==frame
  raw.append(frame)
 restored,meta=d.assemble(raw,require_snapshot=False);assert restored==data
 assert f(src,length,pages,dest,1024)==0
 cases.append({'bytes':length,'pages':pages,'sha256':meta['sha256'],'passed':True})
for length in (0,2097153):assert f(ctypes.create_string_buffer(b'x'),length,0,ctypes.create_string_buffer(1024),1024)==0
for bad in (b'HERO-INVENTORY-I3B-QR1\nT=2097153;C=00000000;P=1/4097;O=0;N=1;D=00000000\n\nx',raw[-1][:-1],raw[-1]+b'x'):
 try:d.parse_frame(bad)
 except ValueError:pass
 else:raise AssertionError('accepted malformed frame')
report={'passed':True,'native_boundary_and_decoder_roundtrip_cases':cases,'invalid_limits_rejected':True,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest()}
(O/'qr-boundary-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases),'largest_pages':4096}))
