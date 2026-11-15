"""Compiled identity/QR code and strict semantic/error transport tests, local only."""
from pathlib import Path
import ctypes,hashlib,importlib.util,json,sys,zlib
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());OUT=HERE/'core_transport_tests';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'));from PIL import Image,ImageDraw
import zxingcpp
from decode_linux_log import decode
spec=importlib.util.spec_from_file_location('p3decode',ROOT/'analysis/aitweaker_lock/probe_p3_kvm/decode_captures.py');p3=importlib.util.module_from_spec(spec);spec.loader.exec_module(p3)
dll=ctypes.CDLL(str(HERE/'build/core_test.dll'));dll.lc_exact_line.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_char_p];dll.lc_exact_line.restype=ctypes.c_int
dll.lc_identity.argtypes=[ctypes.c_uint]*8;dll.lc_identity.restype=ctypes.c_int
dll.lc_frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t];dll.lc_frame.restype=ctypes.c_size_t
dll.qrcodegen_encodeBinary.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_bool];dll.qrcodegen_encodeBinary.restype=ctypes.c_bool
dll.qrcodegen_getSize.argtypes=[ctypes.c_void_p];dll.qrcodegen_getSize.restype=ctypes.c_int;dll.qrcodegen_getModule.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];dll.qrcodegen_getModule.restype=ctypes.c_bool
tests=[]
def check(name,value):tests.append({'name':name,'pass':bool(value)});assert value,name
for expected in [b'Pro WS W790E-SAGE SE',b'1904']:
 for suffix in [b'',b'\n',b'\r',b'\r\n',b' ',b'\t',b'\n\n',b'\0',b'\nextra']:
  raw=expected+suffix;check('DMI exact LF policy '+repr(raw),bool(dll.lc_exact_line(raw,len(raw),expected))==(suffix in [b'',b'\n']))
 for raw in [expected.lower(),expected[:-1],b' '+expected,b'wrong',b'']:
  if raw!=expected:check('DMI mismatch '+repr(raw),not dll.lc_exact_line(raw,len(raw),expected))
identity=[0x046b,0xff31,0,0,2,8,6,0x50];check('Exact target tuple',dll.lc_identity(*identity)==1)
for i in range(8):
 a=identity.copy();a[i]^=1;check('Each target component necessary '+str(i),dll.lc_identity(*a)==0)
for n in [0,1,768,769]:
 b=b'x'*n;buf=ctypes.create_string_buffer(5000);value=dll.lc_frame(b,n,buf,5000);check('Frame bound '+str(n),bool(value)==(1<=n<=768))
 if value:
  check('Exact output cap accepted '+str(n),dll.lc_frame(b,n,buf,value)==value);check('Output cap one byte short '+str(n),dll.lc_frame(b,n,buf,value-1)==0)
sources=sorted((HERE/'native_submit_tests').glob('*.txt'))
for directory in [HERE/'vm_tests_final03']:
 sources+=sorted(directory.glob('*/linux-log.txt'))
qr_rows=[]
for i,path in enumerate(sources):
 data=path.read_bytes();is_lab=b'LAB_SELECTOR_ONLY' in data;sem=decode(data,allow_lab=is_lab);check('Semantic '+path.parent.name+'/'+path.name,sem['complete'])
 tmp=ctypes.create_string_buffer(5000);qr=ctypes.create_string_buffer(5000);n=dll.lc_frame(data,len(data),tmp,5000);frame=bytes(tmp.raw[:n]);check('Native QR encode '+str(i),dll.qrcodegen_encodeBinary(tmp,n,qr,1,1,30,-1,True))
 size=dll.qrcodegen_getSize(qr);scale=3;im=Image.new('RGB',((size+8)*scale,(size+8)*scale),'white');draw=ImageDraw.Draw(im)
 for y in range(size):
  for x in range(size):
   if dll.qrcodegen_getModule(qr,x,y):draw.rectangle(((x+4)*scale,(y+4)*scale,(x+5)*scale-1,(y+5)*scale-1),fill='black')
 target=OUT/f'qr-{i:03}.png';im.save(target);decoded=zxingcpp.read_barcodes(im);check('Native QR roundtrip '+str(i),len(decoded)==1 and bytes(decoded[0].bytes)==frame)
 assembled,meta=p3.assemble([frame],require_inventory=False);check('Frozen P3 decoder '+str(i),assembled==data)
 qr_rows.append({'source':path.relative_to(HERE).as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'png':target.name,'png_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'module_size':size})
positive=(HERE/'native_submit_tests/exact_ua_then_success.txt').read_bytes()
mutations={
 'three_commands':positive.replace(b'SG_IO_CALLS=2',b'SG_IO_CALLS=3'),
 'wrong_crc_is_transport_test':positive+b'X',
 'first_ua_changed':positive.replace(b'700006000000000A00000000290000000000',b'700006000000000A000000002A0000000000'),
 'first_data_changed':positive.replace(b'18,1,0000000000000000',b'18,1,0000000100000000'),
 'second_bad_guard':positive.replace(b'0,1,00007FFF00000200',b'0,0,00007FFF00000200'),
 'capacity_disagrees':positive.replace(b'LAST_LBA=00007FFF',b'LAST_LBA=00007FFE'),
 'ownership_missing':positive.replace(b'CHECKS=1FF',b'CHECKS=0FF'),
 'module_missing':positive.replace(b'MODULES=8',b'MODULES=7'),
 'dmi_missing':positive.replace(b'DMI_MATCH=1',b'DMI_MATCH=0'),
 'wrong_expected_board':positive.replace(b'Pro WS W790E-SAGE SE',b'Pro WS W790-ACE'),
 'wrong_usb':positive.replace(b'USB=046B:FF31',b'USB=046B:FF32'),
 'pending_final':positive.replace(b'PROBE_COMPLETE',b'PROBE_PENDING'),
 'packet_duplicate':positive.replace(b'A2=',b'A1='),
 'declared_sense_short':positive.replace(b',18,1,',b',17,1,'),
 'false_success_flag':positive.replace(b'VALID=1',b'VALID=0'),
 'changed_write_count':positive.replace(b'PROBE_STORAGE_WRITES=0',b'PROBE_STORAGE_WRITES=1'),
}
for name,data in mutations.items():
 try:decode(data);rejected=False
 except (ValueError,UnicodeError):rejected=True
 check('Semantic corruption '+name,rejected)
for n in [0,1,len(positive)-1]:
 try:decode(positive[:n]);rejected=False
 except (ValueError,UnicodeError):rejected=True
 check('Incomplete log '+str(n),rejected)
framebuf=ctypes.create_string_buffer(5000);n=dll.lc_frame(positive,len(positive),framebuf,5000);bad=bytearray(framebuf.raw[:n]);bad[-4]^=1
try:p3.parse_frame(bytes(bad));rejected=False
except Exception:rejected=True
check('P3 corrupted body CRC rejects',rejected)
report={'status':'PASS','dll_sha256':hashlib.sha256((HERE/'build/core_test.dll').read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'decoder_sha256':hashlib.sha256((HERE/'decode_linux_log.py').read_bytes()).hexdigest(),'checks':tests,'check_count':len(tests),'qr_count':len(qr_rows),'max_log_bytes':max(r['bytes'] for r in qr_rows),'qr':qr_rows,'scope':'Compiled core identity/framing/QR encoder plus strict Python log decoder. Full actual production ELF response/control flow is separately replayed; kernel ownership separately booted in QEMU. No hardware.'}
(OUT/'summary.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps({k:report[k] for k in ['status','check_count','qr_count','max_log_bytes']}))
