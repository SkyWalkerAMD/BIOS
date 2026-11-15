"""Native helper tests at a real Windows PAGE_NOACCESS boundary, no hardware."""
from pathlib import Path
import ctypes as C,hashlib,json,struct
P=Path(__file__).resolve().parent
lib=C.CDLL(str(P/'capture_test.dll'))
class Map(C.Structure):_fields_=[('data',C.c_void_p),('bytes',C.c_size_t),('ds',C.c_size_t)]
def mapping(start,pages=1,typ=4,attrs=0):
 b=C.create_string_buffer(struct.pack('<IIQQQQ',typ,0,start,0,pages,attrs)+bytes(8));return b,Map(C.addressof(b),48,48)
lib.i4_range_readable.argtypes=[C.POINTER(Map),C.c_void_p,C.c_size_t];lib.i4_range_readable.restype=C.c_int
lib.i4_path_copy.argtypes=[C.POINTER(Map),C.c_void_p,C.c_void_p,C.POINTER(C.c_size_t)];lib.i4_path_copy.restype=C.c_uint64
lib.i4_media_bytes.argtypes=[C.c_uint64];lib.i4_media_bytes.restype=C.c_size_t
lib.i4_media_fields_equal.argtypes=[C.c_uint64,C.c_void_p,C.c_void_p];lib.i4_media_fields_equal.restype=C.c_int
k=C.WinDLL('kernel32',use_last_error=True)
k.VirtualAlloc.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32];k.VirtualAlloc.restype=C.c_void_p
k.VirtualProtect.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32,C.POINTER(C.c_uint32)];k.VirtualProtect.restype=C.c_int
k.VirtualFree.argtypes=[C.c_void_p,C.c_size_t,C.c_uint32];k.VirtualFree.restype=C.c_int
rows=[]
def check(name,condition):assert condition,name;rows.append(dict(case=name,passed=True))
base=k.VirtualAlloc(None,8192,0x3000,4);assert base
old=C.c_uint32();assert k.VirtualProtect(base+4096,4096,1,C.byref(old))
dest=C.create_string_buffer(1024)
try:
 backing,m=mapping(base)
 def copy(at,data):
  C.memmove(at,data,len(data));n=C.c_size_t(777);e=lib.i4_path_copy(C.byref(m),at,dest,C.byref(n));return e,n.value
 e,n=copy(base+4092,b'\x7f\xff\x04\0');check('end_node_at_guard',e==0 and n==4)
 e,n=copy(base+4092,b'\x01\x01\x06\0');check('node_crosses_guard_rejected',e!=0 and n==0)
 e,n=copy(base+4094,b'\x7f\xff');check('header_crosses_guard_rejected',e!=0 and n==0)
 e,n=copy(base+4000,b'\x01\x01\0\0');check('zero_node_rejected',e!=0)
 raw=b'\x01\x01\xfc\x03'+bytes(1016)+b'\x7f\xff\x04\0'
 e,n=copy(base+3072,raw);check('1024_byte_path_ends_at_guard',e==0 and n==1024 and dest.raw==raw)
 n=C.c_size_t();check('near_uint64_wrap_rejected',lib.i4_path_copy(C.byref(m),0xfffffffffffffe00,dest,C.byref(n))!=0)
 check('null_path_rejected',lib.i4_path_copy(C.byref(m),None,dest,C.byref(n))!=0)
 check('range_crosses_guard_rejected',lib.i4_range_readable(C.byref(m),base+4095,2)==0)
 check('range_last_byte_accepted',lib.i4_range_readable(C.byref(m),base+4095,1)==1)
 for typ in (0,7,8,9,10,11,12,13,14,15):
  b,mm=mapping(base,typ=typ);check('untrusted_memory_type_'+str(typ),lib.i4_range_readable(C.byref(mm),base,1)==0)
 for typ in range(1,7):
  b,mm=mapping(base,typ=typ);check('readable_memory_type_'+str(typ),lib.i4_range_readable(C.byref(mm),base,1)==1)
 b,mm=mapping(base,attrs=0x2000);check('read_protected_rejected',lib.i4_range_readable(C.byref(mm),base,1)==0)
 b,mm=mapping(0xfffffffffffff000,pages=2);check('descriptor_overflow_rejected',lib.i4_range_readable(C.byref(mm),0xfffffffffffff000,1)==0)
 b,mm=mapping(base);mm.ds=32;check('short_descriptor_rejected',lib.i4_range_readable(C.byref(mm),base,1)==0)
 b,mm=mapping(base);mm.bytes=47;check('nondivisible_map_rejected',lib.i4_range_readable(C.byref(mm),base,1)==0)
 for rev,n in [(0,0),(0x10000,32),(0x20000,32),(0x20001,44),(0x2001f,48),(0x30000,48)]:check('revision_'+hex(rev),lib.i4_media_bytes(rev)==n)
 a=C.create_string_buffer(48);b=C.create_string_buffer(48);check('media_equal',lib.i4_media_fields_equal(0x2001f,a,b)==1)
 b[9]=b'X';b[20]=b'Y';check('padding_not_semantic_change',lib.i4_media_fields_equal(0x2001f,a,b)==1)
 b[12]=b'X';check('block_size_change_detected',lib.i4_media_fields_equal(0x2001f,a,b)==0)
finally:assert k.VirtualFree(base,0,0x8000)
result=dict(passed=True,real_noaccess_boundary=True,guard_pages_freed=True,cases=rows,dll_sha256=hashlib.sha256((P/'capture_test.dll').read_bytes()).hexdigest())
(P/'guard-page-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(rows)}))
