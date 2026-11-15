"""Execute compiled sampler bounds and changing-state cases with synthetic memory."""
from pathlib import Path
import ctypes as c,hashlib,json,struct
HERE=Path(__file__).resolve().parent;OUT=HERE/'build'
class Globals(c.Structure):
 _fields_=[(n,c.c_uint64) for n in ('app','stage','boot_services','string_hii','history')]+[(n,c.c_uint32) for n in ('history_root','history_capacity','history_count','reserved')]
class Sample(c.Structure):
 _fields_=[('globals',Globals)]+[(n,c.c_uint64) for n in ('page_array','page','hii','frames','extras')]+[(n,c.c_uint32) for n in ('current_index','page_count','menu_mode','frame_count','extra_count')]+[(n,c.c_uint16) for n in ('form','index','parent')]+[(n,c.c_uint8) for n in ('redraw','exit_flag','page_flags','reserved')]
COPY=c.CFUNCTYPE(c.c_int,c.c_void_p,c.c_uint64,c.c_void_p,c.c_size_t)
def descriptor(start=0x1000,pages=2,kind=4,attr=0):return struct.pack('<IIQQQQ',kind,0,start,0,pages,attr)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 dll=c.CDLL(str(OUT/'native_sample_test.dll'))
 dll.ns_range.argtypes=[c.c_void_p,c.c_size_t,c.c_size_t,c.c_uint32,c.c_uint64,c.c_size_t];dll.ns_range.restype=c.c_int
 dll.ns_sample.argtypes=[COPY,c.c_void_p,c.c_uint64,c.c_size_t,c.POINTER(Sample)];dll.ns_sample.restype=c.c_int
 results=[]
 def check(name,actual,expected):
  assert actual==expected,(name,actual,expected)
  results.append({'name':name,'passed':True})
 def bound(name,data,address,length,expected,stride=40,version=1):
  check(name,dll.ns_range(data,len(data),stride,version,address,length),expected)
 for kind in range(16):bound('memory_type_'+str(kind),descriptor(kind=kind),0x1800,16,int(1<=kind<=6))
 for name,address,length,expected in [('first',0x1000,1,1),('last',0x2fff,1,1),('whole',0x1000,8192,1),('before',0xfff,2,0),('after',0x3000,1,0),('cross_end',0x2fff,2,0),('zero',0x1000,0,0),('low_address',0,1,0),('overflow',0xfffffffffffffff0,32,0)]:bound(name,descriptor(),address,length,expected)
 bound('read_protection_capability_refused',descriptor(attr=0x2000),0x1000,4,0)
 bound('write_protection_does_not_preclude_read',descriptor(attr=0x20000),0x1000,4,1)
 bound('adjacent_descriptor_crossing_refused',descriptor(pages=1)+descriptor(start=0x2000,pages=1),0x1ff0,32,0)
 bound('overlap_refused',descriptor()+descriptor(start=0x2000,pages=1),0x2100,16,0)
 bound('overlap_partially_covers_range',descriptor()+descriptor(start=0x2000,pages=1),0x1ff0,32,0)
 bound('bad_descriptor_version',descriptor(),0x1000,4,0,version=2)
 bound('bad_descriptor_stride',descriptor(),0x1000,4,0,stride=39)
 bound('unknown_trailing_descriptor',descriptor()+b'X',0x1000,4,0)
 bound('zero_page_descriptor',descriptor(pages=0),0x1000,4,0)
 bound('misaligned_physical',descriptor(start=0x1001),0x1800,4,0)
 bound('overflow_descriptor',descriptor(start=0xfffffffffffff000,pages=2),0x1000,4,0)
 bound('stride_48',descriptor()+bytes(8),0x1000,4,1,stride=48)
 BASE=0x100000;APP=0x200000;TABLE=0x300000;PAGE=0x400000
 def run(name,expected,mutate=None,drift=None,missing=None,image_bytes=909312):
  image=bytearray(909312);app=bytearray(0x60);table=bytearray(32);page=bytearray(0x68)
  def put(buf,off,val,size):buf[off:off+size]=val.to_bytes(size,'little')
  put(image,0xafdd0,APP,8);put(image,0xafcb0,0x1234,8);put(image,0xafbc8,0x900000,8);put(image,0xbabe8,0xffffffffffffffff,8)
  put(image,0xafddc,1,4);put(image,0xafde0,2,4);put(image,0xafde8,0x600000,8);put(image,0xafe00,2,4)
  put(app,0x28,2,4);put(app,0x2c,4,4);put(app,0x30,TABLE,8);put(app,0x58,1,1)
  put(table,16,PAGE,8);put(page,0x20,0x123456789,8);put(page,0x2a,0x2713,2);put(page,0x30,2,2);put(page,0x32,1,2)
  memory={BASE:image,APP:app,TABLE:table,PAGE:page};calls={};ranges=[]
  if mutate:mutate(memory,put)
  @COPY
  def read(_,address,destination,length):
   calls[address]=calls.get(address,0)+1;ranges.append((address,length))
   if drift:drift(memory,put,address,calls[address])
   if missing==address:return 0
   for start,buf in memory.items():
    if start<=address and length<=len(buf)-(address-start):
     raw=bytes(buf[address-start:address-start+length]);c.memmove(destination,raw,length);return 1
   return 0
  output=Sample();c.memset(c.byref(output),0xa5,c.sizeof(output))
  check(name,dll.ns_sample(read,None,BASE,image_bytes,c.byref(output)),expected)
  if expected==0:
   assert output.form==0x2713 and output.hii==0x123456789 and output.current_index==2
   assert all(a!=output.hii and a!=output.globals.string_hii for a,n in ranges),'Opaque HII handle was dereferenced'
  if expected not in (0,1):assert bytes(output)==bytes(c.sizeof(output)),name+' leaked a rejected partial sample'
 run('valid_stable_structure',0)
 run('inactive',1,lambda m,p:p(m[BASE],0xafdd0,0,8))
 run('wrong_image_size',2,image_bytes=909311)
 run('global_unmapped',3,missing=BASE+0xafbc8)
 run('app_unmapped',4,missing=APP)
 run('unaligned_app',4,lambda m,p:p(m[BASE],0xafdd0,APP+1,8))
 run('zero_pages',5,lambda m,p:p(m[APP],0x2c,0,4))
 run('excessive_pages',5,lambda m,p:p(m[APP],0x2c,4097,4))
 run('index_outside_page_array',5,lambda m,p:p(m[APP],0x28,4,4))
 run('history_count_exceeds_capacity',5,lambda m,p:p(m[BASE],0xafe00,3,4))
 run('page_slot_unmapped',6,missing=TABLE+16)
 run('page_unmapped',6,missing=PAGE)
 run('page_identity_wrong_index',7,lambda m,p:p(m[PAGE],0x30,3,2))
 run('excessive_frames',7,lambda m,p:p(m[PAGE],0x4c,65,4))
 run('nonzero_count_null_frames',7,lambda m,p:p(m[PAGE],0x4c,1,4))
 run('excessive_extra_controls',7,lambda m,p:p(m[PAGE],0x58,4097,4))
 run('global_changed_during_sample',8,drift=lambda m,p,a,n:p(m[BASE],0xafcb0,0x999,8) if a==BASE+0xafcb0 and n==2 else None)
 run('app_changed_during_sample',8,drift=lambda m,p,a,n:p(m[APP],0x58,0,1) if a==APP and n==2 else None)
 run('page_pointer_changed_during_sample',8,drift=lambda m,p,a,n:p(m[TABLE],16,PAGE+0x1000,8) if a==TABLE+16 and n==2 else None)
 run('page_hii_changed_during_sample',8,drift=lambda m,p,a,n:p(m[PAGE],0x20,0x7777,8) if a==PAGE and n==2 else None)
 run('inactive_changed_during_sample',8,lambda m,p:p(m[BASE],0xafdd0,0,8),lambda m,p,a,n:p(m[BASE],0xafdd0,APP,8) if a==BASE+0xafdd0 and n==2 else None)
 report={'passed':True,'cases':len(results),'checks':results,'dll_sha256':sha(OUT/'native_sample_test.dll'),'source_sha256':sha(HERE/'native_sample.c'),'header_sha256':sha(HERE/'native_sample.h'),'sample_bytes':c.sizeof(Sample),'scope':'Actual compiled C, bounded synthetic memory. No physical reads or writes. Not authorization proof.'}
 (OUT/'sample_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':True,'cases':len(results),'sample_bytes':c.sizeof(Sample)}))
if __name__=='__main__':main()
