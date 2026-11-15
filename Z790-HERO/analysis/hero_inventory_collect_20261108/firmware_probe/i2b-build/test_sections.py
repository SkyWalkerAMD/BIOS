"""Exercise the compiled top-level section parser with archive bodies and fuzz."""
from pathlib import Path
import ctypes as C,hashlib,json,random,struct,unittest,zlib
P=Path(__file__).resolve().parent;ROOT=P.parents[3]
D=C.CDLL(str(P/'capture_test.dll'))
class Item(C.Structure):_fields_=[(x,C.c_uint32) for x in ['offset','size','payload','payload_size','type']]
class Sections(C.Structure):_fields_=[(x,C.c_uint32) for x in ['count','pe_count','encapsulated']]+[('items',Item*64)]
D.fp_sections_parse.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p];D.fp_sections_parse.restype=C.c_int
COUNTS={'calls':0}
def sec(kind,payload,extended=False):
 header=b'\xff\xff\xff'+bytes([kind])+struct.pack('<I',len(payload)+8) if extended else (len(payload)+4).to_bytes(3,'little')+bytes([kind])
 b=header+payload;return b+bytes(-len(b)%4)
def call(data,n=None):
 source=C.create_string_buffer(data);buffer=(C.c_ubyte*(C.sizeof(Sections)+32))(*([0xa5]*(C.sizeof(Sections)+32)))
 result=D.fp_sections_parse(source,len(data) if n is None else n,C.addressof(buffer)+16)
 assert bytes(buffer[:16])==b'\xa5'*16 and bytes(buffer[-16:])==b'\xa5'*16 and source.raw[:len(data)]==data
 parsed=Sections.from_buffer_copy(bytes(buffer[16:-16]));assert parsed.count<=64
 for s in parsed.items[:parsed.count]:assert s.payload+s.payload_size<=len(data)
 COUNTS['calls']+=1;return result,parsed
class Tests(unittest.TestCase):
 def test_standard_and_extended_headers(self):
  for ext in [False,True]:
   data=sec(0x13,b'\x06\x08',ext)+sec(0x10,b'PAYLOAD',ext)
   r,s=call(data);self.assertEqual(r,0);self.assertEqual((s.count,s.pe_count),(2,1))
   item=s.items[1];self.assertEqual(data[item.payload:item.payload+item.payload_size],b'PAYLOAD')
 def test_invalid_sizes_truncation_and_padding(self):
  for data in [b'\0'*4,b'\x03\x00\x00\x10',b'\xff\xff\xff\x10',b'\xff\xff\xff\x10\0\0\0\0',
               b'\x10\0\0\x10DATA',b'\x05\0\0\x10X\x01\0\0']:
   self.assertNotEqual(call(data)[0],0)
  data=sec(0x10,b'0123456789')
  for n in range(1,14):
   if n>=4:self.assertNotEqual(call(data[:n])[0],0)
 def test_padding_limits(self):
  self.assertEqual(call(b'\x05\0\0\x10X')[0],0)
  self.assertEqual(call(b'\x05\0\0\x10X\xff\xff\xff')[0],0)
  self.assertEqual(call(b'\x05\0\0\x10X\xff\x01\xff')[0],5)
 def test_count_and_cap_boundaries(self):
  self.assertEqual(call(sec(0x19,b'')*64)[1].count,64)
  self.assertEqual(call(sec(0x19,b'')*65)[0],4)
  self.assertEqual(call(b'X',1048577)[0],1)
  data=(1048576).to_bytes(3,'little')+b'\x19'+bytes(1048576-4)
  self.assertEqual(call(data)[0],0)
 def test_multiple_pe_and_encapsulation_not_silently_unwrapped(self):
  r,s=call(sec(1,b'COMPRESSED')+sec(2,b'GUIDED')+sec(0x10,b'A')+sec(0x10,b'B'))
  self.assertEqual((r,s.count,s.pe_count,s.encapsulated),(0,4,2,2))
 def test_archived_actual_target_ffs(self):
  rows=[]
  for label,path in [('RC3 R2','analysis/hero_ipmi_r2/HeroIpmiCoreR2.ffs'),('RC2/RC3 P5','analysis/hero_ipmi_p5/HeroIpmiNativeP5.ffs'),('RC4 P6','analysis/hero_ipmi_p6_20261104/HeroIpmiNativeP6.ffs')]:
   p=ROOT/path;raw=p.read_bytes();self.assertEqual(int.from_bytes(raw[20:23],'little'),len(raw));body=raw[24:]
   result,s=call(body);self.assertEqual((result,s.pe_count,s.encapsulated),(0,1,0))
   records=[]
   for item in s.items[:s.count]:
    data=body[item.payload:item.payload+item.payload_size]
    row={'type':f'{item.type:02X}','offset':item.offset,'section_bytes':item.size,'payload_bytes':len(data),'payload_crc32':f'{zlib.crc32(data):08X}'}
    if item.type==0x13:row['depex_hex']=data.hex().upper()
    if item.type==0x10:row['pe_sha256']=hashlib.sha256(data).hexdigest()
    records.append(row)
   rows.append({'label':label,'path':path,'ffs_sha256':hashlib.sha256(raw).hexdigest(),'body_bytes':len(body),'body_crc32':f'{zlib.crc32(body):08X}','body_sha256':hashlib.sha256(body).hexdigest(),'sections':records})
  (P/'known-ffs-bodies.json').write_text(json.dumps({'scope':'Archived files only, not current .71 body readback','files':rows},indent=2)+'\n')
 def test_fuzz_bounds(self):
  rng=random.Random(0x493242)
  for _ in range(20000):call(rng.randbytes(rng.randrange(4096)))
 def test_null_pointers(self):
  self.assertEqual(D.fp_sections_parse(None,16,None),1)
  out=Sections();self.assertEqual(D.fp_sections_parse(None,16,C.byref(out)),1);self.assertEqual(out.count,0)
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 report={'passed':result.wasSuccessful(),'tests':result.testsRun,**COUNTS,'fuzz_cases':20000,'scope':'Host compiled C parser, archived FFS bytes and synthetic data; no hardware reads.',
  'dll_sha256':hashlib.sha256((P/'capture_test.dll').read_bytes()).hexdigest(),'failures':[str(t) for t,_ in result.failures],'errors':[str(t) for t,_ in result.errors]}
 (P/'section-tests.json').write_text(json.dumps(report,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)
