"""Host execute the real freestanding module with fake UEFI read interfaces."""
from pathlib import Path
import ctypes as C,hashlib,json,random,struct,unittest,uuid,zlib
P=Path(__file__).resolve().parent
D=C.CDLL(str(P/'firmware_probe_test.dll'));U=C.c_uint64;PTR=C.c_void_p
D.firmware_probe.argtypes=[PTR,PTR,PTR];D.firmware_probe.restype=U
D.fp_path_targets.argtypes=[PTR,C.c_size_t,C.POINTER(C.c_uint)];D.fp_path_targets.restype=C.c_int
D.fp_range_readable.argtypes=[PTR,C.c_size_t,C.c_size_t,U,C.c_size_t];D.fp_range_readable.restype=C.c_int
R2=uuid.UUID('89924765-f984-4ad3-839b-51fdce378d88').bytes_le
P5=uuid.UUID('261135b0-7b73-49c0-bcc8-2f9cf4eef19e').bytes_le
LI=uuid.UUID('5b1b31a1-9562-11d2-8e3f-00a0c969723b').bytes_le
FV=uuid.UUID('220e73b6-6bdb-4413-8405-b974b108619a').bytes_le
END=b'\x7f\xff\x04\x00';ERR=lambda n:(1<<63)|n
CBMAP=C.CFUNCTYPE(U,C.POINTER(U),PTR,C.POINTER(U),C.POINTER(U),C.POINTER(C.c_uint32))
CBENUM=C.CFUNCTYPE(U,C.c_uint32,PTR,PTR,C.POINTER(U),C.POINTER(PTR))
CBHANDLE=C.CFUNCTYPE(U,PTR,PTR,C.POINTER(PTR))
CBFREE=C.CFUNCTYPE(U,PTR)
CBFILE=C.CFUNCTYPE(U,PTR,PTR,PTR,C.POINTER(U),C.POINTER(C.c_uint8),C.POINTER(C.c_uint32),C.POINTER(C.c_uint32))
CBSECTION=C.CFUNCTYPE(U,PTR,PTR,C.c_uint8,U,C.POINTER(PTR),C.POINTER(U),C.POINTER(C.c_uint32))
CBAPPEND=C.CFUNCTYPE(None,PTR,PTR,C.c_size_t)

def desc(start,pages=1,kind=4,attr=0):return struct.pack('<IIQQQQ',kind,0,start,0,pages,attr)+b'\0'*8
def path(guid):return b'\x04\x06\x14\x00'+guid+END
def pe(marker):
 b=bytearray(256);b[:2]=b'MZ';struct.pack_into('<I',b,60,64);b[64:68]=b'PE\0\0';struct.pack_into('<H',b,68,0x8664);b[-1]=marker;return bytes(b)
PE={R2:pe(0x52),P5:pe(0x50)}

class Fake:
 def __init__(self,mode='normal'):
  self.mode=mode;self.refs=[];self.ranges=[];self.callbacks=[];self.log=[];self.calls=[];self.freed=[];self.failures=[];self.reentry=None
  self.st=self.alloc(120);self.bs=self.alloc(376);self.poke(self.st+96,self.bs)
  self.lis=[];self.lpaths=[]
  for idx,guid in enumerate([R2,P5]):
   li=self.alloc(96);pth=self.alloc(24,kind=11 if mode=='mmio_path' and not idx else 4);img=self.alloc(256)
   C.memmove(pth,path(guid),24);C.memmove(img,PE[guid],256)
   self.poke(li,0x1000);self.poke(li+32,pth);self.poke(li+64,img);self.poke(li+72,256)
   if mode=='bad_path' and not idx:C.memmove(pth,b'\x04\x06\x00\x00',4)
   self.lis.append(li);self.lpaths.append(pth)
  self.lh=self.alloc(16);self.poke(self.lh,self.lis[0]);self.poke(self.lh+8,self.lis[1])
  self.fv=self.alloc(80);self.fh=self.alloc(8);self.poke(self.fh,self.fv)
  self.poke(self.bs+56,self.cb(CBMAP,self.getmap));self.poke(self.bs+312,self.cb(CBENUM,self.enum))
  self.poke(self.bs+152,self.cb(CBHANDLE,self.handle));self.poke(self.bs+72,self.cb(CBFREE,self.free))
  self.poke(self.fv+16,self.cb(CBFILE,self.readfile));self.poke(self.fv+24,self.cb(CBSECTION,self.readsection))
  self.append_cb=CBAPPEND(self.append);self.callbacks.append(self.append_cb)
 def alloc(self,n,kind=4):
  b=C.create_string_buffer(n+8192);self.refs.append(b);at=(C.addressof(b)+4095)&~4095
  self.ranges.append((at,(n+4095)//4096,kind));return at
 def poke(self,p,v):C.c_uint64.from_address(p).value=v
 def cb(self,typ,fn):
  f=typ(fn);self.callbacks.append(f);at=C.cast(f,PTR).value;self.ranges.append((at&~4095,1,3));return at
 def getmap(self,size,out,key,stride,version):
  self.calls.append('getmap')
  if self.mode=='map_too_large':size[0]=131073;return ERR(5)
  data=b''.join(desc(*r) for r in self.ranges);C.memmove(out,data,len(data));size[0]=len(data);stride[0]=48;version[0]=1;key[0]=7;return 0
 def enum(self,search,guid,key,count,out):
  self.calls.append('enum');g=C.string_at(guid,16)
  if search!=2:self.failures.append('non protocol search')
  if g==LI:
   out[0]=self.lh
   if self.mode=='count_over':count[0]=1025
   elif self.mode in ['fv_only','r2_absent']:
    out[0]=self.lh+8;count[0]=1
   else:count[0]=2
  elif g==FV:out[0]=self.fh;count[0]=65 if self.mode=='count_over' else 1
  else:self.failures.append('unexpected GUID');return ERR(14)
  return 0
 def handle(self,handle,guid,out):
  self.calls.append('handle');g=C.string_at(guid,16)
  if g==LI and handle in self.lis:out[0]=handle;return 0
  if g==FV and handle==self.fv:out[0]=self.fv;return 0
  return ERR(14)
 def free(self,p):self.calls.append('free');self.freed.append(p);return 0
 def readfile(self,this,guid,buffer,size,kind,attributes,auth):
  self.calls.append('readfile');g=C.string_at(guid,16)
  if buffer:self.failures.append('ReadFile must be metadata-only')
  if self.mode=='r2_absent' and g==R2:return ERR(14)
  if self.mode=='file_error':return ERR(15)
  size[0]=1048577 if self.mode=='file_too_large' else 260;kind[0]=7;attributes[0]=0;return 0
 def readsection(self,this,guid,kind,instance,buffer,size,auth):
  self.calls.append('readsection');g=C.string_at(guid,16)
  if kind!=0x10 or instance!=0 or not buffer[0] or size[0]!=1048576:self.failures.append('ReadSection input contract')
  if self.mode=='pointer_replaced':buffer[0]=0x1234;size[0]=256;return 0
  if self.mode=='buffer_warning':size[0]=1048577;return 4
  if self.mode=='buffer_large_success':size[0]=1048577;return 0
  if self.mode=='canary':C.c_uint8.from_address(buffer[0]+1048576).value=0
  C.memmove(buffer[0],PE[g],len(PE[g]));size[0]=len(PE[g]);auth[0]=0;return 0
 def append(self,ctx,text,n):
  self.log.append(C.string_at(text,n).decode('ascii'))
  if self.mode=='reentry' and self.reentry is None:
   self.reentry=-1;self.reentry=D.firmware_probe(self.st,self.append_cb,None)
 def run(self):
  status=D.firmware_probe(self.st,self.append_cb,None);return status,''.join(self.log)

class Tests(unittest.TestCase):
 def runfake(self,mode='normal'):
  f=Fake(mode);status,log=f.run();self.assertEqual(f.failures,[]);self.assertEqual(len(f.freed),2)
  self.assertLess(len(log),131072);self.assertIn('FIRMWARE_PROBE_I1_END',log)
  return f,status,log
 def test_loaded_and_fv_both_present(self):
  f,status,log=self.runfake();self.assertEqual(status,0)
  for label in ['FP_R2_LOADED_MATCHES','FP_P5_P6_LOADED_MATCHES','FP_R2_FV_FILES','FP_P5_P6_FV_FILES','FP_R2_PE_SECTIONS']:
   self.assertIn(label+'=0000000000000001',log)
  self.assertIn(f'FP_FV_PE_CRC32={zlib.crc32(PE[R2]):016X}',log);self.assertEqual(f.calls.count('readsection'),2)
  (P/'mock-normal-transcript.txt').write_bytes(log.encode('ascii'))
 def test_fv_present_without_loaded_image(self):
  _,status,log=self.runfake('fv_only');self.assertEqual(status,0)
  self.assertIn('FP_R2_LOADED_MATCHES=0000000000000000',log);self.assertIn('FP_R2_FV_FILES=0000000000000001',log)
 def test_notfound_does_not_claim_rc2(self):
  _,status,log=self.runfake('r2_absent');self.assertEqual(status,0)
  self.assertIn('FP_R2_FV_FILES=0000000000000000',log);self.assertIn('absence does not prove RC version',log)
 def test_warn_or_large_return_not_hashed(self):
  for mode in ['buffer_warning','buffer_large_success']:
   f,status,log=self.runfake(mode);self.assertEqual(status,ERR(33));self.assertNotIn('FP_FV_PE_CRC32=',log)
   self.assertIn('FP_R2_PE_SECTIONS=0000000000000000',log)
 def test_metadata_bound_prevents_section_call(self):
  f,status,log=self.runfake('file_too_large');self.assertEqual(status,ERR(33));self.assertNotIn('readsection',f.calls)
 def test_changed_buffer_pointer_stops_without_deref_or_free(self):
  f,status,log=self.runfake('pointer_replaced');self.assertEqual(status,ERR(33));self.assertEqual(f.calls.count('readsection'),1)
  self.assertNotIn(0x1234,f.freed);self.assertIn('BUFFER_CONTRACT_FAILED',log)
 def test_canary_damage_stops(self):
  f,status,log=self.runfake('canary');self.assertEqual(status,ERR(33));self.assertEqual(f.calls.count('readsection'),1)
  self.assertIn('BUFFER_CONTRACT_FAILED',log)
 def test_bad_path_or_mmio_not_dereferenced_as_valid(self):
  for mode in ['bad_path','mmio_path']:
   _,status,log=self.runfake(mode);self.assertEqual(status,ERR(33));self.assertIn('FP_R2_LOADED_MATCHES=0000000000000000',log)
 def test_large_counts_or_map_stop_before_handle_access(self):
  for mode in ['count_over','map_too_large']:
   f,status,log=self.runfake(mode);self.assertEqual(status,ERR(33));self.assertNotIn('handle',f.calls)
 def test_read_denied_is_incomplete(self):
  f,status,log=self.runfake('file_error');self.assertEqual(status,ERR(33));self.assertNotIn('readsection',f.calls)
 def test_reentry_rejected(self):
  f,status,log=self.runfake('reentry');self.assertEqual(status,0);self.assertEqual(f.reentry,ERR(20))
 def test_invalid_main_arguments(self):
  self.assertEqual(D.firmware_probe(None,None,None),ERR(2))
 def test_memory_guards(self):
  def run(rows,at,n=1,stride=48):
   b=C.create_string_buffer(b''.join(rows));return D.fp_range_readable(b,len(b.raw)-1,stride,at,n)
  self.assertEqual(run([desc(0x1000),desc(0x2000)],0x1fff,2),1)
  self.assertEqual(run([desc(0x1000),desc(0x3000)],0x1fff,2),0)
  for kind in [0,7,8,11,12,13,14,0xffffffff]:self.assertEqual(run([desc(0x1000,kind=kind)],0x1000),0)
  self.assertEqual(run([desc(0x1000,attr=0x2000)],0x1000),0)
  self.assertEqual(run([desc(0x1000,pages=0xffffffffffffffff)],0x1000),0)
  self.assertEqual(run([desc(0x1000)],0xffffffffffffffff,2),0)
  self.assertEqual(run([desc(0x1000)],0x1000,0),0)
  self.assertEqual(run([desc(0x1000)],0x1000,1,39),0)
 def test_path_boundaries_and_fuzz(self):
  def run(data,n=None):
   b=C.create_string_buffer(data);v=C.c_uint(99);ok=D.fp_path_targets(b,len(data) if n is None else n,C.byref(v));return ok,v.value
  self.assertEqual(run(path(R2)),(1,1));self.assertEqual(run(path(P5)),(1,2))
  self.assertEqual(run(path(R2)[:-4]+b'\x7f\x01\x04\x00'+path(P5)),(1,3))
  self.assertEqual(run(END),(1,0));self.assertEqual(run(path(R2)[:-4]),(0,0))
  self.assertEqual(run(path(R2),4097),(0,0));self.assertEqual(run(b'\x04\x06\x04\x00'+END),(0,0))
  self.assertEqual(run(b'\x01\x01\x04\x00'*128+END),(0,0))
  rng=random.Random(0x465650)
  for _ in range(10000):
   raw=rng.randbytes(rng.randrange(512));ok,value=run(raw)
   self.assertIn(ok,[0,1]);self.assertLessEqual(value,3)

if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 report={'passed':result.wasSuccessful(),'tests':result.testsRun,'random_paths':10000,'scope':'Host fake UEFI services only; no BMC, real firmware read, or hardware test.',
  'dll_sha256':hashlib.sha256((P/'firmware_probe_test.dll').read_bytes()).hexdigest(),
  'failures':[str(t) for t,_ in result.failures],'errors':[str(t) for t,_ in result.errors]}
 (P/'tests.json').write_text(json.dumps(report,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)
