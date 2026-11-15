from pathlib import Path
import ctypes as C,struct,uuid,unittest,json,hashlib,sys
P=Path(__file__).resolve().parent;ROOT=P.parents[2];sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
D=C.CDLL(str(P/'dxe_state_probe_test.dll'));U=C.c_uint64;PTR=C.c_void_p
class Match(C.Structure):_fields_=[('address',U),('raw',C.c_uint8*0x90),('depex',C.c_uint8*256),('which',C.c_uint32),('depex_bytes',C.c_uint32),('depex_readable',C.c_uint32)]
class Result(C.Structure):_fields_=[('base',U),('head',U),('identity',C.c_uint32),('running',C.c_uint32),('complete',C.c_uint32),('status',C.c_uint32),('nodes',C.c_uint32),('matches',C.c_uint32),('count',C.c_uint32*2)]+[(n,C.c_uint32) for n in ['initialized','dependent','untrusted','scheduled','unrequested','depex_error']]+[('match',Match*8),('visited',U*1024)]
READ=C.CFUNCTYPE(C.c_int,PTR,U,PTR,C.c_size_t,C.c_uint)
GETMAP=C.CFUNCTYPE(U,C.POINTER(U),PTR,C.POINTER(U),C.POINTER(U),C.POINTER(C.c_uint32))
APPEND=C.CFUNCTYPE(None,PTR,PTR,C.c_size_t)
D.dx_state_snapshot.argtypes=[READ,PTR,U,U,C.POINTER(Result)];D.dx_state_snapshot.restype=C.c_int
D.dx_range.argtypes=[PTR,C.c_size_t,C.c_size_t,U,C.c_size_t,C.c_uint];D.dx_range.restype=C.c_int
D.dxe_state_probe.argtypes=[PTR,PTR,PTR];D.dxe_state_probe.restype=U
CORE=bytes(pefile.PE(str(P/'DxeCore.efi')).get_memory_mapped_image());BASE=0x100000;HEAD=BASE+0x16c10;RUN=BASE+0x17bd8
TARGET=[uuid.UUID(x).bytes_le for x in ['89924765-f984-4ad3-839b-51fdce378d88','261135b0-7b73-49c0-bcc8-2f9cf4eef19e']]
def q(b,n,v):struct.pack_into('<Q',b,n,v)
class Fake:
 def __init__(self,count=2,mode='ok'):
  self.core=bytearray(CORE);self.parts={BASE:self.core};self.calls=[];self.mode=mode;self.seen=0
  self.nodes=[0x200000+i*0x1000 for i in range(count)]
  q(self.core,HEAD-BASE,self.nodes[0]+8 if count else HEAD);q(self.core,HEAD-BASE+8,self.nodes[-1]+8 if count else HEAD);self.core[RUN-BASE]=0
  for i,at in enumerate(self.nodes):
   b=bytearray(0x90);q(b,0,0x72767264);q(b,8,self.nodes[i+1]+8 if i+1<count else HEAD);q(b,16,self.nodes[i-1]+8 if i else HEAD)
   b[0x30:0x40]=TARGET[i] if i<2 else uuid.UUID(int=i+1).bytes_le;b[0x74]=1;self.parts[at]=b
  self.cb=READ(self.read)
 def read(self,ctx,at,out,n,code):
  self.calls.append((at,n,code))
  if self.mode=='deny_data' and code==0:return 0
  if self.mode=='deny_code' and code:return 0
  for base,b in self.parts.items():
   if base<=at and at+n<=base+len(b):
    data=bytes(b[at-base:at-base+n])
    if self.mode=='change_node' and at==self.nodes[0]:
     self.seen+=1
     if self.seen==2:data=data[:0x74]+bytes([0])+data[0x75:]
    if self.mode=='change_head' and at==HEAD:
     self.seen+=1
     if self.seen==2:data=b'\0'*n
    C.memmove(out,data,n);return 1
  return 0
 def go(self,start=None):
  r=Result();v=D.dx_state_snapshot(self.cb,None,BASE+0x75b8,start or BASE+0x76b8,C.byref(r));return v,r
class Tests(unittest.TestCase):
 def test_normal(self):
  v,r=Fake().go();self.assertEqual(v,0);self.assertEqual(r.complete,1);self.assertEqual(list(r.count),[1,1]);self.assertEqual(r.nodes,2);self.assertEqual(r.dependent,2)
 def test_empty(self):
  v,r=Fake(0).go();self.assertEqual(v,0);self.assertEqual(list(r.count),[0,0])
 def test_core_identity(self):
  f=Fake();f.core[0x8a0c]^=1;v,r=f.go();self.assertEqual(v,2);self.assertFalse(r.identity)
 def test_start_mismatch(self):self.assertEqual(Fake().go(BASE+0x76b9)[0],2)
 def test_code_not_readable(self):self.assertEqual(Fake(mode='deny_code').go()[0],2)
 def test_running(self):
  f=Fake();f.core[RUN-BASE]=1;v,r=f.go();self.assertEqual(v,3);self.assertEqual(r.nodes,0)
 def test_data_not_readable(self):self.assertEqual(Fake(mode='deny_data').go()[0],4)
 def test_signature(self):
  f=Fake();f.parts[f.nodes[0]][0]=0;self.assertEqual(f.go()[0],5)
 def test_wrong_backlink(self):
  f=Fake();q(f.parts[f.nodes[1]],16,HEAD);self.assertEqual(f.go()[0],5)
 def test_cycle(self):
  f=Fake();q(f.parts[f.nodes[1]],8,f.nodes[0]+8);self.assertEqual(f.go()[0],5)
 def test_cap(self):self.assertEqual(Fake(1025).go()[0],6)
 def test_node_changed(self):self.assertEqual(Fake(mode='change_node').go()[0],7)
 def test_head_changed(self):self.assertEqual(Fake(mode='change_head').go()[0],7)
 def test_statuses(self):
  f=Fake();f.parts[f.nodes[0]][0x74]=0;f.parts[f.nodes[0]][0x77]=1;f.parts[f.nodes[1]][0x78]=1
  v,r=f.go();self.assertEqual(v,0);self.assertEqual(r.untrusted,1);self.assertEqual(r.initialized,1)
 def test_depex(self):
  f=Fake();b=f.parts[f.nodes[0]];q(b,0x50,0x900000);q(b,0x58,2);f.parts[0x900000]=b'\x06\x08';v,r=f.go();self.assertEqual(v,0);self.assertEqual(r.match[0].depex_readable,1);self.assertEqual(bytes(r.match[0].depex[:2]),b'\x06\x08')
 def test_bad_depex_bounds_skipped(self):
  f=Fake();b=f.parts[f.nodes[0]];q(b,0x50,0xffffffffffffffff);q(b,0x58,257);v,r=f.go();self.assertEqual(v,0);self.assertEqual(r.match[0].depex_readable,0)
 def test_map(self):
  def probe(kind,attr,code=0,at=0x1000,n=4096):
   d=struct.pack('<IIQQQQ',kind,0,0x1000,0,1,attr);return D.dx_range(d,len(d),40,at,n,code)
  self.assertEqual(probe(4,0),1);self.assertEqual(probe(3,0,1),1)
  for t in [0,1,2,5,6,7,8,9,10,11,12,13,14]:self.assertEqual(probe(t,0),0)
  self.assertEqual(probe(4,0,1),0);self.assertEqual(probe(3,0x2000),0);self.assertEqual(probe(3,0,at=0x1fff,n=2),0)
 def test_adapter_missing_service(self):
  st=C.create_string_buffer(120);bs=C.create_string_buffer(376);struct.pack_into('<Q',st,96,C.addressof(bs));self.assertEqual(D.dxe_state_probe(C.addressof(st),None,None),(1<<63)|2)
 def test_full_adapter_only_memory_map(self):
  refs=[];ranges=[];log=[];calls=[];reentry=[]
  def alloc(n,kind):
   b=C.create_string_buffer(n+8192);refs.append(b);p=(C.addressof(b)+4095)&~4095;ranges.append((p,(n+4095)//4096,kind));return p
  core=alloc(len(CORE),3);C.memmove(core,CORE,len(CORE));head=core+0x16c10;at=alloc(0x90,4)
  C.c_uint64.from_address(head).value=at+8;C.c_uint64.from_address(head+8).value=at+8;C.c_uint8.from_address(core+0x17bd8).value=0
  b=bytearray(0x90);q(b,0,0x72767264);q(b,8,head);q(b,16,head);b[0x30:0x40]=TARGET[0];b[0x78]=1;C.memmove(at,bytes(b),len(b))
  st=C.create_string_buffer(120);bs=C.create_string_buffer(376);struct.pack_into('<Q',st,96,C.addressof(bs));struct.pack_into('<Q',bs,0xc8,core+0x75b8);struct.pack_into('<Q',bs,0xd0,core+0x76b8)
  def getmap(size,out,key,stride,version):
   calls.append('GetMemoryMap');data=b''.join(struct.pack('<IIQQQQ',t,0,p,0,n,0) for p,n,t in ranges);C.memmove(out,data,len(data));size[0]=len(data);stride[0]=40;version[0]=1;key[0]=9;return 0
  def append(ctx,p,n):
   log.append(C.string_at(p,n))
   if not reentry:reentry.append(0);reentry[0]=D.dxe_state_probe(C.addressof(st),C.cast(acb,PTR),None)
  mcb=GETMAP(getmap);acb=APPEND(append);struct.pack_into('<Q',bs,56,C.cast(mcb,PTR).value)
  self.assertEqual(D.dxe_state_probe(C.addressof(st),C.cast(acb,PTR),None),0);self.assertEqual(calls,['GetMemoryMap']);self.assertEqual(reentry,[(1<<63)|20])
  text=b''.join(log);self.assertIn(b'DX_COMPLETE=0000000000000001',text);self.assertIn(b'DX_R2_COUNT=0000000000000001',text);self.assertIn(b'DX_INITIALIZED=0000000000000001',text)
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests);r=unittest.TextTestRunner(verbosity=2).run(suite)
 (P/'probe-tests.json').write_text(json.dumps(dict(tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),dll_sha256=hashlib.sha256((P/'dxe_state_probe_test.dll').read_bytes()).hexdigest(),scope='Actual C offline callback and bounds tests; no real firmware services'),indent=2)+'\n')
 sys.exit(not r.wasSuccessful())
