from pathlib import Path
import ctypes as C,hashlib,json,unittest,uuid
P=Path(__file__).resolve().parent;D=C.CDLL(str(P/'depex_probe_test.dll'))
U=C.c_uint64;PTR=C.c_void_p;ERR=lambda n:(1<<63)|n
D.depex_probe.argtypes=[PTR,PTR,PTR];D.depex_probe.restype=U
LO=C.CFUNCTYPE(U,PTR,PTR,C.POINTER(PTR));GV=C.CFUNCTYPE(U,PTR,PTR,C.POINTER(C.c_uint32),C.POINTER(U),PTR);AP=C.CFUNCTYPE(None,PTR,PTR,C.c_size_t)
GUIDS=['30cfe3e7-3de1-4586-be20-deaba1b3b793','6441f818-6362-4e44-b570-7dba31dd2453','ef9fc172-a1b2-4693-b327-6d32fc416042','0fd96974-23aa-4cdc-b9cb-98d17750322a','6a1ee763-d47a-43b4-aabe-ef1de2ab56fc']
class Fake:
 def __init__(self,statuses=None,mode='eight'):
  self.statuses=statuses or [0]*5;self.mode=mode;self.calls=[];self.log=[];self.errors=[];self.reentry=None
  self.st=C.create_string_buffer(120);self.bs=C.create_string_buffer(376);self.rt=C.create_string_buffer(96)
  self.locate=LO(self.lp);self.variable=GV(self.gv);self.append=AP(self.out)
  for b,off,v in [(self.st,96,C.addressof(self.bs)),(self.st,88,C.addressof(self.rt)),(self.bs,320,C.cast(self.locate,PTR).value),(self.rt,72,C.cast(self.variable,PTR).value)]:U.from_buffer(b,off).value=v
 def lp(self,g,r,out):
  guid=str(uuid.UUID(bytes_le=C.string_at(g,16)));self.calls.append(('locate',guid));idx=GUIDS.index(guid)
  out[0]=None  # Marker protocols legitimately return success plus NULL.
  return self.statuses[idx]
 def gv(self,name,guid,attrs,size,data):
  self.calls.append(('getvar',))
  if C.string_at(name,32).decode('utf-16le')!='NetworkStackVar\0':self.errors.append('name')
  if str(uuid.UUID(bytes_le=C.string_at(guid,16)))!='d1405d16-7afc-4695-bb12-41459d3695a2':self.errors.append('guid')
  if size[0]!=64:self.errors.append('unbounded buffer')
  if self.mode=='notfound':return ERR(14)
  if self.mode=='too_large':size[0]=65;return ERR(5)
  if self.mode=='lying_success':size[0]=65;return 0
  if self.mode=='damaged_notfound':C.c_uint8.from_address(data+64).value=0;return ERR(14)
  value=b'\x01\x02\x03\x04\x05\x06\x07\x08' if self.mode!='full' else bytes(range(64))
  C.memmove(data,value,len(value));size[0]=len(value);attrs[0]=7;return 0
 def out(self,ctx,data,n):
  self.log.append(C.string_at(data,n).decode('ascii'))
  if self.mode=='reentry' and self.reentry is None:self.reentry=-1;self.reentry=D.depex_probe(self.st,self.append,None)
 def run(self):return D.depex_probe(self.st,self.append,None),''.join(self.log)
class Tests(unittest.TestCase):
 def check(self,statuses=None,mode='eight'):
  f=Fake(statuses,mode);status,log=f.run();self.assertEqual(f.errors,[]);self.assertEqual(len(f.calls),6);self.assertEqual([c[1] for c in f.calls[:5]],GUIDS)
  self.assertIn('HERO_DEPEX_READONLY_D1_END',log);self.assertLess(len(log),8192);return f,status,log
 def test_null_marker_success_is_present(self):
  _,s,log=self.check();self.assertEqual(s,0)
  self.assertIn('DP_R2_DEPEX_AT_CAPTURE=0000000000000001',log);self.assertIn('DP_P6_DEPEX_AT_CAPTURE=0000000000000001',log)
  self.assertEqual(log.count('DP_INTERFACE=0000000000000000'),5)
 def test_missing_common_variable_write_blocks_both_at_capture(self):
  _,s,log=self.check([0,ERR(14),0,0,0]);self.assertEqual(s,0)
  self.assertIn('DP_R2_DEPEX_AT_CAPTURE=0000000000000000',log);self.assertIn('DP_P6_DEPEX_AT_CAPTURE=0000000000000000',log)
 def test_single_dependency_and_informational_package_list(self):
  for statuses,r2,p6 in [([ERR(14),0,0,0,0],0,1),([0,0,ERR(14),0,0],1,0),([0,0,0,0,ERR(14)],1,1)]:
   _,s,log=self.check(statuses);self.assertEqual(s,0)
   self.assertIn(f'DP_R2_DEPEX_AT_CAPTURE={r2:016X}',log);self.assertIn(f'DP_P6_DEPEX_AT_CAPTURE={p6:016X}',log)
 def test_unknown_and_false_dominance(self):
  _,s,log=self.check([ERR(14),ERR(7),0,0,0]);self.assertEqual(s,ERR(33))
  self.assertIn('DP_R2_DEPEX_AT_CAPTURE=0000000000000000',log);self.assertIn('DP_P6_DEPEX_AT_CAPTURE=0000000000000002',log)
 def test_raw_variable_size_attributes_exact(self):
  _,s,log=self.check();self.assertEqual(s,0)
  self.assertIn('DP_NETWORK_RAW=0102030405060708',log);self.assertIn('DP_NETWORK_ATTRIBUTES=0000000000000007',log)
  self.assertIn('DP_NETWORK_EXPECTED_8_BYTES=0000000000000001',log)
  (P/'mock-probe-transcript.txt').write_bytes(log.encode('ascii'))
 def test_variable_absent_not_inferred_from_zero_data(self):
  _,s,log=self.check(mode='notfound');self.assertEqual(s,0);self.assertNotIn('DP_NETWORK_RAW=',log);self.assertNotIn('DP_NETWORK_BYTE0=',log)
 def test_large_and_corrupt_reads_never_export_data(self):
  for mode in ['too_large','lying_success','damaged_notfound']:
   _,s,log=self.check(mode=mode);self.assertEqual(s,ERR(33));self.assertNotIn('DP_NETWORK_RAW=',log)
 def test_maximum_buffer_not_overread(self):
  _,s,log=self.check(mode='full');self.assertEqual(s,0);self.assertIn('DP_NETWORK_RAW='+bytes(range(64)).hex().upper(),log)
 def test_invalid_inputs_and_reentry(self):
  self.assertEqual(D.depex_probe(None,None,None),ERR(2));f,s,log=self.check(mode='reentry');self.assertEqual(s,0);self.assertEqual(f.reentry,ERR(20))
if __name__=='__main__':
 r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 report={'passed':r.wasSuccessful(),'tests':r.testsRun,'scope':'Compiled standalone C with fake LocateProtocol/GetVariable only; no hardware access.',
  'dll_sha256':hashlib.sha256((P/'depex_probe_test.dll').read_bytes()).hexdigest(),'failures':[str(t) for t,_ in r.failures],'errors':[str(t) for t,_ in r.errors]}
 (P/'tests.json').write_text(json.dumps(report,indent=2)+'\n');raise SystemExit(0 if r.wasSuccessful() else 1)
