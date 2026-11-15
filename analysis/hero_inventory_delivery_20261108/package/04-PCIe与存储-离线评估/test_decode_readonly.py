"""Synthetic decoder boundary tests plus real historical SMBIOS assertions."""
from pathlib import Path
import hashlib,json,struct,unittest
from decode_readonly import CaptureError,decode_pci,decode_path,block_observation
OUT=Path(__file__).resolve().parent
def config(header=0):
 b=bytearray(256);struct.pack_into('<HH',b,0,0x8086,0x1234);b[14]=header;b[9:12]=bytes((2,8,1));return b
def path(*nodes):return b''.join(nodes)+bytes.fromhex('7FFF0400')
NVME=struct.pack('<BBHIQ',3,23,16,1,0)
SATA=struct.pack('<BBHHHH',3,18,10,2,0xffff,0)
USB=bytes.fromhex('030506000100')
MEDIA=dict(media_present=True,logical_partition=False,removable=False,read_only=False,last_block=99,block_size=512,media_id=1)
class Tests(unittest.TestCase):
 def test_standard_header(self):
  b=config();b[44:48]=bytes.fromhex('43107856');r=decode_pci(bytes(b),0,1,0,0)
  self.assertEqual(r['class_code'],'0x010802');self.assertEqual(r['subsystem_id'],'0x5678');self.assertFalse(r['publication_allowed'])
 def test_bridge_not_subsystem(self):self.assertNotIn('subsystem_id',decode_pci(bytes(config(1)),0,0,1,0))
 def test_absent(self):
  with self.assertRaises(CaptureError):decode_pci(bytes([255])*256,0,0,0,0)
 def test_bad_address(self):
  for bdf in ((65536,0,0,0),(0,256,0,0),(0,0,32,0),(0,0,0,8),(False,0,0,0)):
   with self.assertRaises(CaptureError):decode_pci(bytes(config()),*bdf)
 def test_bound(self):
  for n in (0,64,255,257,4096):
   with self.assertRaises(CaptureError):decode_pci(bytes(n),0,0,0,0)
 def test_pcie_link(self):
  b=config();b[6]=16;b[52]=64;b[64:68]=bytes((16,0,2,0));struct.pack_into('<I',b,76,5|(16<<4));struct.pack_into('<H',b,82,4|(8<<4))
  r=decode_pci(bytes(b),0,1,0,0)['pcie'];self.assertEqual((r['max_speed_raw'],r['max_lanes_raw'],r['speed_raw'],r['lanes_raw']),(5,16,4,8))
 def test_rc_endpoint_no_link(self):
  b=config();b[6]=16;b[52]=252;b[252:]=bytes((16,0,0x92,0));self.assertNotIn('speed_raw',decode_pci(bytes(b),0,0,2,0)['pcie'])
 def test_truncated_pcie(self):
  b=config();b[6]=16;b[52]=252;b[252:]=bytes((16,0,2,0))
  with self.assertRaises(CaptureError):decode_pci(bytes(b),0,0,0,0)
 def test_cap_cycle(self):
  b=config();b[6]=16;b[52]=64;b[64:66]=bytes((1,64))
  with self.assertRaises(CaptureError):decode_pci(bytes(b),0,0,0,0)
 def test_cap_pointer(self):
  for ptr in (2,63,65,255):
   b=config();b[6]=16;b[52]=ptr
   with self.assertRaises(CaptureError):decode_pci(bytes(b),0,0,0,0)
 def test_nvme_path(self):self.assertEqual(decode_path(path(NVME))['namespace']['id'],1)
 def test_device_path_bounds(self):
  for raw in (b'',b'\x03\x17\x00\x00',NVME,bytes.fromhex('7F010400'),bytes.fromhex('7FFF040000'),b'\x01\x01\x06\x00\xff\x00'+path(),path(*([bytes.fromhex('01020400')]*64))):
   with self.assertRaises(CaptureError):decode_path(raw)
 def test_namespace_capacity_not_drive(self):
  r=block_observation(MEDIA,path(NVME));self.assertTrue(r['identity_collection_candidate']);self.assertEqual(r['address_space_capacity_bytes'],51200);self.assertIsNone(r['physical_drive_capacity_bytes']);self.assertFalse(r['publication_allowed'])
 def test_sata_candidate(self):self.assertTrue(block_observation(MEDIA,path(SATA))['identity_collection_candidate'])
 def test_virtual_usb_and_cdrom(self):
  for raw in (path(USB),path(USB,NVME),path(bytes.fromhex('04020400'))):self.assertIn('external_or_virtual_media',block_observation(MEDIA,raw)['exclusions'])
 def test_partition_and_missing(self):
  self.assertIn('partition',block_observation(dict(MEDIA,logical_partition=True),path(NVME))['exclusions'])
  self.assertIsNone(block_observation(dict(MEDIA,media_present=False),path(NVME))['address_space_capacity_bytes'])
 def test_capacity_overflow(self):
  with self.assertRaises(CaptureError):block_observation(dict(MEDIA,last_block=0xffffffffffffffff),path(NVME))
 def test_bad_media(self):
  for change in ({'block_size':0},{'block_size':513},{'block_size':33554432},{'last_block':-1},{'read_only':0}):
   with self.assertRaises(CaptureError):block_observation(dict(MEDIA,**change),path(NVME))
 def test_real_smbios_limitations(self):
  evidence=json.loads((OUT/'hero71-smbios-pcie.json').read_text())
  self.assertEqual(evidence['metadata']['table_sha256'],'940783c88715c867508eea91c92e3642d737a948774c3475b19da9481e405162')
  rows=[r for r in evidence['slots_and_onboard'] if r['type']==9]
  self.assertEqual(len(rows),6);self.assertEqual(sum(r['address_known'] for r in rows),2)
  self.assertEqual({r['designation']:r['bdf'] for r in rows if r['address_known']},{'PCIEX4(G4)':'0000:00:1B.4','M.2_2':'0000:00:1D.0'})
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
 with (OUT/'decoder-tests.txt').open('w',encoding='utf-8') as f:r=unittest.TextTestRunner(stream=f,verbosity=2).run(suite)
 result=dict(tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),hardware_operations=0,source_sha256=hashlib.sha256((OUT/'decode_readonly.py').read_bytes()).hexdigest())
 (OUT/'decoder-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));raise SystemExit(not r.wasSuccessful())
