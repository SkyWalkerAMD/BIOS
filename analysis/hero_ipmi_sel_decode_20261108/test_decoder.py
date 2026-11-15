"""Validate the compiled formatter with captured records and boundary cases."""
from pathlib import Path
import ctypes as C,datetime as dt,hashlib,json,random,struct,unittest
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
DLL=C.CDLL(str(HERE/'sel_decode_test.dll'))
FN=DLL.sel_format_record;FN.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t];FN.restype=C.c_int
COUNTS={'bounded_formats':0,'captures':0};MAXIMUM={'length':0,'text':''}

def record(kind=2,stamp=0x6aeaba27,stype=8,sensor=0xe3,event=0x6f,data1=0,revision=4,rid=1):
    return struct.pack('<HBIH7B',rid,kind,stamp,0x20,revision,stype,sensor,event,data1,0xff,0xff)

def call(raw,cap=160,length=None):
    source=C.create_string_buffer(raw) if raw is not None else None
    buffer=(C.c_ubyte*(cap+32))(*([0xa5]*(cap+32)))
    status=FN(C.addressof(buffer)+16,cap,C.addressof(source) if source else None,len(raw) if length is None and raw is not None else (length or 0))
    assert bytes(buffer[:16])==b'\xa5'*16 and bytes(buffer[16+cap:])==b'\xa5'*16
    b=bytes(buffer[16:16+cap])
    if cap:assert 0 in b
    text=b.split(b'\0',1)[0].decode('ascii')
    if source is not None:assert source.raw[:len(raw)]==raw
    COUNTS['bounded_formats']+=1
    if len(text)>MAXIMUM['length']:MAXIMUM.update(length=len(text),text=text)
    return status,text

class Tests(unittest.TestCase):
    def test_system_direction_fields_and_raw(self):
        for direction,word in [(0,'ASSERT'),(0x80,'DEASSERT')]:
            raw=record(event=0x6f|direction,data1=1,rid=0x23)
            status,text=call(raw)
            self.assertEqual(status,0);self.assertIn('SYS #0023',text)
            self.assertIn('PSU(08)#E3 '+word+' E=6F/1 Failure',text)
            self.assertTrue(text.endswith(raw.hex().upper()))
            self.assertNotIn('Recovered',text)  # Deassertion is not auto-labeled healthy.
    def test_unsupported_hardware_version(self):
        raw=record(stype=0x2b,sensor=0xbf,data1=4)
        self.assertIn('Version(2B)#BF ASSERT E=6F/4 HW revision invalid',call(raw)[1])
    def test_sensor_specific_not_applied_to_generic(self):
        raw=record(stype=8,event=1,data1=1)
        text=call(raw)[1]
        self.assertIn('Lower NC rising',text);self.assertNotIn('Failure',text)
        text=call(record(stype=8,event=3,data1=1))[1]
        self.assertIn('State asserted',text);self.assertNotIn('Failure',text)
    def test_data2_and_data3_are_not_scaled_or_named(self):
        raw=bytearray(record(stype=1,event=1,data1=0xc8));raw[14:]=b'\x20\x10'
        text=call(bytes(raw))[1]
        self.assertIn('E=01/8 Upper critical falling',text)
        self.assertNotIn(' C',text);self.assertNotIn('32',text.split(' | ')[0])
        self.assertTrue(text.endswith(bytes(raw).hex().upper()))
    def test_all_preinit_and_unspecified_boundaries(self):
        for stamp in [0,1,0x12ceaa28,0x1fffffff]:
            text=call(record(stamp=stamp))[1]
            self.assertIn(f'PRE+{stamp}s',text);self.assertNotIn('BMC@',text)
        text=call(record(stamp=0xffffffff))[1]
        self.assertIn('TIME?',text);self.assertNotIn('2106',text)
    def test_calendar_boundaries_without_timezone_claim(self):
        stamps=[0x20000000,0x7fffffff,0x80000000,0xfffffffe]
        for date in ['2000-02-28T23:59:59','2000-02-29T00:00:00','2000-03-01T00:00:00',
                     '2100-02-28T23:59:59','2100-03-01T00:00:00','2026-11-08T00:00:00']:
            stamps.append(int((dt.datetime.fromisoformat(date)-dt.datetime(1970,1,1)).total_seconds()))
        for stamp in stamps:
            text=call(record(stamp=stamp))[1]
            expected=(dt.datetime(1970,1,1)+dt.timedelta(seconds=stamp)).strftime('%Y-%m-%d %H:%M:%S')
            self.assertIn('BMC@'+expected,text);self.assertNotIn('UTC',text)
    def test_oem_record_ranges_and_raw(self):
        for kind in range(0xc0,0xe0):
            raw=bytearray(record(kind=kind));raw[7:10]=bytes.fromhex('3f0a00')
            text=call(bytes(raw))[1]
            self.assertIn(f'OEM-T {kind:02X}',text);self.assertIn('MFG=000A3F',text)
            self.assertNotIn('ASSERT',text);self.assertTrue(text.endswith(bytes(raw).hex().upper()))
        for kind in range(0xe0,0x100):
            text=call(record(kind=kind))[1]
            self.assertIn(f'OEM-N {kind:02X}',text);self.assertIn('no timestamp',text)
            self.assertNotIn('BMC@',text);self.assertNotIn('ASSERT',text)
    def test_reserved_records_not_mislabeled_oem(self):
        for kind in range(0xc0):
            if kind==2:continue
            text=call(record(kind=kind))[1]
            self.assertIn(f'UNKNOWN type={kind:02X}',text)
            self.assertNotIn('OEM',text);self.assertNotIn('BMC@',text);self.assertNotIn('ASSERT',text)
    def test_system_oem_events_do_not_decode_data_offset(self):
        for event in range(0x70,0x80):
            text=call(record(event=event,stype=8,data1=1))[1]
            self.assertIn(f'ASSERT E={event:02X} OEM data',text)
            self.assertNotIn('Failure',text);self.assertNotIn('/1',text.split(' | ')[0])
    def test_unknown_event_and_evm_revision(self):
        for event in [0,0xd,0x6e]:
            text=call(record(event=event))[1]
            self.assertIn('Reserved/unspecified',text);self.assertNotIn('Presence',text)
        for rev in [0,1,2,3,5,255]:
            text=call(record(revision=rev))[1]
            self.assertIn(f'EvM={rev:02X} unsupported',text);self.assertNotIn('ASSERT',text)
    def test_invalid_lengths_and_null(self):
        for length in list(range(16))+[17,32,2**32]:
            status,text=call(bytes(32),length=length)
            self.assertEqual(status,1);self.assertEqual(text,'Invalid SEL record')
        self.assertEqual(call(None,length=16),(1,'Invalid SEL record'))
        self.assertEqual(FN(None,160,None,16),1)
    def test_all_buffer_capacities_guarded(self):
        raw=record(stype=0x28,event=1,data1=0xb)
        for cap in range(161):
            status,text=call(raw,cap=cap)
            if not cap:self.assertEqual(status,1)
            elif len(text)<len(call(raw)[1]):self.assertEqual(status,2)
            else:self.assertEqual(status,0)
    def test_standard_matrix_full_raw_fits_160(self):
        for stype in list(range(0x2d))+[0x80,0xc6,0xff]:
            for event in list(range(0xd))+[0xd,0x6e,0x6f,0x70,0x7f]:
                for offset in range(16):
                    for direction in [0,0x80]:
                        raw=record(stype=stype,event=event|direction,data1=offset|0xc0,rid=0xffff)
                        status,text=call(raw)
                        self.assertEqual(status,0);self.assertLess(len(text),160)
                        self.assertTrue(text.endswith(raw.hex().upper()))
    def test_random_records_full_raw_fits(self):
        rng=random.Random(0x53454c)
        for i in range(20000):
            raw=bytearray(rng.randbytes(16))
            if i%2:raw[2]=2;raw[9]=4
            status,text=call(bytes(raw))
            self.assertEqual(status,0);self.assertTrue(text.endswith(bytes(raw).hex().upper()))
    def test_captured_71_records(self):
        source=ROOT/'analysis/hero_ipmi_p5_field_20261104/transactions.json'
        rows=[]
        for tx in json.loads(source.read_text()):
            if tx['netfn_cmd']!='0A/43' or tx['completion_code']!=0:continue
            packet=bytes.fromhex(tx['response_hex']);self.assertEqual(len(packet),21)
            raw=packet[5:];status,text=call(raw);self.assertEqual(status,0)
            self.assertTrue(text.endswith(raw.hex().upper()))
            rows.append({'record_id':int.from_bytes(raw[:2],'little'),'record_hex':raw.hex(),'display':text})
        self.assertEqual(len(rows),15)
        self.assertIn('PRE+',rows[0]['display'])
        self.assertIn('Presence',rows[0]['display'])
        self.assertIn('Failure',rows[1]['display'])
        self.assertIn('HW revision invalid',rows[2]['display'])
        COUNTS['captures']=len(rows)
        (HERE/'captured-71-examples.json').write_text(json.dumps({'source':str(source.relative_to(ROOT)),
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'scope':'2026-11-04 captured .71 SEL bytes replayed through formatter; not a new live capture or current 29-record inventory.',
            'records':rows},indent=2)+'\n')

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'passed':result.wasSuccessful(),'tests':result.testsRun,**COUNTS,'maximum_text':MAXIMUM,
        'dll_sha256':hashlib.sha256((HERE/'sel_decode_test.dll').read_bytes()).hexdigest(),
        'sources':{n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in ['sel_decode.c','sel_decode.h','test_decoder.py']},
        'scope':'Host execution of the compiled C formatter. No firmware/BMC changes. No actual BIOS rendering verified.',
        'errors':[str(t) for t,_ in result.errors],'failures':[str(t) for t,_ in result.failures]}
    (HERE/'tests.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
