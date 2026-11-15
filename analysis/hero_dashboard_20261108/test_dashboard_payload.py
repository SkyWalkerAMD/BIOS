from pathlib import Path
import hashlib,json,unittest
import dashboard_payload as payload
import dashboard_ipmi as probe

OUT=Path(__file__).resolve().parent

class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.identity=json.loads((OUT/'identity-from-live-smbios.json').read_text())
        self.values=['3107','11/28/2025','ASUSTeK COMPUTER INC.','ROG MAXIMUS Z790 HERO','Rev 1.xx','000000000000000']
    def test_real_capture(self):
        bios,board=payload.from_records(self.identity['records'])
        self.assertEqual(bios,b'\0' + b'3107\0' + b'11/28/2025\0')
        self.assertEqual(board,b'\x02ASUSTeK COMPUTER INC.\0ROG MAXIMUS Z790 HERO\0Rev 1.xx\0'+b'000000000000000'+b'\0')
        self.assertEqual(len(bios),17)
        self.assertEqual(len(board),70)
    def test_reject_noncanonical(self):
        invalid=[(0,'31070'),(0,'ABCD'),(1,'11/31/2025'),(1,'1/28/2025'),
                 (2,''),(2,'A'*33),(3,'A'*65),(4,'x\0y'),(5,'x\ny'),(5,'字'),(5,'A'*33)]
        for index,value in invalid:
            values=self.values.copy();values[index]=value
            with self.subTest(index=index,value=value),self.assertRaises(ValueError):payload.build(*values)
    def test_duplicate_and_missing_indices(self):
        records=[r for r in self.identity['records'] if r['type'] in (0,2)]
        with self.assertRaises(ValueError):payload.from_records(records+[records[0]])
        with self.assertRaises(ValueError):payload.from_records(records[:1])
        bad=json.loads(json.dumps(records));bad[0]['strings']=[]
        with self.assertRaises(ValueError):payload.from_records(bad)
    def test_wire_plan(self):
        plan=probe.publish_plan()
        self.assertEqual([(n,c) for n,c,p in plan],[(6,1),(48,3),(48,3),(48,4),(48,3),(48,4),(48,3)])
        self.assertEqual([p[0] for n,c,p in plan if c==4],[2,0])
        self.assertTrue(all(len(p)<=192 for n,c,p in plan))
        # Creator layout: only four Type2 strings. No asset/location strings.
        self.assertNotIn(b'Default string',plan[3][2])

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PayloadTests))
    report={'passed':result.wasSuccessful(),'tests':result.testsRun,'invalid_field_cases':11,
            'source_sha256':hashlib.sha256((OUT/'dashboard_payload.py').read_bytes()).hexdigest(),
            'transport_source_sha256':hashlib.sha256((OUT/'dashboard_ipmi.py').read_bytes()).hexdigest(),
            'hardware_executed_by_tests':False}
    (OUT/'payload-tests.json').write_text(json.dumps(report,indent=2)+'\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
