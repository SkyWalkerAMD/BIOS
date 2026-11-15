from pathlib import Path
import json
import unittest
import decode_i4_inventory as decoder

ROOT = decoder.ROOT
SAMPLE = ROOT / 'analysis/hero_pcie_collect_i4_20261108/vm/OVMF-PCIE-I4.TXT'


class DecoderTests(unittest.TestCase):
    def setUp(self):
        self.raw = SAMPLE.read_bytes()

    def test_real_ovmf(self):
        d = decoder.decode(self.raw)
        self.assertEqual(d['counts']['pci'], {'total': 6, 'decoded': 6})
        self.assertTrue(d['disk'][0]['identity']['atapi'])
        self.assertEqual(d['disk'][0]['identity']['model'], 'QEMU DVD-ROM')
        self.assertEqual(d['disk'][0]['pci_parent_bdf'], '0000:00:1F.2')
        self.assertFalse(d['publication_allowed'])

    def test_virtual_cd_not_drive(self):
        d = decoder.decode(self.raw)
        self.assertFalse(any(b['identity_collection_candidate'] for b in d['block']))

    def test_crc_failure_retained_as_error(self):
        bad = self.raw.replace(b'CONFIG_CRC32=C2D65EEC', b'CONFIG_CRC32=00000000')
        d = decoder.decode(bad)
        self.assertEqual(d['counts']['pci']['decoded'], 5)
        self.assertIn('CRC', d['pci'][0]['error'])

    def test_duplicate_field(self):
        bad = self.raw.replace(b'INDEX=00000000', b'INDEX=00000000\r\nINDEX=00000000', 1)
        with self.assertRaises(decoder.InvalidCapture):
            decoder.decode(bad)

    def test_incomplete(self):
        for tail in (b'I4_CATALOG_END', b'CAPTURE_COMPLETE=0000000000000001'):
            with self.assertRaises(decoder.InvalidCapture):
                decoder.decode(self.raw[:self.raw.index(tail)])

    def test_count_mismatch(self):
        bad = self.raw.replace(b'ENUM_COUNT=0000000000000006', b'ENUM_COUNT=0000000000000007')
        with self.assertRaises(decoder.InvalidCapture):
            decoder.decode(bad)

    def test_duplicate_handle(self):
        groups, _ = decoder.parse_catalog(self.raw)
        a, b = [r['HANDLE'].encode() for r in groups['PCI']['records'][:2]]
        with self.assertRaises(decoder.InvalidCapture):
            decoder.decode(self.raw.replace(b'HANDLE=' + b, b'HANDLE=' + a, 1))

    def test_ata_checksum_invalid(self):
        raw = bytearray(512)
        raw[510] = 0xa5
        with self.assertRaises(decoder.InvalidCapture):
            decoder.ata_identity(bytes(raw))

    def test_nvme_not_misread_as_controller(self):
        p = ROOT / 'analysis/hero_pcie_collect_i4_20261108/vm-nvme-first/OVMF-PCIE-I4.TXT'
        d = decoder.decode(p.read_bytes())
        nvme = [r for r in d['disk'] if r.get('interface_guid') == decoder.NVME]
        self.assertEqual(len(nvme), 1)
        self.assertTrue(nvme[0]['valid'])
        self.assertNotIn('model', nvme[0]['identity'])
        self.assertNotIn('serial_number', nvme[0]['identity'])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DecoderTests))
    (decoder.HERE / 'i4-decoder-tests.json').write_text(json.dumps(dict(passed=result.wasSuccessful(), tests=result.testsRun, failures=len(result.failures), errors=len(result.errors)), indent=2) + '\n', encoding='utf-8')
    raise SystemExit(not result.wasSuccessful())
