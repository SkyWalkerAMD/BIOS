"""Exercise real prior failing bytes and corruption checks; never build a CAP."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
import build_candidate as build
from verify_candidate import strict_new_driver

ROOT = build.ROOT
FIXED = ROOT / 'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/R2-sectionfix.ffs'


def digest(b):
    return hashlib.sha256(b).hexdigest()


def reheader(data):
    data = bytearray(data)
    data[20:23] = len(data).to_bytes(3, 'little')
    data[16] = 0
    data[16] = -(sum(data[:16]) + sum(data[18:23])) & 255
    return bytes(data)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.good = FIXED.read_bytes()
        self.temp = tempfile.TemporaryDirectory(dir=build.HERE, prefix='guard-')
        self.path = Path(self.temp.name) / 'driver.ffs'

    def tearDown(self):
        assert Path(self.temp.name).resolve().is_relative_to(build.HERE.resolve())
        self.temp.cleanup()

    def entry(self, data):
        self.path.write_bytes(data)
        pe = build.strict_sections(self.good[24:])[1][1]
        return dict(path=str(self.path.relative_to(ROOT)), sha256=digest(data),
                    pe_sha256=digest(pe), guid=build.R2, role='sensors_dashboard')

    def test_real_fixed_driver(self):
        guid, data, meta = build.driver_artifact(self.entry(self.good))
        self.assertEqual(guid, build.R2)
        self.assertEqual(meta['pe_bytes'], 22016)
        strict_new_driver(data)

    def test_original_two_byte_tail_regression(self):
        bad = reheader(self.good + b'\0\0')
        with self.assertRaises(ValueError):
            build.driver_artifact(self.entry(bad))
        with self.assertRaises(AssertionError):
            strict_new_driver(bad)

    def test_bad_checksum(self):
        bad = bytearray(self.good)
        bad[16] ^= 1
        with self.assertRaises(ValueError):
            build.driver_artifact(self.entry(bytes(bad)))

    def test_changed_ffs_hash(self):
        entry = self.entry(self.good)
        entry['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            build.driver_artifact(entry)

    def test_changed_pe_hash(self):
        entry = self.entry(self.good)
        entry['pe_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            build.driver_artifact(entry)

    def test_mismatched_guid(self):
        entry = self.entry(self.good)
        entry['guid'] = build.P6
        with self.assertRaises(ValueError):
            build.driver_artifact(entry)

    def test_inventory_cannot_replace_sensor(self):
        entry = self.entry(self.good)
        entry['role'] = 'inventory'
        with self.assertRaises(ValueError):
            build.driver_artifact(entry)

    def test_section_truncation(self):
        body = self.good[24:]
        for cut in (1, 2, 3, 4):
            with self.assertRaises(ValueError):
                build.strict_sections(body[:-cut])


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(GuardTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    (build.HERE / 'builder-guard-tests.json').write_text(json.dumps(dict(
        passed=result.wasSuccessful(), tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors),
        actual_fixed_r2_sha256=digest(FIXED.read_bytes()), firmware_generated=False), indent=2) + '\n')
    raise SystemExit(not result.wasSuccessful())
