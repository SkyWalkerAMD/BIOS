"""Boundary/integrity and source-identity tests; all data is synthetic."""
import copy
import struct
import unittest
import zlib
from smbios_inventory import CaptureError, compose, parse_capture


def rec(typ, handle, size, values=(), strings=()):
    b = bytearray(size)
    struct.pack_into('<BBH', b, 0, typ, size, handle)
    for offset, width, value in values:
        b[offset:offset + width] = value.to_bytes(width, 'little')
    return bytes(b) + b'\0'.join(s.encode() for s in strings) + (b'\0\0' if strings else b'\0\0')


def table():
    system = bytearray(rec(1, 1, 27, [(4, 1, 1), (5, 1, 2), (7, 1, 3)], ['ASUS', 'System Product Name', 'Default string']))
    system[8:24] = bytes.fromhex('33221100554477668899aabbccddeeff')
    return b''.join([
        rec(0, 0, 24, [(5, 1, 1)], ['3107']), bytes(system),
        rec(2, 2, 15, [(4, 1, 1), (5, 1, 2), (7, 1, 3)], ['ASUSTeK', 'ROG MAXIMUS Z790 HERO', 'BOARD-ONLY']),
        rec(4, 4, 48, [(4, 1, 1), (5, 1, 3), (7, 1, 2), (16, 1, 3),
                       (20, 2, 6200), (24, 1, 65), (35, 1, 24), (36, 1, 24), (37, 1, 32)],
            ['LGA1700', 'Intel', 'i9-14900KS']),
        rec(17, 17, 92, [(8, 2, 64), (10, 2, 64), (12, 2, 0x7fff), (16, 1, 1), (18, 1, 0x22),
                         (21, 2, 0xffff), (23, 1, 2), (24, 1, 3), (26, 1, 4), (28, 4, 32768),
                         (32, 2, 4800), (40, 1, 3), (84, 4, 6400)], ['DIMM_A2', 'Vendor', 'DIMM-REAL', 'PN']),
        rec(17, 18, 40, [(12, 2, 0), (16, 1, 1)], ['DIMM_A1']), rec(127, 65535, 4)
    ])


def capture(data=None, version=(3, 6), kind=3):
    data = table() if data is None else data
    ep = bytearray(24 if kind == 3 else 31)
    if kind == 3:
        ep[:5] = b'_SM3_'; ep[6] = len(ep); ep[7:9] = bytes(version)
        struct.pack_into('<I', ep, 12, len(data)); struct.pack_into('<Q', ep, 16, 0x4000)
        ep[5] = -sum(ep) & 255
    else:
        ep[:4] = b'_SM_'; ep[5] = len(ep); ep[6:8] = bytes(version); ep[16:21] = b'_DMI_'
        struct.pack_into('<H', ep, 22, len(data)); struct.pack_into('<I', ep, 24, 0x4000)
        struct.pack_into('<H', ep, 28, 7); ep[21] = -sum(ep[16:31]) & 255; ep[4] = -sum(ep) & 255
    from smbios_inventory import structures
    records = structures(data)
    lines = ['HERO-SMBIOS-I1', f'ENTRY{kind}_HEX_BEGIN', ep.hex(), f'ENTRY{kind}_HEX_END',
             f'SOURCE_KIND={kind:02X}', f'MAJOR={version[0]:02X}', f'MINOR={version[1]:02X}',
             'TABLE_ADDRESS=0000000000004000', f'TABLE_BOUND={len(data):08X}', f'TABLE_USED={len(data):08X}',
             f'STRUCTURES={len(records):08X}', f'TYPE127_OFFSET={records[-1]["offset"]:08X}', f'TABLE_CRC32={zlib.crc32(data):08X}']
    for typ in (0, 1, 2, 3, 4, 9, 16, 17, 41, 127):
        lines.append(f'TYPE_{typ:02X}_COUNT={sum(r["type"] == typ for r in records):08X}')
    lines += ['TABLE_HEX_BEGIN', data.hex(), 'TABLE_HEX_END', 'CAPTURE_VALID=01']
    return '\n'.join(lines) + '\n'


class Tests(unittest.TestCase):
    def payload(self, text=None):
        records, meta = parse_capture(capture() if text is None else text)
        return compose(records, meta)

    def test_actual_source_identity_and_fallback(self):
        s = self.payload()['Systems'][0]
        self.assertEqual(s['Model'], 'ROG MAXIMUS Z790 HERO')
        self.assertEqual(s['Manufacturer'], 'ASUS')
        self.assertEqual(s['BiosVersion'], '3107')
        self.assertNotIn('SerialNumber', s)  # must not copy the board serial

    def test_uuid_26_little_endian_fields(self):
        self.assertEqual(self.payload()['Systems'][0]['UUID'], '00112233-4455-6677-8899-aabbccddeeff')

    def test_uuid_before_26_network_order(self):
        self.assertEqual(self.payload(capture(version=(2, 5), kind=2))['Systems'][0]['UUID'],
                         '33221100-5544-7766-8899-aabbccddeeff')

    def test_cpu_not_donor_values(self):
        cpu = self.payload()['Systems'][0]['Processors'][0]
        self.assertEqual((cpu['TotalCores'], cpu['TotalEnabledCores'], cpu['TotalThreads']), (24, 24, 32))
        self.assertNotIn('MaxSpeedMHz', cpu)
        self.assertEqual(cpu['Id'], 'DevType1_CPU0')
        self.assertNotIn('Health', cpu['Status'])

    def test_reported_maximum_requires_explicit_inclusion(self):
        rs, meta = parse_capture(capture())
        self.assertEqual(compose(rs, meta, True)['Systems'][0]['Processors'][0]['MaxSpeedMHz'], 6200)

    def test_dimm_capacity_mib_and_transfer_rate(self):
        dimm = self.payload()['Systems'][0]['Memory'][0]
        self.assertEqual(dimm['CapacityMiB'], 32768)
        self.assertEqual(dimm['AllowedSpeedsMHz'], [6400])
        self.assertEqual(dimm['OperatingSpeedMhz'], 4800)  # donor legacy property name, no divide by 2
        self.assertEqual(dimm['MemoryDeviceType'], 'DDR5')
        self.assertNotIn('MemoryLocation', dimm)  # topology not inferred from a string

    def test_empty_dimm_is_not_omitted(self):
        dimm = self.payload()['Systems'][0]['Memory'][1]
        self.assertEqual(dimm['CapacityMiB'], 0)
        self.assertEqual(dimm['Status']['State'], 'Absent')

    def test_extended_cpu_counts(self):
        rs, meta = parse_capture(capture())
        cpu = next(r for r in rs if r['type'] == 4); b = bytearray(cpu['data'])
        b[35:38] = b'\xff\xff\xff'; struct.pack_into('<HHH', b, 42, 256, 255, 512); cpu['data'] = bytes(b)
        c = compose(rs, meta)['Systems'][0]['Processors'][0]
        self.assertEqual((c['TotalCores'], c['TotalEnabledCores'], c['TotalThreads']), (256, 255, 512))

    def test_unknown_size_not_published_as_zero(self):
        rs, meta = parse_capture(capture()); dimm = next(r for r in rs if r['type'] == 17)
        b = bytearray(dimm['data']); b[12:14] = b'\xff\xff'; dimm['data'] = bytes(b)
        d = compose(rs, meta)['Systems'][0]['Memory'][0]
        self.assertNotIn('CapacityMiB', d); self.assertNotIn('Status', d)

    def test_uuid_sentinel_omitted(self):
        for value in (0, 255):
            rs, meta = parse_capture(capture()); sy = next(r for r in rs if r['type'] == 1)
            b = bytearray(sy['data']); b[8:24] = bytes([value]) * 16; sy['data'] = bytes(b)
            self.assertNotIn('UUID', compose(rs, meta)['Systems'][0])

    def test_wrong_board_blocked(self):
        rs, meta = parse_capture(capture()); next(r for r in rs if r['type'] == 2)['strings'][1] = 'ProArt Z790 Creator'
        with self.assertRaises(CaptureError): compose(rs, meta)

    def test_bad_string_index_blocked(self):
        rs, meta = parse_capture(capture()); rec = next(r for r in rs if r['type'] == 4)
        b = bytearray(rec['data']); b[7] = 99; rec['data'] = bytes(b)
        with self.assertRaises(CaptureError): compose(rs, meta)

    def test_capture_integrity_cases(self):
        text = capture()
        invalid = [text.replace('CAPTURE_VALID=01', 'CAPTURE_VALID=00'), text + text,
                   text.replace('TABLE_HEX_END', 'TABLE_HEX_MISSING'), text.replace('TABLE_USED=', 'WRONG='),
                   text.replace('TABLE_CRC32=', 'TABLE_CRC32=1'), text.replace('STRUCTURES=00000007', 'STRUCTURES=00000008'),
                   text.replace('TYPE_04_COUNT=00000001', 'TYPE_04_COUNT=00000002'), text.replace('TABLE_ADDRESS=0000000000004000', 'TABLE_ADDRESS=0000000000005000')]
        for broken in invalid:
            with self.subTest(broken=broken[:40]), self.assertRaises(CaptureError): parse_capture(broken)

    def test_no_crc_or_health_fabrication(self):
        p = self.payload(); self.assertEqual(p['GroupCrcList'], {})
        self.assertNotIn('Health', p['Systems'][0].get('Status', {}))


if __name__ == '__main__':
    unittest.main()
