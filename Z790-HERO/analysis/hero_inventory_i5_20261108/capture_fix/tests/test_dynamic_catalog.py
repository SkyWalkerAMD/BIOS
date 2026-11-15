"""Native C catalogue tests. All inputs come from local captures or synthetic tables."""
import copy
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import unittest
import zlib

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[2]
BASE = ROOT / 'analysis/hero_inventory_20261108'
sys.path.insert(0, str(BASE))
from smbios_inventory import block, compose, parse_capture, structures
from test_smbios_inventory import rec, table


class Item(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('kind', 'index', 'json_offset', 'json_bytes', 'source_offset')]
    _fields_ += [('source_handle', c.c_uint16), ('reserved', c.c_uint16)]


class Catalog(c.Structure):
    _fields_ = [(n, c.c_uint32) for n in ('version', 'valid', 'result', 'error_offset', 'warnings',
                'item_count', 'cpu_count', 'dimm_count', 'json_bytes', 'table_bytes', 'table_crc32')]
    _fields_ += [('smbios_major', c.c_uint8), ('smbios_minor', c.c_uint8), ('reserved', c.c_uint8 * 2),
                ('uuid', c.c_char * 37), ('bios_version', c.c_char * 256), ('board_model', c.c_char * 256),
                ('board_manufacturer', c.c_char * 256), ('items', Item * 41), ('json', c.c_char * 32768)]


def raw_records(raw):
    items = structures(raw)
    return [raw[r['offset']:(items[i+1]['offset'] if i+1 < len(items) else len(raw))]
            for i, r in enumerate(items)]


def modify(raw, typ, offset, width, value, ordinal=0):
    values = raw_records(raw)
    index = [i for i, r in enumerate(values) if r[0] == typ][ordinal]
    item = bytearray(values[index]); item[offset:offset+width] = value.to_bytes(width, 'little')
    values[index] = bytes(item)
    return b''.join(values)


def replace_record(raw, typ, value, ordinal=0):
    values = raw_records(raw)
    index = [i for i, r in enumerate(values) if r[0] == typ][ordinal]
    values[index] = value
    return b''.join(values)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = HERE / 'build'; out.mkdir(exist_ok=True)
        zig = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
        env = os.environ.copy(); env['ZIG_GLOBAL_CACHE_DIR'] = str(out / 'zig-global'); env['ZIG_LOCAL_CACHE_DIR'] = str(out / 'zig-local')
        commands = [[str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc', '-isystem', str(zig.parent / 'lib/include'),
                     '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                     '-mno-red-zone', '-c', str(HERE / 'source/hero_inventory_catalog.c'), '-o', str(out / 'catalog.obj')],
                    [str(zig), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/opt:ref', '/timestamp:0',
                     '/out:' + str(out / 'catalog.dll'), str(out / 'catalog.obj'), '/export:HeroInventoryBuild',
                     '/export:HeroInventoryCatalogSize', '/export:HeroInventoryScratchSize']]
        for cmd in commands:
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=HERE)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        cls.lib = c.CDLL(str(out / 'catalog.dll'))
        cls.lib.HeroInventoryBuild.argtypes = [c.c_void_p, c.c_uint32, c.c_uint8, c.c_uint8, c.POINTER(Catalog), c.c_void_p]
        cls.lib.HeroInventoryBuild.restype = c.c_int
        cls.scratch_size = cls.lib.HeroInventoryScratchSize()
        assert cls.lib.HeroInventoryCatalogSize() == c.sizeof(Catalog)
        cls.capture = (ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_text('utf8')
        cls.actual = block(cls.capture, 'TABLE')
        (out / 'build.json').write_text(json.dumps({'commands': commands, 'catalog_bytes': c.sizeof(Catalog),
            'scratch_bytes': cls.scratch_size, 'dll_sha256': hashlib.sha256((out/'catalog.dll').read_bytes()).hexdigest()}, indent=2)+'\n')

    def build(self, raw=None, version=(3, 6), expected=0):
        raw = table() if raw is None else raw
        source = c.create_string_buffer(raw); out = Catalog(); work = c.create_string_buffer(self.scratch_size+64)
        c.memset(work, 0xA5, self.scratch_size+64)
        # Canary buffers make bounds visible without relying on an OS fault.
        guarded_type = type('Guarded', (c.Structure,), {'_fields_': [('pre', c.c_uint8*32), ('value', Catalog), ('post', c.c_uint8*32)]})
        guarded = guarded_type(); c.memset(c.addressof(guarded), 0xA5, c.sizeof(guarded))
        result = self.lib.HeroInventoryBuild(source, len(raw), *version, c.byref(guarded.value), c.byref(work,32))
        self.assertEqual(bytes(guarded.pre), b'\xA5'*32); self.assertEqual(bytes(guarded.post), b'\xA5'*32)
        self.assertEqual(c.string_at(work,32),b'\xA5'*32)
        self.assertEqual(c.string_at(c.addressof(work)+32+self.scratch_size,32),b'\xA5'*32)
        out = guarded.value
        if expected is not None: self.assertEqual(result, expected)
        if result:
            self.assertFalse(out.valid); self.assertEqual(out.result, result)
            self.assertEqual(out.item_count, 0); self.assertEqual(out.json_bytes, 0)
            return out, [], []
        self.assertEqual(out.valid, 1)
        bodies = []
        for item in out.items[:out.item_count]:
            data = c.string_at(c.addressof(out) + Catalog.json.offset + item.json_offset, item.json_bytes)
            self.assertEqual(c.string_at(c.addressof(out) + Catalog.json.offset + item.json_offset + item.json_bytes, 1), b'\0')
            bodies.append(data)
        return out, [json.loads(x) for x in bodies], bodies

    def test_actual_six_items_byte_identical_to_frozen_legacy(self):
        out, docs, bodies = self.build(self.actual, (3, 5))
        names = ['system.patch.json', 'DevType1_CPU0.post.json'] + [f'DevType2_DIMM{i}.post.json' for i in range(4)]
        self.assertEqual(out.item_count, 6); self.assertEqual(out.cpu_count, 1); self.assertEqual(out.dimm_count, 4)
        self.assertEqual(out.uuid.decode(), '9b296595-55eb-e689-5fd2-08bfb8eeda44')
        self.assertEqual(out.table_crc32, zlib.crc32(self.actual))
        report = []
        for name, body in zip(names, bodies):
            expected = (BASE / 'hero71-legacy' / name).read_bytes()
            self.assertEqual(body, expected)
            report.append({'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'byte_identical': True})
        (HERE / 'build/actual-parity.json').write_text(json.dumps(report, indent=2)+'\n')

    def test_current_capture_unconsumed_type34_is_not_decoded(self):
        text = (ROOT / 'analysis/hero_ipmi_complete_live_20261108/hero71-i1-current.TXT').read_text('ascii')
        raw = block(text, 'TABLE')
        self.assertEqual(len(raw), 5971)
        self.assertEqual(zlib.crc32(raw), 0x8B120398)
        out, docs, bodies = self.build(raw, (3, 5))
        old, old_docs, old_bodies = self.build(self.actual, (3, 5))
        self.assertEqual(bodies, old_bodies)
        self.assertEqual(out.item_count, 6)
        self.assertNotEqual(out.table_crc32, old.table_crc32)
        self.assertEqual(raw[3390], 0x8B)
        self.assertTrue(all(b'18668b447074616c' not in x for x in bodies))

    def test_unconsumed_strings_do_not_escape_into_inventory(self):
        for typ in (34, 128, 200):
            unused = bytes([typ, 4, typ, 2]) + b'Unused\x00\x18\x66\x8b\xfc\x00\x00'
            raw = table()[:-6] + unused + table()[-6:]
            self.assertEqual(self.build(raw)[2], self.build()[2])
        # This second CPU string is not selected by any published field.
        unused_cpu = rec(4,4,48,[(16,1,1)],['Model'])[:-1] + b'\xff\xfe\x00\x00'
        self.assertEqual(self.build(replace_record(table(),4,unused_cpu))[1][1]['Model'], 'Model')

    def test_unconsumed_record_still_requires_structural_bounds(self):
        raw = table()[:-6] + b'\x80\x04\x01\x02' + b'\xff' * 256 + b'\0\0' + table()[-6:]
        self.build(raw, expected=6)
        self.build(table()[:-6] + b'\x80\x04\x01\x02\xff\x00', expected=3)

    def test_synthetic_semantic_parity_with_python_reference(self):
        raw = table(); records = structures(raw)
        source = compose(records, {'major': 3, 'minor': 6})['Systems'][0]
        expected_system = {k: source[k] for k in ('Model', 'Manufacturer', 'BiosVersion', 'UUID', 'SerialNumber', 'SKU') if k in source}
        _, docs, _ = self.build(raw)
        self.assertEqual(docs, [expected_system] + source['Processors'] + source['Memory'])

    def test_uuid_versions_and_sentinels(self):
        _, modern, _ = self.build(version=(2, 6)); _, old, _ = self.build(version=(2, 5))
        self.assertEqual(modern[0]['UUID'], '00112233-4455-6677-8899-aabbccddeeff')
        self.assertEqual(old[0]['UUID'], '33221100-5544-7766-8899-aabbccddeeff')
        for value in (0, (1<<128)-1): self.build(modify(table(), 1, 8, 16, value), expected=10)

    def test_identity_uses_own_records_and_omits_placeholders_board_serial(self):
        out, docs, _ = self.build()
        self.assertEqual(out.bios_version.decode(), '3107')
        self.assertEqual(out.board_model.decode(), 'ROG MAXIMUS Z790 HERO')
        self.assertEqual(docs[0]['Manufacturer'], 'ASUS'); self.assertNotIn('SerialNumber', docs[0])
        self.assertNotIn('BOARD-ONLY', json.dumps(docs))
        raw = replace_record(table(), 0, rec(0, 0, 24, [(5,1,1)], ['NEXT-BIOS']))
        self.assertEqual(self.build(raw)[1][0]['BiosVersion'], 'NEXT-BIOS')

    def test_json_escaping_unicode_and_whitespace(self):
        model = '  CPU "quoted" \\ café 中文 😀\u3000'
        raw = replace_record(table(), 4, rec(4,4,48,[(16,1,1),(5,1,3)], [model]))
        _, docs, bodies = self.build(raw)
        self.assertEqual(docs[1]['Model'], model.strip())
        self.assertTrue(all(x<128 for x in bodies[1]))
        self.assertIn(b'\\u00e9', bodies[1]); self.assertIn(b'\\ud83d\\ude00', bodies[1])

    def test_utf8_invalid_overlong_surrogates_and_controls_rejected(self):
        for suffix in (b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\x80', b'A\x01B', b'A\x7fB'):
            raw = replace_record(table(), 4, rec(4,4,48,[(16,1,1)], ['PLACE']))
            raw = raw.replace(b'PLACE\0\0', suffix+b'\0\0')
            self.build(raw, expected=4)

    def test_invalid_string_index_cannot_read_next_record(self):
        self.build(modify(table(),4,16,1,255), expected=5)

    def test_string_limit_is_bounded(self):
        raw = replace_record(table(),4,rec(4,4,48,[(16,1,1)],['x'*255]))
        self.assertEqual(len(self.build(raw)[1][1]['Model']),255)
        self.build(raw.replace(b'x'*255,b'x'*256),expected=6)

    def test_each_required_type_missing_and_singletons_ambiguous(self):
        for typ in (0,1,2,4,17):
            data = b''.join(r for r in raw_records(table()) if r[0]!=typ)
            self.build(data,expected=8)
        for typ in (0,1,2):
            values = raw_records(table()); extra = bytearray(next(r for r in values if r[0]==typ))
            extra[2:4]=(300+typ).to_bytes(2,'little'); values.insert(-1,bytes(extra))
            self.build(b''.join(values),expected=9)

    def test_duplicate_handle_and_truncated_structure(self):
        self.build(modify(table(),4,2,2,2),expected=7)
        for broken in (table()[:-1],table()[:-6],b'\x00\x03\x00\x00\x00\x00',table()+b'\0'):
            self.build(broken,expected=3)

    def test_consumed_types_require_their_base_layout(self):
        for typ, handle, minimum in ((0,0,18),(1,1,25),(2,2,8),(4,4,26),(17,17,21)):
            self.build(replace_record(table(),typ,rec(typ,handle,minimum-1)),expected=3)

    def test_missing_identity_and_invalid_argument_overlap_fail(self):
        self.build(modify(table(),0,5,1,0),expected=11)
        out=Catalog();work=c.create_string_buffer(self.scratch_size);raw=c.create_string_buffer(table())
        self.assertEqual(self.lib.HeroInventoryBuild(raw,len(table()),3,6,c.byref(out),work),0)
        old=c.string_at(c.byref(out),c.sizeof(out))
        self.assertEqual(self.lib.HeroInventoryBuild(c.byref(out),len(table()),3,6,c.byref(out),work),1)
        self.assertEqual(c.string_at(c.byref(out),c.sizeof(out)),old)
        self.assertEqual(self.lib.HeroInventoryBuild(None,0,3,6,c.byref(out),work),1)

    def test_table_length_version_and_end_marker_boundaries(self):
        self.build(b'\0'*5,expected=2); self.build(b'\0'*262145,expected=2)
        self.build(version=(4,0),expected=14)
        self.build(replace_record(table(),127,rec(127,65535,5)),expected=3)
        self.build(replace_record(table(),127,rec(127,65535,4,strings=['extra'])),expected=3)

    def test_extended_cpu_counts_and_old_short_255(self):
        raw=table()
        for off in (35,36,37): raw=modify(raw,4,off,1,255)
        for off,value in ((42,256),(44,255),(46,512)): raw=modify(raw,4,off,2,value)
        cpu=self.build(raw)[1][1]
        self.assertEqual([cpu[k] for k in ('TotalCores','TotalEnabledCores','TotalThreads')],[256,255,512])
        short=rec(4,4,38,[(35,1,255),(36,1,255),(37,1,255)])
        cpu=self.build(replace_record(table(),4,short))[1][1]
        self.assertEqual(cpu['TotalCores'],255); self.assertEqual(cpu['TotalThreads'],255)

    def test_unknown_and_reserved_cpu_counts_omitted(self):
        raw=table()
        for off in (35,36,37): raw=modify(raw,4,off,1,0)
        cpu=self.build(raw)[1][1]; self.assertNotIn('TotalCores',cpu)
        raw=modify(raw,4,35,1,255);raw=modify(raw,4,42,2,65535)
        self.assertNotIn('TotalCores',self.build(raw)[1][1])

    def test_empty_unknown_mib_and_kib_capacity_cases(self):
        for raw_size, expected_cap, expected_state in ((0,0,'Absent'),(65535,None,None),(1024,1024,'Enabled'),(0x8400,1,'Enabled'),(0x8100,None,'Enabled'),(0x8000,None,'Enabled')):
            out,docs,_=self.build(modify(table(),17,12,2,raw_size))
            dimm=docs[2]
            self.assertEqual(dimm.get('CapacityMiB'),expected_cap)
            self.assertEqual(dimm.get('Status',{}).get('State'),expected_state)

    def test_extended_size_maximum_and_reserved_bit(self):
        self.assertEqual(self.build(modify(table(),17,28,4,0x7fffffff))[1][2]['CapacityMiB'],0x7fffffff)
        self.assertNotIn('CapacityMiB',self.build(modify(table(),17,28,4,0))[1][2])
        for bad in (0x80000000,0xffffffff): self.build(modify(table(),17,28,4,bad),expected=13)

    def test_unknown_and_extended_speed_no_division_by_two(self):
        raw=modify(table(),17,21,2,0);raw=modify(raw,17,32,2,0)
        dimm=self.build(raw)[1][2]
        self.assertNotIn('AllowedSpeedsMHz',dimm);self.assertNotIn('OperatingSpeedMhz',dimm)
        raw=modify(table(),17,84,4,65535);raw=modify(raw,17,32,2,65535);raw=modify(raw,17,88,4,65536)
        dimm=self.build(raw)[1][2]
        self.assertEqual(dimm['AllowedSpeedsMHz'],[65535]);self.assertEqual(dimm['OperatingSpeedMhz'],65536)
        self.build(modify(raw,17,84,4,0x80000000),expected=13)

    def test_short_record_missing_extended_size_or_speed_is_omitted(self):
        raw=replace_record(table(),17,rec(17,17,28,[(12,2,32767),(21,2,65535)]))
        dimm=self.build(raw)[1][2]
        self.assertNotIn('CapacityMiB',dimm);self.assertNotIn('AllowedSpeedsMHz',dimm)

    def test_no_invented_health_crc_or_cpu_clock(self):
        out,docs,_=self.build()
        for obj in docs:self.assertNotIn('Health',obj.get('Status',{}))
        self.assertNotIn('MaxSpeedMHz',docs[1]); self.assertNotIn('GroupCrcList',docs[0])

    def test_count_bounds_preserve_all_slots_including_empty(self):
        values=raw_records(table()); values=[v for v in values if v[0] not in (4,17)]
        cpus=[rec(4,100+i,38,[(5,1,3)]) for i in range(8)]
        dimms=[rec(17,200+i,28,[(12,2,0)]) for i in range(32)]
        raw=b''.join(values[:-1]+cpus+dimms+values[-1:]); out,docs,_=self.build(raw)
        self.assertEqual(out.item_count,41);self.assertEqual(docs[-1]['Id'],'DevType2_DIMM31')
        self.build(b''.join(values[:-1]+cpus+[rec(4,190,38)]+dimms+values[-1:]),expected=6)
        self.build(b''.join(values[:-1]+cpus+dimms+[rec(17,299,28)]+values[-1:]),expected=6)

    def test_total_json_limit_invalidates_whole_catalogue(self):
        values=[v for v in raw_records(table()) if v[0]!=17]
        dims=[rec(17,200+i,28,[(16,1,1),(23,1,1),(24,1,1),(26,1,1)],['中'*85]) for i in range(32)]
        self.build(b''.join(values[:-1]+dims+values[-1:]),expected=12)

    def test_deterministic_bytes_with_randomized_caller_scratch(self):
        expected=self.build(self.actual,(3,5))[2]
        out=Catalog();work=c.create_string_buffer(self.scratch_size);src=c.create_string_buffer(self.actual)
        c.memset(c.addressof(out),0xAA,c.sizeof(out));c.memset(work,0x55,self.scratch_size)
        self.assertEqual(self.lib.HeroInventoryBuild(src,len(self.actual),3,5,c.byref(out),work),0)
        result=[c.string_at(c.addressof(out)+Catalog.json.offset+i.json_offset,i.json_bytes) for i in out.items[:out.item_count]]
        self.assertEqual(result,expected)

    def test_seeded_corruptions_never_exceed_declared_bounds(self):
        rng=random.Random(0x713107)
        raw=self.actual
        for _ in range(400):
            bad=bytearray(raw)
            for _ in range(rng.randrange(1,5)):bad[rng.randrange(len(bad))]=rng.randrange(256)
            out,docs,bodies=self.build(bytes(bad),(3,5),expected=None)
            if out.valid:
                self.assertLessEqual(out.json_bytes,32768);self.assertLessEqual(len(docs),41)
                self.assertTrue(all(body.startswith(b'{') and body.endswith(b'}') for body in bodies))


if __name__=='__main__':unittest.main()
