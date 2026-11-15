"""Run the exact I3b legacy publisher using synthetic HTTP/platform callbacks."""
import copy
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
ERR = 1 << 63


class Reply(c.Structure):
    _fields_ = [('status', c.c_uint), ('body', c.c_void_p), ('length', c.c_uint64)]


CALLBACK = c.CFUNCTYPE(c.c_uint64, c.c_uint, c.c_uint, c.c_void_p, c.c_uint64, c.c_char_p, c.POINTER(Reply))


class Model:
    def __init__(self):
        partial = json.loads((ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-internal-i3-native-stack.PARTIAL.json').read_text('utf8'))
        self.docs = {r['resource_id']: copy.deepcopy(r['body']) for r in partial['resources'] if 'body' in r}
        systems_read = json.loads((ROOT / 'analysis/hero_ipmi_continued_live_20261108/responses/530-get.json').read_text('utf8'))
        self.docs[12] = copy.deepcopy(systems_read['result']['body'])
        self.expected = [json.loads((BASE / 'hero71-legacy' / name).read_bytes()) for name in (
            'system.patch.json', 'DevType1_CPU0.post.json', 'DevType2_DIMM0.post.json',
            'DevType2_DIMM1.post.json', 'DevType2_DIMM2.post.json', 'DevType2_DIMM3.post.json')]
        self.writes = []
        self.calls = []
        self.buffers = []
        self.failure = ''
        self.patch_result = 200
        self.drop_after_apply = False
        self.hidden_after_apply = False
        self.raw_overrides = {}
        self.old_system = copy.deepcopy(self.docs[1])
        self.callback = CALLBACK(self.handle)

    def add(self, item):
        resource = item + 6
        data = copy.deepcopy(self.expected[item])
        coll = 2 if item == 1 else 3
        path = self.docs[coll]['@odata.id'] + '/' + data['Id']
        data['@odata.id'] = path
        self.docs[resource] = data
        self.docs[coll]['Members'].append({'@odata.id': path})
        self.docs[coll]['Members@odata.count'] += 1

    def respond(self, ptr, code, data):
        content = data if isinstance(data, bytes) else json.dumps(data, separators=(',', ':')).encode('ascii')
        buffer = c.create_string_buffer(content)
        self.buffers.append(buffer)
        ptr[0] = Reply(code, c.addressof(buffer), len(content))
        return 0

    def handle(self, method, resource, body, size, etag, reply):
        try:
            self.calls.append((method, resource))
            if not method:
                assert not body and size == 0 and not etag
                if resource in self.raw_overrides:
                    return self.respond(reply, 200, self.raw_overrides[resource])
                document = self.old_system if self.hidden_after_apply and resource == 1 else self.docs.get(resource)
                return self.respond(reply, 200 if document is not None else 404, document or {'error': {}})
            value = json.loads(c.string_at(body, size))
            self.writes.append((method, resource, value, etag))
            if method == 2:
                assert resource == 1 and value == self.expected[0]
                assert etag.decode() == self.docs[1]['@odata.etag']
                if self.patch_result in (200, 201, 204) or self.drop_after_apply:
                    self.docs[1].update(value)
                    self.docs[1]['@odata.etag'] = '"after-system-patch"'
                if self.drop_after_apply:
                    return ERR | 18
                return self.respond(reply, self.patch_result, {})
            assert method == 1 and resource in (2, 3) and not etag
            item = next(i for i in range(1, 6) if self.expected[i]['Id'] == value['Id'])
            assert value == self.expected[item] and resource == (2 if item == 1 else 3)
            self.add(item)
            return self.respond(reply, 201, value)
        except Exception as error:
            self.failure = repr(error)
            return ERR | 33


class NativeLegacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = BASE / 'native/build'; out.mkdir(exist_ok=True)
        zig = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
        includes = ROOT / 'analysis/hero_inventory_publish_i3b_20261108/source'
        env = os.environ.copy(); env['ZIG_GLOBAL_CACHE_DIR'] = str(out / 'zig-global'); env['ZIG_LOCAL_CACHE_DIR'] = str(out / 'zig-local')
        exports = ['i71_test_reset', 'i71_test_source', 'i71_test_tls_active', 'i71_test_matches', 'i71_test_token_count',
                   'inventory_legacy71_preflight', 'inventory_legacy71_step', 'inventory_legacy71_state', 'inventory_legacy71_completed_mask']
        commands = [[str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc', '-isystem', str(zig.parent / 'lib/include'),
                     '-I', str(includes), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin',
                     '-fno-stack-protector', '-mno-red-zone', '-c', str(BASE / 'native/test_legacy71_adapter.c'), '-o', str(out / 'legacy71_test.obj')],
                    [str(zig), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/opt:ref', '/timestamp:0',
                     '/out:' + str(out / 'legacy71_test.dll'), str(out / 'legacy71_test.obj'), *['/export:' + name for name in exports]]]
        for cmd in commands:
            result = subprocess.run(cmd, env=env, cwd=BASE, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        lib = c.CDLL(str(out / 'legacy71_test.dll'))
        lib.i71_test_reset.argtypes = [CALLBACK]
        lib.i71_test_source.argtypes = [c.c_int, c.c_uint64]
        lib.i71_test_tls_active.argtypes = [c.c_int]
        lib.i71_test_matches.argtypes = [c.c_uint, c.c_char_p, c.c_uint64]
        lib.i71_test_token_count.argtypes = [c.c_char_p, c.c_uint64]
        lib.inventory_legacy71_preflight.restype = lib.inventory_legacy71_step.restype = c.c_uint64
        cls.lib = lib
        (out / 'legacy71-build.json').write_text(json.dumps({'commands': commands,
            'dll_sha256': hashlib.sha256((out / 'legacy71_test.dll').read_bytes()).hexdigest()}, indent=2) + '\n')

    def setUp(self):
        self.model = Model(); self.lib.i71_test_reset(self.model.callback)

    def tearDown(self):
        self.assertFalse(self.model.failure)

    def test_real_partial_read_shapes_pass_and_preflight_never_writes(self):
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertEqual(self.model.writes, [])
        self.assertEqual(self.lib.inventory_legacy71_state(), 1)

    def test_real_json_token_counts_are_bounded(self):
        counts = {}
        for resource in (0, 1, 2, 3, 12):
            body = json.dumps(self.model.docs[resource], separators=(',', ':')).encode('ascii')
            count = self.lib.i71_test_token_count(body, len(body))
            self.assertGreater(count, 0); self.assertLess(count, 512)
            counts[resource] = {'bytes': len(body), 'tokens': count}
        (BASE / 'native/build/real-preflight-shapes.json').write_text(json.dumps(counts, indent=2) + '\n')

    def test_six_steps_publish_exact_frozen_values_and_final_readback(self):
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        for i in range(6):
            self.assertEqual(self.lib.inventory_legacy71_step(), 0)
            self.assertEqual(len(self.model.writes), i + 1)
        self.assertEqual(self.lib.inventory_legacy71_state(), 3)
        self.assertEqual(self.lib.inventory_legacy71_completed_mask(), 63)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(len(self.model.writes), 6)

    def test_reboot_new_preflight_skips_existing_matching_resources(self):
        self.model.docs[1].update(self.model.expected[0])
        for i in range(1, 6): self.model.add(i)
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 3)
        self.assertEqual(self.model.writes, [])

    def test_same_id_different_cpu_blocks_preflight(self):
        self.model.add(1); self.model.docs[7]['TotalCores'] = 8
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.writes, [])

    def test_other_host_uuid_and_source_mismatch_block(self):
        self.model.docs[1]['UUID'] = '12345678-1234-1234-1234-123456789abc'
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.lib.i71_test_reset(self.model.callback); self.lib.i71_test_source(0, 12345)
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertEqual(self.model.writes, [])

    def test_other_real_identity_with_missing_uuid_is_not_overwritten(self):
        for field, value in [('Model', 'ProArt Z790-CREATOR WIFI'), ('Manufacturer', 'OtherVendor'), ('BiosVersion', '3002')]:
            model = Model(); self.lib.i71_test_reset(model.callback)
            model.docs[1][field] = value
            self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
            self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
            self.assertEqual(model.writes, [])

    def test_source_or_boot_changed_after_preflight_blocks(self):
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.lib.i71_test_source(1, 54321)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.writes, [])

    def test_error_http_holds_without_following_cpu_post(self):
        self.model.patch_result = 400
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        for _ in range(3): self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertEqual(len(self.model.writes), 1)

    def test_connection_lost_after_write_applied_is_not_replayed(self):
        self.model.drop_after_apply = True
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(len(self.model.writes), 1)
        self.assertEqual(self.model.docs[1]['UUID'], self.model.expected[0]['UUID'])

    def test_ack_without_matching_readback_has_three_read_attempts(self):
        self.model.hidden_after_apply = True
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        before = len(self.model.calls)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        calls = self.model.calls[before:]
        self.assertEqual(calls.count((0, 1)), 4)  # one pre-write GET + three verification GETs
        self.assertEqual(len(self.model.writes), 1)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)

    def test_metadata_race_and_missing_etag_do_not_patch(self):
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.model.docs[1]['Model'] = 'Changed'
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.writes, [])
        self.lib.i71_test_reset(self.model.callback)
        self.model.docs[1]['Model'] = ' '
        del self.model.docs[1]['@odata.etag']
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.writes, [])

    def test_escaped_duplicate_key_wrong_units_and_unknown_member_rejected(self):
        value = json.dumps(self.model.expected[3]).encode()
        self.assertEqual(self.lib.i71_test_matches(3, value, len(value)), 1)
        value = value.replace(b'32768', b'32')
        self.assertEqual(self.lib.i71_test_matches(3, value, len(value)), 0)
        value = b'{"Id":"x","\\u0049d":"y"}'
        self.assertEqual(self.lib.i71_test_matches(1, value, len(value)), 0)
        self.model.docs[2]['Members'] = [{'@odata.id': '/redfish/v1/Systems/Other/CPU0'}]
        self.model.docs[2]['Members@odata.count'] = 1
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)

    def test_post_target_appearing_between_preflight_and_step_is_skipped(self):
        self.model.docs[1].update(self.model.expected[0])
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.model.add(1)
        self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.writes, [])


if __name__ == '__main__':
    unittest.main()
