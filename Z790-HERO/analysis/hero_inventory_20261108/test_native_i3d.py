"""I3d native continuation tests with actual .71 response fixtures and mocked I/O.

This executes the production C engine in a native DLL. It performs no network,
USB, firmware or BMC operations; only callback-owned in-memory documents change.
"""
import copy
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

from test_native_legacy71 import CALLBACK, ERR, Model as LegacyModel

BASE = Path(__file__).resolve().parent
HERE = BASE / 'native_i3d'
ROOT = BASE.parents[1]
SUMMARY = json.loads((HERE / 'processor-summary.patch.json').read_bytes())


class Model(LegacyModel):
    def __init__(self):
        super().__init__()
        self.docs[1] = json.loads((ROOT / 'analysis/hero_ipmi_continued_live_20261108/responses/697-get.json').read_text('utf8'))['result']['body']
        self.docs[2] = json.loads((BASE / 'cpu-orphan-collection-701.json').read_text('utf8'))['result']['body']
        self.docs[7] = json.loads((BASE / 'cpu-orphan-member-702.json').read_text('utf8'))['result']['body']
        self.index_new = False
        self.http_get = {}
        self.transport_get = set()
        self.post_result = 201
        self.summary_result = 204
        self.lose_post = False
        self.lose_summary = False
        self.corrupt_post_readback = False
        self.hide_post_readback = False
        self.hide_summary_readback = False
        self.before_get = None

    def add_orphan(self, item):
        self.add(item)
        coll = 2 if item == 1 else 3
        self.docs[coll]['Members'] = [x for x in self.docs[coll]['Members'] if x['@odata.id'] != self.docs[item+6]['@odata.id']]
        self.docs[coll]['Members@odata.count'] = len(self.docs[coll]['Members'])

    def handle(self, method, resource, body, size, etag, reply):
        try:
            self.calls.append((method, resource))
            if not method:
                assert not body and size == 0 and not etag
                if self.before_get:
                    self.before_get(resource)
                if resource in self.transport_get:
                    return ERR | 18
                if resource in self.http_get:
                    return self.respond(reply, self.http_get[resource], {'error': {}})
                if resource in self.raw_overrides:
                    return self.respond(reply, 200, self.raw_overrides[resource])
                value = self.docs.get(resource)
                return self.respond(reply, 200 if value is not None else 404, value or {'error': {}})
            value = json.loads(c.string_at(body, size))
            self.writes.append((method, resource, value, etag))
            if method == 2:
                assert resource == 1 and value == SUMMARY
                assert etag.decode() == self.docs[1]['@odata.etag']
                if (self.summary_result in (200, 201, 204) or self.lose_summary) and not self.hide_summary_readback:
                    self.docs[1].setdefault('ProcessorSummary', {}).update(copy.deepcopy(value['ProcessorSummary']))
                    self.docs[1]['@odata.etag'] = '"after-summary"'
                if self.lose_summary:
                    return ERR | 18
                return self.respond(reply, self.summary_result, {})
            # I3d is deliberately unable to create a CPU or rewrite identity.
            assert method == 1 and resource == 3 and not etag
            item = next(i for i in range(2, 6) if self.expected[i]['Id'] == value['Id'])
            assert value == self.expected[item]
            if (self.post_result in (200, 201, 204) or self.lose_post) and not self.hide_post_readback:
                if self.index_new:
                    self.add(item)
                else:
                    self.add_orphan(item)
                if self.corrupt_post_readback:
                    self.docs[item+6]['CapacityMiB'] += 1
            if self.lose_post:
                return ERR | 18
            return self.respond(reply, self.post_result, {})
        except Exception as error:
            self.failure = repr(error)
            return ERR | 33


class NativeI3dTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = HERE / 'build'; out.mkdir(exist_ok=True)
        zig = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
        includes = ROOT / 'analysis/hero_inventory_publish_i3b_20261108/source'
        env = os.environ.copy(); env['ZIG_GLOBAL_CACHE_DIR'] = str(out / 'zig-global'); env['ZIG_LOCAL_CACHE_DIR'] = str(out / 'zig-local')
        exports = ['i71_test_reset', 'i71_test_source', 'i71_test_tls_active', 'i71_test_matches', 'i71_test_token_count',
                   'inventory_legacy71_preflight', 'inventory_legacy71_step', 'inventory_legacy71_state',
                   'inventory_legacy71_completed_mask', 'inventory_legacy71_indexed_mask',
                   'inventory_legacy71_summary_step', 'inventory_legacy71_summary_state', 'inventory_legacy71_write_allowed']
        commands = [[str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc', '-isystem', str(zig.parent / 'lib/include'),
                     '-I', str(includes), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin',
                     '-fno-stack-protector', '-mno-red-zone', '-c', str(HERE / 'test_legacy71_adapter.c'), '-o', str(out / 'i3d_test.obj')],
                    [str(zig), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/opt:ref', '/timestamp:0',
                     '/out:' + str(out / 'i3d_test.dll'), str(out / 'i3d_test.obj'), *['/export:' + name for name in exports]]]
        for cmd in commands:
            result = subprocess.run(cmd, env=env, cwd=BASE, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
        cls.lib = c.CDLL(str(out / 'i3d_test.dll'))
        cls.lib.i71_test_reset.argtypes = [CALLBACK]
        cls.lib.i71_test_source.argtypes = [c.c_int, c.c_uint64]
        cls.lib.i71_test_tls_active.argtypes = [c.c_int]
        cls.lib.inventory_legacy71_write_allowed.argtypes = [c.c_uint, c.c_uint, c.c_char_p, c.c_uint64]
        for name in ('inventory_legacy71_preflight', 'inventory_legacy71_step', 'inventory_legacy71_summary_step'):
            getattr(cls.lib, name).restype = c.c_uint64
        (out / 'build.json').write_text(json.dumps({'commands': commands, 'dll_sha256': hashlib.sha256((out / 'i3d_test.dll').read_bytes()).hexdigest()}, indent=2) + '\n')

    def setUp(self):
        self.model = Model(); self.lib.i71_test_reset(self.model.callback)

    def tearDown(self):
        self.assertFalse(self.model.failure)

    def ready(self):
        self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)

    def test_actual_orphan_and_system_are_reused_with_five_direct_probes(self):
        self.ready()
        self.assertEqual(self.lib.inventory_legacy71_completed_mask(), 3)
        self.assertEqual(self.lib.inventory_legacy71_indexed_mask(), 0)
        for resource in range(7, 12): self.assertIn((0, resource), self.model.calls)
        self.assertFalse(self.model.writes)

    def test_member_requires_exact_uri_even_when_body_values_match(self):
        del self.model.docs[7]['@odata.id']
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.model.docs[7]['@odata.id'] = '/redfish/v1/Systems/Other/Processors/DevType1_CPU0'
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertFalse(self.model.writes)

    def test_transport_guard_only_accepts_four_frozen_dimms_and_summary(self):
        for item in range(6):
            data = json.dumps(self.model.expected[item], separators=(',', ':')).encode('ascii')
            for method in range(4):
                for resource in range(13):
                    result = self.lib.inventory_legacy71_write_allowed(method, resource, data, len(data))
                    self.assertEqual(bool(result), item >= 2 and method == 1 and resource == 3)
        summary = (HERE / 'processor-summary.patch.json').read_bytes()
        self.assertTrue(self.lib.inventory_legacy71_write_allowed(2, 1, summary, len(summary)))
        self.assertFalse(self.lib.inventory_legacy71_write_allowed(2, 1, summary + b' ', len(summary)+1))
        self.assertFalse(self.lib.inventory_legacy71_write_allowed(2, 1, None, 0))

    def test_four_dimm_posts_direct_success_collection_warning(self):
        self.ready()
        for item in range(2, 6):
            self.assertEqual(self.lib.inventory_legacy71_step(), 0)
            self.assertEqual(len(self.model.writes), item-1)
        self.assertEqual(self.lib.inventory_legacy71_state(), 4)
        self.assertEqual(self.lib.inventory_legacy71_completed_mask(), 63)
        self.assertEqual(self.lib.inventory_legacy71_indexed_mask(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)

    def test_complete_collections_receive_distinct_full_success_state(self):
        self.model.docs[2]['Members'] = [{'@odata.id': self.model.docs[7]['@odata.id']}]
        self.model.docs[2]['Members@odata.count'] = 1
        self.model.index_new = True
        self.ready()
        for _ in range(4): self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 3)
        self.assertEqual(self.lib.inventory_legacy71_indexed_mask(), 62)

    def test_existing_matching_dimm_orphan_is_not_reposted(self):
        self.model.add_orphan(2)
        self.ready()
        self.assertEqual(self.lib.inventory_legacy71_completed_mask(), 7)
        self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.writes[0][2]['Id'], 'DevType2_DIMM1')

    def test_reboot_with_all_orphans_completes_read_only(self):
        for item in range(2, 6): self.model.add_orphan(item)
        self.ready()
        self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 4)
        self.assertFalse(self.model.writes)

    def test_same_id_different_dimm_blocks_even_with_empty_collection(self):
        self.model.add_orphan(3); self.model.docs[9]['CapacityMiB'] = 32
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertFalse(self.model.writes)

    def test_missing_cpu_blocks_continuation_instead_of_recreating(self):
        del self.model.docs[7]
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertFalse(self.model.writes)

    def test_different_cpu_and_system_are_never_overwritten(self):
        self.model.docs[7]['Model'] = 'Another CPU'
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.model = Model(); self.lib.i71_test_reset(self.model.callback)
        self.model.docs[1]['BiosVersion'] = '3001'
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertFalse(self.model.writes)

    def test_member_appearing_as_orphan_after_preflight_is_skipped(self):
        self.ready(); self.model.add_orphan(2)
        self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertFalse(self.model.writes)
        self.assertEqual(self.lib.inventory_legacy71_completed_mask(), 7)

    def test_member_appearing_with_different_values_blocks_post(self):
        self.ready(); self.model.add_orphan(2); self.model.docs[8]['DeviceLocator'] = 'different'
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertFalse(self.model.writes)

    def test_only_actual_404_authorizes_creation(self):
        for code in (401, 403, 409, 500, 503):
            model = Model(); self.lib.i71_test_reset(model.callback); model.http_get[8] = code
            self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
            self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
            self.assertFalse(model.writes)

    def test_fresh_direct_get_transport_failure_never_posts(self):
        self.ready(); self.model.transport_get.add(8)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertFalse(self.model.writes)

    def test_advertised_but_missing_member_is_not_recreated(self):
        path = self.model.docs[3]['@odata.id'] + '/DevType2_DIMM0'
        self.model.docs[3]['Members'] = [{'@odata.id': path}]; self.model.docs[3]['Members@odata.count'] = 1
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertFalse(self.model.writes)

    def test_unexpected_collection_member_and_duplicate_are_rejected(self):
        self.model.docs[2]['Members'] = [{'@odata.id': '/redfish/v1/Systems/Self/Processors/Unknown'}]
        self.model.docs[2]['Members@odata.count'] = 1
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.model.docs[2]['Members'] = [{'@odata.id': self.model.docs[7]['@odata.id']}] * 2
        self.model.docs[2]['Members@odata.count'] = 2
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)

    def test_changed_source_or_boot_blocks_new_write(self):
        self.ready(); self.lib.i71_test_source(1, 12346)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertFalse(self.model.writes)

    def test_lost_response_after_post_does_not_replay_even_if_direct_matches(self):
        self.ready(); self.model.lose_post = True
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertIn(8, self.model.docs)
        for _ in range(3): self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_preflight(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertEqual(len(self.model.writes), 1)

    def test_rejected_post_holds_and_never_advances(self):
        self.ready(); self.model.post_result = 400
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertNotIn(8, self.model.docs)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(len(self.model.writes), 1)

    def test_ack_wrong_direct_values_has_three_readbacks_and_stops(self):
        self.ready(); self.model.corrupt_post_readback = True
        before = len(self.model.calls)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.model.calls[before:].count((0, 8)), 4)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertEqual(len(self.model.writes), 1)

    def test_ack_without_new_direct_resource_is_not_success(self):
        self.ready(); self.model.hide_post_readback = True
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertEqual(self.lib.inventory_legacy71_completed_mask(), 3)

    def test_summary_is_separate_exact_subset_with_fresh_etag(self):
        self.ready(); self.model.docs[1]['@odata.etag'] = '"fresh"'
        self.model.docs[1]['ProcessorSummary'] = {'Status': {'State': 'Enabled'}}
        self.assertEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertEqual(self.model.writes, [(2, 1, SUMMARY, b'"fresh"')])
        self.assertEqual(self.model.docs[1]['ProcessorSummary']['Status']['State'], 'Enabled')
        self.assertEqual(self.lib.inventory_legacy71_summary_state(), 1)
        self.assertEqual(self.lib.inventory_legacy71_state(), 1)
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertEqual(len(self.model.writes), 1)

    def test_summary_matching_existing_value_is_read_only(self):
        self.model.docs[1].update(copy.deepcopy(SUMMARY)); self.ready()
        self.assertEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_summary_state(), 1)
        self.assertFalse(self.model.writes)

    def test_summary_fresh_cpu_mismatch_blocks_patch(self):
        self.ready(); self.model.docs[7]['TotalCores'] = 8
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertFalse(self.model.writes)

    def test_summary_different_meaningful_values_and_missing_etag_block(self):
        for bad in ({'Count': 2}, {'Model': 'Other CPU'}, {'Count': '1'}):
            model = Model(); self.lib.i71_test_reset(model.callback)
            model.docs[1]['ProcessorSummary'] = bad
            self.assertEqual(self.lib.inventory_legacy71_preflight(), 0)
            self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
            self.assertFalse(model.writes)
        self.model = Model(); self.lib.i71_test_reset(self.model.callback); self.ready()
        del self.model.docs[1]['@odata.etag']
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertFalse(self.model.writes)

    def test_summary_unknown_response_holds_without_replay(self):
        self.ready(); self.model.lose_summary = True
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertEqual(self.lib.inventory_legacy71_summary_state(), 2)
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(len(self.model.writes), 1)

    def test_summary_ack_without_readback_stops_after_three_reads(self):
        self.ready(); self.model.hide_summary_readback = True
        before = len(self.model.calls)
        self.assertNotEqual(self.lib.inventory_legacy71_summary_step(), 0)
        self.assertEqual(self.model.calls[before:].count((0, 1)), 4)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)

    def test_final_pass_detects_other_resource_changed_mid_run(self):
        self.ready()
        for _ in range(3): self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        self.model.docs[9]['SerialNumber'] = 'changed'
        self.assertNotEqual(self.lib.inventory_legacy71_step(), 0)
        self.assertEqual(self.lib.inventory_legacy71_state(), 2)
        self.assertEqual(len(self.model.writes), 4)

    def test_request_bound_fits_existing_post_write_audit_reserve(self):
        for item in range(2, 5): self.model.add_orphan(item)
        self.ready(); before = len(self.model.calls)
        self.assertEqual(self.lib.inventory_legacy71_step(), 0)
        calls = self.model.calls[before:]
        write = next(i for i, call in enumerate(calls) if call[0])
        self.assertLessEqual(len(calls[write:]), 15)


if __name__ == '__main__':
    unittest.main()
