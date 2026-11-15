"""Exercise the native C cache engine with real read-only response fixtures.

Only Python callbacks simulate HTTP. No socket, BMC, UEFI or firmware writes.
The catalogue is built by the already tested C SMBIOS library from .71's capture.
"""
import copy
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[1]
sys.path.insert(0, str(BASE / 'dynamic_catalog'))
from test_dynamic_catalog import Catalog
sys.path.insert(0, str(BASE))
from smbios_inventory import block


class Reply(c.Structure):
    _fields_ = [('status', c.c_uint32), ('body', c.c_void_p), ('bytes', c.c_uint32),
                ('etag', c.c_void_p), ('etag_bytes', c.c_uint32)]


class State(c.Structure):
    _fields_ = [(name, c.c_uint32) for name in ('version', 'last_result', 'phase', 'target',
        'attempted_mask', 'acknowledged_mask', 'verified_mask', 'hold', 'last_http_status',
        'exchanges', 'delete_transport_failed', 'delete_http_status', 'delete_target')]


SOURCE = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint64, c.POINTER(Catalog))
RESERVE = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint32)
EXCHANGE = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint32, c.c_uint32, c.c_uint32,
                     c.c_void_p, c.c_uint32, c.c_void_p, c.c_uint32, c.POINTER(Reply))


class Ops(c.Structure):
    _fields_ = [('user', c.c_void_p), ('source_valid', SOURCE), ('reserve', RESERVE), ('exchange', EXCHANGE)]


PATHS = ['/redfish/v1/GlobalLuaTables', '/redfish/v1/Systems/Self',
         '/redfish/v1/Systems/Self/Processors', '/redfish/v1/Systems/Self/Memory',
         '/redfish/v1/Systems/Self/Processors/DevType1_CPU',
         '/redfish/v1/Systems/Self/Memory/DevType2_DIMM']
BODIES = [b'{"Prefixes":["Redfish:Systems:Self:Processors:SRK"]}',
          b'{"Prefixes":["Redfish:Systems:Self:Memory:SRK"]}']


def result_body(name):
    value = json.loads((ROOT / 'analysis/hero_ipmi_continued_live_20261108/responses' / name).read_text('utf8'))
    return value['result']['body']


class Peer:
    def __init__(self, owner):
        self.owner = owner
        self.keep = []
        self.calls = []
        self.budgets = []
        self.good_source = True
        self.budget_ok = True
        self.delete_status = 204
        self.delete_transport = 0
        self.apply_delete = True
        self.etag = b'"1794105187"'
        self.hook = None
        self.delete_seen = False
        self.docs = {(0, 0): copy.deepcopy(owner.cache), (1, 0): copy.deepcopy(owner.system),
                     (2, 0): copy.deepcopy(owner.cpu_empty), (3, 0): self.collection(3, [])}
        self.docs[(4, 0)] = copy.deepcopy(owner.cpu)
        for i in range(4):
            self.docs[(5, i)] = copy.deepcopy(owner.expected[2+i])
            self.docs[(5, i)]['@odata.id'] = PATHS[5] + str(i)
        self.source_cb = SOURCE(self.source)
        self.reserve_cb = RESERVE(self.reserve)
        self.exchange_cb = EXCHANGE(self.exchange)
        self.ops = Ops(None, self.source_cb, self.reserve_cb, self.exchange_cb)

    @staticmethod
    def collection(which, members):
        return {'@odata.id': PATHS[which], 'Members@odata.count': len(members),
                'Members': [{'@odata.id': PATHS[which+2]+str(i)} for i in members]}

    def source(self, _, epoch, cat):
        return int(self.good_source and epoch == 123456 and cat.contents.valid == 1)

    def reserve(self, _, amount):
        self.budgets.append(amount)
        return int(self.budget_ok)

    def exchange(self, _, method, resource, index, body, size, tag, tag_size, output):
        payload = c.string_at(body, size) if body else b''
        etag = c.string_at(tag, tag_size) if tag else b''
        self.calls.append((method, resource, index, payload, etag))
        # Assert in Python outside callback below, since ctypes cannot propagate.
        if self.hook:
            override = self.hook(self, method, resource, index)
            if override is not None:
                return self.respond(output, *override)
        if method:
            self.delete_seen = True
            if self.apply_delete:
                which = 2 if payload == BODIES[0] else 3
                self.docs[(which, 0)] = self.collection(which, range(1 if which == 2 else 4))
            return self.respond(output, self.delete_status, None, self.delete_transport)
        return self.respond(output, 200, self.docs[(resource, index)], 0,
                            self.etag if resource == 0 else None)

    def respond(self, output, status, body, transport=0, etag=None):
        output.contents.status = status
        if body is not None:
            raw = body if isinstance(body, bytes) else json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode()
            data = c.create_string_buffer(raw); self.keep.append(data)
            output.contents.body = c.addressof(data); output.contents.bytes = len(raw)
        if etag is not None:
            data = c.create_string_buffer(etag); self.keep.append(data)
            output.contents.etag = c.addressof(data); output.contents.etag_bytes = len(etag)
        return transport

    @property
    def writes(self):
        return [x for x in self.calls if x[0]]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = HERE / 'build'; cls.out.mkdir(exist_ok=True)
        zig = ROOT / 'tools/zig-x86_64-windows-0.14.1/zig.exe'
        env = os.environ.copy(); env['ZIG_GLOBAL_CACHE_DIR'] = str(cls.out / 'zig-global'); env['ZIG_LOCAL_CACHE_DIR'] = str(cls.out / 'zig-local')
        exports = ['ContextSize', 'Init', 'State', 'Inspect', 'Refresh', 'WriteAllowed', 'Path']
        commands = [[str(zig), 'clang', '-target', 'x86_64-unknown-windows-msvc', '-nostdinc', '-isystem', str(zig.parent / 'lib/include'),
                     '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                     '-mno-red-zone', '-c', str(HERE / 'hero_inventory_cache.c'), '-o', str(cls.out / 'cache.obj')],
                    [str(zig), 'lld-link', '/dll', '/noentry', '/nodefaultlib', '/machine:x64', '/opt:ref', '/timestamp:0',
                     '/out:' + str(cls.out / 'cache.dll'), str(cls.out / 'cache.obj')]
                    + ['/export:HeroInventoryCache' + s for s in exports]]
        for cmd in commands:
            p = subprocess.run(cmd, cwd=HERE, env=env, capture_output=True, text=True)
            if p.returncode: raise RuntimeError(p.stdout+p.stderr)
        cls.lib = c.CDLL(str(cls.out / 'cache.dll'))
        cls.lib.HeroInventoryCacheContextSize.restype = c.c_uint32
        cls.lib.HeroInventoryCacheInit.argtypes = [c.c_void_p, c.c_uint32, c.c_uint64]
        cls.lib.HeroInventoryCacheState.argtypes = [c.c_void_p, c.POINTER(State)]
        for name in ('Inspect', 'Refresh'):
            fn = getattr(cls.lib, 'HeroInventoryCache'+name)
            fn.argtypes = [c.c_void_p, c.c_uint32, c.POINTER(Catalog), c.POINTER(Ops)]
        cls.lib.HeroInventoryCacheWriteAllowed.argtypes = [c.c_uint32, c.c_uint32, c.c_uint32, c.c_void_p, c.c_uint32, c.c_void_p, c.c_uint32]
        cls.lib.HeroInventoryCachePath.argtypes = [c.c_uint32, c.c_uint32, c.c_void_p, c.c_uint32]
        builder = c.CDLL(str(BASE / 'dynamic_catalog/build/catalog.dll'))
        builder.HeroInventoryBuild.argtypes = [c.c_void_p, c.c_uint32, c.c_uint8, c.c_uint8, c.POINTER(Catalog), c.c_void_p]
        raw = block((ROOT / 'analysis/hero_ipmi_continued_live_20261108/hero71-smbios-i1.TXT').read_text('utf8'), 'TABLE')
        cls.catalog = Catalog(); rawbuf = c.create_string_buffer(raw); scratch = c.create_string_buffer(builder.HeroInventoryScratchSize())
        assert builder.HeroInventoryBuild(rawbuf, len(raw), 3, 5, c.byref(cls.catalog), scratch) == 0
        cls.expected = [json.loads(c.string_at(c.addressof(cls.catalog)+Catalog.json.offset+i.json_offset, i.json_bytes))
                        for i in cls.catalog.items[:cls.catalog.item_count]]
        cls.cache = result_body('996-evaluate.json')
        cls.cpu_full = result_body('998-get.json')
        cls.cpu_empty = result_body('701-get.json')
        cls.cpu = result_body('702-get.json')
        cls.system = result_body('697-get.json')
        (cls.out / 'build.json').write_text(json.dumps({'commands': commands, 'context_bytes': cls.lib.HeroInventoryCacheContextSize(),
            'cache_dll_sha256': hashlib.sha256((cls.out/'cache.dll').read_bytes()).hexdigest(), 'live_operations': False}, indent=2)+'\n')

    def setUp(self):
        self.cat = Catalog.from_buffer_copy(self.catalog)
        size = self.lib.HeroInventoryCacheContextSize()
        self.guarded = c.create_string_buffer(size+64)
        c.memset(self.guarded, 0xA5, size+64)
        self.ctx = c.c_void_p(c.addressof(self.guarded)+32)
        self.assertEqual(self.lib.HeroInventoryCacheInit(self.ctx, size, 123456), 0)
        self.peer = Peer(self)

    def tearDown(self):
        size = self.lib.HeroInventoryCacheContextSize()
        self.assertEqual(c.string_at(self.guarded, 32), b'\xA5'*32)
        self.assertEqual(c.string_at(c.addressof(self.guarded)+size+32, 32), b'\xA5'*32)
        for method, resource, index, body, etag in self.peer.writes:
            self.assertEqual((method, resource, index), (3, 0, 0))
            self.assertIn(body, BODIES)
            self.assertTrue(etag.startswith(b'"') and etag.endswith(b'"'))

    def state(self):
        v = State(); self.assertEqual(self.lib.HeroInventoryCacheState(self.ctx, c.byref(v)), 0); return v

    def run_op(self, write=True, target=1):
        return getattr(self.lib, 'HeroInventoryCache'+('Refresh' if write else 'Inspect'))(self.ctx, target, c.byref(self.cat), c.byref(self.peer.ops))

    def test_actual_cpu_cached_empty_readonly_preflight(self):
        self.assertEqual(self.run_op(False), 0)
        self.assertEqual(len(self.peer.calls), 4); self.assertFalse(self.peer.writes)
        self.assertEqual(self.peer.budgets, [4]); self.assertEqual(self.state().phase, 2)

    def test_actual_cpu_one_delete_204_complete_readback(self):
        self.assertEqual(self.run_op(), 2)
        self.assertEqual(self.peer.writes, [(3, 0, 0, BODIES[0], b'"1794105187"')])
        st = self.state(); self.assertEqual((st.attempted_mask, st.acknowledged_mask, st.verified_mask, st.hold), (1,1,1,0))
        self.assertEqual(st.exchanges, 8); self.assertEqual(self.peer.budgets, [8])
        self.assertEqual(self.run_op(), 22); self.assertEqual(len(self.peer.writes), 1)
        self.assertEqual(self.run_op(False), 1)  # read-only inspection remains possible

    def test_actual_cpu_already_indexed_skips_cache_endpoint_and_delete(self):
        self.peer.docs[(2,0)] = copy.deepcopy(self.cpu_full)
        self.assertEqual(self.run_op(), 1); self.assertFalse(self.peer.writes)
        self.assertEqual(len(self.peer.calls), 3)

    def test_memory_four_members_exact_key_and_budget(self):
        self.assertEqual(self.run_op(target=2), 2)
        self.assertEqual(self.peer.writes[0][3], BODIES[1])
        self.assertEqual(len(self.peer.calls), 14); self.assertEqual(self.peer.budgets, [14])
        self.assertEqual(self.state().verified_mask, 2)

    def test_cpu_then_memory_once_each(self):
        self.assertEqual(self.run_op(), 2); self.assertEqual(self.run_op(target=2), 2)
        self.assertEqual((self.state().attempted_mask, self.state().verified_mask), (3,3))
        self.assertEqual(len(self.peer.writes), 2)

    def test_source_change_and_log_budget_reject_before_get(self):
        self.peer.good_source = False; self.assertEqual(self.run_op(), 12); self.assertFalse(self.peer.calls)
        self.peer.good_source = True; self.peer.budget_ok = False
        self.assertEqual(self.run_op(), 13); self.assertFalse(self.peer.calls)

    def test_preflight_rechecks_before_delete_and_no_implicit_replay(self):
        def hook(p,m,r,i):
            if not m and r == 0: p.good_source = False
        self.peer.hook = hook
        self.assertEqual(self.run_op(), 12); self.assertFalse(self.peer.writes)

    def test_system_mismatch_or_other_host_is_not_repaired(self):
        for field in ('Model','Manufacturer','BiosVersion','UUID'):
            self.peer.docs[(1,0)] = copy.deepcopy(self.system); self.peer.docs[(1,0)][field] = 'DIFFERENT'
            self.assertEqual(self.run_op(), 17); self.assertFalse(self.peer.writes)

    def test_child_field_and_path_mismatch_no_delete(self):
        self.peer.docs[(4,0)]['TotalCores'] = 16
        self.assertEqual(self.run_op(), 18); self.assertFalse(self.peer.writes)
        self.peer.docs[(4,0)] = copy.deepcopy(self.cpu); self.peer.docs[(4,0)]['@odata.id'] = PATHS[4]+'1'
        self.assertEqual(self.run_op(), 17); self.assertFalse(self.peer.writes)

    def test_missing_direct_child_never_created(self):
        self.peer.hook = lambda p,m,r,i: (404, {'error':{}}) if r == 4 else None
        self.assertEqual(self.run_op(), 15); self.assertFalse(self.peer.writes)

    def test_unexpected_member_duplicate_count_and_pagination_rejected(self):
        cases = [Peer.collection(2,[1]), Peer.collection(2,[0,0]),
                 dict(Peer.collection(2,[]), **{'Members@odata.count':1}),
                 dict(Peer.collection(2,[]), **{'Members@odata.nextLink':PATHS[2]+'?skip=1'}),
                 dict(Peer.collection(2,[]), **{'@odata.nextLink':PATHS[2]+'?skip=1'})]
        for doc in cases:
            self.peer.docs[(2,0)] = doc; self.assertEqual(self.run_op(), 19); self.assertFalse(self.peer.writes)

    def test_global_capability_404_no_delete(self):
        self.peer.hook = lambda p,m,r,i: (404, {'error':{}}) if r == 0 else None
        self.assertEqual(self.run_op(), 15); self.assertFalse(self.peer.writes)

    def test_global_not_cached_or_duplicate_or_count_invalid(self):
        doc = copy.deepcopy(self.cache)
        doc['Members'] = [x for x in doc['Members'] if x['@odata.id'] != PATHS[2]]
        doc['Members@odata.count'] = len(doc['Members']); self.peer.docs[(0,0)] = doc
        self.assertEqual(self.run_op(), 20)
        self.peer.docs[(0,0)] = copy.deepcopy(self.cache); self.peer.docs[(0,0)]['Members@odata.count'] = 12
        self.assertEqual(self.run_op(), 16)
        self.peer.docs[(0,0)] = copy.deepcopy(self.cache); self.peer.docs[(0,0)]['Members'].append(self.cache['Members'][0]); self.peer.docs[(0,0)]['Members@odata.count'] = 14
        self.assertEqual(self.run_op(), 16); self.assertFalse(self.peer.writes)

    def test_strong_fresh_etag_only(self):
        for tag in ('W/"123"','*','""','"1\r\nx"','"123\\x"','"123 4"','"'+'a'*100+'"'):
            self.peer.docs[(0,0)]['@odata.etag'] = tag; self.peer.etag = tag.encode()
            self.assertEqual(self.run_op(), 21); self.assertFalse(self.peer.writes)
        self.peer.docs[(0,0)]['@odata.etag'] = '"123"'; self.peer.etag = b'"456"'
        self.assertEqual(self.run_op(), 21)

    def test_body_etag_when_http_header_not_exposed(self):
        self.peer.etag = None
        self.assertEqual(self.run_op(), 2)

    def test_uncertain_delete_readback_no_replay_even_if_complete(self):
        self.peer.delete_transport = 1
        self.assertEqual(self.run_op(), 23)
        st = self.state(); self.assertEqual((st.hold,st.attempted_mask,st.acknowledged_mask,st.verified_mask), (1,1,0,1))
        self.assertEqual(st.delete_transport_failed, 1)
        self.assertEqual(self.run_op(), 25); self.assertEqual(self.run_op(target=2), 25)
        self.assertEqual(len(self.peer.writes), 1)
        self.assertEqual(self.run_op(False), 1)

    def test_rejected_delete_readback_then_hold(self):
        self.peer.delete_status = 412; self.peer.apply_delete = False
        self.assertEqual(self.run_op(), 23)
        self.assertEqual((self.state().delete_http_status, self.state().verified_mask), (412,0))
        self.assertEqual(self.run_op(), 25); self.assertEqual(len(self.peer.writes), 1)

    def test_204_with_error_body_is_not_accepted_acknowledgement(self):
        self.peer.hook = lambda p,m,r,i: (204, {'error':{}}) if m else None
        self.assertEqual(self.run_op(), 23)
        self.assertEqual((self.state().acknowledged_mask,self.state().hold), (0,1))

    def test_valid_unicode_in_unrelated_properties_and_uuid_case(self):
        self.peer.docs[(1,0)]['Extra'] = 'café 中文 😀'
        self.peer.docs[(1,0)]['UUID'] = self.peer.docs[(1,0)]['UUID'].upper()
        self.assertEqual(self.run_op(), 2)

    def test_maximum_catalogue_32_dimms_uses_bit31_and_70_exchange_budget(self):
        docs = [copy.deepcopy(self.expected[0])]
        for i in range(8):
            item = copy.deepcopy(self.expected[1]); item['Id'] = f'DevType1_CPU{i}'; docs.append(item)
        for i in range(32):
            item = copy.deepcopy(self.expected[2+i%4]); item['Id'] = f'DevType2_DIMM{i}'; docs.append(item)
        raw = b''
        self.cat.cpu_count = 8; self.cat.dimm_count = 32; self.cat.item_count = 41
        for i, item in enumerate(docs):
            data = json.dumps(item,separators=(',',':')).encode()
            slot = self.cat.items[i]; slot.kind = 1 if not i else 2 if i <= 8 else 3
            slot.index = 0 if not i else i-1 if i <= 8 else i-9
            slot.json_offset = len(raw); slot.json_bytes = len(data); raw += data+b'\0'
        self.cat.json_bytes = len(raw)
        c.memmove(c.addressof(self.cat)+Catalog.json.offset,raw,len(raw))
        for i in range(32):
            item=copy.deepcopy(docs[9+i]);item['@odata.id']=PATHS[5]+str(i)
            self.peer.docs[(5,i)]=item
        def hook(p,m,r,i):
            if m:
                p.docs[(3,0)]=p.collection(3,range(32))
                return 204,None
        self.peer.hook=hook
        self.assertEqual(self.run_op(target=2),2)
        self.assertEqual(self.peer.budgets,[70]);self.assertEqual(len(self.peer.calls),70)
        self.assertEqual(self.state().verified_mask,2)

    def test_204_without_index_change_is_not_success_or_retry(self):
        self.peer.apply_delete = False
        self.assertEqual(self.run_op(), 24)
        self.assertEqual((self.state().hold, self.state().acknowledged_mask, self.state().verified_mask), (1,1,0))
        self.assertEqual(self.run_op(), 25); self.assertEqual(len(self.peer.writes), 1)

    def test_readback_child_changed_after_ack_stops(self):
        def hook(p,m,r,i):
            if m: p.docs[(4,0)]['TotalCores'] = 12
        self.peer.hook = hook
        self.assertEqual(self.run_op(), 18)
        self.assertEqual((self.state().hold, self.state().acknowledged_mask, self.state().verified_mask), (1,1,0))

    def test_network_lost_after_delete_no_more_writes(self):
        self.peer.hook = lambda p,m,r,i: (0,None,1) if p.delete_seen else None
        self.assertEqual(self.run_op(), 14)
        self.assertEqual(self.run_op(), 25); self.assertEqual(len(self.peer.writes),1)

    def test_catalogue_rebinding_or_corruption_is_refused(self):
        self.assertEqual(self.run_op(False), 0)
        self.cat.table_crc32 ^= 1
        self.assertEqual(self.run_op(), 12); self.assertFalse(self.peer.writes)
        self.cat.valid = 0; self.assertEqual(self.run_op(), 11)

    def test_json_limits_duplicates_and_bad_unicode_rejected(self):
        cases = [b'{"@odata.id":"x","@odata.id":"y"}', b'{"a":"\\ud800"}',
                 b'{"a":"\\udc00"}', b'{"a":"\xc0\x80"}', b'{"a":'+b'['*14+b'0'+b']'*14+b'}',
                 b'{"x":['+b'0,'*2050+b'0]}', b' '*32769]
        for raw in cases:
            self.peer.docs[(2,0)] = raw; self.assertEqual(self.run_op(), 16); self.assertFalse(self.peer.writes)

    def test_write_allowlist_is_exact_not_patterns_or_collection_delete(self):
        fn = self.lib.HeroInventoryCacheWriteAllowed
        good = BODIES[0]; tag = b'"1794105187"'
        self.assertEqual(fn(3,0,0,good,len(good),tag,len(tag)),1)
        for bad in [b'{"Patterns":["Redfish:"]}', b'{"Prefixes":"Redfish:Systems:Self:Processors:SRK"}',
                    good+b' ', b'{"Prefixes":["Redfish:Systems:Self:Processors:SRK","Redfish:"]}',
                    b'{"Prefixes":["Redfish:"]}', good[:-1]+b',"Unknown":1}']:
            self.assertEqual(fn(3,0,0,bad,len(bad),tag,len(tag)),0)
        for method,resource,index in [(0,0,0),(1,0,0),(2,0,0),(3,2,0),(3,3,0),(3,0,1)]:
            self.assertEqual(fn(method,resource,index,good,len(good),tag,len(tag)),0)

    def test_fixed_paths_bounds(self):
        for resource, count in enumerate([1,1,1,1,8,32]):
            for index in range(count):
                data=c.create_string_buffer(128)
                self.assertEqual(self.lib.HeroInventoryCachePath(resource,index,data,128),1)
                self.assertEqual(data.value.decode(),PATHS[resource]+(str(index) if resource>=4 else ''))
            data=c.create_string_buffer(128)
            self.assertEqual(self.lib.HeroInventoryCachePath(resource,count,data,128),0)
        data=c.create_string_buffer(4)
        self.assertEqual(self.lib.HeroInventoryCachePath(0,0,data,4),0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
