"""Failure, host-identity, schema and retry boundaries for the offline publisher."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest

import inventory_publish as p
from test_smbios_inventory import capture, table


SYSTEM = '/redfish/v1/Systems/Self'
CPUS = SYSTEM + '/Processors'
MEMORY = SYSTEM + '/Memory'


class Fixture:
    def __init__(self, source=None):
        self.source = source or p.Source.from_capture(capture())
        self.binding = p.Binding('synthetic-boot-a', self.source.table_sha256, self.source.uuid,
                                 'internal-usb', 0x046b, 0xffb0, '12' * 32, '12' * 32)
        self.root = {'@odata.id': p.ROOT, 'RedfishVersion': '1.8.0', 'Oem': {'Ami': {'RtpVersion': '1.8.a'}},
                     'Systems': {'@odata.id': '/redfish/v1/Systems'}}
        self.system = {'@odata.id': SYSTEM, 'Id': 'Self', 'Name': 'System', 'Model': '', 'Manufacturer': '',
                       'BiosVersion': 'NA', 'UUID': 'NA', 'Processors': {'@odata.id': CPUS},
                       'Memory': {'@odata.id': MEMORY}, '@odata.etag': '"synthetic-1"'}
        self.cpu = []
        self.memory = []
        self.capability_status = 404
        self.capability = None
        self.publish_status = {'InventoryData': {'Status': 'Completed', 'Messages': [], 'DeletedModules': []}}
        self.counter = 0

    def snapshot(self, now_ms=100, read_at_ms=100):
        self.counter += 100
        objects = [(p.ROOT, self.root), ('/redfish/v1/Systems', {'Members@odata.count': 1,
                    'Members': [{'@odata.id': SYSTEM}]}), (SYSTEM, self.system)]
        for coll, items in [(CPUS, self.cpu), (MEMORY, self.memory)]:
            objects.append((coll, {'@odata.id': coll, 'Members@odata.count': len(items),
                                  'Members': [{'@odata.id': coll + '/' + item['Id']} for item in items]}))
            for item in items:
                body = copy.deepcopy(item)
                body['@odata.id'] = coll + '/' + item['Id']
                objects.append((body['@odata.id'], body))
        objects.append((p.INVENTORY_STATUS, self.publish_status))
        readings = [p.Observation(uri, 200, body, self.counter + i, read_at_ms, self.binding.session_id)
                    for i, (uri, body) in enumerate(objects)]
        readings.append(p.Observation(p.INVENTORY, self.capability_status, self.capability,
                                     self.counter + len(objects), read_at_ms, self.binding.session_id))
        return p.Snapshot(self.binding, readings, now_ms)

    def apply(self, request):
        body = json.loads(request.body)
        if request.uri == SYSTEM:
            self.system.update(body)
            self.system['@odata.etag'] = '"synthetic-' + str(self.counter) + '"'
        elif request.uri == CPUS:
            self.cpu.append(body)
        elif request.uri == MEMORY:
            self.memory.append(body)
        else:
            raise AssertionError('fixture only applies legacy requests')

    def fill(self):
        system = self.source.document()['Systems'][0]
        self.system.update({k: system[k] for k in p.SYSTEM_KEYS if k in system})
        self.cpu = copy.deepcopy(system['Processors'])
        self.memory = copy.deepcopy(system['Memory'])


def mutate_snapshot(snapshot, uri, change):
    readings = list(snapshot.items.values())
    index = next(i for i, r in enumerate(readings) if r.uri == uri)
    readings[index] = change(readings[index])
    return p.Snapshot(snapshot.binding, readings, snapshot.now_ms)


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def test_per_host_identity_is_generated_from_new_capture(self):
        raw = bytearray(table())
        raw[raw.index(bytes.fromhex('33221100554477668899aabbccddeeff')):
            raw.index(bytes.fromhex('33221100554477668899aabbccddeeff')) + 16] = bytes.fromhex('ffeeddccbbaa99887766554433221100')
        source = p.Source.from_capture(capture(bytes(raw).replace(b'3107', b'3201')))
        f = Fixture(source)
        plan = p.preflight(source, f.snapshot())
        expected = json.loads(plan.operations[0].request.body)
        self.assertEqual(expected['UUID'], 'ccddeeff-aabb-8899-7766-554433221100')
        self.assertEqual(expected['BiosVersion'], '3201')
        self.assertNotEqual(source.table_sha256, self.f.source.table_sha256)

    def test_machine_binding_guards(self):
        changes = [{'source_table_sha256': '01' * 32}, {'current_host_uuid': '01234567-89ab-cdef-0123-456789abcdef'},
                   {'observed_leaf_sha256': 'ab' * 32}, {'transport': 'external-lan'}, {'usb_pid': 0x1234},
                   {'pinned_leaf_sha256': ''}, {'session_id': 'session\r\nheader'}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(p.PublishError):
                replace(self.f.binding, **change).check(self.f.source)

    def test_no_uuid_is_not_publishable(self):
        raw = table().replace(bytes.fromhex('33221100554477668899aabbccddeeff'), bytes(16))
        with self.assertRaises(p.PublishError):
            p.Source.from_capture(capture(raw))

    def test_initial_plan_has_no_deletes_crc_or_boot_complete(self):
        plan = p.preflight(self.f.source, self.f.snapshot())
        self.assertEqual([op.request.method for op in plan.operations], ['PATCH', 'POST', 'POST', 'POST'])
        self.assertEqual(len(plan.operations), 4)
        for op in plan.operations:
            self.assertEqual(len(op.request.body), int(dict(op.request.headers)['Content-Length']))
            self.assertNotIn(b'BootComplete', op.request.body)
            self.assertNotIn(b'GroupCrcList', op.request.body)
        self.assertEqual(dict(plan.operations[0].request.headers)['If-Match'], '"synthetic-1"')

    def test_complete_legacy_roundtrip_and_idempotent_new_preflight(self):
        plan = p.preflight(self.f.source, self.f.snapshot())
        w = p.Workflow(plan)
        while w.phase == 'READY':
            request = w.next_write(self.f.snapshot())
            self.assertEqual(w.journal[-1]['event'], 'WRITE_INTENT')
            self.f.apply(request)
            w.acknowledge(204 if request.method == 'PATCH' else 201, w.last_sequence + 1)
            self.assertTrue(w.verify(self.f.snapshot())['matches'])
        self.assertEqual(w.phase, 'WRITES_VERIFIED')
        self.assertTrue(w.final_verify(self.f.snapshot())['matches'])
        self.assertEqual(w.phase, 'CORE_VERIFIED')
        self.assertEqual(p.preflight(self.f.source, self.f.snapshot()).operations, ())

    def test_exact_existing_resource_is_skipped(self):
        self.f.cpu = self.f.source.document()['Systems'][0]['Processors']
        plan = p.preflight(self.f.source, self.f.snapshot())
        self.assertNotIn(CPUS, [op.request.uri for op in plan.operations])

    def test_changed_or_foreign_existing_resource_blocks_whole_plan(self):
        for mode in ('changed', 'foreign'):
            f = Fixture()
            f.cpu = copy.deepcopy(f.source.document()['Systems'][0]['Processors'])
            if mode == 'changed':
                f.cpu[0]['TotalCores'] = 8
            else:
                f.cpu[0]['Id'] = 'AlienCPU0'
            with self.subTest(mode=mode), self.assertRaises(p.PublishError):
                p.preflight(f.source, f.snapshot())

    def test_old_machine_uuid_blocks_before_first_write(self):
        self.f.system['UUID'] = '11223344-5566-7788-9900-aabbccddeeff'
        with self.assertRaises(p.PublishError):
            p.preflight(self.f.source, self.f.snapshot())

    def test_stale_future_and_mixed_session_reads_are_rejected(self):
        for now, read in [(31_101, 100), (100, 101)]:
            with self.subTest(now=now), self.assertRaises(p.PublishError):
                p.preflight(self.f.source, self.f.snapshot(now, read))
        snapshot = self.f.snapshot()
        with self.assertRaises(p.PublishError):
            mutate_snapshot(snapshot, SYSTEM, lambda r: replace(r, session_id='another-boot'))

    def test_collection_completeness_and_ownership(self):
        for alteration in [lambda b: b.update({'Members@odata.count': 2}),
                           lambda b: b.update({'Members@odata.nextLink': '/redfish/v1/next'}),
                           lambda b: b.update({'Members': [{'@odata.id': '/redfish/v1/Systems/Other/Processors/CPU0'}], 'Members@odata.count': 1}),
                           lambda b: b.update({'Members@odata.count': True})]:
            snapshot = self.f.snapshot()
            def change(r):
                b = copy.deepcopy(r.body); alteration(b); return replace(r, body=b)
            with self.assertRaises(p.PublishError):
                p.preflight(self.f.source, mutate_snapshot(snapshot, CPUS, change))

    def test_no_foreign_origin_or_traversal(self):
        for uri in ['https://evil.test/redfish/v1/Systems', '//evil.test/redfish/v1',
                    '/redfish/v1/../Sessions', '/redfish/v1/%2e%2e/Secrets', '/redfish/v1/?x=1',
                    '/redfish/v1/Systems\r\nHost:x', '/redfish/v1/./Systems']:
            with self.subTest(uri=uri), self.assertRaises(p.PublishError): p.safe_uri(uri)

    def test_schema_error_and_non_success_get(self):
        for status in (401, 403, 404, 500):
            snap = mutate_snapshot(self.f.snapshot(), SYSTEM, lambda r: replace(r, status=status))
            with self.subTest(status=status), self.assertRaises(p.PublishError): p.preflight(self.f.source, snap)
        for root in [{'Oem': None}, {'Oem': []}, {'RedfishVersion': '9.0'}]:
            self.f.root.update(root)
            with self.assertRaises(p.PublishError): p.preflight(self.f.source, self.f.snapshot())

    def test_duplicate_and_nonfinite_json_rejected(self):
        for data in [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'\xff', b'{', b'']:
            with self.subTest(data=data), self.assertRaises(p.PublishError): p.decode_response(data)
        self.assertEqual(p.decode_response(b'{"a":1}'), {'a': 1})

    def test_encoded_byte_length_and_headers_do_not_accept_injection(self):
        request = p.json_request('PATCH', SYSTEM, {'Model': '主板 / Café'})
        self.assertEqual(int(dict(request.headers)['Content-Length']), len(request.body))
        self.assertEqual(json.loads(request.body)['Model'], '主板 / Café')
        with self.assertRaises(p.PublishError): p.json_request('DELETE', SYSTEM, {})
        with self.assertRaises(p.PublishError): p.json_request('PATCH', SYSTEM, {}, '"etag"\r\nHost:evil')

    def test_one_write_in_flight_and_no_stale_acknowledgement(self):
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot()))
        w.next_write(self.f.snapshot())
        with self.assertRaises(p.PublishError): w.next_write(self.f.snapshot())
        with self.assertRaises(p.PublishError): w.acknowledge(200, w.last_sequence)

    def test_2xx_without_readback_is_not_success(self):
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot()))
        w.next_write(self.f.snapshot()); w.acknowledge(200, w.last_sequence + 1)
        for attempt in range(3):
            self.assertFalse(w.verify(self.f.snapshot())['matches'])
        self.assertEqual(w.phase, 'HOLD_UNVERIFIED')
        with self.assertRaises(p.PublishError): w.next_write(self.f.snapshot())

    def test_connection_lost_after_applied_write_never_replays(self):
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot()))
        request = w.next_write(self.f.snapshot()); self.f.apply(request)
        w.acknowledge(None, w.last_sequence + 1, 'timeout-after-request')
        with self.assertRaises(p.PublishError): w.next_write(self.f.snapshot())
        self.assertTrue(w.verify(self.f.snapshot())['matches'])
        self.assertEqual(w.phase, 'HOLD_RECONCILED')
        # A deliberate new preflight omits the already-applied System patch.
        new_plan = p.preflight(self.f.source, self.f.snapshot())
        self.assertTrue(all(op.kind != 'system-patch' for op in new_plan.operations))

    def test_rejected_write_never_switches_route_or_retries(self):
        for status in (400, 401, 403, 404, 409, 412, 428, 429, 500, 503, 202):
            f = Fixture(); w = p.Workflow(p.preflight(f.source, f.snapshot()))
            w.next_write(f.snapshot()); w.acknowledge(status, w.last_sequence + 1)
            with self.subTest(status=status), self.assertRaises(p.PublishError): w.next_write(f.snapshot())
            self.assertEqual(w.phase, 'REJECTED_VERIFY')

    def test_even_failed_http_response_does_not_assume_no_mutation(self):
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot()))
        self.f.apply(w.next_write(self.f.snapshot())); w.acknowledge(400, w.last_sequence + 1)
        self.assertTrue(w.verify(self.f.snapshot())['matches'])
        self.assertEqual(w.phase, 'HOLD_RECONCILED')

    def test_stale_readback_cannot_confirm_success(self):
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot()))
        req = w.next_write(self.f.snapshot()); self.f.apply(req)
        stale = self.f.snapshot()
        w.acknowledge(200, max(r.sequence for r in stale.items.values()) + 1)
        self.assertFalse(w.verify(stale)['matches'])
        self.assertEqual(w.phase, 'VERIFY')

    def test_system_etag_or_value_race_requires_new_plan(self):
        for change in [('@odata.etag', '"changed"'), ('Model', 'Unexpected')]:
            f = Fixture(); w = p.Workflow(p.preflight(f.source, f.snapshot()))
            f.system[change[0]] = change[1]
            with self.subTest(change=change), self.assertRaises(p.PublishError): w.next_write(f.snapshot())

    def test_resource_appearing_before_post_is_not_duplicated(self):
        self.f.system.update({k: v for k, v in self.f.source.document()['Systems'][0].items() if k in p.SYSTEM_KEYS})
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot()))
        self.f.cpu = self.f.source.document()['Systems'][0]['Processors']
        with self.assertRaises(p.PublishError): w.next_write(self.f.snapshot())

    def test_verification_is_type_strict_but_uuid_case_insensitive(self):
        self.assertEqual(p.mismatch({'UUID': self.f.source.uuid}, {'UUID': self.f.source.uuid.upper()}), [])
        for got in ('32768', True, None):
            self.assertTrue(p.mismatch({'CapacityMiB': 32768}, {'CapacityMiB': got}))
        self.assertTrue(p.mismatch({'Status': {'State': 'Absent'}}, {'Status': {'State': 'Enabled'}}))
        self.assertTrue(p.mismatch({'UUID': None}, {'UUID': self.f.source.uuid}))

    def test_empty_slots_are_verified_as_slots_not_populated_memory(self):
        self.f.fill()
        plan = p.preflight(self.f.source, self.f.snapshot())
        self.assertEqual(sum(d.get('CapacityMiB', 0) > 0 for d in self.f.memory), 1)
        self.assertEqual(len(self.f.memory), 2)
        self.assertTrue(p.verify_core(plan, self.f.snapshot())['matches'])
        self.f.memory.pop()
        self.assertFalse(p.verify_core(plan, self.f.snapshot())['matches'])

    def test_unknown_health_and_extra_bmc_fields_are_not_fabricated_or_removed(self):
        self.f.fill()
        self.f.system['AssetTag'] = 'user-owned-tag'
        self.f.cpu[0]['Status']['Health'] = 'OK'
        self.assertEqual(p.preflight(self.f.source, self.f.snapshot()).operations, ())

    def test_bulk_requires_capability_and_explicit_partial_snapshot_flag(self):
        with self.assertRaises(p.PublishError): p.preflight(self.f.source, self.f.snapshot(), mode='bulk', allow_partial_bulk=True)
        self.f.capability_status = 200; self.f.capability = {'Id': 'InventoryData'}
        with self.assertRaises(p.PublishError): p.preflight(self.f.source, self.f.snapshot(), mode='bulk')
        self.assertEqual(len(p.preflight(self.f.source, self.f.snapshot(), mode='bulk', allow_partial_bulk=True).operations), 2)

    def test_bulk_finish_requires_positive_post_ack_and_loss_halts(self):
        self.f.capability_status = 200; self.f.capability = {'Id': 'InventoryData'}
        plan = p.preflight(self.f.source, self.f.snapshot(), mode='bulk', allow_partial_bulk=True)
        w = p.Workflow(plan)
        request = w.next_write(self.f.snapshot()); self.assertEqual(request.method, 'POST')
        w.acknowledge(None, w.last_sequence + 1, 'connection-lost')
        with self.assertRaises(p.PublishError): w.next_write(self.f.snapshot())
        w = p.Workflow(plan); w.next_write(self.f.snapshot()); w.acknowledge(201, w.last_sequence + 1)
        request = w.next_write(self.f.snapshot())
        self.assertEqual((request.method, request.body), ('PATCH', b'{"BootComplete":true}'))

    def test_bulk_completed_status_and_core_readback_are_both_required(self):
        self.f.capability_status = 200; self.f.capability = {'Id': 'InventoryData'}
        w = p.Workflow(p.preflight(self.f.source, self.f.snapshot(), mode='bulk', allow_partial_bulk=True))
        w.next_write(self.f.snapshot()); w.acknowledge(200, w.last_sequence + 1)
        w.next_write(self.f.snapshot()); w.acknowledge(200, w.last_sequence + 1)
        self.assertFalse(w.verify(self.f.snapshot())['matches'])  # status alone is insufficient
        self.f.fill(); self.f.publish_status['InventoryData']['Status'] = 'Processing'
        self.assertFalse(w.verify(self.f.snapshot())['matches'])  # values alone are insufficient
        self.f.publish_status['InventoryData']['Status'] = 'Completed'
        self.assertTrue(w.verify(self.f.snapshot())['matches'])
        self.f.publish_status['InventoryData']['Messages'] = ['Warning PropertyMissing (Id : Redfish:Chassis)']
        self.f.publish_status['InventoryData']['DeletedModules'] = ['PCIE']
        self.assertTrue(w.final_verify(self.f.snapshot())['matches'])
        self.assertEqual(w.phase, 'CORE_VERIFIED_WITH_WARNINGS')

    def test_frozen_real_payload_is_not_modified_and_envelope_matches(self):
        base = Path(__file__).resolve().parent / 'hero71-actual'
        source_bytes = (base / 'inventory.pending.json').read_bytes()
        self.assertEqual(p.sha(source_bytes), '06ec92d5c5ecf93fd109eff3c5f4e4cf5061db6f5001e8c60e9df787ce263172')
        self.assertEqual(p.multipart_request(source_bytes).body, (base / 'inventory.multipart.bin').read_bytes())


if __name__ == '__main__':
    unittest.main()
