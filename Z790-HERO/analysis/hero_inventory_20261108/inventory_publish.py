"""Transport-free reference implementation for the HERO inventory publisher.

No sockets, subprocesses, firmware services or BMC writes occur here. A caller
supplies current-host SMBIOS and fresh, authenticated internal-USB GET results.
This module builds a bounded write plan and checks acknowledgement/readback.
The executable UEFI transport must enforce the same binding and state rules.
"""
from dataclasses import dataclass
import copy
import hashlib
import json
import re
import uuid

from smbios_inventory import CaptureError, compose, parse_capture

ROOT = '/redfish/v1/'
INVENTORY = '/redfish/v1/Oem/Ami/InventoryData'
INVENTORY_STATUS = INVENTORY + '/Status'
BOUNDARY = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
MAX_JSON = 256 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
MAX_AGE_MS = 30_000
MAX_VERIFY_READS = 3
ACCEPTED = (200, 201, 204)
SYSTEM_KEYS = ('Model', 'Manufacturer', 'BiosVersion', 'UUID', 'SerialNumber', 'SKU')


class PublishError(ValueError):
    pass


def canonical(value):
    content = json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    if len(content) > MAX_JSON:
        raise PublishError('inventory JSON exceeds bounded size')
    return content


def decode_response(content):
    """Strict JSON boundary for HTTP adapters; rejects duplicate keys and NaN."""
    if not isinstance(content, bytes) or not 0 < len(content) <= MAX_RESPONSE:
        raise PublishError('invalid response byte count')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PublishError('duplicate JSON property')
            result[key] = value
        return result

    def constant(_):
        raise PublishError('non-finite JSON value')

    try:
        obj = json.loads(content.decode('utf8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise PublishError('invalid JSON response') from error
    if not isinstance(obj, dict):
        raise PublishError('response must be a JSON object')

    def depth(value, level=0):
        if level > 32:
            raise PublishError('response nesting too deep')
        if isinstance(value, dict):
            for item in value.values():
                depth(item, level + 1)
        elif isinstance(value, list):
            for item in value:
                depth(item, level + 1)
    depth(obj)
    return obj


def safe_uri(value):
    if not isinstance(value, str) or len(value) > 512 or not re.fullmatch(
            r'/redfish/v1(?:/[A-Za-z0-9_.-]+)*/?', value):
        raise PublishError('only same-service Redfish paths are allowed')
    if any(p in ('.', '..') for p in value.split('/')):
        raise PublishError('relative traversal is not a resource path')
    return value


def link(value):
    if not isinstance(value, dict) or set(value) != {'@odata.id'}:
        raise PublishError('ambiguous resource link')
    return safe_uri(value['@odata.id'])


def sha(value):
    return hashlib.sha256(value).hexdigest()


def validate_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise PublishError('expected a lowercase SHA256 digest')


@dataclass(frozen=True)
class Source:
    payload: bytes
    table_sha256: str
    uuid: str
    bios_version: str

    @classmethod
    def from_capture(cls, text):
        records, meta = parse_capture(text)
        payload = compose(records, meta)
        system = payload['Systems'][0]
        if 'UUID' not in system:
            raise PublishError('valid current-host UUID required for the first publishing implementation')
        if not system['Processors'] or not system['Memory']:
            raise PublishError('incomplete CPU/DIMM capture; no publishing plan generated')
        if len(system['Processors']) > 64 or len(system['Memory']) > 256:
            raise PublishError('CPU/DIMM count exceeds bounded publisher capacity')
        return cls(canonical(payload), meta['table_sha256'], system['UUID'], system['BiosVersion'])

    def document(self):
        return json.loads(self.payload)


@dataclass(frozen=True)
class Binding:
    """The transport owns these facts; a certificate pin is provisioned per BMC."""
    session_id: str
    source_table_sha256: str
    current_host_uuid: str
    transport: str
    usb_vid: int
    usb_pid: int
    pinned_leaf_sha256: str
    observed_leaf_sha256: str

    def check(self, source):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', self.session_id):
            raise PublishError('invalid boot/session identifier')
        validate_digest(self.source_table_sha256)
        validate_digest(self.pinned_leaf_sha256)
        validate_digest(self.observed_leaf_sha256)
        if self.source_table_sha256 != source.table_sha256:
            raise PublishError('payload is not from this boot capture')
        try:
            same_uuid = uuid.UUID(self.current_host_uuid) == uuid.UUID(source.uuid)
        except (ValueError, TypeError, AttributeError) as error:
            raise PublishError('invalid current-host UUID') from error
        if not same_uuid:
            raise PublishError('payload/current-host UUID mismatch')
        if (self.transport, self.usb_vid, self.usb_pid) != ('internal-usb', 0x046b, 0xffb0):
            raise PublishError('publisher restricted to the verified BMC internal USB transport')
        if self.pinned_leaf_sha256 != self.observed_leaf_sha256:
            raise PublishError('peer certificate pin mismatch')


@dataclass(frozen=True)
class Observation:
    uri: str
    status: int
    body: dict | None
    sequence: int
    read_at_ms: int
    session_id: str
    etag: str | None = None


class Snapshot:
    """One boot/session's supplied GET results, not a client that fetches them."""
    def __init__(self, binding, observations, now_ms):
        if type(now_ms) is not int or now_ms < 0:
            raise PublishError('invalid observation clock')
        self.binding = binding
        self.now_ms = now_ms
        self.items = {}
        sequences = set()
        for item in observations:
            safe_uri(item.uri)
            if item.uri in self.items or item.sequence in sequences:
                raise PublishError('duplicate URI or observation sequence')
            if item.session_id != binding.session_id:
                raise PublishError('mixed boot/session observations')
            if type(item.sequence) is not int or item.sequence < 0:
                raise PublishError('invalid read sequence')
            if type(item.read_at_ms) is not int or item.read_at_ms < 0:
                raise PublishError('invalid observation time')
            sequences.add(item.sequence)
            self.items[item.uri] = copy.deepcopy(item)

    def response(self, uri, after=-1):
        if uri not in self.items:
            raise PublishError('missing GET observation: ' + uri)
        result = self.items[uri]
        if not 0 <= self.now_ms - result.read_at_ms <= MAX_AGE_MS:
            raise PublishError('stale/future GET observation: ' + uri)
        if result.sequence <= after:
            raise PublishError('GET predates the operation being verified: ' + uri)
        return result

    def get(self, uri, after=-1):
        result = self.response(uri, after)
        if result.status != 200 or not isinstance(result.body, dict) or 'error' in result.body:
            raise PublishError('resource GET did not return a valid success object: ' + uri)
        if result.body.get('@odata.id', uri) != uri:
            raise PublishError('resource returned a different @odata.id')
        return result.body

    def collection(self, uri, after=-1, details=True):
        body = self.get(uri, after)
        count, members = body.get('Members@odata.count'), body.get('Members')
        if type(count) is not int or not isinstance(members, list) or not 0 <= count <= 256:
            raise PublishError('invalid collection count or members')
        if len(members) != count or 'Members@odata.nextLink' in body:
            raise PublishError('incomplete/paginated collection must be fully collected first')
        paths = [link(item) for item in members]
        if len(set(paths)) != len(paths) or any(not p.startswith(uri.rstrip('/') + '/') for p in paths):
            raise PublishError('duplicate or foreign collection member')
        if not details:
            return paths
        result = {}
        for path in paths:
            member = self.get(path, after)
            ident = member.get('Id')
            if not isinstance(ident, str) or not ident or ident in result:
                raise PublishError('invalid or duplicated resource Id')
            result[ident] = member
        return result


def etag(snapshot, uri):
    observed = snapshot.response(uri)
    header, body = observed.etag, observed.body.get('@odata.etag') if observed.body else None
    if header and body and header != body:
        raise PublishError('conflicting ETag values')
    value = header or body
    if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 256 or
                              any(ord(c) < 32 or ord(c) > 126 for c in value)):
        raise PublishError('invalid ETag header')
    return value


def mismatch(expected, actual, prefix=''):
    """Return mismatched paths; no truthy/integer coercion or invented defaults."""
    result = []
    for key, value in expected.items():
        path = prefix + '/' + key
        got = actual.get(key) if isinstance(actual, dict) else None
        if isinstance(value, dict):
            result += mismatch(value, got, path)
        elif key == 'UUID' and isinstance(got, str):
            if value == got:
                continue  # Exact placeholders are valid when comparing a pre-write baseline.
            try:
                if uuid.UUID(value) != uuid.UUID(got):
                    result.append(path)
            except (ValueError, TypeError, AttributeError):
                result.append(path)
        elif type(value) is not type(got) or value != got:
            result.append(path)
    return result


@dataclass(frozen=True)
class Request:
    method: str
    uri: str
    headers: tuple
    body: bytes

    def manifest(self):
        return {'method': self.method, 'uri': self.uri, 'headers': dict(self.headers),
                'body_bytes': len(self.body), 'body_sha256': sha(self.body)}


def json_request(method, uri, payload, match=None):
    if method not in ('POST', 'PATCH'):
        raise PublishError('no other mutation method is implemented')
    if match is not None and (not isinstance(match, str) or not 1 <= len(match) <= 256 or
                              any(ord(c) < 32 or ord(c) > 126 for c in match)):
        raise PublishError('invalid conditional request header')
    body = canonical(payload)
    headers = [('Content-Type', 'application/json;charset=utf-8'), ('Content-Length', str(len(body))),
               ('OData-Version', '4.0')]
    if match is not None:
        headers.append(('If-Match', match))
    return Request(method, safe_uri(uri), tuple(headers), body)


def multipart_request(payload):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_JSON:
        raise PublishError('invalid multipart JSON byte count')
    prefix = (f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="static_file"; filename="inventory.json"\r\n'
              'Content-Type: application/xml;charset=utf-16\r\n\r\n').encode('ascii')
    body = prefix + payload + f'\r\n--{BOUNDARY}--\r\n'.encode('ascii')
    return Request('POST', INVENTORY,
                   (('Content-Type', 'multipart/form-data; boundary=' + BOUNDARY),
                    ('Content-Length', str(len(body)))), body)


def capability_get_headers():
    return {'Accept': 'application/json;charset=utf-8', 'OData-Version': '4.0',
            'BiosRedfishVersion': '1.8.0', 'BiosRtpVersion': '1.8.a'}


@dataclass(frozen=True)
class Operation:
    kind: str
    request: Request
    expected_json: bytes
    baseline_json: bytes
    collection_uri: str | None = None

    def expected(self):
        return json.loads(self.expected_json)


@dataclass(frozen=True)
class Plan:
    source: Source
    binding: Binding
    mode: str
    system_uri: str
    processors_uri: str
    memory_uri: str
    operations: tuple
    baseline_sequence: int

    def manifest(self):
        return {'mode': self.mode, 'session_id': self.binding.session_id,
                'source_table_sha256': self.source.table_sha256, 'payload_sha256': sha(self.source.payload),
                'current_host_uuid': self.source.uuid, 'bios_version': self.source.bios_version,
                'operations': [{'kind': op.kind, **op.request.manifest()} for op in self.operations],
                'constraints': ['No automatic write retry', 'No DELETE request; bulk replacement side effects remain unverified', 'No fabricated group CRC',
                                'No PCIe/Storage or donor identity', 'Each write requires current readback']}


def preflight(source, snapshot, mode='legacy', allow_partial_bulk=False):
    """Build either route before any writes. Never switch routes mid-session."""
    snapshot.binding.check(source)
    root = snapshot.get(ROOT)
    oem = root.get('Oem')
    ami = oem.get('Ami') if isinstance(oem, dict) else None
    if root.get('RedfishVersion') != '1.8.0' or not isinstance(ami, dict) or ami.get('RtpVersion') != '1.8.a':
        raise PublishError('unverified Redfish/RTP schema version')
    systems_uri = link(root.get('Systems'))
    systems = snapshot.collection(systems_uri, details=False)
    if len(systems) != 1:
        raise PublishError('exactly one System must be discovered for this board')
    system_uri = systems[0]
    current = snapshot.get(system_uri)
    desired = source.document()['Systems'][0]
    known_uuid = current.get('UUID')
    if known_uuid not in (None, '', 'NA', 'N/A', '00000000-0000-0000-0000-000000000000'):
        if mismatch({'UUID': source.uuid}, current):
            raise PublishError('BMC contains another host UUID; explicit stale inventory review required')
    processors_uri, memory_uri = link(current.get('Processors')), link(current.get('Memory'))
    for path in (processors_uri, memory_uri):
        if not path.startswith(system_uri.rstrip('/') + '/'):
            raise PublishError('collection belongs to another System')
    seen_cpu = snapshot.collection(processors_uri)
    seen_memory = snapshot.collection(memory_uri)
    desired_system = {key: desired[key] for key in SYSTEM_KEYS if key in desired}
    operations = []
    if mode == 'legacy':
        changed = {key: value for key, value in desired_system.items() if mismatch({key: value}, current)}
        if changed:
            baseline = {key: current.get(key) for key in changed}
            operations.append(Operation('system-patch', json_request('PATCH', system_uri, changed, etag(snapshot, system_uri)),
                                        canonical(changed), canonical(baseline)))
        for name, coll, present in [('Processors', processors_uri, seen_cpu), ('Memory', memory_uri, seen_memory)]:
            ids = {item['Id'] for item in desired[name]}
            if set(present) - ids:
                raise PublishError('existing inventory uses other IDs; no deletion or duplicate creation')
            for item in desired[name]:
                ident = item['Id']
                if ident in present:
                    if mismatch(item, present[ident]):
                        raise PublishError('existing CPU/DIMM differs; update semantics require separate proof: ' + ident)
                else:
                    operations.append(Operation('resource-post', json_request('POST', coll, item),
                                                canonical(item), b'{}', coll))
    elif mode == 'bulk':
        capability = snapshot.get(INVENTORY)
        if not capability or not allow_partial_bulk:
            raise PublishError('bulk requires valid capability and explicit partial-snapshot opt-in')
        # Creator can report DeletedModules for omitted groups. This is never the
        # automatic fallback of a legacy write, and cannot be called "no delete".
        operations = [Operation('bulk-post', multipart_request(source.payload), b'{}', b'{}'),
                      Operation('bulk-finish', json_request('PATCH', INVENTORY, {'BootComplete': True}), b'{}', b'{}')]
    else:
        raise PublishError('choose one known route: legacy or bulk')
    return Plan(source, snapshot.binding, mode, system_uri, processors_uri, memory_uri,
                tuple(operations), max(item.sequence for item in snapshot.items.values()))


def verify_core(plan, snapshot, after=-1):
    snapshot.binding.check(plan.source)
    if snapshot.binding != plan.binding:
        raise PublishError('verification belongs to another transport session')
    desired = plan.source.document()['Systems'][0]
    failures = mismatch({k: desired[k] for k in SYSTEM_KEYS if k in desired}, snapshot.get(plan.system_uri, after))
    for name, coll in [('Processors', plan.processors_uri), ('Memory', plan.memory_uri)]:
        present = snapshot.collection(coll, after)
        expected = {item['Id']: item for item in desired[name]}
        if set(present) != set(expected):
            failures.append('/' + name + '/Ids')
        for ident, item in expected.items():
            failures += mismatch(item, present.get(ident), '/' + name + '/' + ident)
    warnings = []
    if plan.mode == 'bulk':
        data = snapshot.get(INVENTORY_STATUS, after).get('InventoryData', {})
        if not isinstance(data, dict):
            raise PublishError('invalid InventoryData status object')
        if data.get('Status') != 'Completed':
            failures.append('/InventoryData/Status')
        warnings = {'messages': data.get('Messages', []), 'deleted_modules': data.get('DeletedModules', [])}
    return {'matches': not failures, 'mismatches': failures, 'warnings': warnings}


class Workflow:
    """One request in flight. All retries are reads; no automatic write replay.

    Caller MUST durably save journal after next_write() and BEFORE transmitting
    its returned bytes. On restart create a new preflight, never replay a journal.
    """
    def __init__(self, plan):
        self.plan = plan
        self.index = 0
        self.phase = 'READY' if plan.operations else 'NO_WRITES_NEEDED'
        self.last_sequence = -1
        self.verify_reads = 0
        self.journal = []

    def event(self, state, **data):
        self.journal.append({'event': state, 'operation': self.index, **data})

    def check_snapshot(self, snapshot):
        snapshot.binding.check(self.plan.source)
        if snapshot.binding != self.plan.binding:
            raise PublishError('mixed transport session')

    def next_write(self, snapshot):
        if self.phase != 'READY':
            raise PublishError('no write permitted in phase ' + self.phase)
        self.check_snapshot(snapshot)
        op = self.plan.operations[self.index]
        if op.kind == 'system-patch':
            current = snapshot.get(op.request.uri, self.last_sequence)
            if mismatch(json.loads(op.baseline_json), current):
                raise PublishError('System changed since preflight; build a new plan')
            if dict(op.request.headers).get('If-Match') != etag(snapshot, op.request.uri):
                raise PublishError('System ETag changed since preflight')
        elif op.kind == 'resource-post':
            present = snapshot.collection(op.collection_uri, self.last_sequence)
            if op.expected()['Id'] in present:
                raise PublishError('target ID appeared; do not replay create, run a new preflight')
            desired_ids = {i['Id'] for i in self.plan.source.document()['Systems'][0][
                'Processors' if op.collection_uri == self.plan.processors_uri else 'Memory']}
            if set(present) - desired_ids:
                raise PublishError('foreign resource appeared after preflight')
        elif op.kind == 'bulk-post':
            snapshot.get(INVENTORY, self.last_sequence)
        elif op.kind == 'bulk-finish':
            # Only the accepted POST reaches this state. A failed/lost POST never does.
            if not self.journal or self.journal[-1]['event'] != 'BULK_POST_ACKNOWLEDGED':
                raise PublishError('BootComplete requires this session\'s positive POST acknowledgement')
        self.last_sequence = max(self.last_sequence, *(item.sequence for item in snapshot.items.values()))
        self.phase = 'WAIT_RESULT'
        self.event('WRITE_INTENT', request=op.request.manifest(), after_sequence=self.last_sequence)
        return op.request

    def acknowledge(self, status, sequence, transport_error=None):
        if self.phase != 'WAIT_RESULT' or sequence <= self.last_sequence:
            raise PublishError('unexpected or stale write response')
        self.last_sequence = sequence
        self.verify_reads = 0
        op = self.plan.operations[self.index]
        self.event('WRITE_RESPONSE', status=status, transport_error=transport_error, sequence=sequence)
        if transport_error or status is None:
            self.phase = 'UNKNOWN_VERIFY'
        elif status not in ACCEPTED:
            self.phase = 'REJECTED_VERIFY'
        elif op.kind == 'bulk-post':
            self.event('BULK_POST_ACKNOWLEDGED', status=status)
            self.index += 1
            self.phase = 'READY'
        else:
            self.phase = 'VERIFY'

    def verify(self, snapshot):
        if self.phase not in ('VERIFY', 'UNKNOWN_VERIFY', 'REJECTED_VERIFY'):
            raise PublishError('not awaiting readback')
        self.check_snapshot(snapshot)
        op = self.plan.operations[self.index]
        prior_phase = self.phase
        self.verify_reads += 1
        try:
            if op.kind.startswith('bulk-'):
                result = verify_core(self.plan, snapshot, self.last_sequence)
            elif op.kind == 'system-patch':
                failures = mismatch(op.expected(), snapshot.get(op.request.uri, self.last_sequence))
                result = {'matches': not failures, 'mismatches': failures, 'warnings': []}
            else:
                present = snapshot.collection(op.collection_uri, self.last_sequence)
                failures = mismatch(op.expected(), present.get(op.expected()['Id']))
                result = {'matches': not failures, 'mismatches': failures, 'warnings': []}
        except PublishError as error:
            result = {'matches': False, 'mismatches': [str(error)], 'warnings': []}
        self.event('READBACK', attempt=self.verify_reads, **result)
        if result['matches']:
            if prior_phase != 'VERIFY':
                self.phase = 'HOLD_RECONCILED'
                self.event('HOLD_RECONCILED', reason='write result uncertain/rejected; no automatic continuation')
            else:
                self.index += 1
                self.phase = 'READY' if self.index < len(self.plan.operations) else 'WRITES_VERIFIED'
                self.last_sequence = max(self.last_sequence, *(item.sequence for item in snapshot.items.values()))
        elif self.verify_reads >= MAX_VERIFY_READS:
            self.phase = 'HOLD_UNVERIFIED'
        return result

    def final_verify(self, snapshot):
        if self.phase not in ('WRITES_VERIFIED', 'NO_WRITES_NEEDED'):
            raise PublishError('final verification requires all planned operations to finish')
        result = verify_core(self.plan, snapshot, self.last_sequence)
        self.event('FINAL_CORE_READBACK', **result)
        if result['matches']:
            warning = result['warnings']
            self.phase = 'CORE_VERIFIED_WITH_WARNINGS' if warning and any(warning.values()) else 'CORE_VERIFIED'
        else:
            self.phase = 'HOLD_FINAL_MISMATCH'
        return result
