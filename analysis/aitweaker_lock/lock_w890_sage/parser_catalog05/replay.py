"""Original AMITSE parser against the captured, statically resolvable HII catalog.

UEFI database/string/allocation services are explicit models.  Package handles
are fixture identities; original callback owners and DXE startup are NOT modeled
as trusted.  Missing non-FV packages stay absent, never fabricated as safe pages.
An isolated original SPF mapping exposes the partial-catalog boundary failure.
No firmware image, credential, or hardware state is changed.
"""
from pathlib import Path
import collections, hashlib, json, struct, sys, time, uuid

H = Path(__file__).resolve().parent
B = H.parent
ROOT = B.parents[2]
sys.path.insert(0, str(B / 'integration05'))
from parser_lab import VM, TSE, Q, D, ERR, string_packages
from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RIP


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source(path):
    p = Path(path)
    return p if p.is_absolute() else ROOT / p


class CatalogVM(VM):
    def __init__(self, changed=False):
        super().__init__(changed=changed, hii=0x900013)
        self.catalog_path = B / 'foreign_hii05/catalog.json'
        self.catalog = json.loads(self.catalog_path.read_text())
        self.package_models = {}
        self.omitted = []
        self.input_bindings = []
        self.pool_guard_error = None
        self.spf_reads = 0
        self.unknown_strings = collections.Counter()
        next_handle = 0x910000
        for package in self.catalog['packages']:
            if not package['producer_modules']:
                self.omitted.append({'guid': package['package_list_guid'],
                                     'reason': package['association'],
                                     'hardware_instances': len(package['hardware_instances'])})
                continue
            assert len(package['producer_modules']) == 1
            module = package['producer_modules'][0]
            pe = source(module['path']).read_bytes()
            assert digest(pe) == module['sha256']
            strings = string_packages(pe)
            english_offsets = {s['offset'] for s in module['string_packages'] if s.get('language') == 'en-US'}
            english = [s for s in strings if s['offset'] in english_offsets]
            assert len(english) == 1, (module['module_name'], [s.keys() for s in strings])
            tokens = {int(k): v for k, v in english[0]['strings'].items()}
            blobs = []
            for fp in package['forms_packages']:
                blob = source(fp['blob_path']).read_bytes()
                assert digest(blob) == fp['sha256']
                blobs.append(blob)
                self.input_bindings.append({'path': fp['blob_path'], 'sha256': fp['sha256']})
            is_setup = module['module_name'] == 'Setup'
            for instance in package['hardware_instances']:
                handle = self.hii if is_setup else next_handle
                next_handle += 16
                if is_setup:
                    data, tokens_use = self.package, self.strings
                else:
                    body = b''.join(blobs) + b'\x04\x00\x00\xdf'
                    data = uuid.UUID(package['package_list_guid']).bytes_le + D(20 + len(body)) + body
                    tokens_use = tokens
                assert handle not in self.package_models
                self.package_models[handle] = {
                    'module': module['module_name'], 'data': data, 'strings': tokens_use,
                    'forms': instance['forms'], 'observed_handle': instance['handle'],
                    'guid': package['package_list_guid'],
                }
        # Preserve captured relative ordering, including duplicate package lists.
        observed_order = sorted([(int(p['observed_handle'], 16), h)
                                 for h, p in self.package_models.items()])
        self.handles = [h for _, h in observed_order]
        self.static_extent = 0xf245c
        raw = bytes(self.u.mem_read(self.static, self.static_extent))
        self.static = 0x19000000
        self.u.mem_map(self.static, 0xf3000)
        self.u.mem_write(self.static, raw)
        self.wq(TSE + 0xbabc0, self.static)
        self.u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                        self.guard, begin=self.static, end=self.static + 0xf2fff)

    def guard(self, u, access, address, size, value, _):
        self.spf_reads += 1
        if address + size > self.static + self.static_extent:
            self.pool_guard_error = {
                'kind': 'SPF_EXTENT_OVERFLOW', 'rva': hex(u.reg_read(UC_X86_REG_RIP) - TSE),
                'address_offset': hex(address - self.static), 'size': size,
            }
            self.error = str(self.pool_guard_error)
            u.emu_stop()

    def listpkg(self, a):
        assert a[1] in (0, 2), ('unexpected package type', a[1])
        assert not a[2], 'unmodeled GUID filter'
        cap = self.rq(a[3]); needed = len(self.handles) * 8
        self.wq(a[3], needed)
        if not a[4] or cap < needed:
            return ERR | 5
        self.u.mem_write(a[4], b''.join(Q(h) for h in self.handles))
        return 0

    def export(self, a):
        assert a[1] in self.package_models, hex(a[1])
        data = self.package_models[a[1]]['data']
        cap = self.rq(a[2]); self.wq(a[2], len(data))
        if not a[3] or cap < len(data):
            return ERR | 5
        self.u.mem_write(a[3], data)
        return 0

    def getdriver(self, a):
        if a[1] not in self.package_models:
            return ERR | 14
        # This is a modeled handle only; HandleProtocol retains NOT_FOUND.
        # GetCpuInfo's physically observed NULL driver remains NULL.
        self.wq(a[2], 0 if self.package_models[a[1]]['module'] == 'GetCpuInfo' else a[1] + 0x200000)
        return 0

    def getstring(self, a):
        if a[2] not in self.package_models:
            return ERR | 14
        data = self.package_models[a[2]]['strings'].get(a[3])
        if data is None:
            self.unknown_strings[(self.package_models[a[2]]['module'], a[3])] += 1
            return ERR | 14
        p = (data + '\0').encode('utf-16le')
        cap = self.rq(a[5]); self.wq(a[5], len(p))
        if not a[4] or cap < len(p):
            return ERR | 5
        self.u.mem_write(a[4], p)
        return 0

    def volatile_count(self, a):
        name = bytes(self.u.mem_read(a[0], 128)).decode('utf-16le', errors='replace').split('\0')[0]
        expected = {
            'DynamicPageCount': ('b63bf800-f267-4f55-9217-e97fb3b69846', 4),
            'DynamicPageGroupCount': ('537f1f99-6fc4-40b5-80b2-390b0753c4d0', 2),
            'DynamicPageGroupClass': ('551941e5-0011-4d7f-83ed-e462cbabccc9', 14),
        }
        assert name in expected
        guid, n = expected[name]
        assert bytes(self.u.mem_read(a[1], 16)) == uuid.UUID(guid).bytes_le
        assert a[2:4] == [2, n]
        self.writes.append({'name': name, 'attributes': 2, 'value': bytes(self.u.mem_read(a[4], n)).hex(),
                            'effect': 'volatile explicitly modeled service only'})
        return 0

    def summarize_pages(self):
        table, blob, controls = self.rq(TSE + 0xbaaf0), self.rq(TSE + 0xbabc0), self.rq(TSE + 0xbab08)
        if not table:
            return {'available': False}
        count = self.rd(table)
        assert count <= 4096
        by_module = collections.Counter(); unbound = []; pages = []
        for i in range(count):
            off = self.rd(table + 4 + 4*i)
            p = blob + off
            if not off or not any(q <= p and p + 32 <= q+n for q, n in self.live.items()) and not self.static <= p < self.static + self.static_extent:
                unbound.append({'index': i, 'offset': off, 'reason': 'missing-or-unproved-record'}); continue
            handle, form = self.rq(p), self.rw(p+10)
            module = self.package_models.get(handle, {}).get('module', 'UNBOUND')
            by_module[module] += 1
            pages.append({'index': i, 'form': form, 'hii': handle, 'module': module,
                          'controls': self.rd(p+28)})
        return {'available': True, 'count': count, 'by_module': dict(by_module),
                'missing_records': unbound, 'pages': pages}


def run(changed):
    start = time.monotonic()
    v = CatalogVM(changed=changed)
    result = {'status': 'RUNNING', 'management_actions_inserted': changed,
              'scope': __doc__, 'catalog_sha256': digest(v.catalog_path.read_bytes()),
              'original_tse_sha256': v.original_sha, 'original_spf_container_sha256': v.static_sha,
              'inputs': v.input_bindings, 'modeled_handles': len(v.handles),
              'modeled_forms': sum(x['forms'] for x in v.package_models.values()),
              'omitted_original_unavailable': v.omitted,
              'source_sha256': digest(Path(__file__).read_bytes())}
    try:
        result['return'] = hex(v.run())
        result['status'] = 'PASS_PARSER_RETURN_ONLY' if result['return'] == '0x0' else 'FAIL_NATIVE_STATUS'
    except Exception as e:
        result['status'] = 'FAIL_REPLAY'; result['error'] = str(e)
    result.update(calls=dict(v.calls), spf_accesses=v.spf_reads, spf_guard_error=v.pool_guard_error,
                  writes=v.writes, elapsed_seconds=round(time.monotonic()-start, 3))
    try:
        result['native_pages'] = v.summarize_pages()
    except Exception as e:
        result['page_inspection_error'] = str(e)
    out = H / ('changed.json' if changed else 'original.json')
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: val for k, val in result.items() if k not in ['inputs','native_pages','scope','calls']}, indent=2), flush=True)
    if result.get('native_pages'):
        print('native pages', json.dumps({k: v for k, v in result['native_pages'].items() if k != 'pages'}), flush=True)


if __name__ == '__main__':
    run('--changed' in sys.argv)
