"""Read-only producer audit plus bounded execution of its real TESTONLY PE.

This imports fixture definitions only, never the frozen writer/test main().
It does not supply independent native authority: observer APIs remain the
explicitly modeled test_host.c boundary in these helper-level executions.
"""
from pathlib import Path
import sys
import json
import hashlib
import importlib.util
import uuid

sys.dont_write_bytecode = True
H = Path(__file__).resolve().parent
B = H.parent
R = B.parents[2]
P = B / 'foreign_page08'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def bind(p):
    return {'path': p.relative_to(R).as_posix(), 'bytes': p.stat().st_size,
            'sha256': sha(p)}


def load(p):
    return json.loads(p.read_text(encoding='utf-8-sig'))


def inputs():
    manifest = P / 'component_manifest.json'
    assert sha(manifest) == '1e6b5ee40846e8fb8b37287f99f3d7955bd5636bd3c1fb845fc7025f2e906f5c'
    m = load(manifest)
    for key in ('files', 'external_bindings'):
        for x in m[key]:
            assert x == bind(R / x['path']), x['path']
    build = load(P / 'build/build.json')
    for path, digest in build['sources'].items():
        assert sha(R / path) == digest
    dll = P / 'build/W890ForeignPage08.TESTONLY.dll'
    tests = load(P / 'test_results.json')
    assert tests['component_sha256'] == build['component_sha256'] == sha(dll)
    assert tests['source_sha256'] == sha(P / 'test_component.py')
    assert len(tests['cases']) == tests['scenario_count'] == 41
    assert all(x['pass'] for x in tests['cases'])
    assert tests['mechanical_page_and_callback_samples'] == 607
    assert tests['protected_alias_controls'] == 861
    return m, {'manifest': bind(manifest), 'dll': bind(dll),
        'source': bind(P / 'foreign_page.c'), 'header': bind(P / 'foreign_page.h'),
        'catalog': bind(P / 'scope_catalog.json'), 'tests': bind(P / 'test_results.json')}


def scopes(raw):
    """Independent offset/formset/form scope decoding, no producer parser import."""
    header = int.from_bytes(raw[:4], 'little')
    assert header >> 24 == 2 and header & 0xffffff == len(raw)
    stack = []
    fs = None
    form = None
    at = 4
    rows = {}
    while at < len(raw):
        op, sizebyte = raw[at:at + 2]
        size = sizebyte & 127
        scoped = bool(sizebyte & 128)
        assert size >= 2 and at + size <= len(raw)
        previous = fs, form
        if op == 14:
            assert fs is None and form is None and scoped
            fs = str(uuid.UUID(bytes_le=raw[at + 2:at + 18]))
        elif op == 1:
            assert fs and form is None and scoped and size == 6
            form = int.from_bytes(raw[at + 2:at + 4], 'little')
        rows[at] = {'formset': fs, 'form': form, 'hex': raw[at:at + size].hex(),
                    'op': op, 'size': size}
        if op == 41:
            assert not scoped and size == 2 and stack
            fs, form = stack.pop()
        elif scoped:
            stack.append(previous)
        at += size
    assert at == len(raw) and not stack and fs is None and form is None
    return rows


def main():
    producer, pins = inputs()
    scope = load(P / 'scope_catalog.json')
    policy = {r['module']: r for r in load(B / 'policy05/storage_policy.json')['packages']}
    forms_checked = controls_checked = dynamic_records_checked = 0
    for p in scope['packages']:
        raw = (R / p['blob_path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == p['sha256'] and len(raw) == p['bytes']
        table = scopes(raw)
        for f in p['forms']:
            actual = table[f['offset']]
            assert actual['op'] == 1 and actual['formset'] == f['formset'] and actual['form'] == f['form']
            forms_checked += 1
        for q in p['controls']:
            actual = table[q['offset']]
            assert actual['formset'] == q['formset'] and actual['form'] == q['form'] and actual['hex'] == q['hex']
            controls_checked += 1
        if p['provenance'] == 'FROZEN_POLICY05_UI_SCOPE_ONLY':
            assert p['forms'] == policy[p['name']]['forms'] and p['controls'] == policy[p['name']]['controls']
        elif p['provenance'] == 'ACTUAL_D7_INERT_INSERTION_MAPPING':
            base = policy[p['name'].removesuffix('_PHYSICAL_D7')]
            for field in ('forms', 'controls'):
                assert len(p[field]) == len(base[field])
                for old, new in zip(base[field], p[field]):
                    assert {k:v for k,v in old.items() if k != 'offset'} == {k:v for k,v in new.items() if k != 'offset'}
                    dynamic_records_checked += 1
            for insertion in p['inserted']:
                actual = table[insertion['offset']]
                assert actual['hex'] == insertion['hex'] and actual['op'] in (2, 3)
                assert not bytes.fromhex(actual['hex'])[1] & 128
    assert len(scope['packages']) == 19 and forms_checked == 595

    spec = importlib.util.spec_from_file_location('fp08_review_fixtures', P / 'test_component.py')
    t = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(t)
    cases = []

    def sample(name, fixture, expected):
        value = fixture.call()
        assert value[:2] == expected, (name, value, expected)
        cases.append({'case': name, 'status': 'PASS', 'result': value[0],
                      'classification': value[1], 'export_calls': value[2]})
        return fixture

    setup = t.byname['Setup']
    ai = next(f for f in setup['forms'] if f.get('reason') == 'ORIGINAL_SETUP_AI_PROTECTED_FORM')
    sample('Pinned original Setup Ai page remains protected', t.Fixture(setup, ai), (1, 1))
    socket = t.byname['SocketSetup_PHYSICAL_D7']
    alias = next(q for q in socket['controls'] if q.get('reason') == 'SHARED_MEMORY_PROTECTED_BYTE_OVERLAP')
    sample('Physical SocketMemory protected-byte alias remains protected',
           t.Fixture(socket, t.record_form(socket, alias['form']), alias), (1, 1))
    ref = next(q for q in socket['controls'] if q.get('reason') == 'REFERENCE_TO_DIRECTLY_PROTECTED_FORM')
    parent = t.record_form(socket, ref['form'])
    sample('Protected child REF does not promote its ordinary parent menu', t.Fixture(socket, parent), (1, 0))
    sample('The child REF itself still requires protection', t.Fixture(socket, parent, ref), (1, 1))
    nic = t.byname['NIC_D7_A']
    q = next(q for q in nic['controls'] if q['review_flags'] & 1)
    f = t.record_form(nic, q['form'])
    v = sample('Ordinary NIC callback widget keeps review flag without execution grant', t.Fixture(nic, f, q), (1, 0))
    assert v.out.review_flags & 1
    sample('Identical physical data under a second HII is separately observed',
           t.Fixture(nic, f, q, hii=t.foreign_hii + 0x100), (1, 0))
    v = t.Fixture(nic, f, q)
    v.w(v.desc + 12, t.D(0xffff))
    assert v.call()[0] == 0
    cases.append({'case':'Raw/native QID mismatch is rejected before publication','status':'PASS'})
    v = t.Fixture(nic, f, q)
    sentinel = bytes([0xa5]) * t.C.sizeof(v.out)
    t.C.memmove(t.C.addressof(v.out), sentinel, len(sentinel))
    v.mode(4)
    assert v.call()[0] == 0 and bytes(v.out) == sentinel
    cases.append({'case':'Generation change during Export leaves caller output untouched','status':'PASS'})
    v = t.Fixture(nic, f, q)
    v.mode(64)
    assert v.call()[:2] == (1,0) and t.lib.fp08_test_nested() == 0 and t.lib.fp08_test_exports() == 1
    cases.append({'case':'Nested description cannot overwrite the single export buffer','status':'PASS'})
    original = (R / nic['blob_path']).read_bytes()
    # An inert TEXT is inserted inside the selected FORM in isolated host data.
    # An unrecognized full FORMS size must remain UNKNOWN, not borrow known risk.
    insert = f['offset'] + 6
    changed = bytearray(original[:insert] + bytes.fromhex('0308000000000000') + original[insert:])
    changed[:4] = t.D(len(changed) | 2 << 24)
    assert len(changed) not in {p['bytes'] for p in scope['packages']}
    v = sample('Uncatalogued length remains UNKNOWN even with the exact selected opcode',
               t.Fixture(nic, f, q, forms_override=bytes(changed)), (1, -1))
    assert bytes(v.out.hash) == bytes(32)
    unknown_digest = {'returned_sha256': bytes(v.out.hash).hex(),
                      'actual_sha256': hashlib.sha256(changed).hexdigest(),
                      'classification': -1, 'length': len(changed)}
    other = bytearray(original)
    other[6:22] = uuid.UUID('d58b6c01-45fe-45c1-a64a-f521fe7918e4').bytes_le
    package = uuid.UUID(f['formset']).bytes_le + t.D(20 + len(original) + len(other) + 4) + original + other + b'\x04\0\0\xdf'
    v = t.Fixture(nic, f, q, package_override=package)
    assert v.call()[0] == 0
    cases.append({'case':'Equal FormId in a distinct FORM_SET of the same HII is ambiguous and rejected','status':'PASS'})
    unknown = next(q for q in t.byname['Platform']['controls'] if q['storage_risk'] == -1)
    sample('Unknown Platform extension stays UNKNOWN',
           t.Fixture(t.byname['Platform'], t.record_form(t.byname['Platform'], unknown['form']), unknown), (1,-1))
    assert inputs()[1] == pins
    report = {
      'status':'INDEPENDENT_SCOPE_REVIEW_AND_BOUNDED_HELPER_PE_CASES_PASS_WITH_METADATA_CAVEAT',
      'inputs':pins,
      'verified_manifest_counts':{k:len(producer[k]) for k in ('files','external_bindings')},
      'source':bind(Path(__file__)),
      'catalog_verification':{'distinct_signatures':19,'forms':forms_checked,'controls':controls_checked,
                             'dynamic_records_transferred_without_classification_change':dynamic_records_checked,
                             'count_boundary':'595 FORM records span original and physical variant signatures; they are not 595 simultaneous physical pages.'},
      'producer_results_checked':{'behavior_scenarios':41,'mechanical_samples':607,'protected_alias_queries':861,
                                  'counts_not_combined_into_scenarios':True},
      'independent_cases':cases,
      'production_contract_review':[
        'Caller inputs contain only native page/index/control/output, not owner, HII, formset, native base or permission booleans.',
        'App member uniqueness, raw page HII/FormId, current-page control membership, known type/vtable and raw-descriptor QID/variable-index/IFR-pointer ties are checked before and after Export.',
        'Both full FORMS signature and FORM_SET-local record offset/form/control kind are required for a known catalog classification.',
        'Scoped parsing rejects ambiguous FormId, repeated FORM_SET, malformed package bounds and missing terminal END. Unknown exact data never becomes ordinary.',
        'Protected parent pages cannot be downgraded by ordinary widgets; ordinary parents are not promoted merely by a protected child REF.',
        'Visit, safety epoch, catalog generation and complete HII protocol table are compared across description. Shared buffer reentry is refused.',
        'No native callback, password request, variable service or code-execution permission is issued by the production helper.'
      ],
      'findings':[
        {'id':'FP08-01','severity':'METADATA_CAVEAT_NO_PERMISSION_BYPASS',
         'finding':'catalog() skips SHA when no known package length matches. A valid UNKNOWN view then contains an all-zero forms_sha256, despite the report wording implying a complete SHA is always present.',
         'actual_pe_example':unknown_digest,
         'recommendation':'In the composed consumer treat UNKNOWN as unusable and never treat zero digest as a real identity. Document hash availability or compute the digest for all structurally accepted packages in a separately reviewed derivative.'}
      ],
      'integration_conditions':[
        'Only call the helper at TPL_APPLICATION. Its first no_identity call refreshes the memory map; checking for a false return does not make high-TPL invocation safe.',
        'Use the final revision03 generation-aware observer. This frozen helper manifest references revision01, and its test_host simulates private anchors rather than linking any real observer.',
        'Keep the resulting view private, bind classification and generation in the observer snapshot, and reobserve immediately before the real protected transition.',
        'Cached/high-TPL ticket validators cannot call this exporting helper. They must validate saved view, native membership and generation without UEFI services.',
        'Keep published Setup Security management validation on its existing private publication path; the original Setup catalog does not recognize the modified published package.',
        'Do not link test_host.c, fp08_test_* exports or the TESTONLY DLL into firmware.',
        'An ordinary UI classification and CALLBACK_REVIEW flag are not permission to initiate additional callbacks or variable writes.'
      ],
      'limits':[
        'Actual compiled C parser, SHA256 and classification execute. The native containers, observer roots, memory permissions, HII handles and Export service are explicit TESTONLY host models.',
        'No full native owner proof, original callback execution, GUI operation, cold boot, DXE, firmware variable or hardware test is established here.',
        'The two NON_FV NIC packages prove exact data shape and distinct HII observations, not module provenance or new callback execution permission.',
        'No arbitrary concurrent AP/SMM memory writer resistance is claimed by the bounded read/recheck model.'
      ],
      'producer_inputs_modified':False,'hardware_actions':0,'runtime_authorized':False,
      'firmware_artifact_created':False
    }
    (H/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    external = {P/'component_manifest.json'}
    for key in ('files','external_bindings'):
        external.update(R/x['path'] for x in producer[key])
    r3 = B/'observer_generation08/revision03/component_manifest.json'
    assert sha(r3)=='29245a71a7e0c06d0452c16e92c4646fb52b8cd4d12a42d547cf25c4fb6ab0f1'
    external.add(r3)
    manifest = {'status':report['status'],'path_basis':'workspace root',
      'files':[bind(H/x) for x in ('review.py','review.json')],
      'external_bindings':[bind(x) for x in sorted(external,key=str)]}
    (H/'component_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'cases':len(cases),'catalog_forms':forms_checked,'catalog_controls':controls_checked,
                      'review':bind(H/'review.json'),'manifest':bind(H/'component_manifest.json')}))


if __name__=='__main__':
    main()
