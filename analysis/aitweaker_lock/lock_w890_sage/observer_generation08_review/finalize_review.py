"""Bind the final observer revision to preserved independent counterexamples.

This file reads producer artifacts only. A manifest SHA must be supplied after
the producer explicitly freezes revision03; no test or producer build executes.
"""
from pathlib import Path
import argparse
import hashlib
import json

H = Path(__file__).resolve().parent
B = H.parent
R = B.parents[2]
O = B / 'observer_generation08'
P = O / 'revision03'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def bind(p):
    return {'path': p.relative_to(R).as_posix(),
            'bytes': p.stat().st_size, 'sha256': sha(p)}


def load(p):
    return json.loads(p.read_text(encoding='utf-8-sig'))


def verify_manifest(path, expected):
    assert sha(path) == expected, path
    m = load(path)
    counts = {}
    for field in ('files', 'external_bindings'):
        for entry in m[field]:
            assert bind(R / entry['path']) == entry, entry['path']
        counts[field] = len(m[field])
    return m, counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--r3-manifest-sha', required=True)
    args = ap.parse_args()
    m1, n1 = verify_manifest(O / 'component_manifest.json',
        '4fc68d969c583e39cf1bfbf798dcf52c5bcc6a7fe4e00e8616eb168b9e778d30')
    m3, n3 = verify_manifest(P / 'component_manifest.json', args.r3_manifest_sha)
    dll = P / 'build/W890ObserverGeneration08r3.TESTONLY.dll'
    assert sha(dll) == '33624f054ed50aecaf57150a7afe0cd00c1942b877132e3b13601d056a4ab19b'
    build = load(P / 'build/build.json')
    assert build['component_sha256'] == sha(dll)
    for path, digest in build['sources'].items():
        assert sha(R / path) == digest, path
    baseline = load(P / 'generation_tests.json')
    assert baseline['checks'] == len(baseline['cases']) == 9
    assert all(c['passed'] for c in baseline['cases'])
    assert baseline['component_sha256'] == sha(dll)
    assert baseline['source_sha256'] == sha(P / 'verify_generation.py')
    independent = load(H / 'revision03_replay.json')
    assert len(independent['cases']) == 7
    assert all(c['status'] == 'PASS' for c in independent['cases'])
    assert independent['source'] == bind(H / 'verify_revision03.py')
    for item in independent['inputs'].values():
        assert item == bind(R / item['path'])
    assert independent['inputs']['dll'] == bind(dll)
    r2 = load(H / 'revision02_replay.json')
    assert len(r2['cases']) == 5 and all(c['status'] == 'PASS' for c in r2['cases'])
    for item in r2['inputs'].values():
        assert item == bind(R / item['path'])
    old_repro = load(H / 'revalidation_repro.json')
    assert old_repro['source'] == bind(H / 'reproduce_revalidation.py')
    nested_repro = load(H / 'nested_owner_repro.json')
    assert nested_repro['source'] == bind(H / 'reproduce_nested_owner.py')
    source = (P / 'observer08r3.c').read_text()
    exact_retirement = ('NO_TICKET *owned[3]={&s.effect,&s.manage,&s.lease};'
        'for(unsigned i=0;i<3;i++)if(owned[i]->frame==(uintptr_t)f&&'
        'owned[i]->depth==s.depth)owned[i]->active=0;'
        's.depth--;zero(f,sizeof(*f));')
    assert exact_retirement in source

    report = {
      'status': 'REVISION03_FIXES_VALIDATED_WITHIN_DECLARED_MODEL_NOT_DEPLOYMENT_APPROVAL',
      'review_scope': 'Catalog generation, service-return validation, occupied ticket ownership across nested private native Loop frames.',
      'producer': {'initial_manifest': bind(O / 'component_manifest.json'),
                   'initial_counts': n1,
                   'final_manifest': bind(P / 'component_manifest.json'),
                   'final_counts': n3,
                   'final_dll': bind(dll),
                   'final_source': bind(P / 'observer08r3.c')},
      'producer_baseline': {'checks': 9, 'all_passed': True,
                            'binding': bind(P / 'generation_tests.json'),
                            'independently_reexecuted_here': False},
      'independent_execution': {'final_cases': 7, 'all_passed': True,
                               'binding': bind(H / 'revision03_replay.json'),
                               'intermediate_revision02_cases': 5,
                               'intermediate_binding': bind(H / 'revision02_replay.json')},
      'resolved_findings': [
        {'id': 'OG08-01', 'issue': 'Management validation could report one success after a foreign FORMS update invalidated its ticket during identity services.',
         'resolution': 'Final management validation rechecks ticket generation and private frame; actual final-PE regression rejects the expired ticket, keeps the slot occupied, and permits a different sequence only after legitimate owner leave.',
         'evidence': 'revision03_replay.json management case; preserved revision01 counterexample in revalidation_repro.json.'},
        {'id': 'OG08-02', 'issue': 'Queries and effect scope entry could report success after Setup notification revoked the private frame during identity services.',
         'resolution': 'identity_live rejects fault/ended at return and affected APIs recheck private state before outputs or mint. Actual final PE returns both queries false with outputs untouched and refuses scope mint.',
         'evidence': 'revision03_replay.json first three cases; preserved revision01 counterexamples.'},
        {'id': 'OG08-03', 'issue': 'Related management-enter, cold-lease and publication validation paths needed post-service state checks.',
         'resolution': 'Source review confirms post-service frame/active, cold/active and cold/token checks respectively. This is source verification, not independent exhaustive PE coverage of each related branch.',
         'evidence': 'observer08r3.c and revision03 build source bindings.'},
        {'id': 'OG08-04', 'issue': 'Inner native Loop pop unconditionally cleared active slots still owned by an outer frame.',
         'resolution': 'Before zeroing its frame and decrementing depth, pop retires only slots matching the leaving frame address and depth. Actual B8DC CALL and compiled nested wrappers preserve outer occupancy with and without a foreign notification.',
         'evidence': 'revision03_replay.json last two cases; preserved revision02 actual-PE counterexample in nested_owner_repro.json.'}
      ],
      'confirmed_invariants': [
        'Foreign FORMS updates advance catalog_generation without granting password access or destroying the ordinary private BIOS visit.',
        'An unchanged outer effect ticket is valid again after the inner ordinary Loop returns and blocks a second mint while occupied.',
        'A generation-expired outer effect ticket remains invalid after inner return and still blocks a second mint before its legitimate owner leaves.',
        'A query may return the latest generation after a foreign update, but it cannot return success after Setup identity revocation.',
        'Unknown Setup or NULL HII notifications retain revocation behavior; query APIs mint no authority.',
        'Final tests made no credential or OC variable write, and did not mutate private observer state or substitute an owner boolean.'
      ],
      'remaining_integration_conditions': [
        'Use the final revision03 source, not the unchanged revision01 or intermediate revision02 implementation.',
        'Exclude test_consumer.c, both og08_test_* exports and their registered consumer windows from production integration.',
        'Re-link and revalidate the selected navigation08, foreign-page view and management consumers against the same generation-aware ABI.',
        'Foreign page readers must compare catalog generation around their whole export/object snapshot and discard a changed snapshot.',
        'This review supplies no callback, write-sink, foreign-page or firmware-update permission.'
      ],
      'limits': [
        'UEFI services, native objects, CPU/crypto helpers and notification scheduling remain explicit fixtures; no physical callback timing is inferred.',
        'Original B8DC CALL and compiled wrappers execute. The BrowserLoop body is a sequence/return fixture, so this is not a full GUI or cold-boot test.',
        'Management validation runs actual private cold publication and selected-control checks; its original ConfigAccess caller address is an explicit ABI fixture, not execution of that CALL.',
        'Nested execution tests effect-ticket retirement; shared manage/lease frame matching is reviewed in source rather than claimed as all-path dynamic coverage.',
        'Occupancy and leave rules assume trusted paired consumers and do not protect against an arbitrary firmware memory writer.',
        'No hardware operation, CAP generation, FlashBack acceptance, boot-policy acceptance or deployment readiness is established.'
      ],
      'preserved_evidence': [bind(H / f) for f in (
          'initial_review.json', 'revalidation_repro.json', 'nested_owner_repro.json')],
      'frozen_inputs_modified': False,
      'hardware_actions': 0,
      'runtime_authorized': False
    }
    (H / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    local_names = (
        'README.md', 'finalize_review.py', 'review.json', 'initial_review.py',
        'initial_review.json', 'revision01.diff.txt', 'reproduce_revalidation.py',
        'revalidation_repro.json', 'verify_revision02.py', 'revision02_replay.json',
        'reproduce_nested_owner.py', 'nested_owner_repro.json',
        'verify_revision03.py', 'revision03_replay.json')
    external_paths = {O / 'component_manifest.json', P / 'component_manifest.json',
                      P / 'generation_tests.json', P / 'verify_generation.py', dll,
                      P / 'observer08r3.c', P / 'build/build.json'}
    external_paths.update(R / x for x in build['sources'])
    for producer in (m1, m3):
        for field in ('files', 'external_bindings'):
            external_paths.update(R / x['path'] for x in producer[field])
    for item in r2['inputs'].values():
        external_paths.add(R / item['path'])
    external_paths = {x for x in external_paths if H not in x.parents}
    manifest = {'status': report['status'], 'path_basis': 'workspace root',
      'files': [bind(H / name) for name in local_names],
      'external_bindings': [bind(p) for p in sorted(external_paths, key=str)]}
    (H / 'component_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'review': bind(H / 'review.json'),
                      'manifest': bind(H / 'component_manifest.json'),
                      'local': len(manifest['files']),
                      'external': len(manifest['external_bindings'])}))


if __name__ == '__main__':
    main()
