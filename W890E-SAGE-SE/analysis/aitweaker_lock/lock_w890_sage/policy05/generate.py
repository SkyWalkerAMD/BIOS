"""Describe original IFR storage scope without granting native execution authority.

This table is NOT an authorization decision: exact live producer identity,
package registration, page/control ownership, dynamic updates and callback
effects must be checked by the eventual runtime adapter. Frozen Setup policy is
not changed. GUID/name resolution is local to each actual FORM_SET, never a
global VarStoreId comparison.
"""
from pathlib import Path
import collections, hashlib, json, uuid

H = Path(__file__).resolve().parent
B = H.parent
ROOT = B.parents[2]
UNKNOWN, ORDINARY, PROTECTED = -1, 0, 1
CALLBACK, EXTENSION, UNRESOLVED_REF, STORE_LAYOUT, LIVE_IDENTITY, DYNAMIC_TARGET = 1, 2, 4, 8, 16, 32


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(binding):
    p = ROOT / binding['path']
    data = p.read_bytes()
    assert sha(data) == binding['sha256'], str(p)
    return data


def read():
    cp = B / 'foreign_hii05/catalog.json'
    catalog = json.loads(cp.read_bytes())
    profile = json.loads(checked(catalog['sources']['protected_profile']))
    assert sha((ROOT / catalog['sources']['cap']['path']).read_bytes()) == catalog['sources']['cap']['sha256']
    entries = []
    for pkg in catalog['packages']:
        for fp in pkg['forms_packages']:
            module = next(m for m in pkg['producer_modules'] if m['ffs_guid'] == fp['producer_ffs_guid'])
            entries.append((module, fp, True))
    for module in catalog['unobserved_original_modules']:
        entries.extend((module, fp, False) for fp in module['forms_packages'])
    entries.sort(key=lambda x: (x[0]['ffs_guid'], x[1]['pe_offset']))
    return cp, catalog, profile, entries


def main():
    cp, catalog, profile, entries = read()
    setup_fs = profile['setup_formset_guid'].lower()
    protected_forms = {f['id'] for f in profile['protected_forms']}
    protected_q = set(profile['protected_questions'])
    memory = set(profile['protected_memory_byte_offsets'])
    ids = {(x['guid'].lower(), x['name']): x for x in catalog['protected_variable_identities']}
    all_forms = collections.defaultdict(list)
    sources, packages = [], []
    for module, fp, observed in entries:
        blob = checked({'path': fp['blob_path'], 'sha256': fp['sha256']})
        decoded = json.loads(checked({'path': fp['decoded_path'], 'sha256': fp['decoded_sha256']}))
        assert len(blob) == fp['bytes'] and int.from_bytes(blob[:3], 'little') == len(blob) and blob[3] == 2
        p = {'module': module['module_name'], 'module_guid': module['ffs_guid'],
             'module_sha256': module['sha256'], 'observed': observed,
             'blob_path': fp['blob_path'], 'sha256': fp['sha256'], 'bytes': len(blob),
             'formsets': [], 'forms': [], 'controls': [], 'expressions': [],
             'remaining_runtime_requirements': ['LIVE_PRODUCER_AND_HII_OWNERSHIP', 'DYNAMIC_UPDATE_VALIDATION', 'CALLBACK_EFFECT_CLOSURE']}
        sources.append({'path': fp['blob_path'], 'sha256': fp['sha256']})
        for fs in fp['formsets']:
            fs_index = len(p['formsets']); p['formsets'].append(fs['guid'])
            for form in fs['forms']:
                out = {'formset': fs['guid'], 'formset_index': fs_index, 'form': form['form_id'],
                       'title': form.get('title'), 'record_index': form['index'],
                       'offset': form['package_offset'], 'storage_risk': ORDINARY,
                       'review_flags': LIVE_IDENTITY, 'direct_protected_controls': [],
                       'uncertain_controls': [], 'references': []}
                if fs['guid'] == setup_fs and form['form_id'] in protected_forms:
                    out['storage_risk'] = PROTECTED
                    out['reason'] = 'ORIGINAL_SETUP_AI_PROTECTED_FORM'
                p['forms'].append(out)
                all_forms[(fs['guid'], form['form_id'])].append((p, out))
            for q in fs['questions']:
                assert blob[q['package_offset']:q['package_offset']+q['size']] == bytes.fromhex(q['hex'])
                flags = LIVE_IDENTITY | (CALLBACK if q['callback'] else 0)
                if q.get('ancestor_guid_extensions'):
                    flags |= EXTENSION
                risk, reason = ORDINARY, 'NO_KNOWN_PROTECTED_STORAGE'
                store = q.get('varstore')
                if q['varstore_resolution'] not in ('UNIQUE', 'NO_STORAGE'):
                    risk, reason = UNKNOWN, 'UNRESOLVED_LOCAL_VARSTORE'; flags |= STORE_LAYOUT
                elif store:
                    key = (store['guid'].lower(), store['name'])
                    if key in ids:
                        expected = ids[key]
                        if store['varstore_size'] != expected['declared_size'] or store['attributes'] != expected['attributes']:
                            risk, reason = UNKNOWN, 'PROTECTED_STORE_LAYOUT_MISMATCH'; flags |= STORE_LAYOUT
                        elif key[1] != 'SocketMemoryConfig':
                            risk, reason = PROTECTED, 'EXACT_PROTECTED_GUID_AND_NAME'
                        else:
                            start, width = q['var_offset'], q.get('byte_width')
                            if q['offset_unit'] != 'BYTE_CANDIDATE' or not width or start < 0 or start + width > expected['declared_size']:
                                risk, reason = UNKNOWN, 'MEMORY_OFFSET_OR_WIDTH_UNPROVED'; flags |= STORE_LAYOUT
                            elif memory.intersection(range(start, start + width)):
                                risk, reason = PROTECTED, 'SHARED_MEMORY_PROTECTED_BYTE_OVERLAP'
                            else:
                                reason = 'SHARED_MEMORY_OUTSIDE_PROTECTED_BYTES'
                    elif q['offset_unit'] == 'EXTENSION_DEFINED':
                        risk, reason = UNKNOWN, 'GUID_EXTENSION_STORAGE_SEMANTICS_UNRESOLVED'
                    else:
                        reason = 'EXACT_OTHER_GUID_AND_NAME'
                if fs['guid'] == setup_fs and (q['form_id'] in protected_forms or q['question_id'] in protected_q):
                    risk, reason = PROTECTED, 'ORIGINAL_SETUP_PROTECTED_FORM_OR_QUESTION'
                r = {'formset': fs['guid'], 'formset_index': fs_index, 'form': q['form_id'],
                     'record_index': q['index'], 'offset': q['package_offset'], 'length': q['size'],
                     'opcode': q['op'], 'question': q['question_id'], 'hex': q['hex'],
                     'prompt': q.get('prompt'), 'storage_risk': risk, 'reason': reason,
                     'review_flags': flags, 'varstore': store, 'var_offset': q['var_offset'],
                     'byte_width': q.get('byte_width')}
                if q['op'] == 15:
                    r['reference'] = {'formset': q['target_formset_effective'], 'form': q['target_form'],
                                      'question': q.get('target_question'), 'dynamic': q['dynamic'],
                                      'device_path_string_id': q.get('device_path_string_id')}
                p['controls'].append(r)
            for expr in fs['variable_accesses']:
                p['expressions'].append(expr)
        packages.append(p)
    # Page scope comes only from direct controls, never transitive REF closure.
    # Otherwise a menu link could incorrectly lock an entire Advanced root.
    for p in packages:
        for f in p['forms']:
            for q in p['controls']:
                if q['formset'] != f['formset'] or q['form'] != f['form']:
                    continue
                f['review_flags'] |= q['review_flags']
                if q['opcode'] == 15:
                    f['references'].append(q['offset']); continue
                if q['storage_risk'] == PROTECTED:
                    f['direct_protected_controls'].append(q['offset']); f['storage_risk'] = PROTECTED
                elif q['storage_risk'] == UNKNOWN:
                    f['uncertain_controls'].append(q['offset'])
                    if f['storage_risk'] != PROTECTED:
                        f['storage_risk'] = UNKNOWN
            for expr in p['expressions']:
                if expr['formset_guid'] == f['formset'] and expr['form_id'] == f['form'] and expr['op'] == 44:
                    # No SET exists in the current catalog. Do not silently
                    # permit a future form that adds expression-side writes.
                    f['review_flags'] |= STORE_LAYOUT
                    if f['storage_risk'] != PROTECTED:
                        f['storage_risk'] = UNKNOWN
    for p in packages:
        for q in p['controls']:
            if 'reference' not in q:
                continue
            ref = q['reference']
            targets = all_forms.get((ref['formset'], ref['form']), [])
            ref['candidate_count'] = len(targets)
            # Cross-package zero/dynamic/device-path references need live
            # resolution. A plausible FormId is not enough to select an owner.
            if ref['dynamic'] or not ref['form'] or ref['device_path_string_id']:
                q['review_flags'] |= DYNAMIC_TARGET | UNRESOLVED_REF
                if q['storage_risk'] != PROTECTED:
                    q['storage_risk'], q['reason'] = UNKNOWN, 'DYNAMIC_REFERENCE_NEEDS_LIVE_TARGET'
            elif len(targets) != 1:
                q['review_flags'] |= UNRESOLVED_REF
                if q['storage_risk'] != PROTECTED:
                    q['storage_risk'], q['reason'] = UNKNOWN, 'REFERENCE_TARGET_NOT_UNIQUE_OR_ABSENT'
            else:
                target = targets[0][1]
                ref['target_storage_risk'] = target['storage_risk']
                if target['storage_risk'] == PROTECTED:
                    q['storage_risk'], q['reason'] = PROTECTED, 'REFERENCE_TO_DIRECTLY_PROTECTED_FORM'
                elif target['storage_risk'] == UNKNOWN and q['storage_risk'] != PROTECTED:
                    q['storage_risk'], q['reason'] = UNKNOWN, 'REFERENCE_TO_UNRESOLVED_STORAGE_FORM'
        # REF resolution adds review flags after direct storage-risk analysis.
        # Aggregate those flags only; never propagate a child's risk to its parent.
        for f in p['forms']:
            for q in p['controls']:
                if q['formset'] == f['formset'] and q['form'] == f['form']:
                    f['review_flags'] |= q['review_flags']
        p['controls'].sort(key=lambda x: x['offset'])
        p['forms'].sort(key=lambda x: (x['formset_index'], x['form']))
        assert len({q['offset'] for q in p['controls']}) == len(p['controls'])
        assert len({(f['formset'], f['form']) for f in p['forms']}) == len(p['forms'])
    report = {'schema_version': 1, 'status': 'STATIC_STORAGE_DESCRIPTION_NOT_RUNTIME_AUTHORIZATION',
              'scope': __doc__, 'catalog_sha256': sha(cp.read_bytes()), 'sources': sources,
              'source_sha256': sha(Path(__file__).read_bytes()),
              'flag_definitions': {'CALLBACK_EFFECT_REVIEW': CALLBACK, 'GUID_EXTENSION': EXTENSION,
                  'REF_UNRESOLVED': UNRESOLVED_REF, 'STORAGE_LAYOUT_UNPROVED': STORE_LAYOUT,
                  'LIVE_IDENTITY_REQUIRED': LIVE_IDENTITY, 'DYNAMIC_TARGET': DYNAMIC_TARGET},
              'packages': packages,
              'unresolved_observed_packages': [p['package_list_guid'] for p in catalog['packages'] if not p['producer_modules']]}
    (H / 'storage_policy.json').write_text(json.dumps(report, indent=2) + '\n')
    c = ['/* Generated from exact original IFR. Descriptive only, no authority. */']
    rows = []
    for i, p in enumerate(packages):
        c.append(f'static const uint8_t fs_{i}[][16]={{'+','.join('{'+','.join(str(x) for x in uuid.UUID(g).bytes_le)+'}' for g in p['formsets'])+'};')
        controls = ',\n'.join('{'+','.join(str(x) for x in [q['offset'],q['form'],q['formset_index'],q['length'],q['storage_risk'],q['review_flags']])+'}' for q in p['controls'])
        c.append(f'static const FH05_CONTROL controls_{i}[]={{\n'+(controls or '{0,0,0,0,-1,0}')+'\n};')
        c.append(f'static const FH05_FORM forms_{i}[]={{'+','.join('{'+','.join(str(x) for x in [f['offset'],f['form'],f['formset_index'],f['storage_risk'],f['review_flags']])+'}' for f in p['forms'])+'};')
        h = '{'+','.join(str(x) for x in bytes.fromhex(p['sha256']))+'}'
        rows.append('{'+f'{h},{p["bytes"]},fs_{i},{len(p["formsets"])},controls_{i},{len(p["controls"])},forms_{i},{len(p["forms"])}'+'}')
    c.append('static const FH05_PACKAGE packages[]={'+',\n'.join(rows)+'};')
    (H / 'catalog_data.h').write_text('\n'.join(c)+'\n')
    summary = [{'module': p['module'], 'observed': p['observed'],
                'forms': dict(collections.Counter(str(f['storage_risk']) for f in p['forms'])),
                'controls': dict(collections.Counter(str(q['storage_risk']) for q in p['controls'])),
                'callbacks_requiring_review': sum(bool(q['review_flags'] & CALLBACK) for q in p['controls'])}
               for p in packages]
    (H / 'summary.json').write_text(json.dumps({'status':report['status'], 'modules':summary,
        'storage_policy_sha256':sha((H/'storage_policy.json').read_bytes()),
        'c_table_sha256':sha((H/'catalog_data.h').read_bytes())},indent=2)+'\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
