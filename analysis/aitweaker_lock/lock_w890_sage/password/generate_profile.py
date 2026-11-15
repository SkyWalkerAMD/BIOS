"""Derive a fail-closed 0603 policy from the actual original Setup PE/IFR."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import struct
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASE = ROOT / 'analysis/aitweaker_lock'
sys.path.insert(0, str(BASE))
from inspect_setup import get_module, string_packages
from inspect_forms import packages, decode, QUESTIONS

def sha(data):
    return hashlib.sha256(data).hexdigest()

sources = {}
for name in ['Setup', 'AMITSE', 'PasswordSupport']:
    module, section, raw = get_module('W890_SAGE_0603', name)
    sources[name] = {'guid': module['guid'], 'sha256': sha(raw), 'bytes': len(raw),
                     'path': str(Path('analysis/workstation_20261008') / section['path'])}
    if name == 'Setup':
        setup = raw
strings = string_packages(setup)[0]['strings']
packs = [decode(setup, pack, strings) for pack in packages(setup)]
assert len(packs) == 1
pack = packs[0]
r = pack['records']
stored_ifr = BASE / 'W890_SAGE_0603/Setup_IFR.json'
assert packs == json.loads(stored_ifr.read_text(encoding='utf8'))
formset = next(x['guid'] for x in r if x['op'] == 14)
assert formset == '7b59104a-c00d-4158-87ff-f04d6396a915'
forms = {x['form_id']: x for x in r if x['op'] == 1}
assert len(forms) == sum(x['op'] == 1 for x in r)
root = next(x for x in forms.values() if x['title'] == 'Ai Tweaker')
security = next(x for x in forms.values() if x['title'] == 'Security')
favorites = next(x for x in forms.values() if x['title'] == 'My Favorites')
profile = next(x for x in forms.values() if x['title'] == 'ASUS User Profile')
assert (root['form_id'], security['form_id'], favorites['form_id'], profile['form_id']) == (0x2713, 0x271d, 0x2711, 0x2bfc)
refs = [x for x in r if x['op'] == 15 and 'target_form' in x]
reachable, todo = set(), [root['form_id']]
while todo:
    value = todo.pop()
    if value in reachable:
        continue
    reachable.add(value)
    todo.extend(x['target_form'] for x in refs if x['form'] == value
                and x.get('target_formset', formset) == formset and x['target_form'] in forms)
assert len(reachable) == 27
stores = {x['name']: x for x in r if x['op'] in (36, 38)}
oc, mem = stores['VARSTORE_OCMR_SETTINGS_NAME'], stores['SocketMemoryConfig']
assert (oc['varstore_id'], oc['varstore_size'], mem['varstore_id'], mem['varstore_size']) == (35, 22955, 40, 1219)
oc_questions = [x for x in r if x['op'] in QUESTIONS and x.get('varstore_id') == oc['varstore_id']]
inert = [x for x in oc_questions if x.get('form') not in reachable]
assert len(inert) == 6
assert {x['question_id'] for x in inert} == set(range(1892, 1898))
for x in inert:
    assert x['form'] == 0x271a and x['op'] == 7 and x['size'] == 17
    assert x['prompt_id'] == x['help_id'] == x['flags'] == 0
    scopes = [i for i in x['parents'] if r[i]['op'] == 30]
    assert len(scopes) == 1
    i = scopes[0]
    assert r[i]['hex'] == '1e82' and r[i+1]['hex'] == '4602'
    assert r[i]['end'] == forms[0x271a]['end'] - 2
    assert sum(y.get('question_id') == x['question_id'] for y in r) == 1
inert_offsets = {x['offset'] for x in inert}
active = [x for x in r if x['offset'] not in inert_offsets]
protected = set(reachable) | {favorites['form_id'], profile['form_id']}
protected.update(x['form'] for x in active if x['op'] in QUESTIONS and x.get('varstore_id') == oc['varstore_id'])
assert security['form_id'] not in protected and 0x2719 not in protected and 0x271a not in protected
mem_questions = [x for x in active if x['op'] in QUESTIONS and x.get('form') in reachable and x.get('varstore_id') == mem['varstore_id']]
memory_ranges = []
for x in mem_questions:
    raw = bytes.fromhex(x['hex'])
    assert x['op'] in (5, 7) and x['size'] == 17
    width = 1 << (raw[13] & 3)
    assert width == 1 and x['var_offset'] + width <= mem['varstore_size']
    memory_ranges.append({'offset': x['var_offset'], 'bytes': width,
                          'question_id': x['question_id'], 'form_id': x['form'],
                          'prompt': x['prompt'], 'ifr_offset': x['offset'], 'ifr_hex': x['hex']})
memory_offsets = sorted({i for x in memory_ranges for i in range(x['offset'], x['offset'] + x['bytes'])})
assert len(memory_offsets) == 9
questions = {x['question_id'] for x in active if x['op'] in QUESTIONS and
             (x.get('form') in protected or x.get('varstore_id') == oc['varstore_id'] or
              x.get('varstore_id') == mem['varstore_id'] and x.get('var_offset') in memory_offsets)}
incoming = [x for x in refs if x.get('target_formset', formset) == formset and
            x['target_form'] in protected and x.get('form') not in protected]
questions.update(x['question_id'] for x in incoming)
all_qids = {x['question_id'] for x in r if x['op'] in QUESTIONS}
assert not ({0xffd0, 0xffd1, 0xffd2} & all_qids)
raw_package = setup[pack['offset']:pack['offset'] + pack['length']]
insert = security['end'] - pack['offset'] - 2
assert raw_package[insert:insert+2] == b'\x29\x02'
credential_guid = '7aa1505b-ef11-4c41-9002-427f826903e6'
credential_name = 'AiTweakerPasswordW890V1'
profile_out = {
    'schema': 1, 'status': 'STATIC_PROFILE_0603_NATIVE_ENFORCEMENT_NOT_CONNECTED',
    'board': 'ASUS Pro WS W890E-SAGE SE', 'bios': '0603',
    'sources': sources, 'saved_ifr_sha256': sha(stored_ifr.read_bytes()),
    'fresh_ifr_matches_saved': True, 'setup_formset_guid': formset,
    'root_form': root['form_id'], 'security_form': security['form_id'],
    'favorites_form': favorites['form_id'], 'profile_form': profile['form_id'],
    'protected_forms': [{'id': i, 'title': forms[i]['title'], 'ifr_offset': forms[i]['offset'],
                         'reason': 'Ai Tweaker local reference closure' if i in reachable else 'conservative alternate entry / settings profile UI'} for i in sorted(protected)],
    'protected_questions': sorted(questions), 'ai_questions_count': sum(x['op'] in QUESTIONS and x.get('form') in reachable for x in r),
    'incoming_refs': incoming,
    'inert_exit_descriptors': [{'question_id': x['question_id'], 'form_id': x['form'], 'ifr_hex': x['hex'],
                               'evidence': 'Exact unique descriptor in DISABLE_IF literal TRUE spanning remainder of Exit form.'} for x in inert],
    'oc_store': {k: oc[k] for k in ['name', 'guid', 'varstore_id', 'varstore_size', 'attributes', 'hex', 'offset']},
    'memory_store': {k: mem[k] for k in ['name', 'guid', 'varstore_id', 'varstore_size', 'attributes', 'hex', 'offset']},
    'protected_memory_ranges': memory_ranges, 'protected_memory_byte_offsets': memory_offsets,
    'credential': {'name': credential_name, 'guid': credential_guid, 'attributes': 3, 'bytes': 128,
                   'schema': 'AITWKP01', 'private_namespace': 'new W890 namespace, no W790 migration'},
    'management_questions': {'set_change': 0xffd0, 'clear': 0xffd1, 'verify': 0xffd2},
    'original_forms_package': {'offset': pack['offset'], 'length': len(raw_package), 'sha256': sha(raw_package), 'security_insert_offset': insert},
    'limits': ['No native UI/runtime entrypoint is connected by this pure policy.',
               'Favorites and profile pages are conservatively protected by page identity; actual dispatch must be verified separately.',
               'Non-HII search/EZ/raw hardware paths and other variable stores remain outside proven coverage.',
               'DISABLE_IF exception is valid only for the exact descriptor on the bound Setup Exit form.',
               'No BMC action, hardware NVRAM write or flash operation performed.'],
}
(HERE / 'profile_0603.json').write_text(json.dumps(profile_out, indent=2, ensure_ascii=False) + '\n', encoding='utf8')
(HERE / 'official_forms_0603.pack').write_bytes(raw_package)
def array(name, kind, values, width=16):
    return f'static const {kind} {name}[]={{\n' + ''.join(' '+','.join(hex(x) for x in values[i:i+width])+',\n' for i in range(0, len(values), width)) + '};\n'
h = '/* Generated only from the verified original W890E-SAGE SE 0603 Setup. */\n'
h += array('w890_setup_sha256', 'uint8_t', bytes.fromhex(sources['Setup']['sha256']))
h += array('w890_tse_sha256', 'uint8_t', bytes.fromhex(sources['AMITSE']['sha256']))
h += array('w890_forms_sha256', 'uint8_t', hashlib.sha256(raw_package).digest())
h += array('w890_setup_formset', 'uint8_t', uuid.UUID(formset).bytes_le)
h += array('w890_oc_guid', 'uint8_t', uuid.UUID(oc['guid']).bytes_le)
h += array('w890_memory_guid', 'uint8_t', uuid.UUID(mem['guid']).bytes_le)
h += array('w890_credential_guid', 'uint8_t', uuid.UUID(credential_guid).bytes_le)
h += array('w890_oc_name', 'uint16_t', [ord(c) for c in oc['name']])
h += array('w890_memory_name', 'uint16_t', [ord(c) for c in mem['name']])
h += array('w890_credential_name', 'uint16_t', [ord(c) for c in credential_name])
h += array('w890_protected_forms', 'uint16_t', sorted(protected))
h += array('w890_known_forms', 'uint16_t', sorted(forms))
h += array('w890_protected_questions', 'uint16_t', sorted(questions))
h += array('w890_memory_offsets', 'uint16_t', memory_offsets)
h += 'static const uint8_t w890_inert_exit[][17]={\n' + ''.join(' {'+','.join(hex(b) for b in bytes.fromhex(x['hex']))+'},\n' for x in inert) + '};\n'
h += f'#define W890_ORIGINAL_FORMS_BYTES {len(raw_package)}u\n#define W890_SECURITY_INSERT {insert}u\n'
(HERE / 'w890_policy_data.h').write_text(h, encoding='ascii')
print(json.dumps({'status': profile_out['status'], 'protected_forms': len(protected), 'protected_questions': len(questions),
                  'memory_offsets': [hex(i) for i in memory_offsets], 'inert_exit_descriptors': len(inert)}))
