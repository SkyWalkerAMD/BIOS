"""Bind a bounded, original-byte REA callback review. No target execution."""
from pathlib import Path
import hashlib, json, re, struct, sys, uuid

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
import capstone

def sha(b):
    return hashlib.sha256(b).hexdigest()

def load(p):
    return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def record(p):
    p = Path(p).resolve()
    return {'path': str(p), 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}

def emit(name, data):
    (HERE / name).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')

cat = load(BASE / 'foreign_hii05/catalog.json')
mods = {}
for package in cat['packages']:
    for m in package['producer_modules']:
        if m['module_name'] in ('Platform', 'SocketSetup'):
            p = ROOT / m['local_pe_path']
            assert sha(p.read_bytes()) == m['sha256']
            pe = pefile.PE(str(p))
            text = next(x for x in m['sections'] if x['name'] == '.text')
            assert sha(pe.get_data(text['rva'], text['virtual_size'])) == text['sha256']
            mods[m['module_name']] = {'catalog': m, 'pe': pe, 'image': pe.get_memory_mapped_image(),
                                      'path': p, 'text': text, 'package': package}
tse = BASE / 'navigation/modules/AMITSE.efi'
assert sha(tse.read_bytes()) == '43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
tp = pefile.PE(str(tse))
mods['AMITSE'] = {'pe': tp, 'image': tp.get_memory_mapped_image(), 'path': tse,
                 'text': {'rva': 0x1000, 'virtual_size': 0x91dda,
                          'sha256': sha(tp.get_data(0x1000, 0x91dda))}}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
evidence = []
functions = {}
for p in sorted((HERE / 'rea05').glob('response-*.json')):
    response = load(p)
    assert not response.get('isError'), str(p)
    ev = response.get('structuredContent', {})
    n = ev.get('normalized_result', {})
    if not isinstance(n, dict) or 'procedure' not in n or 'assembly' not in n:
        continue
    digest = ev['subject']['digest']['sha256']
    module = next(k for k, v in mods.items() if sha(v['path'].read_bytes()) == digest)
    m = mods[module]
    rva = int(n['procedure']['address'], 16)
    # Preserve the exact original bytes behind every REA-reported instruction.
    decoded = []
    for line in n['assembly']:
        address = int(line.split(':', 1)[0], 16)
        instruction = next(md.disasm(m['pe'].get_data(address, 15), address, count=1))
        assert m['text']['rva'] <= address < m['text']['rva'] + m['text']['virtual_size']
        decoded.append({'rva': address, 'hex': instruction.bytes.hex(),
                        'decoded': instruction.mnemonic + ' ' + instruction.op_str,
                        'rea_instruction': line})
    ranges = n['procedure']['body']['ranges']
    body = b''.join(m['pe'].get_data(int(x['start'], 16),
                                   int(x['end'], 16) - int(x['start'], 16) + 1) for x in ranges)
    row = {'module': module, 'rva': rva, 'rva_hex': hex(rva),
           'evidence': record(p), 'evidence_id': ev['evidence_id'],
           'provider': ev['provider'], 'subject_sha256': digest,
           'body_ranges': ranges, 'body_sha256': sha(body),
           'raw_instructions': decoded,
           'direct_callees': [{'rva': int(x['address'], 16), 'name': x['name']} for x in n['callees']],
           'unresolved_calls': n['unresolved_calls'],
           'limitations': ev['limitations'],
           'native_execution': False}
    evidence.append(row)
    functions[(module, rva)] = row
assert len(evidence) == 48
emit('native_evidence_index.json', {'status': 'ORIGINAL_STATIC_REA_EVIDENCE_NOT_EXECUTION',
                                  'functions': evidence, 'function_count': len(evidence)})

def function(module, rva):
    row = functions[(module, rva)]
    return {'module': module, 'rva': rva, 'rva_hex': hex(rva),
            'evidence_id': row['evidence_id'], 'response_path': row['evidence']['path'],
            'body_sha256': row['body_sha256']}

def read_utf16(image, address):
    end = address
    while image[end:end + 2] != b'\0\0':
        assert end + 2 < len(image)
        end += 2
    return image[address:end].decode('utf-16-le')

tables = []
for name, start, count, size_slot, name_slot in [('Platform', 0xc6e0, 15, 2, 1),
                                              ('SocketSetup', 0xf420, 7, 1, 2)]:
    m = mods[name]
    image = m['image']
    rows = []
    for i in range(count):
        at = start + i * 24
        vals = struct.unpack_from('<QQQ', image, at)
        g, n, size = vals[0], vals[name_slot], vals[size_slot]
        rows.append({'entry_rva': at, 'raw_hex': image[at:at + 24].hex(),
                     'guid_rva': g, 'guid': str(uuid.UUID(bytes_le=image[g:g + 16])),
                     'name_rva': n, 'name': read_utf16(image, n), 'bytes': size})
    tables.append({'module': name, 'table_rva': start, 'entry_bytes': 24, 'rows': rows,
                   'lookup': 'Platform9008 compares GUID only and selects first matching entry; Socket3B48 uses GUID and NAME header matcher C7A4. No global IFR VarStoreId assumption.'})

# Capture the literal SystemTable -> Boot/RuntimeServices initialization.
captures = []
for name, start, end in [('Platform', 0x1342, 0x135b), ('SocketSetup', 0x16fe, 0x1717)]:
    m = mods[name]
    captures.append({'module': name, 'method': 'Independent Capstone decoding of original PE; not a separate REA dossier',
                     'start_rva': start, 'end_exclusive': end,
                     'bytes_hex': m['pe'].get_data(start, end - start).hex(),
                     'instructions': [f'{x.address:x}: {x.mnemonic} {x.op_str}'
                                      for x in md.disasm(m['pe'].get_data(start, end - start), start)],
                     'interpretation': 'RDX is native initializer SystemTable argument; +0x60 stores BS, +0x58 stores RT. RT+0x48 is GetVariable; RT+0x58 is SetVariable.'})
emit('module_tables.json', {'tables': tables, 'service_pointer_initializers': captures})

protected_offsets = load(BASE / 'password/profile_0603.json')['protected_memory_byte_offsets']
memory_profile_writes = []
for x in md.disasm(mods['SocketSetup']['pe'].get_data(0x3c8c, 0x1f3), 0x3c8c):
    if x.mnemonic not in ('mov', 'and') or not x.operands:
        continue
    dst = x.operands[0]
    if dst.type == capstone.x86.X86_OP_MEM and dst.mem.base == capstone.x86.X86_REG_RBP:
        offset = 0xd0 + dst.mem.disp  # RBP = RSP+0x100; C84C/C940 buffer = RSP+0x30.
        if 0 <= offset < 0x4c3:
            memory_profile_writes.append({'rva': x.address, 'offset': offset, 'width': dst.size,
                                          'bytes_hex': x.bytes.hex()})
direct_changed = {i for w in memory_profile_writes for i in range(w['offset'], w['offset'] + w['width'])}
assert not direct_changed.intersection(protected_offsets)

def branch(action, qids, effects, refs, **extra):
    return {'action_numeric': action, 'question_ids': [f'0x{x:04x}' for x in qids],
            'effects': effects, 'evidence': [function(*r) for r in refs],
            'runtime_authorized': False, **extra}

platform = [
    branch('before action switch', [0x1ed5],
           ['Health Monitor helper invokes indirect protocol+0x30 and updates display strings; it executes before the main Action dispatch.'],
           [('Platform', 0x29cc), ('Platform', 0x4fec)], further_unknown='Underlying monitor protocol operation and string helper are not fully closed.'),
    branch('before switch; helper restricts action<2', [0x1097],
           ['28C8 reads PchSetup browser data. If PchSetup[0x3b]==1, changes IntelSetup browser byte0x361 through87A8/81B4.'],
           [('Platform', 0x29cc), ('Platform', 0x28c8), ('Platform', 0x87a8), ('Platform', 0x81b4)]),
    branch(0, [0x5433], ['May replace caller Value byte with0 when outside the native allowed interval.'], [('Platform', 0x29cc)]),
    branch(1, [0x650],
           ['Application Profile Configuration writes six full variables sequentially through93DC after reads through9370.',
            'Targets: SocketProcessorCoreConfig, SocketMemoryConfig, SocketPowerManagementConfig, SocketMpLinkConfig, SocketIioConfig, SocketSecurityConfig.',
            'The explicit SocketMemory byte changes are0x6,0x7c,0x355; these do not overlap the nine protected bytes. This does not prove whole-buffer safety or authorize the callback.',
            '93DC invokes Runtime SetVariable or the SMM-variable path; it returns0 after that call without preserving setter failure status.'],
           [('Platform', 0x29cc), ('Platform', 0x5930), ('Platform', 0x9370), ('Platform', 0x93dc), ('Platform', 0x8cfc)]),
    branch(1, [0x20b6], ['When Value==0, writes IntelSetup browser bytes0xe9/0xea.'], [('Platform', 0x29cc), ('Platform', 0x87a8)]),
    branch(1, [0x20bd], ['Writes IntelSetup browser byte0xe7; may call94D0 and9870 for native firmware-configuration persistence. The latter reaches95B8/96C4 service paths; their final effects are not closed here.'],
           [('Platform', 0x29cc), ('Platform', 0x94d0), ('Platform', 0x9870)]),
    branch(1, [0x20be], ['Updates PchSetup browser byte0x18. Value==2 directly clears bit0 at MMIO address0xf68018f0 (instruction2E94), then905C writes SocketMemoryConfig byte0xf0 via full-variable setter. Offset0xf0 is outside the nine protected bytes.'],
           [('Platform', 0x29cc), ('Platform', 0x905c), ('Platform', 0x93dc)]),
    branch(1, [0xdff5], ['Writes IntelSetup browser bytes0x338/0x33a with selective request strings.'], [('Platform', 0x29cc), ('Platform', 0x87a8)]),
    branch(2, [], ['Main action branch only frees allocated buffer and returns0; pre-action QID helpers and20E2..20E7 special branch still apply. Not a blanket no-effects permission.'], [('Platform', 0x29cc)]),
    branch(3, [0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x200a, 0x200b],
           ['Calls62B4 (RDMSR0x128 plus hardware-read helper) before QID branch.',
            'Conditional IntelSetup browser bytes0x87..0x8f are updated; the0x37b global snapshot is copied and93DC invoked for IntelSetup persistence.',
            'These QIDs were not found as question records in the supplied static Platform forms. Static branches alone do not prove active-UI reachability.'],
           [('Platform', 0x29cc), ('Platform', 0x62b4), ('Platform', 0x93dc)]),
    branch(4, [], ['Main branch frees allocation and returns0; pre-action QID helpers still apply.'], [('Platform', 0x29cc)]),
    branch(0x1000, [0xdff2, 0xdff3, 0xdff4], ['Reads IntelSetup via GetVariable and may assign caller Value. Final native branch still returns EFI_UNSUPPORTED.'], [('Platform', 0x29cc)])
]
socket = [
    branch(0, [0x2fff], ['Opens native Loading IIO Configuration popup.'], [('SocketSetup', 0x3e80)]),
    branch(0, [0xdff9], ['2288 validates partial-mirroring input using SocketMemory browser data and a native data/HOB structure; may show warning and restore caller Value.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x2288)]),
    branch(0, [0xf304], ['Reads whole SocketMemoryConfig browser block and writes it back unchanged throughC940; both read/write booleans are checked in this branch.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0xc84c), ('SocketSetup', 0xc940)]),
    branch(1, [0xf2c0, 0xf2c1, 0xf2c2],
           ['XMP Profile helper3C8C copies selected memory settings from native/HOB data into SocketMemoryConfig browser data and commits the whole0x4c3 block.',
            '3CE4 ignores C84C read result; no local full-buffer initialization precedes it. On failed read, the subsequent full-block write cannot be considered a protected-byte-preserving change.',
            'Normal-path explicit writes do not overlap the nine Ai bytes, but this fact is insufficient for permission.'],
           [('SocketSetup', 0x3e80), ('SocketSetup', 0x3c8c), ('SocketSetup', 0xc84c), ('SocketSetup', 0xc940)],
           explicit_writes=memory_profile_writes, read_failure_review_required=True),
    branch(1, [0xf291, 0xf292], ['2D0C updates browser SocketMemory bytes0x62/0x63, then reads the real variable, re-applies those bytes and calls SetVariable using returned attributes.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x2d0c)]),
    branch(2, [0xf31d], ['3030 may clamp SocketSecurityConfig byte0x76 using native/HOB limit, write browser data and update HII string tokens0xb8b/0xb8e. RETRIEVE is not necessarily read-only.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x3030), ('SocketSetup', 0xb654), ('SocketSetup', 0xc940)]),
    branch(3, [0xf318], ['2714 copies native/HOB status byte into SocketSecurityConfig browser offset0x152 through a selective request.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x2714), ('SocketSetup', 0xb654)]),
    branch(3, [0xf30d], ['Reads SocketSecurityConfig browser byte0x36 into module globalF4C8; no SetVariable in this exact branch.'], [('SocketSetup', 0x3e80)]),
    branch(4, [0xf30d], ['2074 checks owner-epoch settings. Under its native invalid/empty-epoch condition it updates browser bytes0x36/0x37..0x46 and the real SocketSecurityConfig variable, displays warning and changes F4C8.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x2074)]),
    branch(5, [0xf290, 0xf302], ['Calls2D0C SocketMemory browser+real-variable update path.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x2d0c)]),
    branch(5, [0xf282], ['Value==2 may normalize SocketPowerManagementConfig byte0x3a in browser data and in the actual variable.'], [('SocketSetup', 0x3e80)]),
    branch(5, [0xf281], ['37FC reads actual SocketIioConfig and may set browser bytes0x13f8/0x13f9 to1.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x37fc)]),
    branch(1, [0xf308, 0xf31f], ['24AC may warn then set actual IntelSetup byte0x93; later79E0 may update native/HOB memory and display strings.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x24ac), ('SocketSetup', 0x79e0), ('SocketSetup', 0xb830)]),
    branch(1, [0xf30d], ['1D10 manipulates SocketSecurity owner epoch and browser data, obtains native random values viaD5B8 and may show confirmation. Full randomness/protocol and downstream lifetime are not closed here.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x1d10)]),
    branch(1, [0xf317], ['29C8 offers SGX factory-reset confirmation and changes a set of SocketSecurity browser fields; on native success flows into79E0.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x29c8), ('SocketSetup', 0x79e0)]),
    branch(1, [0xf319, 0xf31a, 0xf31b, 0xf31c, 0xf31d], ['Dedicated helpers2E48/27E8/2F24/3248/3030 manipulate SocketSecurity browser settings and/or warning strings; these are not Ai-password authority.'],
           [('SocketSetup', 0x3e80), ('SocketSetup', 0x2e48), ('SocketSetup', 0x27e8), ('SocketSetup', 0x2f24), ('SocketSetup', 0x3248), ('SocketSetup', 0x3030)]),
    branch(1, [0xf30b, 0xff0f, 0xff10, 0xff14, 0xff15], ['79E0 computes native security memory sizing, may display warning, writes native/HOB qword+0x50 viaB830 and updates display strings via362C. HOB provenance and downstream consumption remain separate.'], [('SocketSetup', 0x3e80), ('SocketSetup', 0x79e0), ('SocketSetup', 0xb830), ('SocketSetup', 0x362c)]),
    branch(1, [0xff12], ['Saves/restores SocketPowerManagement browser settings with module global41CC0 snapshot and14D30 flag; writes offsets0x19..0x1a,0x1c..0x1d,0x39.'], [('SocketSetup', 0x3e80)])
]

routes = [
    {'module': 'Platform', 'entry_rva': 0x26d8, 'evidence': [function('Platform', 0x26d8), function('Platform', 0x4c30), function('Platform', 0x860c)],
     'protected_branch': {'guid': '1bd9831e-b532-469c-a897-b376c2c5aa0b', 'name': 'OcSetup',
                          'declared_bytes': 0x8eb, 'helper_rva': 0x4c30,
                          'sequence': ['GetVariable: native current OcSetup', 'ConfigToBlock: supplied configuration over the native buffer', 'SetVariable: literal attrs3, returned block size, transformed buffer'],
                          'setter_status_ignored': True, 'setter_rva': 0x4cf0,
                          'attribute_note': 'Original code uses3 while IFR advertises7; do not silently normalize these values.'},
     'ordinary_branches': ['PchSetup -> ConfigToBlock ->93DC', 'IntelSetup -> globals/cache -> ConfigToBlock ->93DC', 'MeStorageSetup ->552C (not closed)', 'OneClickRecoverySetup ->A0B4 (not closed)'],
     'runtime_authorized': False},
    {'module': 'SocketSetup', 'entry_rva': 0x3b48, 'evidence': [function('SocketSetup', 0x3b48), function('SocketSetup', 0xc7a4)],
     'lookup_table': 'module_tables.json SocketSetup seven GUID+NAME entries',
     'protected_branch': {'guid': '98cf19ed-4109-4681-b79d-9196757c7824', 'name': 'SocketMemoryConfig',
                          'declared_bytes': 0x4c3, 'entry_index': 3,
                          'sequence': ['GetVariable into global selected buffer', 'ConfigToBlock into same buffer; return ignored', 'SetVariable using original returned attrs and table size'],
                          'config_to_block_status_ignored': True, 'config_to_block_rva': 0x3c35,
                          'setter_rva': 0x3c69, 'setter_status_returned': True},
     'not_in_seven_entry_route_table': ['VARSTORE_OCMR_SETTINGS_NAME', 'OcSetup', 'SocketSecurityConfig'],
     'runtime_authorized': False}
]

question_rows = []
wanted = {'Platform': {0x650, 0x20b6, 0x20bd, 0x20be, 0x1ed5, 0x1097, 0xdff5, 0xd4, 0xd6},
          'SocketSetup': {0xf31d, 0xf318, 0xf30d, 0xf2c0, 0xf2c1, 0xf2c2, 0xf304, 0xf291, 0xf292}}
for name in wanted:
    d = load(BASE / f'foreign_hii05/decoded/{name}_0.json')
    for r in d['records']:
        if r.get('question_id') in wanted[name]:
            question_rows.append({'module': name, **{k: r.get(k) for k in
                                  ['formset_guid', 'formset_record', 'form_id', 'form_record', 'package_offset', 'question_id',
                                   'type', 'hex', 'prompt', 'callback', 'varstore', 'var_offset', 'byte_width']}})
emit('question_examples.json', {'status': 'ORIGINAL_IFR_IDENTITIES_NOT_CALLBACK_PERMISSION', 'questions': question_rows})

mapper = function('AMITSE', 0x3f90c)
emit('action_mapper.json', {'status': 'STATIC_ORIGINAL_ACTION_MAPPING_CONFIRMED', 'function': mapper,
                           'mapping': {'1': 0, '2': 2, '3': 3, '4': 4, '5': 5, '4096': 4096, '4097': 4097,
                                       'other': 'identity'},
                           'uefi_action_constants': {'0': 'CHANGING', '1': 'CHANGED', '2': 'RETRIEVE',
                                                     '3': 'FORM_OPEN', '4': 'FORM_CLOSE', '5': 'SUBMITTED'},
                           'primary_source': 'https://uefi.org/specs/UEFI/2.11/35_HII_Configuration_Processing_and_Browser_Protocol.html#efi-hii-config-access-protocol-callback',
                           'note': 'Assembly is authoritative here; decompiler rendered small integers as DOS-header pointers. No target code was executed in this review. The existing test label close2 must not be read as actual FORM_CLOSE4 coverage.'})

subjects = []
for name, m in mods.items():
    subjects.append({'module': name, 'original_pe': record(m['path']), 'text': m['text'],
                     'callback_bindings': m.get('catalog', {}).get('callback_bindings', []),
                     'live_identity_limit': 'Physical P3 reported foreign owner FFS GUID and RVA, not foreign module .text hashes. These are original0603 static identities, not a current-runtime attestation.' if name != 'AMITSE' else 'Original0603 module for static action-map corroboration.'})
report = {'schema_version': 1, 'status': 'BOUNDED_STATIC_CALLBACK_EFFECT_INVENTORY_NO_AUTHORIZATION',
          'subjects': subjects, 'evidence_index': record(HERE / 'native_evidence_index.json'),
          'module_tables': record(HERE / 'module_tables.json'), 'question_examples': record(HERE / 'question_examples.json'),
          'action_mapper': record(HERE / 'action_mapper.json'),
          'protected_memory_byte_offsets': protected_offsets,
          'callback_branches': {'Platform': platform, 'SocketSetup': socket}, 'route_config': routes,
          'important_conclusions': [
              'A question in an ordinary own-variable form can still call a helper that writes other variables or MMIO; IFR storage classification does not authorize a callback.',
              'Action2 and3 are RETRIEVE and FORM_OPEN after the exact native mapper; both may have cache/string effects. Actual Action4 has its own persistent SocketSecurity path.',
              'Protected OcSetup has a direct original RouteConfig writer even where its question has CALLBACK=false.',
              'SocketMemoryConfig RouteConfig must inspect exact whole-buffer changes before original execution; the native route ignores ConfigToBlock failure before SetVariable.',
              'Socket XMP helper read failure invalidates an otherwise plausible explicit-offset-only whitelist.',
              'No direct OCMR write was identified in the bounded reviewed branches; this is not complete transitive closure or evidence that no OCMR path exists.',
              'Configuration reset/import-like operations include Application Profile Configuration, SGX factory reset and OneClickRecovery route. They retain distinct original effects; no generic import permission is derived.'
          ],
          'remaining_boundaries': [
              'Native indirect monitor/firmware configuration persistence helpers and all descendant protocol implementations are not fully closed.',
              'Runtime page/control/HII identity, lifecycle and nesting remain separate authority requirements.',
              'Foreign callbacks can invoke FormBrowser2.BrowserCallback and alter browser caches; handling cannot be replaced with a caller-supplied owner boolean.',
              'No new hooks, firmware patches, credentials, media, restart or live device action were performed.',
              'This first-layer review neither clears parser blockers nor grants release/flash readiness.'
          ],
          'runtime_authorized': False, 'release_ready': False, 'native_functions_executed': 0,
          'REA_function_dossiers': len(evidence), 'hardware_actions': 0}
emit('first_layer_review.json', report)

assert load(HERE / 'rea05/final-close.json').get('isError') is not True
paths = [p for p in HERE.rglob('*') if p.is_file() and 'tmp' not in p.relative_to(HERE).parts
         and '__pycache__' not in p.relative_to(HERE).parts and p.name != 'component_manifest.json']
external = [BASE / 'foreign_hii05/catalog.json', BASE / 'password/profile_0603.json',
            BASE / 'foreign_hii05/decoded/Platform_0.json', BASE / 'foreign_hii05/decoded/SocketSetup_0.json']
external += [m['path'] for m in mods.values()]
emit('component_manifest.json', {'status': 'FROZEN_STATIC_REVIEW_NO_RUNTIME_PERMISSION',
                                 'local': [record(p) for p in sorted(paths)],
                                 'external': [record(p) for p in external],
                                 'release_ready': False})
print(json.dumps({'functions': len(evidence), 'review': record(HERE / 'first_layer_review.json'),
                  'manifest': record(HERE / 'component_manifest.json')}))
