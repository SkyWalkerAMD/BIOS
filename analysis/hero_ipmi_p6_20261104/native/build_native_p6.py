"""Offline P6 native Setup resources. No firmware flashing or hardware access.

All existing Setup code and variables are retained. The new 32-byte EFI
variable is edited by the native AMITSE browser and saved by normal F10.
This module creates component resources only, not a deployable firmware.
"""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys, uuid

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

p5 = load('p5_resource_helpers', ROOT / 'analysis/hero_ipmi_p5/build_native_payload.py')
pv = load('p5_parser_helpers', ROOT / 'analysis/hero_ipmi_p5/verify_native_payload.py')
u16, u32, u64 = p5.u16, p5.u32, p5.u64
put16, put32, put64 = p5.put16, p5.put32, p5.put64
h, op, package, sha = p5.h, p5.op, p5.package, p5.sha
P5 = ROOT / 'analysis/hero_ipmi_p5'
GUID = 'bef09fe1-8540-4be1-9082-e6624328f435'
NAME, ATTRS, SIZE, STORE_ID, VAR_INDEX = 'HeroIpmiSettings', 3, 32, 0x3f00, 119
DEFAULT = bytes([0, 0, 0, 10, 1] + [0] * 27)

NEXT_BOOT = 'Save with F10. Applied on the next boot; current BMC readings above do not change while editing. '
STRINGS = {
    'L_CONFIG_STATUS': 'Last settings apply',
    'V_CONFIG_STATUS': 'Not reported',
    'CONFIG_STATUS_HELP': 'Result of the last saved IPMI settings request. Configuration is applied on the next boot.',
    'NO_CHANGE': 'Unchanged', 'DISABLED': 'Disabled', 'ENABLED': 'Enabled',
    'NO': 'No', 'YES': 'Yes', 'NO_ACTION': 'No action', 'RESET': 'Reset',
    'POWER_DOWN': 'Power down', 'POWER_CYCLE': 'Power cycle',
    'SOURCE_KEEP': 'Unspecified / keep current', 'SOURCE_STATIC': 'Static', 'SOURCE_DHCP': 'BMC DHCP',
    'ERASE_ONCE': 'Next boot once', 'ERASE_ALWAYS': 'Every boot',
    'FULL_NONE': 'Do nothing', 'FULL_ERASE': 'Erase all records', 'FULL_OLDEST': 'Delete oldest record',
}
FIELDS = []

def field(offset, name, form, title, help_text, *, options=None, minimum=0, maximum=255, default=0):
    key = name.upper()
    STRINGS['CFG_' + key] = title
    STRINGS['CFG_' + key + '_HELP'] = NEXT_BOOT + help_text
    FIELDS.append(dict(offset=offset, name=name, form_id=form, question_id=0x3120 + offset,
                       title_key='CFG_' + key, help_key='CFG_' + key + '_HELP', width=1,
                       minimum=minimum, maximum=maximum, default=default,
                       options=options, control='oneof' if options is not None else 'numeric'))

field(0, 'network_source', 0x3103, 'Configure IP address source',
      'Unspecified / keep current leaves the address, mask and gateway unchanged. Static uses all twelve IPv4 octets below. Applied when saved settings change or a retry is requested, not on every boot. A network change can interrupt remote access.',
      options=[(0, 'SOURCE_KEEP'), (1, 'SOURCE_STATIC'), (2, 'SOURCE_DHCP')], maximum=2)
field(1, 'channel', 0x3103, 'BMC LAN channel (0 = auto)',
      '0 discovers a LAN channel. Values 1 through 11 select a channel explicitly. Changing this alone does not change the network when the source is keep current.', maximum=11)
field(2, 'wdt_enabled', 0x3101, 'Configure OS Watchdog Timer',
      'Enabled starts the timer when booting the OS or another UEFI application. Entering Setup or Shell stops it. The operating system must stop or service the timer to prevent its timeout action.',
      options=[(0, 'DISABLED'), (1, 'ENABLED')], maximum=1)
field(3, 'wdt_minutes', 0x3101, 'OS Wtd Timer Timeout (minutes)',
      'OS boot watchdog timeout in minutes, from 1 through 30.', minimum=1, maximum=30, default=10)
field(4, 'wdt_action', 0x3101, 'OS Wtd Timer Policy',
      'Action when the enabled OS boot watchdog expires. Reset, power down and power cycle can interrupt a running system.',
      options=[(0, 'NO_ACTION'), (1, 'RESET'), (2, 'POWER_DOWN'), (3, 'POWER_CYCLE')], maximum=3, default=1)
field(5, 'sel_global_logging', 0x3102, 'BMC System event logging',
      'Controls global BMC event logging. This differs from Creator SEL Components, which controls BIOS POST event logging. Unchanged preserves the current global BMC setting.',
      options=[(0, 'NO_CHANGE'), (1, 'DISABLED'), (2, 'ENABLED')], maximum=2)
field(6, 'sel_erase', 0x3102, 'Erase SEL on boot',
      'Erasing permanently deletes all BMC event records. Next boot once is consumed before the erase request; a failure is reported without automatic retry. Every boot permanently clears the log on every boot.',
      options=[(0, 'NO'), (1, 'ERASE_ONCE'), (2, 'ERASE_ALWAYS')], maximum=2)
field(7, 'sel_full', 0x3102, 'When SEL is full at boot',
      'Checked at boot. Erase permanently deletes all event records; Delete oldest permanently removes the oldest record if supported. Do nothing retains the log.',
      options=[(0, 'FULL_NONE'), (1, 'FULL_ERASE'), (2, 'FULL_OLDEST')], maximum=2)
for start, group, title in [(8, 'ip', 'Static IP address'), (12, 'mask', 'Static subnet mask'), (16, 'gateway', 'Static gateway')]:
    for octet in range(4):
        field(start + octet, f'{group}_{octet+1}', 0x3103, f'{title} octet {octet+1}',
              f'Octet {octet+1} of the four-part IPv4 value, in network display order, range 0 through 255. Used only when IP address source is Static. All four fields form one address.')
field(20, 'retry_request', 0x3100, 'Retry failed settings on next boot',
      'One explicit retry of previously failed saved settings. The request is consumed once; inspect Last settings apply after the next boot.',
      options=[(0, 'NO'), (1, 'YES')], maximum=1)
assert sorted(x['offset'] for x in FIELDS) == list(range(21))
assert bytes([next(x['default'] for x in FIELDS if x['offset'] == n) for n in range(21)] + [0]*11) == DEFAULT

REPLACE = {
    'HELP': 'HERO native IPMI. Status is refreshed when Setup opens; saved settings apply on the next boot.',
    'NOTE': 'IPMI settings: save with F10; changes take effect on the next boot.',
    'NETWORK_HELP': 'Current BMC LAN status and next-boot settings. A network change can interrupt remote access.',
    'VIEW_HELP': 'First 16 raw BMC event records. Erase policy is configured on the System Event Log page.',
}

def strings_package(b, replacements, additions):
    # Preserve every original block except the four explicitly selected P5
    # single-string blocks. Do not reinterpret or translate stock strings.
    cursor, token, chunks = u32(b, 8), 1, []
    prefix = b[4:cursor]
    while True:
        start = cursor; kind = b[cursor]; cursor += 1
        if kind == 0:
            assert cursor == len(b)
            break
        if kind in (0x14, 0x15, 0x16, 0x17):
            if kind in (0x15, 0x17): cursor += 1
            count = 1
            if kind in (0x16, 0x17): count = u16(b, cursor); cursor += 2
            first = token
            for _ in range(count):
                while b[cursor:cursor+2] != b'\0\0': cursor += 2
                cursor += 2; token += 1
            if first in replacements:
                assert kind == 0x14 and count == 1
                chunks.append(b'\x14' + replacements[first].encode('utf-16le') + b'\0\0')
            else:
                assert not set(range(first, token)) & set(replacements)
                chunks.append(b[start:cursor])
        elif kind == 0x20:
            assert token not in replacements
            cursor += 2; token += 1; chunks.append(b[start:cursor])
        elif kind in (0x21, 0x22):
            width = 2 if kind == 0x21 else 1
            token += int.from_bytes(b[cursor:cursor+width], 'little'); cursor += width
            chunks.append(b[start:cursor])
        else: raise AssertionError((kind, cursor))
    return package(4, prefix + b''.join(chunks) + additions + b'\0')

def build_hii(old, meta):
    packages = p5.read_packages(old)
    old_forms = packages[0]
    old_ops, form_map = p5.scan_forms(old_forms)
    stores = []
    for item in old_ops.values():
        if item[0] in (0x24, 0x25, 0x26): stores.append(u16(item, 18 if item[0] == 0x24 else 2))
        if item[0] in (5, 6, 7, 8, 0xc, 0xf, 0x1c, 0x23):
            assert u16(item, 6) not in {x['question_id'] for x in FIELDS}
    assert STORE_ID not in stores
    scanned = [p5.string_tokens(b) for b in packages[1:-1]]
    assert len(set(x[1] for x in scanned)) == 1
    next_id = scanned[0][1]
    ids = dict(meta['string_ids'])
    ids.update({k:next_id+i for i, k in enumerate(STRINGS)})
    assert len(set(ids.values())) == len(ids)
    additions = b''.join(b'\x14' + s.encode('utf-16le') + b'\0\0' for s in STRINGS.values())
    repl = {ids[k]: s for k, s in REPLACE.items()}
    changed_strings = [strings_package(b, repl, additions) for b in packages[1:-1]]

    # Standard EFI_IFR_VARSTORE_EFI: id, GUID, attrs, size, ASCII name.
    declaration = op(0x26, h(STORE_ID) + uuid.UUID(GUID).bytes_le + struct.pack('<I', ATTRS) + h(SIZE) + NAME.encode('ascii') + b'\0')
    inserted = {form_map[0x3100]['start']: [(None, declaration, 'varstore')]}
    for f in FIELDS:
        q = h(ids[f['title_key']], ids[f['help_key']], f['question_id'], STORE_ID, f['offset']) + b'\0'
        q += bytes([0x10, f['minimum'], f['maximum'], 1]) # u8, unsigned decimal display.
        if f['control'] == 'oneof':
            data = op(5, q, True)
            for val, key in f['options']:
                data += op(9, h(ids[key]) + bytes([0x30 if val == f['default'] else 0, 0, val]))
        else:
            data = op(7, q, True)
            for default_id in (0, 1):
                data += op(0x5b, h(default_id) + bytes([0, f['default']]))
        data += op(0x29)
        inserted.setdefault(form_map[f['form_id']]['end'], []).append((f['form_id'], data, f['name']))
    status = op(3, h(ids['L_CONFIG_STATUS'], ids['CONFIG_STATUS_HELP'], ids['V_CONFIG_STATUS']))
    inserted[form_map[0x3100]['start']+6] = [(0x3100, status, 'config_status')]
    body = bytearray(); offsets = {}; new_controls = []
    for at, data in old_ops.items():
        for fid, new, name in inserted.get(at, []):
            where = 4 + len(body)
            if fid is not None: new_controls.append(dict(name=name, form_id=fid, offset=where))
            body.extend(new)
        offsets[at] = 4 + len(body)
        body.extend(data)
    forms = package(2, body)
    tail = b''.join([forms] + changed_strings + [packages[-1]])
    hii = old[:16] + struct.pack('<I', 20+len(tail)) + tail
    return hii, forms, ids, offsets, new_controls, dict(declaration_offset=form_map[0x3100]['start'],
        declaration_hex=declaration.hex(), first_added_string=next_id,
        replaced_string_ids={k:ids[k] for k in REPLACE}, existing_varstore_ids=stores,
        languages=[x[0] for x in scanned])

def build_spf(old, old_forms, forms, offsets, new_controls):
    table, control, var_start, lengths = [u32(old, at) for at in (0x2c, 0x30, 0x34, 0x38)]
    count = u32(old, table); assert count == 304
    old_ops, _ = p5.scan_forms(old_forms)
    _, new_ops = pv.ifr(forms)
    records=[]; cb=bytearray(old[control:var_start]); seen=set(); fields={x['name']:x for x in FIELDS}
    for i in range(count):
        pos=u32(old,table+4+i*4); end=u32(old,table+8+i*4) if i+1<count else control
        records.append(bytearray(old[pos:end])); record=records[-1]
        for j in range(u32(record,28)):
            c=u32(record,32+j*4)
            if c in seen: continue
            seen.add(c)
            if u16(cb,c+38)!=1: continue
            at=u64(cb,c+40); rel=struct.unpack_from('<q',cb,c+48)[0]
            if at:
                assert old_ops[at] == new_ops[offsets[at]]
                put64(cb,c+40,offsets[at])
            if rel:
                target=at+rel if at else rel
                assert old_ops[target] == new_ops[offsets[target]]
                struct.pack_into('<q',cb,c+48,offsets[target]-offsets[at] if at else offsets[target])
    # Source-derived layout: AMITSE 0x2f3ac writes these fields. Its u8
    # defaults tail is manufacturing value, standard value, followed by
    # (default-id u16, value u8, zero pad) for each explicit IFR DEFAULT.
    for item in new_controls:
        fid, at, name = item['form_id'], item['offset'], item['name']
        page=299+fid-0x3100; opcode=new_ops[at]; field=fields.get(name)
        out=bytearray(64)
        put16(out,20,3 if field is None else 6 if field['control']=='oneof' else 11)
        put16(out,22,page);put16(out,24,0xffff);put32(out,28,1)
        put16(out,32,u16(opcode,4));put16(out,38,1);put64(out,40,at);put16(out,60,u16(opcode,2))
        if field is not None:
            put32(out,8,VAR_INDEX);put16(out,12,field['question_id'])
            put16(out,56,1);put16(out,58,1)
            out.extend(bytes([field['default'],field['default']]))
            if field['control']=='numeric':
                out[16]=2
                for default_id in (0,1): out.extend(h(default_id)+bytes([field['default'],0]))
        item['control_relative']=len(cb);item['control_bytes']=len(out);item['page_index']=page
        cb.extend(out)
    # Assemble each P5 page in IFR order, adding controls and updating only
    # the ordinal of the homepage controls shifted by new status TEXT.
    for page in range(299,304):
        r=records[page]; n=u32(r,28); refs=[u32(r,32+4*j) for j in range(n)]
        refs.extend(x['control_relative'] for x in new_controls if x['page_index']==page)
        refs.sort(key=lambda c:u64(cb,c+40))
        r[32:32+4*n]=b''.join(struct.pack('<I',x) for x in refs)
        put32(r,28,len(refs))
        for ordinal,c in enumerate(refs): put16(cb,c+36,ordinal)
    # Append variable index 119. The disk record is 124 bytes; AMITSE's
    # runtime copy is 128 bytes due to trailing alignment, not field shifts.
    old_vars=old[var_start:lengths]; nv=u32(old_vars,0);assert nv==VAR_INDEX
    chunks=[]
    for i in range(nv):
        a=u32(old_vars,4+4*i);b=u32(old_vars,8+4*i) if i+1<nv else len(old_vars)
        assert b-a==124;chunks.append(old_vars[a:b])
    record=bytearray(124);record[:16]=uuid.UUID(GUID).bytes_le
    encoded=(NAME+'\0').encode('utf-16le');record[16:16+len(encoded)]=encoded
    put32(record,0x60,ATTRS);put32(record,0x64,STORE_ID);put32(record,0x68,0x1000);put16(record,0x78,SIZE)
    chunks.append(bytes(record));nv+=1
    new_vars=bytearray(struct.pack('<I',nv));vpos=4+4*nv
    for c in chunks:new_vars+=struct.pack('<I',vpos);vpos+=len(c)
    new_vars+=b''.join(chunks);assert len(new_vars)-len(old_vars)==128
    prefix=bytearray(old[:table]);nt=bytearray(struct.pack('<I',count));pos=table+4+4*count
    for r in records:nt+=struct.pack('<I',pos);pos+=len(r)
    nc=pos;nvpos=nc+len(cb);nl=nvpos+len(new_vars)
    suffix=bytearray(old[lengths:]);put32(suffix,0,len(forms))
    put32(prefix,0x30,nc);put32(prefix,0x34,nvpos)
    for off in range(0x38,0x48,4):put32(prefix,off,u32(old,off)+nl-lengths)
    result=bytes(prefix+nt+b''.join(records)+cb+new_vars+suffix)
    assert u32(result,0x44)==len(result)
    return result,dict(variable_index=VAR_INDEX,variable_record_hex=record.hex(),
        variable_record_bytes=124,variable_table_count=nv,page_count=count,
        added_controls=len(new_controls),controls=new_controls,
        original_variable_records_preserved=119,original_non_setup_controls_preserved=True)

def main():
    meta=json.loads((P5/'native-payload.json').read_text())
    old_hii=(P5/'Setup-HII-P5.bin').read_bytes();old_spf=(P5/'AMITSESetupData-P5.bin').read_bytes()
    assert sha(old_hii)==meta['hii_sha256'] and sha(old_spf)==meta['spf_sha256']
    setup=p5.SETUP.read_bytes();assert sha(setup)==p5.SETUP_SHA
    hii,forms,ids,mapping,new_controls,hmeta=build_hii(old_hii,meta)
    spf,smeta=build_spf(old_spf,p5.read_packages(old_hii)[0],forms,mapping,new_controls)
    setup_out,pemeta=p5.embed_resource(setup,hii)
    files={'Setup-HII-P6.bin':hii,'Setup-forms-P6.bin':forms,
           'AMITSESetupData-P6.bin':spf,'Setup-P6-RESOURCE-REVIEW.efi':setup_out,
           'HeroIpmiSettings-default.bin':DEFAULT}
    for name,data in files.items():(OUT/name).write_bytes(data)
    value_ids=dict(meta['value_ids']);assert len(value_ids)==40
    value_ids['CONFIG_STATUS']=ids['V_CONFIG_STATUS'];assert len(value_ids)==41
    schema=dict(name=NAME,guid=GUID,size=SIZE,attributes=ATTRS,varstore_id=STORE_ID,
                spf_variable_index=VAR_INDEX,default_hex=DEFAULT.hex(),fields=FIELDS,
                reserved_offsets=list(range(21,32)),apply='Saved by native F10; backend applies next boot')
    (OUT/'settings-schema.json').write_text(json.dumps(schema,indent=2)+'\n')
    report=dict(version='P6 native settings resource components',deployable=False,
        source_p5_meta_sha256=sha((P5/'native-payload.json').read_bytes()),
        original_setup_sha256=sha(setup),p5_hii_sha256=sha(old_hii),p5_spf_sha256=sha(old_spf),
        string_ids=ids,value_ids=value_ids,settings=schema,hii_metadata=hmeta,spf_metadata=smeta,
        pe_metadata=pemeta,old_ifr_offset_map={str(a):b for a,b in mapping.items()},
        files={name:dict(bytes=len(data),sha256=sha(data)) for name,data in files.items()},
        no_question_callbacks=True,no_setup_variable_changes=True,no_code_changes=True,
        limitations=['Component resource output only; parent integrates matching backend and firmware.',
                     'Native editing and F10 save need target hardware confirmation.'])
    (OUT/'native-payload.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(files=report['files'],settings_guid=GUID,varstore_id=hex(STORE_ID),value_ids=len(value_ids),added_controls=len(new_controls)),indent=2))

if __name__=='__main__':main()
