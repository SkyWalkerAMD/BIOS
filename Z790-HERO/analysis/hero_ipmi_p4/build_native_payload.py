"""Offline HERO 3107 native menu resources. Never reads/writes target hardware.

P2/P3 proved that late HII registration is not a usable native GUI integration.
This builds matching Setup IFR, strings and precompiled AMITSESetupData instead.
It is a review payload, not a complete BIOS, flashed image or working feature.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile

SETUP = ROOT / 'analysis/hero_remote_bios_r3/reference/HERO-3107-Setup.efi'
SPF = ROOT / 'analysis/hero_ipmi_p1b/reference/HERO-3107-AMITSESetupData.bin'
SETUP_SHA = '1c4683574c36e972ae0615bb4a899929c1edaa61d5b23dc86da333a62edb53fe'
SPF_SHA = 'f2a72b833418bf4a3a1914462c80b23d12358065745db3783a3546bd284c062e'
INSERT = 0xd8a2
FORM_IDS = list(range(0x3100, 0x3105))

def sha(b):
    return hashlib.sha256(b).hexdigest()

def u16(b, p):
    return struct.unpack_from('<H', b, p)[0]

def u32(b, p):
    return struct.unpack_from('<I', b, p)[0]

def u64(b, p):
    return struct.unpack_from('<Q', b, p)[0]

def put16(b, p, n):
    struct.pack_into('<H', b, p, n)

def put32(b, p, n):
    struct.pack_into('<I', b, p, n)

def put64(b, p, n):
    struct.pack_into('<Q', b, p, n)

def h(*n):
    return struct.pack('<' + 'H' * len(n), *n)

def op(code, payload=b'', scope=False):
    assert len(payload) + 2 < 128
    return bytes([code, len(payload) + 2 | (128 if scope else 0)]) + payload

def package(kind, data):
    assert len(data) + 4 < 0x1000000
    return struct.pack('<I', (kind << 24) | (len(data) + 4)) + data

def read_packages(blob):
    assert len(blob) >= 24 and u32(blob, 16) == len(blob)
    result, p = [], 20
    while p < len(blob):
        n = u32(blob, p) & 0xffffff
        assert 4 <= n <= len(blob) - p
        result.append(blob[p:p+n])
        p += n
    assert result[-1] == b'\4\0\0\xdf' and p == len(blob)
    return result

def string_tokens(b):
    """Strict scanner for the UCS2/skip/duplicate blocks in this exact resource.

    Returns every defined token and the next token (including skipped tokens).
    Unsupported encodings fail closed; existing bytes are never re-encoded.
    """
    assert b[3] == 4 and u32(b, 4) == u32(b, 8)
    p, token, values = u32(b, 8), 1, {}
    assert 46 < p < len(b)
    language = b[46:p].rstrip(b'\0').decode('ascii')
    while p < len(b):
        kind = b[p]
        p += 1
        if kind == 0:
            assert p == len(b)
            return language, token, values
        if kind in (0x14, 0x15, 0x16, 0x17):
            if kind in (0x15, 0x17):
                p += 1
            count = 1
            if kind in (0x16, 0x17):
                count = u16(b, p)
                p += 2
            for _ in range(count):
                start = p
                while p + 2 <= len(b) and b[p:p+2] != b'\0\0':
                    p += 2
                assert p + 2 <= len(b)
                values[token] = b[start:p].decode('utf-16-le')
                token += 1
                p += 2
        elif kind == 0x20:
            values[token] = values[u16(b, p)]
            p += 2
            token += 1
        elif kind in (0x21, 0x22):
            width = 2 if kind == 0x21 else 1
            assert p + width <= len(b)
            token += int.from_bytes(b[p:p+width], 'little')
            p += width
        else:
            raise ValueError(f'Unsupported string block {kind:#x}, {language}, {p-1:#x}')
        assert token <= 0x10000
    raise ValueError('Missing string END')

def scan_forms(b):
    assert b[3] == 2 and u32(b, 0) & 0xffffff == len(b)
    p, scopes, result, forms = 4, [], {}, {}
    while p < len(b):
        n = b[p+1] & 127
        assert 2 <= n <= len(b) - p
        item = b[p:p+n]
        result[p] = item
        if item[0] == 1:
            assert n == 6 and u16(item, 2) not in forms
            forms[u16(item, 2)] = dict(start=p, title=u16(item, 4), controls=[])
        current = next((s[1] for s in reversed(scopes) if s[0] == 1), None)
        if current in FORM_IDS and item[0] in (3, 0xf):
            forms[current]['controls'].append(p)
        if item[0] == 0x29:
            assert n == 2 and scopes
            opened = scopes.pop()
            if opened[0] == 1:
                forms[opened[1]]['end'] = p
        elif item[1] & 128:
            scopes.append((item[0], u16(item, 2) if item[0] == 1 else None))
        p += n
    assert p == len(b) and not scopes
    return result, forms

def make_hii(original):
    packages = read_packages(original)
    assert [b[3] for b in packages] == [2] + [4] * 10 + [0xdf]
    old_forms = packages[0]
    old_ops, old_form_map = scan_forms(old_forms)
    assert len(old_forms) == 326006 and old_form_map[10005]['end'] == INSERT
    assert old_ops[INSERT] == b'\x29\x02' and old_forms[-2:] == b'\x29\x02'
    assert not set(FORM_IDS) & set(old_form_map)
    for item in old_ops.values():
        if item[0] in (5, 6, 7, 8, 0xc, 0xf, 0x1c, 0x23):
            assert not 0x3100 <= u16(item, 6) <= 0x3114
    scanned = [string_tokens(b) for b in packages[1:-1]]
    first_token = max(x[1] for x in scanned)
    spec = importlib.util.spec_from_file_location('p3_labels', OUT.parent / 'hero_ipmi_p3/generate_forms.py')
    labels = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(labels)  # No generator or build is run.
    strings = dict(labels.strings)
    strings['HELP'] = 'HERO native IPMI menu. Offline integration review; read backend binding is pending.'
    strings['NOTE'] = 'P4 review: settings are read-only; live data binding is pending.'
    strings['NETWORK_HELP'] = 'BMC LAN parameters. Configuration writes are not enabled.'
    strings['VIEW_HELP'] = 'First 16 raw BMC event records. Event clearing is not enabled.'
    ids = {key: first_token+i for i, key in enumerate(strings)}
    assert first_token + len(strings) <= 0x10000

    def ref(name, question, form):
        return op(0xf, h(ids[name], ids.get(name+'_HELP', 0), question, 0, 0xffff) + b'\0' + h(form))

    extra = b''
    for fid, name, values in [(0x3100, 'TITLE', labels.values[1:8]),
                             (0x3101, 'WATCHDOG', labels.values[8:13]),
                             (0x3102, 'EVENT', labels.values[13:18]),
                             (0x3103, 'NETWORK', labels.values[18:24]),
                             (0x3104, 'VIEW', labels.values[24:])]:
        extra += op(1, h(fid, ids[name]), True)
        extra += b''.join(op(3, h(ids['L_'+v], 0, ids['V_'+v])) for v in values)
        if fid == 0x3100:
            for j, name in enumerate(('WATCHDOG', 'EVENT', 'NETWORK', 'VIEW'), 1):
                extra += ref(name, 0x3110+j, 0x3100+j)
            for name in ('LED', 'INBAND', 'NOTE'):
                extra += op(3, h(ids[name], 0, 0))
        extra += op(0x29)
    entry = ref('TITLE', 0x3100, 0x3100)
    assert len(entry) == 15
    modified = package(2, old_forms[4:INSERT] + entry + old_forms[INSERT:-2] + extra + old_forms[-2:])
    new_ops, new_forms = scan_forms(modified)
    assert set(new_forms) - set(old_form_map) == set(FORM_IDS)
    for p, item in old_ops.items():
        shifted = p + (15 if p >= INSERT else 0) + (len(extra) if p == len(old_forms)-2 else 0)
        assert new_ops[shifted] == item
    new_packages, languages = [modified], []
    additions = b''.join(b'\x14' + v.encode('utf-16-le') + b'\0\0' for v in strings.values())
    for b, (lang, token, old_values) in zip(packages[1:-1], scanned):
        skip = first_token - token
        pad = b'\x21' + h(skip) if skip else b''
        new = package(4, b[4:-1] + pad + additions + b'\0')
        _, final, new_values = string_tokens(new)
        assert final == first_token + len(strings)
        assert all(new_values[i] == v for i, v in old_values.items())
        assert all(new_values[ids[k]] == v for k, v in strings.items())
        new_packages.append(new)
        languages.append(dict(language=lang, old_next_id=token, first_added_id=first_token,
                              added_count=len(strings), old_defined_preserved=len(old_values)))
    new_packages.append(packages[-1])
    tail = b''.join(new_packages)
    return (original[:16] + struct.pack('<I', 20+len(tail)) + tail,
            modified, ids, languages, labels.values)

def make_spf(original, old_forms, forms):
    assert original[:4] == b'$SPF' and len(original) == 682632
    table, control, variables, lengths = (u32(original, p) for p in (0x2c, 0x30, 0x34, 0x38))
    assert (table, control, variables, lengths) == (0x60, 0xb754, 0xa2344, 0xa5ec8)
    count = u32(original, table)
    assert count == 299 and u32(original, lengths) == len(old_forms)
    old_ops, old_map = scan_forms(old_forms)
    new_ops, new_map = scan_forms(forms)
    records, control_bytes, seen = [], bytearray(original[control:variables]), set()
    rebased, conditions, untouched_other = 0, 0, 0
    for index in range(count):
        p = u32(original, table+4+index*4)
        end = u32(original, table+4+(index+1)*4) if index+1<count else control
        assert p < end <= control
        record = bytearray(original[p:end])
        n = u32(record, 28)
        assert u16(record, 16) == index and 32+n*4 <= len(record)
        for j in range(n):
            c = u32(record, 32+j*4)
            assert c+64 <= len(control_bytes)
            if c in seen:
                continue
            seen.add(c)
            # Source formset index in serialized CONTROL_INFO is independent
            # of the page containing it (e.g. page 0 has foreign references).
            if u16(control_bytes, c+38) != 1:
                untouched_other += 1
                continue
            before = u64(control_bytes, c+40)
            relative = struct.unpack_from('<q', control_bytes, c+48)[0]
            after = before + (15 if before >= INSERT else 0)
            if before:
                assert old_ops[before] == new_ops[after]
                put64(control_bytes, c+40, after)
                rebased += before != after
            if relative:
                condition = before + relative if before else relative
                assert condition in old_ops
                new_condition = condition + (15 if condition >= INSERT else 0)
                assert old_ops[condition] == new_ops[new_condition]
                new_relative = new_condition-after if before else new_condition
                struct.pack_into('<q', control_bytes, c+48, new_relative)
                conditions += 1
        records.append(record)

    # Use only header layout observed in official, unconditional TEXT/REF
    # controls. The new controls have no varstore, callback or defaults.
    def control_info(offset, page, ordinal):
        item = new_ops[offset]
        assert item[0] in (3, 0xf)
        out = bytearray(64)
        put16(out, 20, 3 if item[0] == 3 else 1)
        put16(out, 22, page)
        put16(out, 24, 0xffff)
        put32(out, 28, 1)
        put16(out, 32, u16(item, 4))
        put16(out, 36, ordinal)
        put16(out, 38, 1)
        put64(out, 40, offset)
        put16(out, 60, u16(item, 2))
        if item[0] == 0xf:
            assert len(item) == 15 and u16(item, 8) == 0 and item[12] == 0
            put16(out, 12, u16(item, 6))
            put16(out, 24, 299 + FORM_IDS.index(u16(item, 13)))
        where = len(control_bytes)
        control_bytes.extend(out)
        return where

    advanced = records[35]
    assert u16(advanced, 10) == 10005 and u32(advanced, 28) == 38
    added_ref = control_info(INSERT, 35, 38)
    advanced[32+38*4:32+38*4] = struct.pack('<I', added_ref)
    put32(advanced, 28, 39)
    for number, fid in enumerate(FORM_IDS, 299):
        f = new_map[fid]
        page = bytearray(32)
        put16(page, 8, 1)
        put16(page, 10, fid)
        put16(page, 14, f['title'])
        put16(page, 16, number)
        put16(page, 18, 35 if fid == 0x3100 else 299)
        put32(page, 24, u32(records[35], 24))  # Original Setup refresh metadata.
        put32(page, 28, len(f['controls']))
        for ordinal, offset in enumerate(f['controls']):
            page += struct.pack('<I', control_info(offset, number, ordinal))
        records.append(page)
    new_count = len(records)
    prefix = bytearray(original[:table])
    new_table = bytearray(struct.pack('<I', new_count))
    pos = table+4+new_count*4
    for r in records:
        new_table += struct.pack('<I', pos)
        pos += len(r)
    new_control = pos
    new_variables = new_control + len(control_bytes)
    # Variable, GUID and auxiliary tables retain every original byte except
    # the explicit Setup forms-length discriminator in AMITSE's load path.
    suffix = bytearray(original[variables:])
    put32(suffix, lengths-variables, len(forms))
    for off in range(0x30, 0x48, 4):
        old = u32(original, off)
        new = new_control if off == 0x30 else old + new_variables-variables
        put32(prefix, off, new)
    result = bytes(prefix+new_table+b''.join(records)+control_bytes+suffix)
    assert u32(result, 0x44) == len(result)
    assert u32(result, u32(result, 0x38)) == len(forms)
    return result, dict(old_pages=count, new_pages=new_count, added_forms=FORM_IDS,
                        advanced_controls=[38,39], existing_ifr_pointers_rebased=rebased,
                        existing_condition_pointers_validated=conditions,
                        other_formset_controls_preserved=untouched_other,
                        new_controls=(len(control_bytes)-(variables-control))//64,
                        auxiliary_tables_preserved_except_forms_length=True)

def embed_resource(setup, hii):
    """Grow only the existing HII resource and move the final relocation table.

    Exact-image admission and relocation checks are deliberate: this is not a
    general PE rewriter. No executable instruction or code/data RVA is moved.
    """
    pe = pefile.PE(data=setup)
    assert pe.OPTIONAL_HEADER.ImageBase == 0
    assert pe.OPTIONAL_HEADER.SectionAlignment == pe.OPTIONAL_HEADER.FileAlignment == 32
    assert len(pe.sections) == 6
    rsrc, reloc = pe.sections[-2:]
    assert rsrc.Name.rstrip(b'\0') == b'.rsrc' and reloc.Name.rstrip(b'\0') == b'.reloc'
    assert rsrc.PointerToRawData == rsrc.VirtualAddress == 0x7c080
    assert reloc.PointerToRawData == reloc.VirtualAddress == 0x2ae340
    assert reloc.PointerToRawData+reloc.SizeOfRawData == len(setup)
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress == reloc.VirtualAddress
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for item in block.entries:
            if item.type == 0: continue
            assert item.type == 10 and item.rva+8 <= rsrc.VirtualAddress
            assert pe.get_qword_at_rva(item.rva) < rsrc.VirtualAddress
    data_entry = pe.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].directory.entries[0].data.struct
    assert data_entry.OffsetToData-rsrc.VirtualAddress == 96
    prefix = bytearray(rsrc.get_data()[:96])
    resource_data = hii + bytes((-len(hii)) % 4)
    put32(prefix, data_entry.get_file_offset()-rsrc.PointerToRawData+4, len(resource_data))
    resource = prefix+resource_data
    raw_length = (len(resource)+31) & ~31
    growth = raw_length-rsrc.SizeOfRawData
    assert growth > 0 and growth % 32 == 0
    output = bytearray(setup[:rsrc.PointerToRawData] + resource +
                       bytes(raw_length-len(resource)) + setup[reloc.PointerToRawData:])
    rhead, lhead = rsrc.get_file_offset(), reloc.get_file_offset()
    put32(output, rhead+8, len(resource))
    put32(output, rhead+16, raw_length)
    put32(output, lhead+12, reloc.VirtualAddress+growth)
    put32(output, lhead+20, reloc.PointerToRawData+growth)
    optional = pe.OPTIONAL_HEADER
    for field in ('SizeOfInitializedData','SizeOfImage'):
        put32(output, optional.get_field_absolute_offset(field), getattr(optional,field)+growth)
    put32(output, optional.DATA_DIRECTORY[2].get_field_absolute_offset('Size'), len(resource))
    put32(output, optional.DATA_DIRECTORY[5].get_field_absolute_offset('VirtualAddress'), reloc.VirtualAddress+growth)
    check = pefile.PE(data=output)
    put32(output, optional.get_field_absolute_offset('CheckSum'), check.generate_checksum())
    assert pefile.PE(data=output).verify_checksum()
    return bytes(output), dict(resource_growth=growth, all_executable_sections_unchanged=True,
                               relocation_entries_unchanged=True,
                               limitations='Resource-only component; backend binding and firmware packaging are pending.')

def main():
    setup, spf = SETUP.read_bytes(), SPF.read_bytes()
    assert sha(setup) == SETUP_SHA and sha(spf) == SPF_SHA
    pe = pefile.PE(data=setup)
    res = pe.DIRECTORY_ENTRY_RESOURCE.entries
    assert len(res) == 1 and str(res[0].name) == 'HII'
    entry = res[0].directory.entries[0].directory.entries[0].data.struct
    p = pe.get_offset_from_rva(entry.OffsetToData)
    original = setup[p:p+u32(setup, p+16)]
    hii, forms, ids, languages, value_names = make_hii(original)
    result, metadata = make_spf(spf, read_packages(original)[0], forms)
    modified_pe, pe_metadata = embed_resource(setup, hii)
    OUT.mkdir(exist_ok=True)
    (OUT/'Setup-HII-P4.bin').write_bytes(hii)
    (OUT/'Setup-forms-P4.bin').write_bytes(forms)
    (OUT/'AMITSESetupData-P4.bin').write_bytes(result)
    (OUT/'Setup-P4-RESOURCE-REVIEW.efi').write_bytes(modified_pe)
    report = dict(version='P4 offline native-resource review', deployable=False,
                  target='ROG MAXIMUS Z790 HERO 3107', original_setup_sha256=SETUP_SHA,
                  original_spf_sha256=SPF_SHA, hii_bytes=len(hii), hii_sha256=sha(hii),
                  forms_bytes=len(forms), forms_sha256=sha(forms), spf_bytes=len(result),
                  spf_sha256=sha(result), menu_metadata=metadata, languages=languages,
                  setup_review_sha256=sha(modified_pe), pe_metadata=pe_metadata,
                  string_ids=ids, value_ids={name:ids['V_'+name] for name in value_names},
                  new_controls_read_only=True, no_configuration_callbacks=True,
                  limitations=['Native HERO rendering has not been tested for these resources.',
                               'Read-backend binding into these static strings is not implemented.',
                               'This build does not create a CAP/FFS or change the target machine.'])
    (OUT/'native-payload.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('string_ids','value_ids')}, indent=2))

if __name__ == '__main__':
    main()
