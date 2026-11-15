"""Read-only consistency audit of HERO 3107 IFR and its shipped TSE data.

The layout is derived from this exact firmware and REA's AMITSE consumers.
This does NOT inspect the live TSE cache, patch it, or prove a hang's cause.
"""
from pathlib import Path
import ctypes as C
import hashlib
import json
import struct

P = Path(__file__).resolve().parent
REF = P / 'reference'
if not (REF / 'HERO-3107-AMITSESetupData.bin').exists():
    REF = P.parent / 'hero_ipmi_p1b/reference'
data = (REF / 'HERO-3107-AMITSESetupData.bin').read_bytes()
ifr = (P / 'reference/HERO-3107-forms.bin').read_bytes()
extra = (P / 'HERO-P1c-native-forms.bin').read_bytes()


def u16(b, p):
    return struct.unpack_from('<H', b, p)[0]


def u32(b, p):
    return struct.unpack_from('<I', b, p)[0]


def u64(b, p):
    return struct.unpack_from('<Q', b, p)[0]


def opcodes(b):
    assert b[3] == 2 and int.from_bytes(b[:3], 'little') == len(b)
    p, result, forms = 4, {}, {}
    while p < len(b):
        assert p + 2 <= len(b)
        n = b[p + 1] & 127
        assert 2 <= n <= len(b) - p
        result[p] = b[p:p + n]
        if b[p] == 1:
            assert n == 6 and u16(b, p + 2) not in forms
            forms[u16(b, p + 2)] = u16(b, p + 4)
        p += n
    assert p == len(b)
    return result, forms


assert data[:4] == b'$SPF' and len(data) == 682632
table, control_base = u32(data, 0x2c), u32(data, 0x30)
assert (table, control_base) == (0x60, 0xb754)
count = u32(data, table)
assert count == 299
original_ops, original_forms = opcodes(ifr)
main_pages, controls = [], []
for i in range(count):
    p = u32(data, table + 4 + i * 4)
    assert table + 4 + count * 4 <= p <= control_base - 32
    n = u32(data, p + 28)
    assert p + 32 + n * 4 <= control_base
    assert u16(data, p + 16) == i
    if u16(data, p + 8) != 1:  # Source package index, verified against Setup IFR.
        continue
    form, title = u16(data, p + 10), u16(data, p + 14)
    assert original_forms[form] == title
    main_pages.append(dict(index=i,offset=p,form=form,title=title,controls=n))
    for j in range(n):
        c = control_base + u32(data, p + 32 + j * 4)
        assert control_base <= c <= u32(data, 0x34) - 64
        offset = u64(data, c + 40)
        if offset:
            assert offset in original_ops, (form, hex(c), hex(offset))
        controls.append(dict(form=form,record_offset=c,ifr_offset=offset,
                             question_id=u16(data, c + 12)))
assert {x['form'] for x in main_pages} == set(original_forms)
assert len(main_pages) == len(original_forms) == 292

lib = C.CDLL(str(P / 'native_test.dll'))
splice = lib.native_splice
splice.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t,
                   C.c_uint16, C.c_uint16, C.c_void_p, C.c_size_t,
                   C.POINTER(C.c_size_t)]
splice.restype = C.c_int
dest = C.create_string_buffer(len(ifr) + 15 + len(extra))
n = C.c_size_t()
assert splice(C.create_string_buffer(ifr), len(ifr),
              C.create_string_buffer(extra), len(extra), 123, 124,
              dest, len(dest), C.byref(n))
patched = dest.raw[:n.value]
new_ops, new_forms = opcodes(patched)
insert = 0xd8a2
affected, different = [], []
for c in controls:
    p = c['ifr_offset']
    if p >= insert:
        affected.append(c)
        # Independently verify exactly where every old opcode moved.
        assert new_ops[p + 15] == original_ops[p]
        if new_ops.get(p) != original_ops[p]:
            different.append(c)
new_ids = sorted(set(new_forms) - set(original_forms))
assert new_ids == list(range(0x3100, 0x3105))
report = dict(
    target='ROG MAXIMUS Z790 HERO 3107',
    mode='static consistency audit; no live cache access or patch',
    tse_data_sha256=hashlib.sha256(data).hexdigest(),
    original_ifr_sha256=hashlib.sha256(ifr).hexdigest(),
    original_page_count=count, setup_page_count=len(main_pages),
    setup_control_count=len(controls),
    original_nonzero_ifr_references_validated=sum(bool(c['ifr_offset']) for c in controls),
    original_title_tokens_match=True,
    advanced_page=next(x for x in main_pages if x['form'] == 10005),
    p1c_ifr_insertion=dict(offset=insert,bytes=15),
    serialized_ifr_references_requiring_rebase=len(affected),
    stale_references_pointing_to_different_opcodes=len(different),
    rebase_by_15_preserves_all_affected_original_opcodes=True,
    new_forms_missing_from_shipped_tse_table=new_ids,
    affected_reference_sample=affected[:5],
    limitations=[
        'The static table is not a dump of the current RAM cache.',
        'AMITSE has dynamic package processing; its actual update path still needs verification.',
        'A successful HII update/readback alone does not validate TSE menu integration.',
        'This report is not a complete TSE metadata patch or proof of the freeze root cause.',
    ])
(P / 'native-metadata-audit.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
