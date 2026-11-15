"""Create an analysis-only PE view of the HERO IA32 TE key-publication PEIM.

No instruction/data section bytes are changed and no firmware is repacked.
Only the stripped PE headers are synthesized so the native analysis backend
can map the original TE sections at their original RVAs. Never execute output.
"""
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
rows = json.loads((HERE / 'hero_root_guid_chunk_search.json').read_text())
source = ROOT / rows[0]['path']
data = source.read_bytes()
sig, machine, count, subsystem, stripped, entry, base_code, image_base, reloc_rva, reloc_size, debug_rva, debug_size = struct.unpack_from('<HHBBHIIQIIII', data)
assert (sig, machine, count, stripped) == (0x5A56, 0x14C, 3, 0x1C0)
delta = stripped - 40
view = bytearray(len(data) + delta)
view[stripped:] = data[40:]
view[:2] = b'MZ'
struct.pack_into('<I', view, 0x3C, 0x40)
view[0x40:0x44] = b'PE\0\0'
struct.pack_into('<HHIIIHH', view, 0x44, machine, count, 0, 0, 0, 0xE0, 0x2102)
opt = 0x58
struct.pack_into('<H', view, opt, 0x10B)
struct.pack_into('<III', view, opt + 4, 0x480, 0x180, 0)
struct.pack_into('<III', view, opt + 16, entry, base_code, 0x6C0)
struct.pack_into('<III', view, opt + 28, image_base, 0x40, 0x40)
struct.pack_into('<II', view, opt + 56, 0x840, 0x240)
struct.pack_into('<H', view, opt + 68, subsystem)
struct.pack_into('<I', view, opt + 92, 16)
struct.pack_into('<II', view, opt + 96 + 5 * 8, reloc_rva, reloc_size)
struct.pack_into('<II', view, opt + 96 + 6 * 8, debug_rva, debug_size)
view[opt + 0xE0:opt + 0xE0 + count * 40] = data[40:40 + count * 40]
sections = []
for i in range(count):
    name, virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<8sIIII', data, 40 + i * 40)
    original = data[raw_offset - delta:raw_offset - delta + raw_size]
    reconstructed = view[raw_offset:raw_offset + raw_size]
    assert original == reconstructed
    sections.append(dict(name=name.rstrip(b'\0').decode(), rva=rva, virtual_size=virtual_size,
                         original_te_file_offset=raw_offset - delta,
                         derived_pe_file_offset=raw_offset, raw_size=raw_size,
                         bytes_identical=True, sha256=hashlib.sha256(original).hexdigest()))
dest = HERE / 'HERO-3107-76864548-KeyPeim-ANALYSIS-ONLY.efi'
dest.write_bytes(view)
report = dict(source=str(source), source_sha256=hashlib.sha256(data).hexdigest(),
              output=str(dest), output_sha256=hashlib.sha256(view).hexdigest(),
              kind='Synthetic PE header view of shipped TE; not an original PE artifact or runnable firmware',
              entry_rva=entry, image_base=image_base, stripped_header_delta=delta,
              sections=sections, original_cap_not_modified=True, instructions_and_data_preserved=True,
              limitations=['REA subject digest identifies this derived view; TE source binding is in this manifest.',
                           'Synthesized header metadata is analysis support and not a claim about original stripped bytes.'])
(HERE / 'rootkey_pe_view_manifest.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
