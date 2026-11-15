"""Reproducible byte evidence; no target execution or network access."""
from pathlib import Path
import sys, json, hashlib, zlib
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile, capstone
HERE = Path(__file__).resolve().parent
p = HERE / 'DxeCore.efi'
assert hashlib.sha256(p.read_bytes()).hexdigest() == '5a4a8d96f7de6f714fd4d91e5579d701e4e4a6394b7dc46968d6cb1f07f8efcf'
pe = pefile.PE(str(p)); d = pe.get_memory_mapped_image()
ranges = [('load',0x75b8,0x76b8),('depex',0x8824,0x88ec),('dispatch',0x8a0c,0x8d88),('constructor',0x8fa4,0x9088)]
relocs = [e.rva for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type]
out = []; header = ['/* Generated from the exact audited 3107 DxeCore. Do not hand-edit. */']
for name,start,end in ranges:
    assert not any(start <= x < end for x in relocs)
    data = d[start:end]
    out.append(dict(name=name,rva=start,length=len(data),crc32=f'{zlib.crc32(data):08X}',sha256=hashlib.sha256(data).hexdigest(),relocation_free=True))
    header.append(f'static const uint8_t dx_anchor_{name}[] = {{\n'+',\n'.join(' '+','.join(f'0x{x:02x}' for x in data[i:i+16]) for i in range(0,len(data),16))+'\n};')
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    (HERE/f'{name}.asm').write_text('\n'.join(f'{i.address:08X} {i.bytes.hex():24} {i.mnemonic} {i.op_str}' for i in cs.disasm(data,start))+'\n')
header += ['typedef struct { uint32_t rva,bytes; const uint8_t *p; } DX_ANCHOR;',
           'static const DX_ANCHOR dx_anchors[] = {']
header += [f' {{{start:#x},sizeof(dx_anchor_{name}),dx_anchor_{name}}},' for name,start,end in ranges]
header += ['};']
(HERE/'dxe_core_anchors.h').write_text('\n'.join(header)+'\n')
(HERE/'code-identity.json').write_text(json.dumps(dict(source=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size_of_image=pe.OPTIONAL_HEADER.SizeOfImage,anchors=out,load_image_rva=0x75b8,start_image_rva=0x76b8,dispatch_rva=0x8a0c,discovered_list_rva=0x16c10,scheduled_list_rva=0x16bf0,dispatcher_running_rva=0x17bd8,entry_size=0x90,entry_signature=0x72767264),indent=2)+'\n')
print(json.dumps(out))
