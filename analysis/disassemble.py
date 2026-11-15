"""Disassemble extracted PE/TE bodies for local static analysis only."""
from pathlib import Path
import sys
import json
import re
import struct
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools/pydeps'))
import capstone
import pefile
from inventory import ROOT

data = json.loads((ROOT / 'analysis/inventory.json').read_text(encoding='utf-8'))
dest = ROOT / 'analysis/disassembly'
dest.mkdir(exist_ok=True)
selected = set(sys.argv[1:])
for cap, mods in data.items():
    label = 'standard' if 'proart_standard' in cap else 'donor' if 'IPMI' in cap else 'hero'
    for m in mods:
        if m['guid'] not in selected:
            continue
        md = ROOT / m['path']
        for p in md.rglob('body.bin'):
            if not ('PE32 image' in p.parent.name or 'TE image' in p.parent.name):
                continue
            b = p.read_bytes()
            if b[:2] == b'MZ':
                pe = pefile.PE(data=b)
                machine = pe.FILE_HEADER.Machine
                image_base = pe.OPTIONAL_HEADER.ImageBase
                entry = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
                sections = [(s.Name.decode('ascii').rstrip('\0'), s.VirtualAddress, s.PointerToRawData,
                             s.SizeOfRawData, s.Characteristics) for s in pe.sections]
                def offset(addr):
                    return pe.get_offset_from_rva(addr - image_base)
            elif b[:2] == b'VZ':
                machine = struct.unpack_from('<H', b, 2)[0]
                image_base = struct.unpack_from('<Q', b, 16)[0]
                stripped = struct.unpack_from('<H', b, 6)[0] - 40
                entry = image_base + struct.unpack_from('<I', b, 8)[0]
                sections = []
                for i in range(b[4]):
                    o = 40 + 40*i
                    vs, va, size, raw = struct.unpack_from('<4I', b, o+8)
                    flags = struct.unpack_from('<I', b, o+36)[0]
                    sections.append((b[o:o+8].decode('ascii').rstrip('\0'), va, raw-stripped, size, flags))
                def offset(addr):
                    rva = addr-image_base
                    for _, va, raw, size, _ in sections:
                        if va <= rva < va+size:
                            return raw+rva-va
                    raise ValueError()
            else:
                continue
            lines = [f'{cap}\n{m["guid"]}\nMachine {machine:#x} base {image_base:#x} entry {entry:#x}\n{sections}\n']
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if machine == 0x14c else capstone.CS_MODE_64)
            cs.detail = True
            cs.skipdata = True
            for name, va, raw, size, flags in sections:
                if not flags & 0x20000000:
                    continue
                lines.append(f'\nSECTION {name}')
                for ins in cs.disasm(b[raw:raw+size], image_base+va):
                    notes = []
                    for op in ins.operands if ins.id else []:
                        addr = None
                        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                            addr = ins.address+ins.size+op.mem.disp
                        elif machine == 0x14c and op.type == capstone.x86.X86_OP_MEM and not op.mem.base and not op.mem.index:
                            addr = op.mem.disp & 0xffffffff
                        elif machine == 0x14c and op.type == capstone.x86.X86_OP_IMM:
                            addr = op.imm & 0xffffffff
                        if addr is not None:
                            try:
                                off = offset(addr)
                                ref = b[off:off+140]
                                ascii_s = re.match(rb'[ -~]{4,}', ref)
                                wide_s = re.match(rb'(?:[ -~]\x00){4,}', ref)
                                notes.append(f'[{addr:#x}] ' + (wide_s[0].decode('utf-16-le') if wide_s else ascii_s[0].decode() if ascii_s else ref[:16].hex()))
                            except Exception:
                                notes.append(f'[{addr:#x}]')
                    lines.append(f'{ins.address:08x}: {ins.bytes.hex():28} {ins.mnemonic:8} {ins.op_str:45} ' + ' ; '.join(notes))
            out = dest / f'{label}_{m["guid"]}.txt'
            out.write_text('\n'.join(lines), encoding='utf-8')
            print(out.name, hex(entry), len(lines))
