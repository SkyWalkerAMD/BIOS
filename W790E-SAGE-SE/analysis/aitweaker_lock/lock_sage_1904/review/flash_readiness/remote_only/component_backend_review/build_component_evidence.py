"""Offline ELF32/ARM metadata and call-site evidence; never executes target code."""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = next(p for p in HERE.parents if (p / 'tools/pydeps').is_dir())
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

LIBRARIES = {
    'compamibios': ('libcompamibios.so.13.0.1', 'fa6a4f658e6b59756aeb8fb0a4066f4be0502c3c2841d0dff71975cce6b71187'),
    'compmanager': ('libcomponent_manager.so.13.8.3', 'd579f5e607e7bb58fb7d8b8007bc144603eaf04b784534007bc218a3ca03295f'),
    'comphelper': ('libcomponent_manager_helper.so.13.3.4', '5ab5fc76817c203377b00db72a1f0203a1876763bc8800ca71c6f1695eedb75c'),
    'comppdk': ('libpdkapp.so.13.2.4', '35459aed01642e815001dc0e319f25ac79ae3ed72607d0895452513ebe38b567'),
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

class Elf32:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        b = self.data
        assert b[:7] == b'\x7fELF\x01\x01\x01' and struct.unpack_from('<H', b, 18)[0] == 40
        shoff = struct.unpack_from('<I', b, 32)[0]
        shsize, shnum, shstr = struct.unpack_from('<HHH', b, 46)
        assert shsize == 40 and shoff + shnum * shsize <= len(b)
        raw = [struct.unpack_from('<10I', b, shoff + i * shsize) for i in range(shnum)]
        names = raw[shstr]
        namebytes = b[names[4]:names[4] + names[5]]
        self.sections = []
        for v in raw:
            n = namebytes[v[0]:].split(b'\0', 1)[0].decode('ascii')
            self.sections.append(dict(zip(('name_index','type','flags','va','offset','size','link','info','alignment','entry_size'), v), name=n))
        self.byname = {s['name']: s for s in self.sections}
        self.symbols = []
        ds = self.byname['.dynsym']
        st = self.sections[ds['link']]
        sb = b[st['offset']:st['offset'] + st['size']]
        for off in range(ds['offset'], ds['offset'] + ds['size'], ds['entry_size']):
            n, value, size, info, other, shndx = struct.unpack_from('<IIIBBH', b, off)
            name = sb[n:].split(b'\0', 1)[0].decode('utf-8')
            self.symbols.append({'name': name, 'va': value, 'size': size, 'info': info, 'other': other, 'section_index': shndx})
        self.relocations = {}
        self.plt = {}
        for section in self.sections:
            if section['type'] != 9:
                continue
            assert section['entry_size'] == 8
            for i, off in enumerate(range(section['offset'], section['offset'] + section['size'], 8)):
                va, info = struct.unpack_from('<II', b, off)
                symbol = self.symbols[info >> 8]
                self.relocations[va] = {'type': info & 255, 'symbol': symbol['name'], 'symbol_va': symbol['va'], 'symbol_defined': symbol['section_index'] != 0}
                if section['name'] == '.rel.plt':
                    self.plt[self.byname['.plt']['va'] + 20 + 12 * i] = symbol['name']
        self.names = {s['va']: s['name'] for s in self.symbols if s['section_index'] and (s['info'] & 15) == 2}
        self.names.update(self.plt)

    def offset(self, va, size=1):
        for sec in self.sections:
            if sec['type'] != 8 and sec['va'] <= va and va + size <= sec['va'] + sec['size']:
                off = sec['offset'] + va - sec['va']
                if off + size <= len(self.data):
                    return off
        return None

    def string(self, va):
        sec = next((s for s in self.sections if s['name'] in ('.rodata', '.data') and s['va'] <= va < s['va'] + s['size']), None)
        if sec is None:
            return None
        off = sec['offset'] + va - sec['va']
        limit = sec['offset'] + sec['size']
        end = self.data.find(b'\0', off, limit)
        if end < 0 or end - off < 1 or end - off > 2048:
            return None
        text = self.data[off:end]
        if not all(32 <= c < 127 or c in (9, 10, 13) for c in text):
            return None
        return text.decode('ascii')

    def literal(self, va):
        off = self.offset(va, 4)
        if off is None:
            return {'elf_va': hex(va), 'mapped': False}
        value = struct.unpack_from('<I', self.data, off)[0]
        result = {'elf_va': hex(va), 'file_offset': hex(off), 'raw_u32': hex(value)}
        reloc = self.relocations.get(va)
        if reloc:
            result['relocation'] = reloc
            if reloc['symbol_defined'] and reloc['type'] == 2:
                target = reloc['symbol_va'] + value
            elif reloc['type'] == 23:
                target = value
            else:
                target = None
        else:
            target = value
        if target is not None:
            result['target_elf_va'] = hex(target)
            if target in self.names:
                result['target_function'] = self.names[target]
            text = self.string(target)
            if text is not None:
                result['target_string'] = text
        return result

def main():
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    output = {'method': 'Read-only Ghidra decompilation plus independent ELF32 dynamic symbols, ARM PLT and Capstone call-site inspection',
              'address_convention': 'ELF VAs are link-time addresses (load bias 0). Ghidra default analysis adds 0x10000. No address here is a measured BMC runtime address.',
              'limitations': ['Decompilation is evidence, not original source.', 'Disassembly spans exported symbol sizes, which may include literal pools; only genuine call sites cross-checked against decompiled bodies are used in findings.', 'Undefined imported calls and dynamic board hooks require separate implementation review.', 'No target execution, emulation, device access, or flash commands.'],
              'libraries': {}}
    ann = HERE / 'annotated_decompile'
    ann.mkdir(exist_ok=True)
    for label, (filename, expected) in LIBRARIES.items():
        path = BASE / 'bmc_backend/5308416/usr/local/lib' / filename
        ddir = BASE / (label + '_decompile')
        assert path.exists() and (ddir / 'function_inventory.json').exists()
        elf = Elf32(path)
        digest = sha(elf.data)
        if expected:
            assert digest == expected
        invpath = ddir / 'function_inventory.json'
        inventory = json.loads(invpath.read_text())
        assert inventory['executable_sha256'] == digest
        entry = {'path': str(path.relative_to(ROOT)), 'size': len(elf.data), 'sha256': digest,
                 'ghidra_inventory_path': str(invpath.relative_to(ROOT)), 'ghidra_inventory_sha256': sha(invpath.read_bytes()),
                 'ghidra_language': inventory['language'], 'sections': elf.sections,
                 'imported_functions': [s['name'] for s in elf.symbols if not s['section_index'] and s['name']],
                 'functions': {}}
        if label == 'compamibios':
            table = next(s for s in elf.symbols if s['name'] == 'amibios_cmd_tbl')
            assert table['size'] == 14 * 8
            entry['amibios_command_dispatch'] = []
            for delta in range(0, table['size'], 8):
                va = table['va'] + delta
                command = struct.unpack_from('<H', elf.data, elf.offset(va, 2))[0]
                pointer = elf.literal(va + 4)
                entry['amibios_command_dispatch'].append({'command': command, 'table_elf_va': hex(va), 'handler': pointer})
        for cpath in sorted(ddir.glob('*.c')):
            content = cpath.read_text()
            name = cpath.name.split('-', 1)[1][:-2]
            sym = next((s for s in elf.symbols if s['name'] == name and s['section_index']), None)
            if sym is None:
                continue
            off = elf.offset(sym['va'], sym['size'])
            assert off is not None
            calls = []
            for insn in md.disasm(elf.data[off:off + sym['size']], sym['va']):
                if insn.mnemonic in ('bl', 'blx'):
                    call = {'elf_va': hex(insn.address), 'ghidra_va': hex(insn.address + 0x10000), 'bytes': insn.bytes.hex(), 'mnemonic': insn.mnemonic, 'operand': insn.op_str}
                    if insn.op_str.startswith('#'):
                        target = int(insn.op_str[1:], 0)
                        call['target_elf_va'] = hex(target)
                        call['target_name'] = elf.names.get(target)
                    else:
                        call['indirect'] = True
                    calls.append(call)
            literal_refs = {}
            for ref in sorted(set(re.findall(r'(?:DAT_|PTR_)([0-9a-fA-F]{8})', content))):
                literal_refs['DAT_or_PTR_' + ref] = elf.literal(int(ref, 16) - 0x10000)
            fn = {'elf_va': hex(sym['va']), 'ghidra_va': hex(sym['va'] + 0x10000), 'size': sym['size'],
                  'bytes_sha256': sha(elf.data[off:off + sym['size']]), 'decompile_path': str(cpath.relative_to(ROOT)),
                  'decompile_sha256': sha(cpath.read_bytes()), 'call_sites': calls, 'literal_references': literal_refs}
            entry['functions'][name] = fn
            apath = ann / (label + '-' + cpath.name)
            annotated = '/* Offline literal/relocation map. ELF VA = Ghidra VA - 0x10000.\n' + json.dumps(literal_refs, indent=2, ensure_ascii=False).replace('*/', '* /') + '\n*/\n' + content
            apath.write_text(annotated, encoding='utf-8')
            fn['annotated_decompile_path'] = str(apath.relative_to(ROOT))
            fn['annotated_decompile_sha256'] = sha(apath.read_bytes())
        output['libraries'][label] = entry
    output['script_sha256'] = sha(Path(__file__).read_bytes())
    target = HERE / 'elf_callsite_evidence.json'
    target.write_text(json.dumps(output, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'path': str(target), 'sha256': sha(target.read_bytes()), 'libraries': {k: len(v['functions']) for k, v in output['libraries'].items()}}))

if __name__ == '__main__':
    main()
