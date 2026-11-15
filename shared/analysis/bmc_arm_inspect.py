"""Read-only ARM ELF inspection of the downloaded ASUS BMC firmware."""
from pathlib import Path
import struct
import sys
import json

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/pydeps'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN


class Elf32:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        assert self.data[:6] == b'\x7fELF\x01\x01'
        h = struct.unpack_from('<HHIIIIIHHHHHH', self.data, 16)
        assert h[1] == 40, 'Expected ARM'
        shoff, shsize, shnum, shstrndx = h[5], h[10], h[11], h[12]
        self.sections = []
        for i in range(shnum):
            s = struct.unpack_from('<10I', self.data, shoff+i*shsize)
            self.sections.append(dict(zip(('nameoff','type','flags','addr','off','size','link','info','align','entsize'),s)))
        st = self.sections[shstrndx]
        names = self.data[st['off']:st['off']+st['size']]
        for s in self.sections:
            s['name'] = names[s['nameoff']:].split(b'\0')[0].decode()
        self.symbols = []
        self.symbol_tables = {}
        for si,s in enumerate(self.sections):
            if s['type'] not in (2,11): continue
            st=self.sections[s['link']]
            names=self.data[st['off']:st['off']+st['size']]
            table=[]
            for o in range(s['off'],s['off']+s['size'],s['entsize']):
                n,v,z,info,other,shndx=struct.unpack_from('<IIIBBH',self.data,o)
                table.append(dict(name=names[n:].split(b'\0')[0].decode(errors='replace'),value=v,size=z,type=info&15,bind=info>>4,section=shndx))
            self.symbol_tables[si]=table
            self.symbols.extend(table)
        self.byname={s['name']:s for s in self.symbols if s['name']}
        self.relocs={}
        for s in self.sections:
            if s['type'] != 9: continue
            for o in range(s['off'],s['off']+s['size'],s['entsize']):
                a,info=struct.unpack_from('<II',self.data,o)
                sy=self.symbol_tables[s['link']][info>>8]
                self.relocs[a]=dict(type=info&255,symbol=sy['name'],value=sy['value'])

    def off(self,va):
        for s in self.sections:
            if s['type']!=8 and s['addr']<=va<s['addr']+s['size']:
                return s['off']+va-s['addr']
        raise ValueError(hex(va))

    def read(self,va,n):
        o=self.off(va)
        return self.data[o:o+n]

    def disasm(self,name):
        s=self.byname[name]
        addr=s['value']&~1
        cs=Cs(CS_ARCH_ARM, (CS_MODE_THUMB if s['value']&1 else CS_MODE_ARM)|CS_MODE_LITTLE_ENDIAN)
        cs.detail=True
        labels={s['value']&~1:s['name'] for s in self.symbols if s['value']}
        lines=[f"{name}: VA=0x{addr:X} size=0x{s['size']:X} mode={'thumb' if s['value']&1 else 'arm'}"]
        for ins in cs.disasm(self.read(addr,s['size']),addr):
            note=''
            if ins.mnemonic in ('bl','b','blx') and ins.op_str.startswith('#'):
                target=int(ins.op_str[1:],0)
                note=labels.get(target,'')
                # ARM PLT stub target ends in ldr pc, [ip, #imm]!, with an associated GOT relocation.
                try:
                    stub=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(self.read(target,12),target))
                    if len(stub)==3 and stub[0].mnemonic=='add' and stub[0].op_str.startswith('ip, pc, #'):
                        first=stub[0].op_str.split('#')[1].rstrip(', ')
                        # Immediate rotate syntax is emitted for the common zero high addend.
                        add0=int(first,0)
                        assert add0==0 or len(stub[0].op_str.split('#'))==2
                        got=target+8+add0+int(stub[1].op_str.split('#')[1],0)+int(stub[2].op_str.split('#')[1].rstrip(']!'),0)
                        note=self.relocs.get(got,{}).get('symbol',note)
                except (ValueError,IndexError): pass
            if ins.mnemonic.startswith('ldr') and '[pc, #' in ins.op_str:
                try:
                    disp=ins.op_str.split('[pc, #')[1].split(']')[0]
                    lit=((ins.address+4)&~3 if s['value']&1 else ins.address+8)+int(disp,0)
                    val=struct.unpack('<I',self.read(lit,4))[0]
                    note+=f' literal@{lit:X}=0x{val:X}'
                    if lit in self.relocs:
                        note+=' '+str(self.relocs[lit])
                except (ValueError,struct.error): pass
            lines.append(f'{ins.address:08X}: {ins.mnemonic:8} {ins.op_str:38} {note}')
        return '\n'.join(lines)+'\n'


if __name__=='__main__':
    e=Elf32(sys.argv[1])
    if len(sys.argv)>2:
        for name in sys.argv[2:]: print(e.disasm(name))
    else:
        print(json.dumps(dict(symbols=e.symbols,relocs=e.relocs,sections=e.sections),indent=2))
