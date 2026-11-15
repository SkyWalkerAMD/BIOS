"""Bounded offline ELF analysis. No device/network/OS ioctl execution."""
from pathlib import Path
import hashlib,json,re,struct,sys

HERE=Path(__file__).resolve().parent
REMOTE=HERE.parent
PRIOR=REMOTE/'media_attach_review02'
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN

SOURCE=PRIOR/'backend/usr/local/lib/libnbd.so.13.4.3'
EXPECTED='dbeec9c80fd0821d259b5cf746aa5aff8d4859d2f22ae4de952ee6ec61dd1e6b'

def elf_parts(raw):
    assert raw[:6]==b'\x7fELF\x01\x01'
    phoff=struct.unpack_from('<I',raw,28)[0]
    phsz,phnum=struct.unpack_from('<HH',raw,42)
    return [struct.unpack_from('<8I',raw,phoff+i*phsz) for i in range(phnum)]

def vbytes(raw,va,n):
    for typ,off,v,p,fs,ms,flags,al in elf_parts(raw):
        if typ==1 and v<=va and va+n<=v+fs:return raw[off+va-v:off+va-v+n]
    raise ValueError(hex(va))

def main():
    raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    # Ghidra's imported ET_DYN base is 0x10000; ELF RVAs remain unchanged.
    literals=[]
    for addr in [0x19ec,0x19f0,0x19f4,0x19f8,0x19fc,0x1a00,0x1a04,0x2f38,0x2f3c,0x2f40,0x2f4c,0x2f50,0x2f54,0x2f58]:
        b=vbytes(raw,addr,4);v=struct.unpack('<I',b)[0]
        literals.append({'elf_rva':hex(addr),'ghidra_address':hex(addr+0x10000),'bytes':b.hex(),'value':hex(v)})
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    ranges=[(0x163c,0x19ec,'nbd_client'),(0x2aac,0x2f38,'nbd_init'),(0x14a0,0x1614,'nbd_server')]
    dis=[]
    for start,end,name in ranges:
        rows=[{'address':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'op_str':i.op_str} for i in md.disasm(vbytes(raw,start,end-start),start)]
        dis.append({'name':name,'elf_rva':hex(start),'bytes':end-start,'instructions':rows})
    shoff=struct.unpack_from('<I',raw,32)[0];shsz,shnum=struct.unpack_from('<HH',raw,46)
    sections=[struct.unpack_from('<10I',raw,shoff+i*shsz) for i in range(shnum)]
    relocs=[]
    for section in sections:
        if section[1]!=9:continue
        symbols=sections[section[6]];strings=sections[symbols[6]]
        for off in range(section[4],section[4]+section[5],section[9]):
            where,info=struct.unpack_from('<II',raw,off)
            if where not in [0x2f50,0x2f54]:continue
            no,value,size,kind,other,shndx=struct.unpack_from('<IIIBBH',raw,symbols[4]+(info>>8)*symbols[9])
            p=strings[4]+no;name=raw[p:raw.index(0,p)].decode('ascii')
            relocs.append({'elf_rva':hex(where),'type':info&255,'symbol':name,'symbol_rva':hex(value),'addend':hex(struct.unpack('<I',vbytes(raw,where,4))[0])})
    assert {x['symbol'] for x in relocs}=={'nbd_server','nbd_client'}
    out={'source':str(SOURCE.relative_to(ROOT)),'sha256':EXPECTED,'elf_type':struct.unpack_from('<H',raw,16)[0],
         'ghidra_base_bias':'0x10000','literal_pool':literals,'thread_entry_relocations':relocs,'disassembly':dis}
    (HERE/'nbd_static.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({'literal_pool':literals,'thread_entry_relocations':relocs},indent=2))

if __name__=='__main__':main()
