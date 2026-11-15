"""Bounded read-only lookup of kernel geometry symbols and data references."""
from pathlib import Path
import hashlib,json,struct,re
HERE=Path(__file__).resolve().parent
KERNEL=HERE/'kernel_uncompressed.bin'
EXPECTED='bd66e8480131f0336c7641c700205ecd8d48a1aad5ee8101c9eb16ebf4708197'

def main():
    raw=KERNEL.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    targets=['fsg_lun_open','fsg_lun_close','fsg_store_file','nbd_ioctl','nbd_set_size','nbd_alloc_config','do_read_capacity','fsg_main_thread']
    rows=[]
    for name in targets:
        pos=0;matches=[]
        while True:
            pos=raw.find(name.encode()+b'\0',pos)
            if pos<0:break
            matches.append(pos);pos+=len(name)+1
        for off in matches:
            refs={}
            for base in [0xc0008000,0x80008000,0xc0000000,0x80000000]:
                needle=struct.pack('<I',base+off);at=0;hits=[]
                while len(hits)<64:
                    at=raw.find(needle,at)
                    if at<0:break
                    if at%4==0:hits.append(hex(at))
                    at+=4
                if hits:refs[hex(base)]=hits
            rows.append({'symbol':name,'string_offset':hex(off),'absolute_references':refs})
    # Relative export records use an offset from each field's own location.
    matchmap={int(r['string_offset'],16):r for r in rows}
    for off in range(0,len(raw)-4,4):
        relative=struct.unpack_from('<i',raw,off)[0]
        if off+relative in matchmap:
            matchmap[off+relative].setdefault('relative_references',[]).append(hex(off))
    # Record possible kallsyms token dictionary anchors, only for symbol lookup.
    anchors={}
    for seq in [b'a\0b\0c\0d\0e\0f\0',b'0\0' + b'1\0' + b'2\0' + b'3\0']:
        at=0;hits=[]
        while len(hits)<16:
            at=raw.find(seq,at)
            if at<0:break
            hits.append(hex(at));at+=len(seq)
        anchors[seq.hex()]=hits
    out={'source_sha256':EXPECTED,'targets':rows,'token_anchors':anchors}
    (HERE/'kernel_targets.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
