"""Extract the original public image's FIT kernel, no guest execution."""
from pathlib import Path
import hashlib,json,struct,zlib,lzma
from kernel_inventory import HERE,REMOTE,SOURCE,EXPECTED

def main():
    raw=SOURCE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    start=36831232+64
    words=struct.unpack_from('>10I',raw,start)
    magic,total,off_struct,off_strings,off_mem,version,last,boot,strings_size,struct_size=words
    assert magic==0xd00dfeed and total<5*1024*1024 and start+total<=len(raw)
    fit=raw[start:start+total];strings=fit[off_strings:off_strings+strings_size]
    p=off_struct;nodes={};stack=[]
    while p<off_struct+struct_size:
        tag=struct.unpack_from('>I',fit,p)[0];p+=4
        if tag==1:
            end=fit.index(0,p);name=fit[p:end].decode('ascii');p=(end+4)&~3
            stack.append(name);nodes['/'.join(stack)]={}
        elif tag==2:stack.pop()
        elif tag==3:
            n,no=struct.unpack_from('>II',fit,p);p+=8
            end=strings.index(0,no);name=strings[no:end].decode('ascii')
            val=fit[p:p+n];assert len(val)==n
            nodes['/'.join(stack)][name]={'data':val,'fit_offset':p};p=(p+n+3)&~3
        elif tag==4:pass
        elif tag==9:break
        else:raise ValueError(tag)
    rows=[]
    for path,props in nodes.items():
        row={'path':path,'properties':{}}
        for name,info in props.items():
            b=info['data']
            row['properties'][name]={'bytes':len(b),'fit_offset':info['fit_offset'],'sha256':hashlib.sha256(b).hexdigest()}
            if len(b)<256:row['properties'][name]['hex']=b.hex()
        if props.get('type',{}).get('data')==b'kernel\0':
            comp=props['compression']['data'].rstrip(b'\0').decode('ascii')
            b=props['data']['data']
            (HERE/'kernel_fit_data.bin').write_bytes(b)
            if comp=='gzip':
                obj=zlib.decompressobj(31);k=obj.decompress(b,32*1024*1024);assert obj.eof
            elif comp=='none':k=b
            else:raise ValueError('Unsupported kernel compression '+comp)
            embedded=[]
            if k[0x24:0x28]==b'\x18\x28\x6f\x01':
                for mark in [b'\x1f\x8b\x08',b'\xfd7zXZ\0',b'\x89LZO\0\r\n\x1a\n']:
                    pos=0
                    while len(embedded)<32:
                        pos=k.find(mark,pos)
                        if pos<0:break
                        embedded.append({'marker':mark.hex(),'offset':pos});pos+=len(mark)
                for candidate in embedded:
                    try:
                        if candidate['marker']=='1f8b08':
                            obj=zlib.decompressobj(31);decoded=obj.decompress(k[candidate['offset']:],32*1024*1024)
                        elif candidate['marker']=='fd377a585a00':
                            obj=lzma.LZMADecompressor(memlimit=64*1024*1024);decoded=obj.decompress(k[candidate['offset']:],max_length=32*1024*1024)
                        else:continue
                        if obj.eof and b'Linux version ' in decoded:
                            k=decoded;candidate['decoded_kernel_bytes']=len(k);break
                    except (zlib.error,lzma.LZMAError):pass
            (HERE/'kernel_uncompressed.bin').write_bytes(k)
            at=k.find(b'Linux version ')
            row['extracted']={'compression':comp,'bytes':len(k),'sha256':hashlib.sha256(k).hexdigest(),
                              'linux_banner':k[at:at+256].split(b'\0')[0].decode('ascii',errors='replace') if at>=0 else None,
                              'leading_hex':k[:64].hex(),'embedded_candidates':embedded}
        rows.append(row)
    out={'source_sha256':EXPECTED,'fit_offset':start,'fit_bytes':total,'nodes':rows}
    (HERE/'fit_kernel.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps([x for x in rows if 'extracted' in x],indent=2))
if __name__=='__main__':main()
