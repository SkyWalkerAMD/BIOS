"""Put one DXE FFS in free space of a COPY of QEMU's nested OVMF DXE FV.

Only this known lab OVMF layout is supported. Never accepts ASUS CAP as input.
The decompressed original bytes are unchanged outside erased free space.
"""
from pathlib import Path
import hashlib,json,lzma,struct,uuid
OUT=Path(__file__).resolve().parent;ROOT=next(p for p in OUT.parents if (p/'tools/qemu-11.1.0/qemu-system-x86_64.exe').is_file())
CODE=ROOT/'tools/qemu-11.1.0/share/edk2-x86_64-code.fd'
FFS_GUID=uuid.UUID('2fe3d914-96b9-4cdc-8344-d684706fd345')
def digest(b):return hashlib.sha256(b).hexdigest()
def section(kind,data):
    b=(len(data)+4).to_bytes(3,'little')+bytes([kind])+data
    return b+b'\0'*((-len(b))%4)
def ffs_for_driver(data,guid=FFS_GUID,label='VM LAB DXE ONLY',depex=None):
    if depex is None:
        # Require both architectural protocols before any NV-variable access.
        depex=b'\x02'+uuid.UUID('1e5668e2-8481-11d4-bcf1-0080c73c8881').bytes_le+b'\x02'+uuid.UUID('6441f818-6362-4e44-b570-7dba31dd2453').bytes_le+b'\x03\x08'
    body=section(0x13,depex)+section(0x10,data)+section(0x15,(label+'\0').encode('utf-16-le'))
    h=bytearray(guid.bytes_le+b'\0\0'+bytes([7,0x40])+(24+len(body)).to_bytes(3,'little')+b'\0')
    h[16]=(-sum(h))&255;h[17]=(-sum(body))&255;h[23]=0xf8
    assert (sum(h)-h[17]-h[23])&255==0
    return bytes(h)+body
def valid_fv(data,p):
    assert data[p+40:p+44]==b'_FVH'
    n=struct.unpack_from('<Q',data,p+32)[0];h=struct.unpack_from('<H',data,p+48)[0]
    assert sum(struct.unpack('<'+'H'*(h//2),data[p:p+h]))&65535==0
    assert p+n<=len(data) and h>=0x48
    return n,h
def find_free(data,p):
    n,h=valid_fv(data,p);q=p+h;files=[]
    while q+24<=p+n:
        if data[q:q+24]==b'\xff'*24:return q,p+n-q,files
        size=int.from_bytes(data[q+20:q+23],'little');assert size>=24 and q+size<=p+n
        files.append({'offset':hex(q),'size':size,'guid':str(uuid.UUID(bytes_le=data[q:q+16])),'sha256':digest(data[q:q+size])})
        q=(q+size+7)&~7
    raise ValueError('No erased space')
def inject(driver,output):
    output=Path(output).resolve();assert output.is_relative_to(OUT) and output.suffix=='.fd'
    source=CODE.read_bytes();assert len(source)==0x37c000
    outer_size,_=valid_fv(source,0);assert outer_size==0x348000
    start=0x78;old_size=int.from_bytes(source[start+20:start+23],'little');h=bytearray(source[start:start+24]);assert h[18]==0xb
    sec=start+24;assert source[sec+3]==2 and uuid.UUID(bytes_le=source[sec+4:sec+20])==uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf')
    dataoff=int.from_bytes(source[sec+20:sec+22],'little');raw=lzma.decompress(source[sec+dataoff:start+old_size],format=lzma.FORMAT_ALONE)
    assert valid_fv(raw,0xe0090)[0]==0xe80000
    free,available,oldfiles=find_free(raw,0xe0090);ffs=ffs_for_driver(Path(driver).read_bytes());assert len(ffs)<available
    modified=bytearray(raw);assert modified[free:free+len(ffs)]==b'\xff'*len(ffs);modified[free:free+len(ffs)]=ffs
    assert modified[:free]==raw[:free] and modified[free+len(ffs):]==raw[free+len(ffs):]
    packed=lzma.compress(bytes(modified),format=lzma.FORMAT_ALONE,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':1<<24,'lc':3,'lp':0,'pb':2}])
    # Python writes an unknown output length; EDK II requires the known length.
    packed=packed[:5]+len(modified).to_bytes(8,'little')+packed[13:]
    # Python/liblzma rejects an EOS marker combined with a known-size ALONE
    # header. Validate the unchanged LZMA stream independently as RAW; OVMF's
    # actual EDK II decoder is also exercised by run_vm.py.
    assert lzma.decompress(packed[13:],format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':1<<24,'lc':3,'lp':0,'pb':2}])==modified
    sh=bytearray(source[sec:sec+dataoff]);sh[:3]=(len(sh)+len(packed)).to_bytes(3,'little');body=bytes(sh)+packed
    h[20:23]=(24+len(body)).to_bytes(3,'little');h[16]=h[17]=0;state=h[23];h[23]=0;h[16]=(-sum(h))&255;h[17]=((-sum(body))&255) if h[19]&0x40 else 0xaa;h[23]=state
    assert start+24+len(body)<outer_size
    result=source[:start]+bytes(h)+body+b'\xff'*(outer_size-start-24-len(body))+source[outer_size:]
    assert len(result)==len(source)
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(result)
    report={'source_sha256':digest(source),'output_sha256':digest(result),'driver_sha256':digest(Path(driver).read_bytes()),'driver_guid':str(FFS_GUID),'ffs_offset_in_decompressed_section':hex(free),'ffs_bytes':len(ffs),'original_dxe_files_unchanged':len(oldfiles),'original_uncompressed_bytes_unchanged_outside_erased_space':True,'source_path':str(CODE),'output_path':str(output),'note':'Lab OVMF only; no ASUS capsule and no signing claim.'}
    output.with_suffix('.json').write_text(json.dumps(report,indent=2),encoding='utf8');return report
if __name__=='__main__':print(json.dumps(inject(OUT/'build/RESIDENT.EFI',OUT/'build/OVMF-LAB.fd'),indent=2))
