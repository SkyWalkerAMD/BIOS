"""Read-only byte audit of the existing M1d HII package and released EFI."""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
OUT=Path(__file__).resolve().parent; ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile

src=ROOT/'analysis/hero_hii_m1d_kvm/source'
h=(src/'minimal.h').read_text()
initializer=re.search(r'minimal_packages\[\]\s*=\s*\{(.*?)\};',h,re.S).group(1)
b=bytes(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]{2})\b',initializer))
assert len(b)==4067 and struct.unpack_from('<I',b,16)[0]==len(b)
guid=str(uuid.UUID(bytes_le=b[:16]));packages=[];ofs=20;strings={};ifr=[]
while ofs<len(b):
    header=struct.unpack_from('<I',b,ofs)[0];length=header&0xffffff;typ=header>>24
    assert length>=4 and ofs+length<=len(b)
    packages.append(dict(offset=hex(ofs),length=length,type=hex(typ)))
    if typ==2:
        p=ofs+4;scopes=[]
        while p<ofs+length:
            op=b[p];size=b[p+1]&127;scope=b[p+1]>>7
            assert size>=2 and p+size<=ofs+length
            ifr.append(dict(offset=hex(p),opcode=hex(op),length=size,scope=scope,bytes=b[p:p+size].hex()))
            if op==0x29:assert size==2 and not scope;scopes.pop()
            elif scope:scopes.append(op)
            p+=size
        assert not scopes and p==ofs+length
    elif typ==4:
        hp=struct.unpack_from('<II',b,ofs+4);assert hp==(52,52)
        assert b[ofs+46:ofs+52]==b'en-US\0'
        assert struct.unpack_from('<H',b,ofs+44)[0]==1
        p=ofs+52;sid=1
        while b[p]!=0:
            assert b[p]==0x14;p+=1;start=p
            while b[p:p+2]!=b'\0\0':p+=2
            strings[sid]=b[start:p].decode('utf-16-le');p+=2;sid+=1
        assert p==ofs+length-1
    ofs+=length
assert ofs==len(b) and packages[-1]['type']=='0xdf' and packages[-1]['length']==4
assert [x['bytes'] for x in ifr]==[
    '0e978474f033ed7c94409adfc219535d9acc2500260000','018601002500',
    '0308270000000000','2902','2902']
assert len(strings)==39
efi=ROOT/'analysis/hero_hii_m1d_kvm/payload/EFI/BOOT/BOOTX64.EFI'
raw=efi.read_bytes();pe=pefile.PE(data=raw)
assert pe.get_data(0xa300,len(b))==b
assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
def sha(data):return hashlib.sha256(data).hexdigest()
report=dict(all_passed=True,scope='read-only package/PE byte audit, no SendForm execution',
    package_bytes=len(b),package_sha256=sha(b),package_list_guid=guid,packages=packages,ifr=ifr,
    string_count=len(strings),referenced_strings={i:strings[i] for i in (1,37,38,39)},
    package_embedded_exactly_at_efi_rva='0xa300',image_sha256=sha(raw),
    sources={p.name:sha(p.read_bytes()) for p in (src/'diag.c',src/'minimal.h',src/'efi_min.h')})
(OUT/'hii-byte-audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
