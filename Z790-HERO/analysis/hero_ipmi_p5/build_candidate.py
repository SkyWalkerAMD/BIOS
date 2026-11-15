"""Rebuild one DXE FV; never writes to a device or overwrites the original.

Original inner FV has only 1456 free bytes. Encapsulate the replacement Setup
PE32 in the existing platform LZMA GUID format, retaining DEPEX and version.
Preserve every other FFS byte-for-byte. No signature bypass is performed.
"""
from pathlib import Path
import hashlib,json,lzma,struct,uuid,subprocess
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
OFFICIAL=ROOT/'analysis/hero_3107_official'
ORIGINAL=OFFICIAL/'ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
SETUP='899407d7-99fe-43d8-9a21-79ec328cac21'
SPF='fe612b72-203c-47b1-8560-a66d946eb371'
LZMA_GUID=uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le
DRIVER='261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
BASE=0x12d1000;LENGTH=0x9f0000
def sha(b):return hashlib.sha256(b).hexdigest()
def u24(b):return int.from_bytes(b[:3],'little')
def align(n,a):return (n+a-1)//a*a
def make_section(kind,body):
    n=len(body)+4
    return (n.to_bytes(3,'little')+bytes([kind])+body) if n<0xffffff else b'\xff'*3+bytes([kind])+struct.pack('<I',len(body)+8)+body
def sections(blob):
    out=[];p=0
    while p<len(blob):
        if len(blob)-p<4:assert not any(blob[p:]);break
        n=u24(blob[p:]);h=4
        if n==0xffffff:n=struct.unpack_from('<I',blob,p+4)[0];h=8
        assert n>=h and p+n<=len(blob),(p,n,len(blob))
        out.append((blob[p+3],blob[p+h:p+n],blob[p:p+n]))
        end=p+n;p=align(end,4);assert not any(blob[end:p])
    return out
def pack_sections(parts):
    b=b''
    for i,part in enumerate(parts):
        b+=part
        if i+1<len(parts):b+=bytes((-len(b))%4)
    return b
def guided(plain):
    cache=P/'compression';cache.mkdir(exist_ok=True)
    source=cache/(sha(plain)+'.bin');dest=source.with_suffix('.lzma');source.write_bytes(plain)
    subprocess.run([str(P/'host-lzma/encode.exe'),str(source),str(dest)],check=True)
    z=dest.read_bytes();assert struct.unpack_from('<Q',z,5)[0]==len(plain)
    assert lzma.decompress(z,format=lzma.FORMAT_ALONE)==plain
    assert len(z)+24<0xffffff
    return make_section(2,LZMA_GUID+struct.pack('<HH',24,1)+z)
def rebuild_file(old,body):
    h=bytearray(old[:24]);assert h[19]==0 and h[23]==0xf8
    h[20:23]=(24+len(body)).to_bytes(3,'little');h[16]=0;h[17]=0xaa
    h[16]=(-(sum(h[:16])+sum(h[18:23])))&255
    return bytes(h)+body
def files(fv):
    assert fv[40:44]==b'_FVH';assert struct.unpack_from('<Q',fv,32)[0]==len(fv)
    header=struct.unpack_from('<H',fv,48)[0]
    assert not sum(struct.unpack('<'+'H'*(header//2),fv[:header]))&0xffff
    p=align(header,8);out=[]
    while p+24<=len(fv) and fv[p:p+24]!=b'\xff'*24:
        h=fv[p:p+24];n=u24(h[20:]);assert h[19]==0 and 24<=n<0xffffff and p+n<=len(fv)
        assert (sum(h[:17])+sum(h[18:23]))&255==0 and h[17]==0xaa and h[23]==0xf8
        out.append(dict(offset=p,guid=str(uuid.UUID(bytes_le=h[:16])),data=fv[p:p+n]))
        end=p+n;p=align(end,8);assert fv[end:p]==b'\xff'*(p-end)
    assert fv[p:]==b'\xff'*(len(fv)-p)
    return out,p
def pack_fv(original,replacements,extra=()):
    old,old_end=files(original);header=struct.unpack_from('<H',original,48)[0]
    out=original[:align(header,8)];offsets=[]
    for item in old:
        data=replacements.get(item['guid'],item['data']);offsets.append(dict(guid=item['guid'],old=item['offset'],new=len(out),bytes=len(data)))
        out+=data;out+=b'\xff'*((-len(out))%8)
    for data in extra:out+=data;out+=b'\xff'*((-len(out))%8)
    used=len(out);assert used<=len(original),(used,len(original))
    out+=b'\xff'*(len(original)-used)
    new,_=files(out);assert len(new)==len(old)+len(extra)
    for a,b in zip(old,new):
        assert a['guid']==b['guid']
        if a['guid'] not in replacements:assert a['data']==b['data']
    return out,dict(old_free=len(original)-old_end,new_free=len(original)-used,files=len(new),offsets=offsets)
def main():
    original=ORIGINAL.read_bytes();assert sha(original)=='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
    meta=json.loads((P/'native-verification.json').read_text());assert meta['passed']
    inv=next(iter(json.loads((OFFICIAL/'inventory.json').read_text()).values()))
    setup_path=ROOT/next(x['path'] for x in inv if x['guid'].lower()==SETUP)
    inner_path=setup_path.parent
    inner=(inner_path/'header.bin').read_bytes()+(inner_path/'body.bin').read_bytes()
    old_files,_=files(inner);by_guid={x['guid']:x['data'] for x in old_files};assert len(by_guid)==len(old_files)
    original_setup=sections(by_guid[SETUP][24:]);assert [x[0] for x in original_setup]==[0x13,0x10,0x14]
    replacement_pe=(P/'Setup-P5-RESOURCE-REVIEW.efi').read_bytes()
    new_setup=rebuild_file(by_guid[SETUP],pack_sections([original_setup[0][2],guided(make_section(0x10,replacement_pe)),original_setup[2][2]]))
    old_spf=sections(by_guid[SPF][24:]);assert len(old_spf)==1 and old_spf[0][0]==2
    assert old_spf[0][1][:16]==LZMA_GUID
    spf_sections=sections(lzma.decompress(old_spf[0][1][20:],format=lzma.FORMAT_ALONE))
    assert [x[0] for x in spf_sections]==[0x18,0x15]
    assert spf_sections[0][1][:16]==uuid.UUID(SPF).bytes_le
    new_spf=rebuild_file(by_guid[SPF],guided(pack_sections([make_section(0x18,spf_sections[0][1][:16]+(P/'AMITSESetupData-P5.bin').read_bytes()),spf_sections[1][2]])))
    rebuilt_inner,inner_info=pack_fv(inner,{SETUP:new_setup,SPF:new_spf})
    outer=original[BASE:BASE+LENGTH];outer_files,_=files(outer)
    item=next(x for x in outer_files if x['guid']=='9e21fd93-9c72-4c15-8c4b-e77f1db2d792')
    wrapper=item['data'];outer_guid=item['guid'];s=sections(wrapper[24:]);assert len(s)==1 and s[0][0]==2 and s[0][1][:16]==LZMA_GUID
    unpacked=lzma.decompress(s[0][1][20:],format=lzma.FORMAT_ALONE);items=sections(unpacked)
    assert len(items)==2 and items[1][0]==0x17 and items[1][1]==inner
    new_wrapper=rebuild_file(wrapper,guided(pack_sections([items[0][2],make_section(0x17,rebuilt_inner)])))
    driver=(P/'HeroIpmiNativeP5.ffs').read_bytes();assert str(uuid.UUID(bytes_le=driver[:16]))==DRIVER
    rebuilt_outer,outer_info=pack_fv(outer,{outer_guid:new_wrapper},[driver])
    candidate=original[:BASE]+rebuilt_outer+original[BASE+LENGTH:]
    assert len(candidate)==len(original) and candidate[:BASE]==original[:BASE] and candidate[BASE+LENGTH:]==original[BASE+LENGTH:]
    # FIT includes microcode entries and a TXT policy entry. No Boot Guard
    # ACM/KM/BPM entries in this vendor file. This is not a live fuse check.
    fitptr=struct.unpack_from('<Q',original,len(original)-0x40)[0];fitoff=fitptr-(0x100000000-(len(original)-0x1000))+0x1000
    assert original[fitoff:fitoff+8]==b'_FIT_   '
    count=u24(original[fitoff+8:]);fit=original[fitoff:fitoff+count*16]
    assert candidate[fitoff:fitoff+count*16]==fit
    fits=[]
    for i in range(count):
        entry=fit[i*16:(i+1)*16];fits.append(dict(address=hex(struct.unpack_from('<Q',entry)[0]),type=entry[14]&127,checksum_valid_bit=bool(entry[14]&128)))
    out=P/'candidate';out.mkdir(exist_ok=True)
    destination=out/'HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP';destination.write_bytes(candidate)
    (P/'P5-inner-fv.bin').write_bytes(rebuilt_inner)
    report=dict(version='P5 RC1 TEST CANDIDATE',hardware_validated=False,official_asus_release=False,original_sha256=sha(original),candidate_sha256=sha(candidate),candidate_bytes=len(candidate),changed_container=dict(offset=hex(BASE),length=hex(LENGTH)),outside_container_byte_identical=True,original_capsule_header_preserved=True,asus_signature_valid_for_modified_payload=False,ffs_changes=[SETUP,SPF,outer_guid],added_ffs=DRIVER,inner=inner_info,outer=outer_info,fit_entries=fits,boot_guard_note='No ACM/KM/BPM FIT entry in original image; live platform enforcement not determined.',limitations=['Native menu rendering and cold/warm boot are not hardware validated.','Only read-only BMC state; no LAN/watchdog/SEL configuration setters.','ASUS update/FlashBack acceptance of modified capsule is unverified.','Official recovery CAP is not a board-specific SPI backup.'])
    (P/'candidate-build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('inner','outer')},indent=2))
if __name__=='__main__':main()
