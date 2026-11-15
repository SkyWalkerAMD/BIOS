"""Offline, byte-bound module inventory from ACE1904 original DXE container.

Writes only this review directory. Does not execute a firmware module.
"""
from pathlib import Path
import hashlib, json, lzma, re, struct, uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / 'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
SHA = '03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
LZMA = uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf')

def sha(b): return hashlib.sha256(b).hexdigest()
def align(n, a): return (n+a-1)&~(a-1)
def sections(b, origin, level=0):
    assert level < 8
    found=[]; p=0
    while p+4<=len(b) and b[p:p+4]!=b'\xff'*4:
        size=int.from_bytes(b[p:p+3],'little');kind=b[p+3];hdr=4
        if size==0xffffff: size=struct.unpack_from('<I',b,p+4)[0];hdr=8
        assert size>=hdr and p+size<=len(b),(origin,p,size,len(b))
        payload=b[p+hdr:p+size]
        ref={'container':origin,'section_offset':p,'section_type':kind,'section_size':size,'payload_sha256':sha(payload)}
        if kind==0x15: found.append(('ui',payload.decode('utf-16le').rstrip('\0'),ref))
        elif kind==0x10: found.append(('pe',payload,ref))
        elif kind==2:
            g=uuid.UUID(bytes_le=b[p+hdr:p+hdr+16]);off=struct.unpack_from('<H',b,p+hdr+16)[0]
            if g==LZMA:
                packed=b[p+off:p+size];raw=lzma.decompress(packed,format=lzma.FORMAT_ALONE)
                found+=sections(raw,ref,level+1)
            else: found.append(('unhandled_guid',str(g),ref))
        p=align(p+size,4)
    return found

def main():
    source=SOURCE.read_bytes(); assert sha(source)==SHA
    reference=ROOT/'analysis/aitweaker_lock/lock_w890_sage/release_review/checked_modules.json'
    names_by_guid={m['guid'].lower():m['name'] for m in json.loads(reference.read_text(encoding='utf8'))['modules'] if m.get('name')}
    container=0x3181078; sec=container+24; sec_size=int.from_bytes(source[sec:sec+3],'little')
    raw=lzma.decompress(source[sec+24:sec+sec_size],format=lzma.FORMAT_ALONE)
    inner=16;assert raw[inner+40:inner+44]==b'_FVH'
    length=struct.unpack_from('<Q',raw,inner+32)[0];hdr=struct.unpack_from('<H',raw,inner+48)[0]
    p=align(inner+hdr,8);items=[];selected=[]
    target=HERE/'native_inputs';target.mkdir(exist_ok=True)
    while p+24<=inner+length and raw[p:p+24]!=b'\xff'*24:
        size=int.from_bytes(raw[p+20:p+23],'little');guid=str(uuid.UUID(bytes_le=raw[p:p+16]));kind=raw[p+18]
        assert 24<=size and p+size<=inner+length
        ss=sections(raw[p+24:p+size],{'inner_offset':p,'ffs_guid':guid}) if kind not in (0x01,0xf0) else []
        names=[v for k,v,_ in ss if k=='ui'];pes=[(v,r) for k,v,r in ss if k=='pe']
        item={'guid':guid,'inner_offset':p,'ffs_bytes':size,'ffs_sha256':sha(raw[p:p+size]),'names':names,'pe_count':len(pes)}
        items.append(item)
        reference_name=names_by_guid.get(guid,'')
        if any(re.search('Fmp|Firmware|SecureFlash|Capsule|FwUpdate|FlashUpdate|EzFlash|SMIFlash|Flash|Crypto',n,re.I) for n in names+[reference_name]):
            for i,(pe,ref) in enumerate(pes):
                name=re.sub('[^A-Za-z0-9_-]','_',names[0] if names else reference_name);path=target/f'{name}-{guid[:8]}-{i}.efi';path.write_bytes(pe)
                selected.append({**item,'reference_name_from_W890_GUID':reference_name,'reference_name_is_not_byte_identity':True,'pe_path':str(path.relative_to(ROOT)),'pe_sha256':sha(pe),'pe_bytes':len(pe),'derivation':ref})
        p=align(p+size,8)
    report={'source':str(SOURCE.relative_to(ROOT)),'source_sha256':SHA,'scope':'Only original main DXE FV; other original FVs not enumerated here. Most ACE UI names are stripped; selected reference names come from same GUID in W890 inventory and do not establish identical behavior.','name_reference_sha256':sha(reference.read_bytes()),'outer_container_offset':container,'decompressed_sha256':sha(raw),'module_count':len(items),'all_modules':items,'selected_modules':selected}
    (HERE/'ace_update_module_inventory.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'module_count':len(items),'selected_modules':selected},indent=2))

if __name__=='__main__':main()
