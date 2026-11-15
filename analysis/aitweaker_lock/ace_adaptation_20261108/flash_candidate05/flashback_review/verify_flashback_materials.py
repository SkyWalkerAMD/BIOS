"""Verify FlashBack package materials and exact original EC inputs, offline only."""
from pathlib import Path
import hashlib
import json
import lzma
import struct
import uuid

BASE=Path(__file__).resolve().parent
CASE=BASE.parent
ROOT=next(p for p in BASE.parents if (p/'tools/pydeps').is_dir())
sha=lambda b:hashlib.sha256(b).hexdigest()


def ref(p):
    b=p.read_bytes()
    return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':sha(b)}


def write(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf8')


def main():
    checks=[]
    def check(v,label):
        assert v,label
        checks.append(label)
    paths={
      'official':ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP',
      'candidate_original_header':CASE/'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin',
      'candidate_engineering_header':CASE/'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'}
    expected={'official':'03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29',
      'candidate_original_header':'9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455',
      'candidate_engineering_header':'e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08'}
    raw={k:p.read_bytes() for k,p in paths.items()}
    formats={}
    metadata=(BASE/'inputs/ASUS_USBFLASHBACK-BB3BF734.bin').read_bytes()
    for name,b in raw.items():
        check(sha(b)==expected[name],name+' immutable CAP identity')
        check(len(b)==0x4001000 and struct.unpack_from('<I',b,0x10)[0]==0x1000 and struct.unpack_from('<I',b,0x18)[0]==len(b),name+' full CAP length, declared header and total length')
        check(b[:16]==raw['official'][:16],name+' capsule GUID equals official')
        check(b[0x3ff1014:0x3ff1014+62]==metadata,name+' exact original USBFLASH metadata')
        check(b[0x3ecd7ed:0x3ecd7ed+12]==b'PWW790A.CAP\0',name+' exact BIOSRenamer filename field')
        formats[name]={'file':ref(paths[name]),'CAP_header_bytes':0x1000,'payload_bytes':0x4000000,
                       'payload_sha256':sha(b[0x1000:]),'capsule_guid':str(uuid.UUID(bytes_le=b[:16])),
                       'flashback_filename':'PWW790A.CAP','filename_CAP_offset':'0x3ecd7ed',
                       'usbflashback_metadata_CAP_offset':'0x3ff1014','usbflashback_metadata_sha256':sha(metadata)}
    check(raw['candidate_original_header'][:4096]==raw['official'][:4096],'chosen candidate preserves every original header byte')
    check(raw['candidate_original_header'][4096:]==raw['candidate_engineering_header'][4096:],'two modified CAPs have byte-identical candidate05 payload')
    check(sha(raw['candidate_original_header'][4096:])=='2dd240c1ddb8890500ce028bb7de25d2db8f687117f4c0d2a57ba400ffbe9809','candidate05 payload exact identity')
    allowed=[(0x48,0x248),(0x258,0x458)]
    hdif=[i for i,(a,b) in enumerate(zip(raw['candidate_original_header'][:4096],raw['candidate_engineering_header'][:4096])) if a!=b]
    check(all(any(s<=i<e for s,e in allowed) for i in hdif),'engineering variant changes only the two RSA modulus/signature pairs within header')

    # Recover the exact selected input files from the immutable official CAP,
    # not from the existing dump alone. Also show their preservation in05.
    decoder_notes=[]
    def expand_lzma(packed):
        try:return lzma.decompress(packed,format=lzma.FORMAT_ALONE)
        except lzma.LZMAError:
            # The already-reviewed05 builder explicitly encodes a known output
            # length while retaining EOS. liblzma ALONE rejects that combination;
            # decode the unchanged stream as RAW and check both EOS and length.
            props=packed[0];lc=props%9;v=props//9;lp=v%5;pb=v//5
            length=int.from_bytes(packed[5:13],'little')
            check(props<225 and length<0x4000000,'bounded known-size guided LZMA properties')
            dec=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':int.from_bytes(packed[1:5],'little'),'lc':lc,'lp':lp,'pb':pb}])
            result=dec.decompress(packed[13:])
            check(dec.eof and not dec.unused_data and len(result)==length,'known-size/EOS stream RAW decode exact output length and end')
            decoder_notes.append('Used documented05 known-size+EOS RAW decoder; host ALONE rejection is not a firmware rejection. Existing independent UEFIExtract/VM validation is not rerun here.')
            return result
    def main_dxe(b):
        sec=0x3181078+24
        size=int.from_bytes(b[sec:sec+3],'little')
        check(b[sec+3]==2 and uuid.UUID(bytes_le=b[sec+4:sec+20])==uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf'),'main DXE guided-LZMA container identity')
        offset=struct.unpack_from('<H',b,sec+20)[0]
        return expand_lzma(b[sec+offset:sec+size])
    def leaves(b):
        off=0
        while off+4<=len(b):
            n=int.from_bytes(b[off:off+3],'little');kind=b[off+3]
            if n<4 or off+n>len(b):break
            if kind==2 and b[off+4:off+20]==uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le:
                delta=struct.unpack_from('<H',b,off+20)[0]
                yield from leaves(expand_lzma(b[off+delta:off+n]))
            else:yield kind,b[off+4:off+n]
            off=(off+n+3)&~3
    def ffs(expanded,guid):
        marker=uuid.UUID(guid).bytes_le
        offsets=[];cursor=0
        while True:
            i=expanded.find(marker,cursor)
            if i<0:break
            cursor=i+1
            n=int.from_bytes(expanded[i+20:i+23],'little')
            if n>=24 and i+n<=len(expanded) and expanded[i+18] in (2,7):offsets.append((i,n))
        check(len(offsets)==1,guid+' unique exact FFS header')
        i,n=offsets[0];return i,expanded[i:i+n]
    expanded={k:main_dxe(raw[k]) for k in ['official','candidate_original_header']}
    check(sha(expanded['official'])=='44870490759ccab9c94bfef90fe0430a151c4cdfe40e2eb2758ba30880172725','original expanded main DXE exact identity')
    ec=[]
    for guid,kind,file_name in [
        ('2cc919d9-5995-4f3f-9169-62301a6c72ac',0x10,'ECUpdateFramework-2CC919D9.efi'),
        ('38715e0a-ecd3-4776-8ac4-7d93510a7468',0x19,'MBEC-W790-0120-38715E0A.bin')]:
        off,original=ffs(expanded['official'],guid);new_off,new=ffs(expanded['candidate_original_header'],guid)
        check(original==new,guid+' complete original FFS preserved in candidate05')
        content=[data for t,data in leaves(original[24:]) if t==kind]
        check(len(content)==1,guid+' unique expected leaf section')
        p=BASE/'inputs'/file_name
        check(content[0]==p.read_bytes(),file_name+' exact original CAP-derived bytes')
        ec.append({'ffs_guid':guid,'original_inner_offset':hex(off),'candidate_inner_offset':hex(new_off),
                   'ffs_bytes':len(original),'ffs_sha256':sha(original),'input':ref(p),'original_and_candidate_ffs_identical':True})
    report={'status':'PASS_FLASHBACK_MATERIAL_FORMAT_AND_IDENTITY_ONLY','checks':len(checks),'check_names':checks,
            'variants':formats,'header_difference_byte_count_between_candidates':len(hdif),'EC_inputs':ec,
            'script':ref(Path(__file__)),'decoder_notes':decoder_notes,'no_controller_acceptance_claim':True,'no_hardware_access':True,
            'limit':'Format/metadata/unchanged-EC proofs do not establish the physical FlashBack controller signature policy or successful flash.'}
    write(BASE/'materials_validation.json',report)
    print(json.dumps({'checks':len(checks),'report':ref(BASE/'materials_validation.json')},ensure_ascii=False))


if __name__=='__main__':main()
