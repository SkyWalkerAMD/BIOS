"""Strict offline ASUS W790-ACE 1904 review candidate builder.

Outputs retain the original 4096-byte signed capsule header. Its signature is
INVALID after payload modification. No signing, authentication bypass, flashing,
physical BIOS access, or hardware-boot compatibility claim is provided.

The nested DXE FV can grow only at its tail. The recompressed container must fit
within its original allocation; every other outer FFS remains at the same offset.
"""
from pathlib import Path
import argparse,hashlib,json,lzma,struct,uuid
from inject_ovmf import OUT,ROOT,digest,ffs_for_driver,valid_fv,find_free
SOURCE=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
SOURCE_SHA='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
GUID=uuid.UUID('97f9cf3d-1209-4c68-a827-e547d0531904')
OUTER=0x3181000;CONTAINER=0x3181078;SECTION=CONTAINER+24;INNER=0x10
FILTER={'id':lzma.FILTER_LZMA1,'dict_size':1<<24,'lc':3,'lp':0,'pb':2,'mode':lzma.MODE_NORMAL,'mf':lzma.MF_BT4,'nice_len':273}
def align(n,a):return (n+a-1)&~(a-1)
def ffs_header(old,body,kind=None):
    h=bytearray(old);assert len(h)==24
    if kind is not None:h[18]=kind
    h[20:23]=(24+len(body)).to_bytes(3,'little');h[16]=h[17]=0;state=h[23];h[23]=0;h[16]=(-sum(h))&255;h[17]=((-sum(body))&255) if h[19]&0x40 else 0xaa;h[23]=state
    assert (sum(h)-h[17]-h[23])&255==0
    return bytes(h)
def padding_file(size):
    assert size>=24 and size%8==0
    h=uuid.UUID(int=(1<<128)-1).bytes_le+b'\0\0'+bytes([0xf0,0])+b'\0'*3+b'\xf8'
    body=b'\xff'*(size-24);return ffs_header(h,body)+body
def validate_ffs(data,p,n):
    h=data[p:p+24];size=int.from_bytes(h[20:23],'little');assert 24<=size<=n
    assert (sum(h)-h[17]-h[23])&255==0,(hex(p),'header checksum')
    if h[19]&0x40:assert (sum(data[p+24:p+size])+h[17])&255==0,(hex(p),'data checksum')
    else:assert h[17]==0xaa
def build(driver,output,fixture=False):
    output=Path(output).resolve();assert output.is_relative_to(OUT) and output.name.endswith('.review.bin')
    source=SOURCE.read_bytes();assert digest(source)==SOURCE_SHA and len(source)==0x4001000
    data=Path(driver).read_bytes();assert data[:2]==b'MZ'
    outer_size,_=valid_fv(source,OUTER);assert outer_size==0x59f000
    original_free,outer_available,outer_files=find_free(source,OUTER)
    original_size=int.from_bytes(source[CONTAINER+20:CONTAINER+23],'little');assert original_size==0x36bba0
    assert uuid.UUID(bytes_le=source[CONTAINER:CONTAINER+16])==uuid.UUID('9e21fd93-9c72-4c15-8c4b-e77f1db2d792')
    sec_size=int.from_bytes(source[SECTION:SECTION+3],'little');sec_header=source[SECTION:SECTION+24]
    assert sec_header[3]==2 and uuid.UUID(bytes_le=sec_header[4:20])==uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf')
    assert sec_header[20:24]==b'\x18\0\x01\0'
    raw=lzma.decompress(source[SECTION+24:SECTION+sec_size],format=lzma.FORMAT_ALONE)
    assert raw[:12]==bytes.fromhex('0800001900000000ffffff17')
    old_fv_size,header_size=valid_fv(raw,INNER);assert old_fv_size==0x11c6000
    assert len(raw)==old_fv_size+16
    assert uuid.UUID(bytes_le=raw[INNER+0x60:INNER+0x70])==uuid.UUID('5c60f367-a505-419a-859e-2a4ff6ca6fe5')
    free,available,files=find_free(raw,INNER)
    ffs=ffs_for_driver(data,GUID,'FIXTURE ONLY - NOT LOCK' if fixture else 'AiTweaker Lock W790 ACE 1904')
    blocks,block_size=struct.unpack_from('<II',raw,INNER+56);assert blocks*block_size==old_fv_size and block_size==0x1000
    extra=align(max(0,len(ffs)-available),block_size)
    modified=bytearray(raw+b'\xff'*extra);assert modified[free:free+len(ffs)]==b'\xff'*len(ffs)
    modified[free:free+len(ffs)]=ffs
    struct.pack_into('<I',modified,12,len(modified)-8)
    struct.pack_into('<Q',modified,INNER+32,old_fv_size+extra)
    struct.pack_into('<I',modified,INNER+56,blocks+extra//block_size)
    modified[INNER+50:INNER+52]=b'\0\0';checksum=(-sum(struct.unpack('<'+'H'*(header_size//2),modified[INNER:INNER+header_size])))&65535
    struct.pack_into('<H',modified,INNER+50,checksum);valid_fv(modified,INNER)
    for f in files:
        p=int(f['offset'],16);assert digest(modified[p:p+f['size']])==f['sha256'];validate_ffs(modified,p,f['size'])
    validate_ffs(modified,free,len(ffs));assert modified[free+len(ffs):]==b'\xff'*(len(modified)-free-len(ffs))
    packed=lzma.compress(bytes(modified),format=lzma.FORMAT_ALONE,filters=[FILTER]);packed=packed[:5]+len(modified).to_bytes(8,'little')+packed[13:]
    assert lzma.decompress(packed[13:],format=lzma.FORMAT_RAW,filters=[FILTER])==modified
    sh=bytearray(sec_header);sh[:3]=(24+len(packed)).to_bytes(3,'little');body=bytes(sh)+packed
    replacement=ffs_header(source[CONTAINER:CONTAINER+24],body)+body
    needed=align(len(replacement),8);padding=original_size-needed
    if padding<24:
        raise ValueError(f'Recompressed container cannot safely fit original slot: required {needed}+24, available {original_size}. Original files will not be moved.')
    replacement+=b'\xff'*(needed-len(replacement))+padding_file(padding)
    assert len(replacement)==original_size
    result=source[:CONTAINER]+replacement+source[CONTAINER+original_size:]
    assert result[:CONTAINER]==source[:CONTAINER] and result[CONTAINER+original_size:]==source[CONTAINER+original_size:]
    assert result[:4096]==source[:4096] and len(result)==len(source)
    valid_fv(result,OUTER);validate_ffs(result,CONTAINER,len(body)+24);validate_ffs(result,CONTAINER+needed,padding)
    for f in outer_files:
        p=int(f['offset'],16)
        if p!=CONTAINER:assert digest(result[p:p+f['size']])==f['sha256']
    output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(result)
    report={'purpose':'REVIEW ONLY; NOT A FLASH PACKAGE','fixture_only':fixture,'source_capsule_sha256':SOURCE_SHA,'candidate_sha256':digest(result),'source_capsule':str(SOURCE),'candidate':str(output),'contains_original_4096_byte_signed_capsule_header':True,'capsule_signature_valid':False,'signature_note':'Original signature bytes are preserved but no longer authenticate the changed payload. No signing or authentication bypass performed.','hardware_boot_compatibility':'UNKNOWN','boot_guard_coverage':'UNKNOWN; no key or measured/verified boot assumptions','driver':str(Path(driver).resolve()),'driver_sha256':digest(data),'driver_ffs_guid':str(GUID),'driver_ffs_bytes':len(ffs),'inner_fv_original_bytes':old_fv_size,'inner_fv_new_bytes':old_fv_size+extra,'inner_free_original_bytes':available,'inner_tail_growth_bytes':extra,'original_inner_ffs_count_unchanged':len(files),'original_inner_ffs_offsets_preserved':True,'original_inner_ffs_bytes_preserved':True,'outer_original_ffs_count':len(outer_files),'outer_other_ffs_bytes_offsets_preserved':True,'outer_container_offset':hex(CONTAINER),'outer_container_original_allocation':original_size,'outer_container_new_ffs_size':24+len(body),'outer_slot_padding_ffs_bytes':padding,'outer_erase_area_unused_bytes':outer_available,'all_bytes_outside_original_container_allocation_preserved':True,'depex':['EFI_VARIABLE_ARCH_PROTOCOL','EFI_VARIABLE_WRITE_ARCH_PROTOCOL','AND','END'],'compressor':'Python LZMA1 16MiB BT4 nice_len273 with explicit EDK2 output size; RAW roundtrip verified','independent_uefiextract_validation':'PENDING until verify_asus_review.py is run'}
    output.with_suffix('.json').write_text(json.dumps(report,indent=2),encoding='utf8');return report
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--driver',type=Path,default=OUT.parent/'driver/build/AiTweakerLock1904.efi');p.add_argument('--output',type=Path,default=OUT/'asus_review/W790-ACE-1904-lock.review.bin');p.add_argument('--fixture',action='store_true');a=p.parse_args();print(json.dumps(build(a.driver,a.output,a.fixture),indent=2))
