"""Independent read-only audit of the two SECTIONFIX candidate containers.

Does not import the builder or its parsing helpers. Does not rebuild candidates,
execute firmware, access a BMC, or write outside this audit directory.
"""
from pathlib import Path
import hashlib
import json
import lzma
import struct
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
FV_OFFSET=0x12d1000
FV_SIZE=0x9f0000
CAP_BYTES=33558528
WRAPPER='9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
LZMA_GUID='ee4e5898-3914-4259-9d6e-dc7bd79403cf'
TARGETS={'89924765-f984-4ad3-839b-51fdce378d88':'R2',
         '261135b0-7b73-49c0-bcc8-2f9cf4eef19e':'P6'}
INPUTS=[
 ('observed','analysis/hero_ipmi_p6_20261104/review-20261108/container-441b61136974/P6-RC4.CAP',
  '441b61136974278a0c6fc0d46edc159c1f1557c981ae9e4a4b42b67eb65fba0f',
  '7fd2648b6d3d82aa83c8c9936260c15eb4d1f8f65cdf745b8ec53ee07d914f2a'),
 ('latest','analysis/hero_ipmi_p6_20261104/firmware/HERO-3107-IPMI-P6-R2-RC4-UNSIGNED.CAP',
  '44256d23a952234e99bb81743bdcca28a5472a6406eceb18a82a82667b7dcff5',
  '66420b42a5251a1209cac9865d3a1d8d5f1e03e512b4b9ce98ba0d29b81be131')]


def sha(data): return hashlib.sha256(data).hexdigest()
def align(value, amount): return (value+amount-1)&~(amount-1)
def u24(data): return int.from_bytes(data[:3],'little')
def guid(data): return str(uuid.UUID(bytes_le=data[:16]))


def volume(data):
    assert len(data)>=64 and data[40:44]==b'_FVH'
    length=struct.unpack_from('<Q',data,32)[0]
    header=struct.unpack_from('<H',data,48)[0]
    attrs=struct.unpack_from('<I',data,44)[0]
    assert length==len(data) and 56<=header<=len(data) and header%2==0
    assert sum(struct.unpack('<'+'H'*(header//2),data[:header]))&65535==0
    assert attrs&0x800  # these existing volumes use erase polarity 1
    block=56;block_bytes=0
    while True:
        assert block+8<=header
        count,size=struct.unpack_from('<II',data,block);block+=8
        if not count and not size: break
        assert count and size
        block_bytes+=count*size
    assert block_bytes==len(data)
    cursor=align(header,8);items=[]
    while cursor+24<=len(data) and data[cursor:cursor+24]!=b'\xff'*24:
        h=data[cursor:cursor+24];size=u24(h[20:23]);attr=h[19]
        assert 24<=size<0xffffff and not attr&1  # no large-file header in these fixed inputs
        assert cursor+size<=len(data)
        assert (sum(h)-h[17]-h[23])&255==0
        assert h[23]==0xf8
        body=data[cursor+24:cursor+size]
        if attr&0x40: assert (sum(body)+h[17])&255==0
        else: assert h[17]==0xaa
        items.append({'guid':guid(h),'offset':cursor,'header':h,'body':body,'raw':data[cursor:cursor+size]})
        next_offset=align(cursor+size,8)
        assert data[cursor+size:next_offset]==b'\xff'*(next_offset-cursor-size)
        cursor=next_offset
    assert data[cursor:]==b'\xff'*(len(data)-cursor)
    assert len({x['guid'] for x in items})==len(items)
    return {'header':data[:align(header,8)],'items':items,'files':{x['guid']:x for x in items},
            'free_bytes':len(data)-cursor,'filesystem_guid':guid(data[16:32])}


def sections(data, allow_last_two=False):
    cursor=0;items=[]
    while True:
        assert cursor+4<=len(data),(cursor,len(data))
        length=u24(data[cursor:]);head=4
        if length==0xffffff:
            assert cursor+8<=len(data);head=8;length=struct.unpack_from('<I',data,cursor+4)[0]
        assert head<=length and cursor+length<=len(data)
        end=cursor+length
        items.append({'type':data[cursor+3],'head':head,'offset':cursor,
                      'raw':data[cursor:end],'body':data[cursor+head:end]})
        if end==len(data): return items, True
        if allow_last_two and len(data)-end==2 and data[end:]==b'\0\0':return items,False
        nxt=align(end,4)
        assert nxt<len(data) and data[end:nxt]==b'\0'*(nxt-end),(end,nxt,len(data))
        cursor=nxt


def open_wrapper(item):
    outer,strict=sections(item['body']);assert strict and len(outer)==1 and outer[0]['type']==2
    s=outer[0];assert guid(s['body'])==LZMA_GUID
    data_offset,attrs=struct.unpack_from('<HH',s['body'],16)
    assert data_offset==s['head']+20 and attrs==1
    compressed=s['raw'][data_offset:]
    declared=struct.unpack_from('<Q',compressed,5)[0]
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    unpacked=decoder.decompress(compressed)
    assert decoder.eof and not decoder.unused_data and len(unpacked)==declared
    stream,strict=sections(unpacked);assert strict and len(stream)==2 and stream[1]['type']==0x17
    return stream,volume(stream[1]['body'])


def pe_info(data):
    assert data[:2]==b'MZ' and len(data)>=0x40
    pe=struct.unpack_from('<I',data,0x3c)[0];assert pe+24<=len(data) and data[pe:pe+4]==b'PE\0\0'
    machine,count=struct.unpack_from('<HH',data,pe+4)
    optional=struct.unpack_from('<H',data,pe+20)[0]
    assert machine==0x8664 and count and pe+24+optional+40*count<=len(data)
    off=pe+24;assert struct.unpack_from('<H',data,off)[0]==0x20b
    entry=struct.unpack_from('<I',data,off+16)[0]
    subsystem=struct.unpack_from('<H',data,off+68)[0]
    assert subsystem==11  # EFI boot services driver
    executable_entry=False
    for i in range(count):
        s=pe+24+optional+i*40
        vs,va,rawsize,rawptr=struct.unpack_from('<IIII',data,s+8)
        chars=struct.unpack_from('<I',data,s+36)[0]
        if rawsize:assert rawptr+rawsize<=len(data)
        if chars&0x20000000 and va<=entry<va+max(vs,rawsize):executable_entry=True
    assert executable_entry
    return {'machine':'x86_64','subsystem':subsystem,'entry_rva':hex(entry),'sections':count,
            'bytes':len(data),'sha256':sha(data)}


reports=[]
for name,rel,old_sha,new_sha in INPUTS:
    candidate=ROOT/f'analysis/hero_ipmi_sectionfix_20261108/candidate-{name}/HERO-3107-IPMI-SECTIONFIX-{name.upper()}-UNSIGNED.CAP'
    old=(ROOT/rel).read_bytes();new=candidate.read_bytes()
    assert sha(old)==old_sha and sha(new)==new_sha
    assert len(old)==len(new)==CAP_BYTES
    assert old[:FV_OFFSET]==new[:FV_OFFSET] and old[FV_OFFSET+FV_SIZE:]==new[FV_OFFSET+FV_SIZE:]
    assert old[:0x1000]==new[:0x1000]
    ov=volume(old[FV_OFFSET:FV_OFFSET+FV_SIZE]);nv=volume(new[FV_OFFSET:FV_OFFSET+FV_SIZE])
    assert ov['header']==nv['header'] and list(ov['files'])==list(nv['files'])
    outer_changed=[g for g in ov['files'] if ov['files'][g]['raw']!=nv['files'][g]['raw']]
    assert outer_changed==[WRAPPER]
    os,oi=open_wrapper(ov['files'][WRAPPER]);ns,ni=open_wrapper(nv['files'][WRAPPER])
    assert os[0]['raw']==ns[0]['raw'] and oi['header']==ni['header']
    assert list(oi['files'])==list(ni['files'])
    changed=[g for g in oi['files'] if oi['files'][g]['raw']!=ni['files'][g]['raw']]
    assert set(changed)==set(TARGETS)
    details={}
    for g,label in TARGETS.items():
        a=oi['files'][g];b=ni['files'][g]
        assert a['body']==b['body']+b'\0\0' and len(a['raw'])==len(b['raw'])+2
        header_delta=[i for i in range(24) if a['header'][i]!=b['header'][i]]
        assert all(i in (16,20,21,22) for i in header_delta)
        before,before_valid=sections(a['body'],allow_last_two=True)
        after,after_valid=sections(b['body'])
        assert not before_valid and after_valid and [s['type'] for s in after]==[0x13,0x10,0x15]
        assert len(before)==len(after) and all(x['raw']==y['raw'] for x,y in zip(before,after))
        assert b['raw']==(candidate.parent/f'{label}-sectionfix.ffs').read_bytes()
        details[label]={'guid':g,'old_ffs_bytes':len(a['raw']),'new_ffs_bytes':len(b['raw']),
                        'old_ffs_sha256':sha(a['raw']),'new_ffs_sha256':sha(b['raw']),
                        'old_strict_section_end':before_valid,'new_strict_section_end':after_valid,
                        'header_checksum_valid':True,'file_checksum_mode':'fixed AA; checksum flag unset',
                        'changed_header_offsets':header_delta,'all_section_bytes_identical':True,
                        'removed_final_bytes':'0000','pe':pe_info(after[1]['body']),
                        'depex_bytes':len(after[0]['body']),'depex_sha256':sha(after[0]['body']),
                        'ui_bytes':len(after[2]['body']),'ui_sha256':sha(after[2]['body'])}
    reports.append({'variant':name,'input':rel,'input_sha256':old_sha,
                    'candidate':str(candidate.relative_to(ROOT)),'candidate_sha256':new_sha,
                    'capsule_bytes':len(new),'dxe_span':{'offset':hex(FV_OFFSET),'bytes':hex(FV_SIZE)},
                    'outside_dxe_and_capsule_header_byte_identical':True,
                    'outer_fv_header_checksum_valid':True,'inner_fv_header_checksum_valid':True,
                    'outer_files':len(ov['files']),'inner_files':len(oi['files']),
                    'outer_changed_guids':outer_changed,'inner_changed_guids':changed,
                    'all_unrelated_ffs_bytes_identical':True,'all_ffs_header_checksums_valid':True,
                    'compressed_stream_exact_roundtrip':True,
                    'details':details,'offline_checks_passed':True,
                    'hardware_boot_or_flash_validated_by_this_audit':False,
                    'ASUS_signature_revalidated':False,'new_automatic_inventory_code':False})
result={'audit':'independent structural parser; no builder imports or candidate mutation',
        'script_sha256':sha(Path(__file__).read_bytes()),'passed':True,'variants':reports,
        'limitations':['Structural acceptance does not prove DXE dispatch or boot on hardware.',
                       'Modified capsules are not newly ASUS signed.',
                       'No automatic System Inventory uploader was added by this padding repair.']}
(HERE/'independent-sectionfix-review.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'passed':True,'variants':[{k:r[k] for k in ('variant','candidate_sha256','outer_files','inner_files','offline_checks_passed')} for r in reports]},indent=2))
