"""Replace only the pinned AMITSE firmware file, entirely in memory.

Other inner files retain their bytes and offsets. If the replacement does not
fit its old extent, that extent becomes a standards-defined erased PAD file and
the non-fixed AMITSE file is appended to the inner volume. The outer compressed
carrier keeps its original extent; no other outer file is moved. The result is
not saved or designated flashable. Platform dispatch is separately unproved.
"""
from pathlib import Path
import json, lzma, struct, uuid, sys
from merge_pe import HERE, BASE, ROOT, baseline, sha, need, align
sys.path.insert(0,str(BASE/'release_review'))
from validate_layout import read_fv, ffs_sequence
from lzma_known_size import encode as encode_known_size
from lzma_search05 import encode as encode_search

CAP_SHA='c7b12934cd0904a9cd4cfca53f656931bd5164e3bc30b99b043c2c2cb39a92d1'
TSE_GUID='b1da0adf-4f77-4070-a88e-bffe1c60529a'
LZMA_GUID=uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le

def sections(raw):
    """Final section needs no padding; any inter-section padding must be zero."""
    rows=[]; at=0
    while at<len(raw):
        need(at+4<=len(raw),'section header bounds')
        size=int.from_bytes(raw[at:at+3],'little');hs=4
        if size==0xffffff:
            need(at+8<=len(raw),'extended section header');size=struct.unpack_from('<I',raw,at+4)[0];hs=8
        need(hs<=size<=len(raw)-at,'section bounds')
        rows.append({'offset':at,'size':size,'header':hs,'type':raw[at+3]})
        end=at+size
        if end==len(raw):break
        at=align(end,4);need(at<=len(raw) and raw[end:at]==b'\0'*(at-end),'section alignment padding')
    return rows

def sec(kind,data):
    n=4+len(data);need(n<0xffffff,'bounded normal section')
    return n.to_bytes(3,'little')+bytes([kind])+data

def guided(uncompressed, original_header, dictionary=0x1000000,depth=0):
    need(len(original_header)==24 and original_header[3]==2 and original_header[4:20]==LZMA_GUID,
         'original GUID section')
    need(original_header[20:24]==bytes.fromhex('18000100'),'data offset and processing-required flag')
    compressed=encode_search(uncompressed,dictionary,depth)if depth else encode_known_size(uncompressed,dictionary)
    need(lzma.decompress(compressed,format=lzma.FORMAT_ALONE)==uncompressed,'LZMA exact roundtrip')
    header=bytearray(original_header);header[:3]=(24+len(compressed)).to_bytes(3,'little')
    return bytes(header)+compressed

def file_header(original,body):
    h=bytearray(original);need(len(h)==24 and not h[19]&1,'normal file header')
    n=24+len(body);need(n<0xffffff,'normal file size')
    h[20:23]=n.to_bytes(3,'little');h[17]=(-sum(body))&255 if h[19]&0x40 else 0xaa
    h[16]=0;h[16]=(-(sum(h)-h[17]-h[23]))&255
    return bytes(h)+body

def same_extent(header,new_guided,extent):
    end=align(len(new_guided),4);remaining=extent-24-end
    if remaining<4:return None
    body=new_guided+b'\0'*(end-len(new_guided))+sec(0x19,b'\xff'*(remaining-4))
    need(len(body)==extent-24,'carrier extent')
    return file_header(header,body)

def pad_file(size):
    need(24<=size<0xffffff,'pad file extent')
    # For FFS_PAD the file Name is not used for lookup; all data remains erased.
    h=bytearray(b'\xff'*16+b'\0\xaa\xf0\0'+size.to_bytes(3,'little')+b'\xf8')
    h[16]=(-(sum(h)-h[17]-h[23]))&255
    return bytes(h)+b'\xff'*(size-24)

def compose_fv(new_pe, expected_sha, inner_encoding='original_lzma',dictionary=0x1000000,depth=0):
    need(inner_encoding in ('original_lzma','plain_sections'),'reviewed inner section format')
    need(dictionary in (0x1000000,0x2000000),'bounded dictionary profile')
    need(depth in (0,512,2048,8192),'bounded encoder search depth')
    need(sha(new_pe)==expected_sha,'replacement PE identity')
    volumes=json.loads((BASE/'release_review/checked_dxe_volumes.json').read_text())['volumes']
    im=next(x for x in volumes if x['full_size']==0x1a42000)
    om=next(x for x in volumes if x['full_size']==0x630000)
    inner=read_fv(im);outer=read_fv(om)
    files,free=ffs_sequence(inner,im['header_size'])
    tse=next(x for x in files if x['guid']==TSE_GUID);start=tse['offset'];end=start+tse['size']
    original_ffs=inner[start:end];h=original_ffs[:24]
    need(h[18]==7 and h[19]==0 and h[23]==0xf8,'pinned non-fixed original DXE file attributes')
    original_guided=original_ffs[24:];parts=sections(original_guided)
    need(len(parts)==1 and parts[0]['type']==2,'one original guided section')
    original_payload=lzma.decompress(original_guided[24:],format=lzma.FORMAT_ALONE)
    leafs=sections(original_payload);need([x['type']for x in leafs]==[0x10,0x15],'AMITSE PE and UI sections')
    pe_section=leafs[0];need(original_payload[4:pe_section['size']]==baseline(),'original PE equals profile')
    tail=original_payload[leafs[1]['offset']:]
    new_payload=sec(0x10,new_pe);new_payload+=b'\0'*(align(len(new_payload),4)-len(new_payload));new_payload+=tail
    new_guided=guided(new_payload,original_guided[:24],dictionary,depth)if inner_encoding=='original_lzma'else None
    if new_guided is not None:replacement=same_extent(h,new_guided,tse['size']);new_body=new_guided
    else:
        new_body=new_payload;replacement=None
        need([x['type']for x in sections(new_body)]==[0x10,0x15],'direct PE32/UI sections')
        need(new_body[4:4+len(new_pe)]==new_pe,'direct PE identity')
    updated=bytearray(inner);appended=False;pad=None
    if replacement is not None:
        updated[start:end]=replacement;new_ffs_offset=start
    else:
        appended=True;pad=pad_file(tse['size']);updated[start:end]=pad
        replacement=file_header(h,new_body);new_ffs_offset=free
        new_length=align(free+len(replacement),4096)
        need(0<=new_length-len(inner)<=0x200000,'bounded inner volume growth')
        updated=updated[:free]+replacement+b'\xff'*(new_length-free-len(replacement))
        need(struct.unpack_from('<II',updated,0x38)==(len(inner)//4096,4096),'original block map')
        ext_at=struct.unpack_from('<H',updated,0x34)[0]
        need(struct.unpack_from('<I',updated,ext_at+16)[0]==20,'no growth-sensitive FV extension entries')
        struct.pack_into('<Q',updated,0x20,new_length);struct.pack_into('<I',updated,0x38,new_length//4096)
        hs=struct.unpack_from('<H',updated,0x30)[0];struct.pack_into('<H',updated,0x32,0)
        struct.pack_into('<H',updated,0x32,(-sum(struct.unpack('<'+'H'*(hs//2),updated[:hs])))&65535)
    newfiles,newfree=ffs_sequence(updated,im['header_size'])
    others=[x for x in files if x['guid']!=TSE_GUID]
    for f in others:need(f in newfiles,'unrelated original FFS bytes/offset changed')
    actual=[x for x in newfiles if x['guid']==TSE_GUID]
    need(len(actual)==1 and actual[0]['offset']==new_ffs_offset,'one active target file')
    need(sections(new_payload)[1]['type']==0x15 and new_payload[-len(tail):]==tail,'UI preserved')
    carrier=om['files'][0];ca=carrier['offset'];cz=ca+carrier['size'];oldcarrier=outer[ca:cz]
    oldouter_guided=oldcarrier[24:]
    opayload=lzma.decompress(oldouter_guided[24:],format=lzma.FORMAT_ALONE)
    oparts=sections(opayload);need([x['type']for x in oparts]==[0x19,0x17],'outer RAW then FV')
    need(oparts[1]['header']==8 and opayload[16:]==inner,'original inner FV matches decompression')
    npayload=bytearray(opayload[:16])+updated;struct.pack_into('<I',npayload,12,len(updated)+8)
    nguided=guided(bytes(npayload),oldouter_guided[:24],dictionary,depth)
    ncarrier=same_extent(oldcarrier[:24],nguided,carrier['size'])
    need(ncarrier is not None,f'replacement must fit original outer carrier extent: min={24+len(nguided)}, old={carrier["size"]}, mode={inner_encoding}')
    nouter=outer[:ca]+ncarrier+outer[cz:]
    old_outer_files,old_free=ffs_sequence(outer,om['header_size'])
    new_outer_files,new_free=ffs_sequence(nouter,om['header_size'])
    need(old_outer_files[1:]==new_outer_files[1:] and old_free==new_free,'outer neighbors/tail preserved')
    cap_path=ROOT/'analysis/workstation_20261008/W890_SAGE_0603/Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'
    cap=cap_path.read_bytes();need(sha(cap)==CAP_SHA,'official capsule identity')
    outer_offset=0x1841000;need(cap[outer_offset:outer_offset+len(outer)]==outer,'outer capsule offset')
    candidate=cap[:outer_offset]+nouter+cap[outer_offset+len(outer):]
    need(len(candidate)==len(cap),'capsule length unchanged')
    report={'status':'IN_MEMORY_CONTAINER_COMPOSITION_NOT_FLASH_READY','release_ready':False,
      'original_capsule_sha256':sha(cap),'replacement_pe_sha256':sha(new_pe),
      'candidate_in_memory_sha256':sha(candidate),'capsule_bytes':len(candidate),
      'target_file':TSE_GUID,'original_file_offset':start,'replacement_file_offset':new_ffs_offset,
      'inner_encoding':inner_encoding,'inner_replacement_ffs_bytes':len(replacement),
      'outer_guided_bytes':len(nguided),'outer_carrier_bytes':carrier['size'],
      'lzma_dictionary_bytes':dictionary,'lzma_properties_hex':nguided[24:29].hex(),
      'encoder_search_depth':depth,
      'appended_after_pad':appended,'preserved_other_inner_files':len(others),
      'original_inner_bytes':len(inner),'inner_bytes':len(updated),'inner_sha256':sha(updated),
      'preserved_other_outer_files':len(old_outer_files)-1,'outer_sha256':sha(nouter),
      'original_outer_offset':outer_offset,'outer_length_unchanged':True,
      'original_update_signature_invalidated':True,'candidate_saved':False,
      'format_sources':['https://uefi.org/specs/PI/1.10/V3_Code_Definitions.html',
                        'https://uefi.org/specs/PI/1.8/V3_Design_Discussion.html'],
      'limitations':['Container and relocation consistency do not establish driver functionality or whole boot.',
        'If moved, the target is non-fixed and accessed by FFS GUID; actual ASUS dispatcher behavior remains untested.',
        'No original-signature acceptance, host startup-integrity or recovery claim.']}
    memory={'original_tse_section':original_guided,'original_tse_payload':original_payload,
            'tse_section':new_guided,'tse_payload':new_payload,
            'outer_section':nguided,'outer_payload':bytes(npayload),'candidate':candidate}
    return memory,report
