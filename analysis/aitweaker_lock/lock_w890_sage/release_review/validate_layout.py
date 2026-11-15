"""Bounded W890 firmware-container capacity experiment; emits no BIOS image.

Uses a real, pinned non-dispatching provider only. It builds an expanded inner
FV and compresses it in memory, then verifies old FFS bytes and round-trip.
No resulting inner FV, CAP or ROM is written. A fitting compressed stream is
capacity evidence, never evidence of ASUS dispatch or boot compatibility.
"""
from pathlib import Path
import argparse, hashlib, json, lzma, struct, uuid
from lzma_known_size import encode as encode_known_size, controls as codec_controls

HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def require(ok,msg):
    if not ok:raise ValueError(msg)
def align(n,a):return (n+a-1)&~(a-1)
def section(kind,body):
    size=len(body)+4
    return size.to_bytes(3,'little')+bytes([kind])+body
def parse_sections(data):
    out=[];pos=0
    while pos<len(data):
        require(pos+4<=len(data),'section header bounds')
        size=int.from_bytes(data[pos:pos+3],'little');hs=4
        if size==0xffffff:
            require(pos+8<=len(data),'large section bounds');size=struct.unpack_from('<I',data,pos+4)[0];hs=8
        require(size>=hs and pos+size<=len(data),'section body bounds')
        out.append(dict(offset=pos,size=size,header_size=hs,type=data[pos+3],sha256=sha(data[pos:pos+size])))
        pos=align(pos+size,4)
    require(pos==len(data),'section alignment boundary')
    return out
def file_for_driver(efi,guid):
    # EFI_DEP_FALSE (0x07), EFI_DEP_END (0x08): never dispatch this packing test.
    body=section(0x13,b'\x07\x08');body+=b'\x00'*(align(len(body),4)-len(body))
    body+=section(0x10,efi)
    h=bytearray(uuid.UUID(guid).bytes_le+b'\x00\xaa\x07\x00'+(24+len(body)).to_bytes(3,'little')+b'\xf8')
    h[16]=(-(sum(h)-h[17]-h[23]))&255
    require((sum(h)-h[17]-h[23])&255==0,'new FFS header checksum')
    sections=parse_sections(body)
    require(len(sections)==2 and sections[0]['type']==0x13 and sections[1]['type']==0x10,'new FFS section types')
    require(body[4:6]==b'\x07\x08','FALSE DEPEX')
    require(body[sections[1]['offset']+4:]==efi,'new FFS PE identity')
    return bytes(h)+body,sections
def read_fv(entry):
    p=Path(entry['directory']);data=(p/'header.bin').read_bytes()+(p/'body.bin').read_bytes()
    require(sha(data)==entry['full_sha256'],'original FV identity');return data
def ffs_sequence(data,header_size):
    pos=align(header_size,8);out=[]
    while pos<len(data):
        if data[pos:pos+24]==b'\xff'*24:
            require(data[pos:]==b'\xff'*(len(data)-pos),'erased tail');break
        h=data[pos:pos+24];require(len(h)==24,'FFS bounds')
        size=int.from_bytes(h[20:23],'little');hs=24
        if h[19]&1:
            require(size==0xffffff,'extended FFS marker');size=struct.unpack_from('<Q',data,pos+24)[0];hs=32
        require(hs<=size<=len(data)-pos,'FFS size')
        full=data[pos:pos+size];hh=full[:hs]
        require((sum(hh)-hh[17]-hh[23])&255==0,'FFS header sum')
        require(((sum(full[hs:])+h[17])&255==0) if h[19]&0x40 else h[17]==0xaa,'FFS data sum')
        out.append(dict(guid=str(uuid.UUID(bytes_le=bytes(h[:16]))),offset=pos,size=size,sha256=sha(full)))
        pos=align(pos+size,8)
    return out,pos

def main(argv=None,observe_memory=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--efi',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--file-guid',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    require(args.output.resolve().is_relative_to(HERE.resolve()),'report must stay in review directory')
    efi=args.efi.read_bytes();require(sha(efi)==args.sha256,'pinned EFI')
    require(efi[:2]==b'MZ','PE DOS signature');peoff=struct.unpack_from('<I',efi,0x3c)[0]
    require(efi[peoff:peoff+4]==b'PE\0\0','PE signature');require(struct.unpack_from('<H',efi,peoff+4)[0]==0x8664,'x64 PE')
    require(struct.unpack_from('<H',efi,peoff+24+68)[0]==11,'DXE boot service driver subsystem')
    inventory=json.loads((HERE/'checked_dxe_volumes.json').read_text())['volumes']
    inner_meta=next(x for x in inventory if x['full_size']==0x1a42000)
    outer_meta=next(x for x in inventory if x['full_size']==0x630000)
    inner=read_fv(inner_meta);outer=read_fv(outer_meta)
    ext_offset=struct.unpack_from('<H',inner,0x34)[0]
    ext_size=struct.unpack_from('<I',inner,ext_offset+16)[0]
    require(ext_size==20 and ext_offset+ext_size<=inner_meta['header_size'],
            'baseline FV extension header has no growth-sensitive entries')
    files,free=ffs_sequence(inner,inner_meta['header_size'])
    require(len(files)==473 and free==inner_meta['free_offset'],'W890 inner inventory')
    require(args.file_guid.lower() not in [f['guid'] for f in files],'new GUID unique')
    added,sections=file_for_driver(efi,args.file_guid)
    needed_end=align(free+len(added),8)
    new_length=max(len(inner),align(needed_end,4096))
    require(new_length-len(inner)<=0x100000,'bounded packing experiment growth limit')
    expanded=bytearray(inner[:free]+added+b'\xff'*(new_length-free-len(added)))
    require(struct.unpack_from('<II',expanded,0x38)==(len(inner)//4096,4096),'single original block map')
    require(expanded[0x40:0x48]==bytes(8),'block map terminator')
    struct.pack_into('<Q',expanded,0x20,new_length)
    struct.pack_into('<I',expanded,0x38,new_length//4096)
    hs=struct.unpack_from('<H',expanded,0x30)[0];struct.pack_into('<H',expanded,0x32,0)
    struct.pack_into('<H',expanded,0x32,(-sum(struct.unpack('<'+'H'*(hs//2),expanded[:hs])))&65535)
    require(sum(struct.unpack('<'+'H'*(hs//2),expanded[:hs]))&65535==0,'expanded FV checksum')
    newfiles,newfree=ffs_sequence(expanded,inner_meta['header_size'])
    require(newfiles[:-1]==files and len(newfiles)==474,'all old inner FFS retain exact bytes and offsets')
    require(newfiles[-1]['guid']==args.file_guid.lower() and newfiles[-1]['offset']==free,'appended FFS location')
    carrier=outer_meta['files'][0]
    require(carrier['guid']=='9e21fd93-9c72-4c15-8c4b-e77f1db2d792','expected compressed carrier')
    sourcefile=outer[carrier['offset']:carrier['offset']+carrier['size']]
    compressed=sourcefile[24+24:]
    require(compressed[0]==0x5d and struct.unpack_from('<I',compressed,1)[0]==0x1000000,'original LZMA properties')
    unpacked=lzma.decompress(compressed,format=lzma.FORMAT_ALONE)
    seq=parse_sections(unpacked);require(len(seq)==2 and seq[0]['type']==0x19 and seq[1]['type']==0x17,'original raw + FV sections')
    fvsec=seq[1];require(fvsec['header_size']==8 and unpacked[fvsec['offset']+8:]==inner,'decompressed FV exact identity')
    payload=bytearray(unpacked[:16]);payload+=expanded
    struct.pack_into('<I',payload,12,new_length+8)
    require(parse_sections(payload)[1]['size']==new_length+8,'large FV section length')
    codec=codec_controls()
    recompressed=encode_known_size(bytes(payload))
    require(lzma.decompress(recompressed,format=lzma.FORMAT_ALONE)==payload,'exact compression round-trip')
    proposed_carrier_size=24+24+len(recompressed)
    next_offset=outer_meta['files'][1]['offset']
    keep_offsets_possible=align(carrier['offset']+proposed_carrier_size,8)<=next_offset
    shifted_remaining=align(carrier['offset']+proposed_carrier_size,8)+(outer_meta['free_offset']-next_offset)
    same_offsets=None
    # Preserve the original carrier FFS length. Add a separate RAW section in
    # its remaining space, never unaccounted bytes inside the LZMA stream.
    body_end=align(24+len(recompressed),4)
    padding_length=carrier['size']-24-body_end
    if keep_offsets_possible and padding_length>=4:
        original_sections=parse_sections(sourcefile[24:])
        require(len(original_sections)==1 and original_sections[0]['type']==2,'single original GUID-defined section')
        gh=bytearray(sourcefile[24:48]);gh[:3]=(24+len(recompressed)).to_bytes(3,'little')
        newbody=bytes(gh)+recompressed
        newbody+=b'\x00'*(align(len(newbody),4)-len(newbody))
        newbody+=section(0x19,b'\xff'*(padding_length-4))
        require(len(newbody)+24==carrier['size'],'same-size carrier')
        newhead=bytearray(sourcefile[:24])
        newhead[17]=(-sum(newbody))&255 if newhead[19]&0x40 else 0xaa
        newhead[16]=0
        newhead[16]=(-(sum(newhead)-newhead[17]-newhead[23]))&255
        newcarrier=bytes(newhead)+newbody
        rebuilt=bytearray(outer);rebuilt[carrier['offset']:carrier['offset']+carrier['size']]=newcarrier
        oldouter,oldouterfree=ffs_sequence(outer,outer_meta['header_size'])
        newouter,newouterfree=ffs_sequence(rebuilt,outer_meta['header_size'])
        require(oldouter[1:]==newouter[1:] and oldouterfree==newouterfree,'seven outer FFS unchanged with same erased tail')
        require(newouter[0]['size']==oldouter[0]['size'] and newouter[0]['offset']==oldouter[0]['offset'],'carrier extent unchanged')
        ns=parse_sections(newbody)
        require(len(ns)==2 and ns[0]['type']==2 and ns[1]['type']==0x19,'GUID-defined plus RAW padding sections')
        require(newbody[4:24]==sourcefile[28:48],'original GUID/data offset/attributes preserved')
        require(lzma.decompress(newbody[24:ns[0]['size']],format=lzma.FORMAT_ALONE)==payload,'embedded carrier exact round-trip')
        require(rebuilt[:carrier['offset']]==outer[:carrier['offset']] and rebuilt[carrier['offset']+carrier['size']:]==outer[carrier['offset']+carrier['size']:],'changes confined to original carrier extent')
        same_offsets=dict(status='PASS_IN_MEMORY_STRUCTURAL_CHECKS_ONLY',outer_sha256=sha(rebuilt),
            carrier_sha256=sha(newcarrier),carrier_size=len(newcarrier),raw_padding_section_bytes=padding_length,
            sections=ns,other_ffs_unchanged=7,other_ffs_offsets_unchanged=True,outer_fv_header_unchanged=True,
            original_erased_tail_unchanged=True,outer_length_unchanged=True,
            limitation='Extra RAW padding section is structurally valid here; ASUS decompressor/dispatcher acceptance is not executed.')
    result=dict(status='PASS_MEMORY_ONLY_LAYOUT_EXPERIMENT_NOT_A_BOOT_CANDIDATE',release_ready=False,
      script_sha256=sha(Path(__file__).read_bytes()),efi=dict(path=str(args.efi.resolve()),size=len(efi),sha256=sha(efi)),
      ffs=dict(guid=args.file_guid,size=len(added),sha256=sha(added),depex_hex='0708',dispatch=False,sections=sections),
      original_inner_sha256=sha(inner),original_outer_sha256=sha(outer),
      inner=dict(original_size=len(inner),proposed_size=new_length,growth=new_length-len(inner),
                 original_free_bytes=len(inner)-free,proposed_free_bytes=new_length-newfree,old_ffs_unchanged=473,
                 extension_header_size=ext_size,extension_entries=0,
                 changed_original_fields=['FvLength','BlockMap[0].NumBlocks','FV header checksum'],expanded_memory_sha256=sha(expanded)),
      compressed=dict(original_bytes=len(compressed),proposed_bytes=len(recompressed),roundtrip_exact=True,codec=codec,
                      properties_hex=bytes(recompressed[:5]).hex(),uncompressed_bytes=len(payload),sha256=sha(recompressed)),
      outer=dict(original_carrier_size=carrier['size'],proposed_min_carrier_size=proposed_carrier_size,
                 original_size=len(outer),other_file_count=7,can_preserve_other_file_offsets=keep_offsets_possible,
                 all_files_fit_if_repacked=shifted_remaining<=len(outer),free_if_repacked=len(outer)-shifted_remaining,
                 same_offset_container_experiment=same_offsets,
                 unknowns=['ASUS dispatcher/decompressor acceptance of the expanded FV and additional RAW padding section is untested.',
                           'Moving other outer files requires proving address/location independence; no movement is performed here.']),
      limits=['Uses the actual UNBOUND TESTONLY provider with FALSE DEPEX; no original entry-point integration.',
              'No CAP, ROM, inner FV or compressed candidate written; derived bytes only exist in memory.',
              'FV format checks and compression capacity do not establish ASUS dispatch, boot, signing or update acceptance.',
              'The original main FV and all source files are left unchanged.'],
      original_inputs_unchanged=read_fv(inner_meta)==inner and read_fv(outer_meta)==outer and args.efi.read_bytes()==efi)
    if observe_memory:
        require(same_offsets is not None,'native callback requires same-offset carrier experiment')
        observe_memory(dict(original_section=sourcefile[24:],original_output=unpacked,
            proposed_section=newbody[:ns[0]['size']],proposed_output=bytes(payload)))
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['status','ffs','inner','compressed','outer','original_inputs_unchanged']}))

if __name__=='__main__':main()
