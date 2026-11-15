"""Independent, read-only CAP/FV/FFS audit. Does not import P5 builders."""
from pathlib import Path
from collections import Counter
import hashlib, json, lzma, struct, uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE, SIZE = 0x12D1000, 0x9F0000
LZMA = 'ee4e5898-3914-4259-9d6e-dc7bd79403cf'
WRAPPER = '9e21fd93-9c72-4c15-8c4b-e77f1db2d792'
SETUP = '899407d7-99fe-43d8-9a21-79ec328cac21'
SPF = 'fe612b72-203c-47b1-8560-a66d946eb371'
DRIVER = '261135b0-7b73-49c0-bcc8-2f9cf4eef19e'

def sha(b): return hashlib.sha256(b).hexdigest()
def guid(b): return str(uuid.UUID(bytes_le=b))
def n24(b): return int.from_bytes(b[:3], 'little')
def up(n, a): return (n+a-1)//a*a

def fv_read(b):
    assert b[40:44] == b'_FVH'
    size, = struct.unpack_from('<Q', b, 32)
    attributes, = struct.unpack_from('<I', b, 44)
    header_size, = struct.unpack_from('<H', b, 48)
    ext_offset, = struct.unpack_from('<H', b, 52)
    assert size == len(b) and header_size >= 56 and not header_size % 2
    assert sum(struct.unpack('<'+'H'*(header_size//2),b[:header_size])) & 0xffff == 0
    block_sum = 0
    for p in range(56,header_size,8):
        count,length = struct.unpack_from('<II',b,p)
        if (count,length)==(0,0): break
        assert count and length
        block_sum += count*length
    assert block_sum == size
    if ext_offset:
        ext_size, = struct.unpack_from('<I',b,ext_offset+16)
        assert ext_size >= 20 and ext_offset+ext_size <= size
    files = []; pos = up(header_size,8)
    erased = 0xff if attributes & 0x800 else 0
    while pos+24 <= size and b[pos:pos+24] != bytes([erased])*24:
        h=b[pos:pos+24]; attrs=h[19]
        assert not attrs & 1, 'Unexpected FFS large header'
        length=n24(h[20:23]); assert 24 <= length < 0xffffff and pos+length <= size
        assert (sum(h)-h[17]-h[23]) & 255 == 0, (pos,'FFS header checksum')
        logical_state=h[23]^erased
        assert logical_state==7, (pos,logical_state)
        body=b[pos+24:pos+length]
        if attrs & 0x40: assert (sum(body)+h[17]) & 255 == 0
        else: assert h[17]==0xaa
        alignment_bits=(attrs>>3)&7
        assert alignment_bits==0, 'A nontrivial alignment needs explicit decoding'
        assert pos%8==0
        files.append(dict(guid=guid(h[:16]),offset=pos,size=length,type=h[18],attributes=attrs,data=b[pos:pos+length]))
        next_pos=up(pos+length,8)
        assert b[pos+length:next_pos] == bytes([erased])*(next_pos-pos-length)
        pos=next_pos
    assert b[pos:] == bytes([erased])*(size-pos)
    info=dict(bytes=size,header_bytes=header_size,extension_offset=ext_offset,
              filesystem_guid=guid(b[16:32]),header_sha256=sha(b[:up(header_size,8)]),
              block_map_total=block_sum,files=len(files),free_bytes=size-pos,used_end=hex(pos),
              file_type_counts={hex(k):v for k,v in sorted(Counter(f['type'] for f in files).items())},
              checksums_valid=True,alignment_valid=True,erase_fill_valid=True)
    return files, info

def sections(b):
    out=[]; pos=0
    while pos < len(b):
        if len(b)-pos < 4:
            assert not any(b[pos:]); break
        size=n24(b[pos:pos+3]); head=4
        if size==0xffffff: size,=struct.unpack_from('<I',b,pos+4); head=8
        assert size >= head and pos+size <= len(b)
        out.append(dict(type=b[pos+3],offset=pos,head=head,data=b[pos:pos+size],body=b[pos+head:pos+size]))
        nxt=up(pos+size,4)
        assert not any(b[pos+size:nxt]); pos=nxt
    return out

def decode(s):
    assert s['type']==2
    b=s['data']; g=guid(b[s['head']:s['head']+16])
    dataoff,attrs=struct.unpack_from('<HH',b,s['head']+16)
    assert g==LZMA and dataoff==s['head']+20 and attrs==1
    z=b[dataoff:]; declared,=struct.unpack_from('<Q',z,5)
    raw=lzma.decompress(z,format=lzma.FORMAT_ALONE)
    assert declared==len(raw)
    return raw,dict(guid=g,data_offset=dataoff,attributes=attrs,encoded_bytes=len(z),
                    decoded_bytes=len(raw),properties=z[:5].hex(),declared_size=declared,
                    decoded_sha256=sha(raw))

def read_image(path):
    cap=path.read_bytes(); outer=cap[BASE:BASE+SIZE]
    files,outer_info=fv_read(outer); by={f['guid']:f for f in files}
    assert len(by)==len(files)
    wrapper_sections=sections(by[WRAPPER]['data'][24:]); assert len(wrapper_sections)==1
    decoded,compression=decode(wrapper_sections[0]); inner_sections=sections(decoded)
    inner=next(s['body'] for s in inner_sections if s['type']==0x17)
    members,inner_info=fv_read(inner); iby={f['guid']:f for f in members}
    assert len(iby)==len(members)
    return dict(cap=cap,outer=outer,outer_files=by,outer_info=outer_info,inner=inner,
                inner_files=iby,inner_info=inner_info,wrapper_compression=compression)

def depex_tokens(body):
    pos=0; stack=[]; tokens=[]
    while pos<len(body):
        op=body[pos];pos+=1
        if op==2:
            assert pos+16<=len(body); v=guid(body[pos:pos+16]);pos+=16
            stack.append(v);tokens.append(['PUSH',v])
        elif op==3:
            assert len(stack)>=2; right=stack.pop();left=stack.pop()
            stack.append(['AND',left,right]);tokens.append(['AND'])
        elif op==8:
            assert pos==len(body) and len(stack)==1;tokens.append(['END'])
        else: raise AssertionError(('Unexpected driver dependency opcode',op))
    return tokens

def main():
    original=read_image(ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP')
    candidate=read_image(ROOT/'analysis/hero_ipmi_p5/candidate/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP')
    assert len(original['cap'])==len(candidate['cap'])==33558528
    assert original['cap'][:BASE]==candidate['cap'][:BASE]
    assert original['cap'][BASE+SIZE:]==candidate['cap'][BASE+SIZE:]
    unchanged=0
    for layer,allowed in [('outer',{WRAPPER}),('inner',{SETUP,SPF})]:
        old=original[layer+'_files'];new=candidate[layer+'_files']
        assert not set(old)-set(new)
        for key in old:
            if key not in allowed: assert old[key]['data']==new[key]['data'];unchanged+=1
        assert original[layer+'_info']['header_sha256']==candidate[layer+'_info']['header_sha256']
    old_setup=sections(original['inner_files'][SETUP]['data'][24:])
    new_setup=sections(candidate['inner_files'][SETUP]['data'][24:])
    assert [s['type'] for s in old_setup]==[0x13,0x10,0x14]
    assert [s['type'] for s in new_setup]==[0x13,0x02,0x14]
    assert old_setup[0]['data']==new_setup[0]['data'] and old_setup[-1]['data']==new_setup[-1]['data']
    setup_decoded,setup_comp=decode(new_setup[1]); setup_pe=sections(setup_decoded)
    assert len(setup_pe)==1 and setup_pe[0]['type']==0x10
    assert setup_pe[0]['body']==(ROOT/'analysis/hero_ipmi_p5/Setup-P5-RESOURCE-REVIEW.efi').read_bytes()
    driver=candidate['outer_files'][DRIVER]
    assert DRIVER not in candidate['inner_files'] and DRIVER not in original['outer_files']
    ds=sections(driver['data'][24:]);assert [s['type'] for s in ds]==[0x13,0x10,0x15]
    driver_depex=depex_tokens(ds[0]['body'])
    original_setup_depex=depex_tokens(old_setup[0]['body'])
    assert {t[1] for t in driver_depex if t[0]=='PUSH'} <= {t[1] for t in original_setup_depex if t[0]=='PUSH'}
    assert ds[1]['body']==(ROOT/'analysis/hero_ipmi_p5/USB/EFI/HERO/HeroIpmiP5.efi').read_bytes()
    aligned=up(driver['size'],8); free=candidate['inner_info']['free_bytes']
    assert free>aligned and int(candidate['inner_info']['used_end'],16)%8==0
    report=dict(scope='Independent Python container parsing, not REA or hardware execution',
        target_sha256=sha(candidate['cap']),original_sha256=sha(original['cap']),
        passed_structural_checks=True,unchanged_ffs_checked=unchanged,
        original={k:original[k] for k in ['outer_info','inner_info','wrapper_compression']},
        candidate={k:candidate[k] for k in ['outer_info','inner_info','wrapper_compression']},
        setup_compression=setup_comp,setup_depex_and_version_preserved=True,
        driver=dict(ffs_bytes=driver['size'],padded_bytes=aligned,current_fv='outer',
                    current_offset=hex(driver['offset']),depex=driver_depex,
                    dependencies_subset_of_original_setup_depex=True,exact_pe_payload_match=True),
        findings=[dict(id='C1',classification='unverified dispatch assumption',
            observation='RC1 adds the driver to the outer FFSv3 FV, whose original non-pad contents are one compressed FV-image and raw/freeform files. All original ordinary DXE drivers within this reviewed outer/inner container reside in the inner FV.',
            risk='Structural validity alone does not prove the platform dispatches newly added outer-FV DXE drivers.',
            recommendation='Place the new driver in the existing inner DXE FV; sufficient space is available after Setup compression.',
            inner_append_offset=candidate['inner_info']['used_end'],free_before=free,
            driver_aligned_bytes=aligned,free_after=free-aligned,
            minimal_builder_change='Read/validate driver before pack_fv(inner,...); pass [driver] as its extra argument. Remove [driver] from pack_fv(outer,...). All other original files remain byte-identical.')],
        observed_lzma_support=dict(dxe_core_ffs='d6a2cb7f-6a18-4e2f-b43b-9920a733700a',
          dxe_core_pe_bytes=111360,guid_file_offset='0x15be0',
          note='Original DXE Core itself is LZMA wrapped and contains this GUID. Registration and DXE decoding call path require native REA confirmation; literal presence alone is insufficient.'),
        unknowns=['Native DXE dispatch and menu operation after flashing','ASUS FlashBack acceptance','Live Boot Guard or other enforcement state'])
    (HERE/'container-review.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['original','candidate']},indent=2))

if __name__=='__main__': main()
