"""Read-only full original / EXP02 / internal EXP03 structural comparison.

Only reports and an extracted driver copy are written beneath this directory.
No device, updater, signing operation, original image mutation, or publication.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import lzma
import re
import struct
import sys
import uuid

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
CASE = LAB.parent
ROOT = CASE.parents[2]
REVIEW = CASE/'review/flash_readiness'
sys.path.insert(0,str(LAB))
sys.path.insert(0,str(REVIEW))
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from verify_asus_review import collect
from verify_capsule_static import parse_capsule, signatures, parse_fit
import pefile

SOURCE = CASE.parent/'official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
EXP02 = LAB/'asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin'
EXP03 = HERE/'W790E-SAGE-SE-1904-lock-EXP03-EBS-SESSION-UNSIGNED.review.bin'
DRIVER = REVIEW/'late_attach_candidate/build/AiTweakerLock1904.efi'
PINS = {
    'original':'aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3',
    'exp02':'95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e',
    'exp03':'1ddac5400265f4c0bd928cc2cc3b2a8b802d22ae20d134f11aa01352385def2c',
}
PIN_DRIVER = 'e41ac0009a5658aff0546e637d0cf89a16edd1d16d726ee97dadf675f46c67d1'
CONTAINER = 0x3181078
ALLOCATION = 0x35f9e8
OUTER = 0x3181000
INNER = 0x10
CONTAINER_GUID = '9E21FD93-9C72-4C15-8C4B-E77F1DB2D792'
DRIVER_GUID = '8B4E0D52-28B5-4D1F-B4BC-750E9D9D1904'
PAD_GUID = 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding='utf8'))


def file(path):
    return {'path':str(path.resolve()),'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())}


def ffs_check(header, body):
    assert len(header) in (24,32)
    size = int.from_bytes(header[20:23],'little')
    if size==0xffffff:
        assert len(header)==32 and header[19]&1
        size=struct.unpack_from('<Q',header,24)[0]
    assert size==len(header)+len(body)
    assert (sum(header)-header[17]-header[23])&255==0
    if header[19]&0x40:
        assert (sum(body)+header[17])&255==0
        kind='computed_data_checksum'
    else:
        assert header[17]==0xaa
        kind='fixed_0xAA_no_data_checksum_attribute'
    return {'bytes':size,'header_bytes':len(header),'type':header[18],'attributes':header[19],
            'header_checksum_valid':True,'data_checksum_mode':kind,'data_checksum_valid':True}


def fv(data, offset):
    assert data[offset+40:offset+44]==b'_FVH'
    n=struct.unpack_from('<Q',data,offset+32)[0]
    h=struct.unpack_from('<H',data,offset+48)[0]
    assert h>=0x48 and h%2==0 and offset+n<=len(data) and h<=n
    assert sum(struct.unpack('<'+'H'*(h//2),data[offset:offset+h]))&0xffff==0
    blocks=[]
    cursor=offset+56
    while True:
        assert cursor+8<=offset+h
        count,size=struct.unpack_from('<II',data,cursor)
        cursor+=8
        if count==size==0:break
        assert count and size
        blocks.append({'count':count,'bytes_per_block':size})
    assert sum(x['count']*x['bytes_per_block'] for x in blocks)==n
    return {'offset':offset,'bytes':n,'header_bytes':h,'header_checksum_valid':True,'block_map':blocks}


def walk_ffs(data, volume):
    end=volume['offset']+volume['bytes']
    pos=volume['offset']+volume['header_bytes']
    result=[]
    while pos+24<=end:
        if data[pos:pos+24]==b'\xff'*24:
            assert data[pos:end]==b'\xff'*(end-pos)
            return result,pos,end-pos
        size=int.from_bytes(data[pos+20:pos+23],'little')
        assert 24<=size<0xffffff and pos+size<=end
        h=data[pos:pos+24];body=data[pos+24:pos+size]
        result.append({'offset':pos,'guid':str(uuid.UUID(bytes_le=h[:16])).upper(),
                       'sha256':sha(h+body),**ffs_check(h,body)})
        next_pos=(pos+size+7)&~7
        assert next_pos<=end
        assert all(x in (0xff,0x00) for x in data[pos+size:next_pos])
        pos=next_pos
    raise AssertionError('No erased FV tail')


def inner_payload(data):
    size=int.from_bytes(data[CONTAINER+20:CONTAINER+23],'little')
    assert str(uuid.UUID(bytes_le=data[CONTAINER:CONTAINER+16])).upper()==CONTAINER_GUID
    ffs_check(data[CONTAINER:CONTAINER+24],data[CONTAINER+24:CONTAINER+size])
    start=CONTAINER+24
    section_size=int.from_bytes(data[start:start+3],'little')
    assert section_size==size-24 and data[start+3]==2
    assert str(uuid.UUID(bytes_le=data[start+4:start+20]))=='ee4e5898-3914-4259-9d6e-dc7bd79403cf'
    assert data[start+20:start+24]==b'\x18\0\x01\0'
    packed=data[start+24:start+section_size]
    prop=packed[0]
    filters=[{'id':lzma.FILTER_LZMA1,'dict_size':int.from_bytes(packed[1:5],'little'),
              'lc':prop%9,'lp':(prop//9)%5,'pb':(prop//9)//5}]
    # Factory stream is size-terminated without an EOS marker; the Python
    # recompressed streams retain EOS and an explicit EDK2 output size.
    # Both are already exact-input hash pinned; select their known decoder form.
    if sha(data)==PINS['original']:
        raw=lzma.decompress(packed,format=lzma.FORMAT_ALONE)
        decoder='ALONE original known-size stream'
    else:
        raw=lzma.decompress(packed[13:],format=lzma.FORMAT_RAW,filters=filters)
        decoder='RAW original LZMA properties, modified stream with EOS'
    declared=int.from_bytes(packed[5:13],'little')
    assert declared in (len(raw),0xffffffffffffffff)
    assert raw[:12]==bytes.fromhex('0800001900000000ffffff17')
    assert int.from_bytes(raw[12:16],'little')==len(raw)-8
    return raw,{'compressed_ffs_bytes':size,'aligned_ffs_bytes':(size+7)&~7,
                'lzma_bytes':len(packed),'declared_raw_bytes':declared,'raw_bytes':len(raw),
                'raw_sha256':sha(raw),'lzma_filter':filters[0],'verification_decoder':decoder}


def extracted_inventory(root):
    rows=[]
    for item in collect(root):
        folder=item['folder']
        header=(folder/'header.bin').read_bytes()
        body=(folder/'body.bin').read_bytes() if (folder/'body.bin').exists() else b''
        rows.append({'guid':item['guid'],'sha256':item['sha256'],
                     'extraction_path':str(folder),**ffs_check(header,body)})
    return rows


def pair_diff(a,b):
    assert len(a)==len(b)
    count=0;first=None;last=None
    for i,(x,y) in enumerate(zip(a[CONTAINER:CONTAINER+ALLOCATION],b[CONTAINER:CONTAINER+ALLOCATION])):
        if x!=y:
            count+=1
            if first is None:first=CONTAINER+i
            last=CONTAINER+i
    assert a[:CONTAINER]==b[:CONTAINER] and a[CONTAINER+ALLOCATION:]==b[CONTAINER+ALLOCATION:]
    return {'changed_bytes':count,'first_changed_cap_offset':first,'last_changed_cap_offset':last,
            'all_changes_within_original_allocation':True,'outside_slot_unchanged':True}


def main():
    paths={'original':SOURCE,'exp02':EXP02,'exp03':EXP03}
    images={name:p.read_bytes() for name,p in paths.items()}
    for name,data in images.items():
        assert sha(data)==PINS[name] and len(data)==0x4001000
    assert sha(DRIVER.read_bytes())==PIN_DRIVER
    for name in ['exp02','exp03']:
        assert images[name][:4096]==images['original'][:4096]
    headers={name:parse_capsule(data) for name,data in images.items()}
    assert headers['original']==headers['exp02']==headers['exp03']
    regions=[]
    for item in headers['original']['regions']:
        a=item['cap_offset'];b=a+item['size']
        hashes={name:sha(data[a:b]) for name,data in images.items()}
        regions.append({**item,'sha256':hashes,'changed_from_original':hashes['exp03']!=hashes['original'],
                        'changed_from_exp02':hashes['exp03']!=hashes['exp02']})
    assert [r['index'] for r in regions if r['changed_from_original']]==[13]
    assert [r['index'] for r in regions if r['changed_from_exp02']]==[13]
    signatures_result={name:signatures(data,headers[name]) for name,data in images.items()}
    assert all(x['valid'] for x in signatures_result['original'].values())
    for name in ['exp02','exp03']:
        assert not signatures_result[name]['firmware_signature']['valid']
        assert signatures_result[name]['certificate_signature']['valid']
    fits={name:parse_fit(data,headers[name]) for name,data in images.items()}
    assert fits['original']==fits['exp02']==fits['exp03']
    extracts={'original':Path(str(SOURCE)+'.dump')}
    verify_reports={}
    for name, report_path in [('exp02',EXP02.parent/'verification.json'),('exp03',HERE/'verification.json')]:
        r=load(report_path)
        assert r['status']=='PASS' and r['candidate_sha256']==PINS[name]
        verify_reports[name]=file(report_path)
        extracts[name]=Path(r['evidence_folder'])/'W790E-SAGE-SE-1904.review.bin.dump'
    inventory={name:extracted_inventory(root) for name,root in extracts.items()}
    assert [len(inventory[n]) for n in ['original','exp02','exp03']]==[623,625,625]
    counters={name:Counter((r['guid'],r['sha256']) for r in rows) for name,rows in inventory.items()}
    original_noncontainer=Counter((r['guid'],r['sha256']) for r in inventory['original'] if r['guid']!=CONTAINER_GUID)
    for name in ['exp02','exp03']:
        assert not original_noncontainer-counters[name]
    delta02=counters['exp02']-counters['exp03'];delta03=counters['exp03']-counters['exp02']
    assert sum(delta02.values())==sum(delta03.values())==3
    assert {g for g,h in delta02}=={CONTAINER_GUID,DRIVER_GUID,PAD_GUID}
    assert {g for g,h in delta03}=={CONTAINER_GUID,DRIVER_GUID,PAD_GUID}
    structure={};raws={};inners={};outers={}
    for name,data in images.items():
        outer=fv(data,OUTER);of,op,ofree=walk_ffs(data,outer)
        raw,compressed=inner_payload(data)
        inner=fv(raw,INNER);inf,ip,ifree=walk_ffs(raw,inner)
        assert len(raw)==inner['bytes']+16
        raws[name]=raw;inners[name]=inf;outers[name]=of
        structure[name]={'outer_fv':outer,'outer_ffs':of,'outer_free_offset':op,'outer_free_bytes':ofree,
                         'compressed_container':compressed,'inner_fv':inner,'inner_ffs':inf,
                         'inner_free_offset':ip,'inner_free_bytes':ifree}
    assert len(inners['original'])==413
    for name in ['exp02','exp03']:
        assert inners[name][:-1]==inners['original']
        assert inners[name][-1]['guid']==DRIVER_GUID
        assert inners[name][-1]['offset']==structure['original']['inner_free_offset']
        assert structure[name]['inner_fv']['bytes']-structure['original']['inner_fv']['bytes']==40960
        assert [f for f in outers[name] if f['guid'] not in (CONTAINER_GUID,PAD_GUID)]==[f for f in outers['original'] if f['guid'] not in (CONTAINER_GUID,PAD_GUID)]
        by_offset={f['offset']:f for f in outers[name]}
        for original_file in outers['original']:
            if original_file['offset']!=CONTAINER:
                assert by_offset[original_file['offset']]==original_file
        assert structure[name]['outer_free_offset']==structure['original']['outer_free_offset']
        assert structure[name]['outer_free_bytes']==structure['original']['outer_free_bytes']
        pads=[f for f in outers[name] if CONTAINER<=f['offset']<CONTAINER+ALLOCATION and f['guid']==PAD_GUID]
        assert len(pads)==1
        pad=pads[0]
        assert pad['offset']+pad['bytes']==CONTAINER+ALLOCATION
        assert pad['bytes']>=24
        structure[name]['original_slot_padding_file']=pad
    assert structure['exp03']['original_slot_padding_file']['bytes']==352
    assert raws['exp02'][:inners['exp03'][-1]['offset']]==raws['exp03'][:inners['exp03'][-1]['offset']]
    # Independently parse inserted FFS sections from the decompressed bytes.
    f=inners['exp03'][-1];body=raws['exp03'][f['offset']+24:f['offset']+f['bytes']]
    sections=[];pos=0
    while pos<len(body):
        n=int.from_bytes(body[pos:pos+3],'little');kind=body[pos+3]
        assert 4<=n and pos+n<=len(body)
        payload=body[pos+4:pos+n]
        sections.append({'type':kind,'bytes':n,'payload_sha256':sha(payload)})
        if kind==0x10:
            assert payload==DRIVER.read_bytes()
            (HERE/'reextracted-AiTweakerLock1904.efi').write_bytes(payload)
            p=pefile.PE(data=payload)
            assert p.OPTIONAL_HEADER.Subsystem==11
            assert p.OPTIONAL_HEADER.CheckSum==p.generate_checksum()
        if kind==0x13:
            expected=b'\x02'+uuid.UUID('1e5668e2-8481-11d4-bcf1-0080c73c8881').bytes_le+b'\x02'+uuid.UUID('6441f818-6362-4e44-b570-7dba31dd2453').bytes_le+b'\x03\x08'
            assert payload==expected
        pos=(pos+n+3)&~3
    assert [s['type'] for s in sections]==[0x13,0x10,0x15]
    old_ff_hashes={f['guid'] for f in inners['original']}
    assert DRIVER_GUID not in old_ff_hashes
    full_inventory=HERE/'ffs_inventories.json';full_inventory.write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf8')
    structures_path=HERE/'container_structure.json';structures_path.write_text(json.dumps(structure,indent=2)+'\n',encoding='utf8')
    attempt=load(HERE/'build_attempt.json')
    for name,h in attempt['inputs'].items():
        assert sha(Path(name).read_bytes())==h,name
    attempt['status']='BUILT_AND_INDEPENDENTLY_VERIFIED_INTERNAL_UNSIGNED_REVIEW_ONLY'
    attempt['three_way_verification']='integration_review.json'
    (HERE/'build_attempt.json').write_text(json.dumps(attempt,indent=2)+'\n',encoding='utf8')
    result={
        'status':'PASS_FULL_THREE_WAY_STRUCTURE_COMPARISON_INTERNAL_UNSIGNED_REVIEW_ONLY',
        'purpose':'Internal review image; not a formal BIOS, signed update, deployable package or permission to flash.',
        'images':{name:file(path) for name,path in paths.items()},'driver':file(DRIVER),
        'whole_image_lengths_equal':True,'capsule_header_4096_bytes_unchanged':True,
        'capsule_layout':headers['original'],'all_22_rom_regions':regions,
        'all_rom_regions_cover_body_disjointly':True,'only_changed_rom_region_index':13,
        'byte_changes':{'original_to_exp02':pair_diff(images['original'],images['exp02']),
                        'original_to_exp03':pair_diff(images['original'],images['exp03']),
                        'exp02_to_exp03':pair_diff(images['exp02'],images['exp03'])},
        'slot':{'cap_offset':CONTAINER,'original_allocation_bytes':ALLOCATION,'outer_fv_offset':OUTER,
                'exp02_padding_bytes':structure['exp02']['original_slot_padding_file']['bytes'],
                'exp03_padding_bytes':352,'following_file_offsets_unchanged':True},
        'ffs':{'counts':{n:len(r) for n,r in inventory.items()},'all_extracted_ffs_headers_and_data_checksum_modes_verified':True,
               'original_noncontainer_files_preserved':622,'inner_original_files_preserved_at_identical_offsets':413,
               'exp02_to_exp03_changed_ffs_guids':sorted([CONTAINER_GUID,DRIVER_GUID,PAD_GUID]),
               'complete_inventory':file(full_inventory),'complete_container_structure':file(structures_path)},
        'embedded_driver':{'source_sha256':PIN_DRIVER,'reextracted':file(HERE/'reextracted-AiTweakerLock1904.efi'),
                           'exact_match':True,'pe_checksum_valid':True,'subsystem':'EFI boot service driver (11)',
                           'ffs_type':'DXE_DRIVER 07','sections_in_order':sections},
        'dispatch':{'depex':'PUSH EFI_VARIABLE_ARCH_PROTOCOL; PUSH EFI_VARIABLE_WRITE_ARCH_PROTOCOL; AND; END',
                    'physical_insertion':'Appended at the existing inner FV erased tail; every original FFS stays at its original inner offset. The nested FV grows by 40960 bytes and is recompressed within the existing outer container allocation.',
                    'ordering_limit':'Physical insertion order and the two architectural-protocol dependencies do not establish automatic attachment before every OEM browser entry. No original apriori/dispatch file was edited. Stage5 first-discovery and one-shot first-attachment failure limitations from the candidate remain.'},
        'cryptographic_verification':signatures_result,
        'signature_interpretation':'Original firmware and certificate signatures mathematically verify. EXP02 and EXP03 preserve original signed header/certificate; the changed payload invalidates its original firmware signature as expected. No new signature, trust-anchor change or update acceptance is claimed. This does not determine all BMC trust-anchor enforcement paths.',
        'fit_unchanged':True,'fit':fits['original'],
        'boot_guard_hardware_state_and_changed_region_coverage':'UNKNOWN; no conclusion from manifest absence or unchanged FIT.',
        'independent_uefiextract_reports':verify_reports,
        'driver_binding_review':file(REVIEW/'late_attach_build_binding_review.json'),
        'build_attempt':file(HERE/'build_attempt.json'),
        'tools':{'script':file(Path(__file__)),'uefiextract':file(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),
                 'capsule_math_parser':file(REVIEW/'verify_capsule_static.py'),'ffs_extract_verifier':file(LAB/'verify_asus_review.py')},
        'all_pinned_original_production_and_exp02_inputs_unchanged':True,
        'no_device_or_client_access':True,'no_flash_or_signing_or_root_publication':True,
        'remaining_acceptance':load(REVIEW/'late_attach_candidate/candidate_summary.json')['unresolved'],
    }
    out=HERE/'integration_review.json'
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'report':str(out),'report_sha256':sha(out.read_bytes()),
                      'candidate_sha256':PINS['exp03'],'driver_sha256':PIN_DRIVER,'padding_bytes':352}))


if __name__=='__main__':
    main()
