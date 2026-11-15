"""Read-only, HERO-specific Boot Guard evidence audit.

This code reads pinned release/candidate CAPs and existing extracted leaf files.
It neither contacts a machine nor writes to firmware. A missing manifest is
recorded as missing evidence, never converted to a live-policy assertion.
"""
from pathlib import Path
import hashlib, json, os, re, struct, uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
ORIGINAL=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
CANDIDATE=ROOT/'analysis/hero_ipmi_p5_rea_review_20261103/rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP'
ORIGINAL_SHA='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
CANDIDATE_SHA='5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
MARKERS=[b'__KEYM__',b'__ACBP__',b'__IBBS__',b'__PMSG__',b'__PMDA__',b'$HASHTBL',b'_AMIPFAT']
VENDOR_GUIDS={
    'AMI':'cbc91f44-a4bc-4a5b-8696-703451d0b053',
    'Phoenix':'389cc6f2-1ea8-467b-ab8a-78e769ae2a15',
}

def sha(b):return hashlib.sha256(b).hexdigest()
def hexn(n):return f'0x{n:X}'
def offsets(b,needle):
    p=0; result=[]
    while (p:=b.find(needle,p))>=0:
        result.append(p);p+=1
    return result

def header(b):
    assert str(uuid.UUID(bytes_le=b[:16]))=='4a3ca68b-7723-48fb-803d-578cc1fec44d'
    size,flags,total,rom,layout=struct.unpack_from('<IIIHH',b,16)
    assert size==rom==4096 and total==len(b)==33558528
    assert flags==0x10001 and layout==0x458
    return dict(capsule_bytes=len(b),header_bytes=size,body_cap_offset=rom,
                flash_bytes=len(b)-rom,physical_base=0x100000000-(len(b)-rom))

def fit(b,h):
    pointer_offset=len(b)-0x40
    address,=struct.unpack_from('<Q',b,pointer_offset)
    p=address-h['physical_base']+h['body_cap_offset']
    assert 0<=p<len(b)-16 and b[p:p+8]==b'_FIT_   '
    count=int.from_bytes(b[p+8:p+11],'little')
    assert 1<=count<=4096 and p+16*count<=len(b)
    table=b[p:p+16*count]; entries=[]
    for i in range(count):
        e=table[i*16:(i+1)*16]
        entry=dict(index=i,address=hexn(int.from_bytes(e[:8],'little')),
                   size_field=int.from_bytes(e[8:11],'little'),reserved=e[11],
                   version=hexn(int.from_bytes(e[12:14],'little')),
                   type=e[14]&127,checksum_valid_flag=bool(e[14]&128),checksum=e[15],raw=e.hex())
        assert entry['reserved']==0
        if entry['type']==1:
            mc_address=int.from_bytes(e[:8],'little')
            off=mc_address-h['physical_base']+h['body_cap_offset']
            assert 0<=off<len(b)-48
            version,revision,date,processor,checksum,loader,flags,data_size,total_size=struct.unpack_from('<9I',b,off)
            assert version==1 and loader==1
            if total_size==0:total_size=2048
            assert total_size>=48 and off+total_size<=len(b)
            entry['microcode']=dict(cap_offset=hexn(off),bytes=total_size,sha256=sha(b[off:off+total_size]),
              processor_signature=hexn(processor),revision=hexn(revision),date_field=hexn(date))
        elif entry['type']==0xA:
            entry['note']='TXT policy has an encoded access descriptor in its address field, not a mapped firmware address.'
        entries.append(entry)
    assert entries[0]['type']==0
    checksum_required=entries[0]['checksum_valid_flag']
    if checksum_required:assert sum(table)&255==0
    return dict(pointer_cap_offset=hexn(pointer_offset),pointer_physical_location='0xFFFFFFC0',
        table_physical_address=hexn(address),table_cap_offset=hexn(p),table_bytes=len(table),entry_count=count,
        table_sha256=sha(table),checksum_required=checksum_required,checksum_sum_mod256=sum(table)&255,
        checksum_interpretation='checked' if checksum_required else 'C_V=0; no checksum validation required',
        raw_signature_offsets=[hexn(v) for v in offsets(b,b'_FIT_   ')],entries=entries,
        startup_acm_entries=[e for e in entries if e['type']==2],
        key_manifest_entries=[e for e in entries if e['type']==0xB],
        boot_policy_manifest_entries=[e for e in entries if e['type']==0xC])

def dump_scan(cap,label):
    base=Path(str(cap)+'.dump');assert base.is_dir()
    records=[]; hits=[]; vendor_files=[]
    for folder,dirs,files in os.walk(base):
        folder=Path(folder)
        if 'info.txt' in files:
            info=(folder/'info.txt').read_text(encoding='utf-8')
            m=re.search(r'^File GUID: ([A-Fa-f0-9-]{36})$',info,re.M)
            if info.startswith('Type: File\n') and m and m[1].lower() in VENDOR_GUIDS.values():
                vendor_files.append(dict(guid=m[1].lower(),path=str(folder.relative_to(base))))
        if dirs or 'body.bin' not in files:continue
        path=folder/'body.bin'; b=path.read_bytes()
        row=dict(path=path.relative_to(base).as_posix(),bytes=len(b),sha256=sha(b));records.append(row)
        for marker in MARKERS:
            found=offsets(b,marker)
            if found:hits.append(row|dict(marker=marker.decode(),offsets=[hexn(v) for v in found],
                context_hex=[b[max(0,v-8):min(len(b),v+40)].hex() for v in found]))
    records.sort(key=lambda x:x['path'])
    payload=(json.dumps(records,sort_keys=True,separators=(',',':'))+'\n').encode()
    out=HERE/f'{label}-leaf-manifest.json';out.write_bytes(payload)
    return dict(existing_extraction=str(base.relative_to(ROOT)),leaf_count=len(records),
        total_leaf_bytes=sum(v['bytes'] for v in records),leaf_manifest=out.name,
        leaf_manifest_sha256=sha(payload),marker_hits=hits,recognized_vendor_hash_ffs=vendor_files,
        limitation='Only existing UEFIExtract leaf bodies are scanned. These are file artifacts, not live SPI reads; opaque encodings and unrecognized protection formats are not ruled out.')

def window(a,b,start,end,label,h):
    assert 0<=start<end<=len(a)
    return dict(label=label,cap_offset=hexn(start),bytes=end-start,
      physical_start=hexn(h['physical_base']+start-h['body_cap_offset']) if start>=h['body_cap_offset'] else None,
      original_sha256=sha(a[start:end]),candidate_sha256=sha(b[start:end]),byte_identical=a[start:end]==b[start:end])

def changed_pages(a,b,first,last):
    changed=[]
    for p in range(first//4096*4096,(last//4096+1)*4096,4096):
        if a[p:p+4096]!=b[p:p+4096]:changed.append(p)
    spans=[]
    for p in changed:
        if spans and spans[-1][1]==p:spans[-1][1]=p+4096
        else:spans.append([p,p+4096])
    return dict(page_size=4096,changed_page_count=len(changed),cap_spans=[dict(start=hexn(x),end_exclusive=hexn(y)) for x,y in spans])

def main():
    a=ORIGINAL.read_bytes();b=CANDIDATE.read_bytes()
    assert sha(a)==ORIGINAL_SHA and sha(b)==CANDIDATE_SHA
    ah,bh=header(a),header(b);assert ah==bh and a[:4096]==b[:4096]
    af,bf=fit(a,ah),fit(b,bh);assert af==bf
    changed=[i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
    assert changed
    count,first,last=len(changed),changed[0],changed[-1];del changed
    assert first>=0x12D1000 and last<0x1CC1000
    assert a[:0x12D1000]==b[:0x12D1000] and a[0x1CC1000:]==b[0x1CC1000:]
    raw={m.decode():dict(original=[hexn(v) for v in offsets(a,m)],candidate=[hexn(v) for v in offsets(b,m)]) for m in MARKERS}
    vendors={name:dict(guid=g,original=[hexn(v) for v in offsets(a,uuid.UUID(g).bytes_le)],
             candidate=[hexn(v) for v in offsets(b,uuid.UUID(g).bytes_le)]) for name,g in VENDOR_GUIDS.items()}
    scans=dict(original=dump_scan(ORIGINAL,'original'),candidate=dump_scan(CANDIDATE,'candidate'))
    windows=[window(a,b,0,4096,'Capsule header (update metadata, not mapped flash)',ah),
             window(a,b,4096,0x701000,'Flash prefix before BIOS region, including release descriptor/ME contents',ah),
             window(a,b,0x12D1000,0x1CC1000,'Rebuilt DXE container',ah),
             window(a,b,len(a)-0x10000,len(a),'Last 64 KiB: comparison window, not a declared IBB range',ah),
             window(a,b,len(a)-16,len(a),'Reset vector final 16 bytes',ah)]
    report=dict(status='STATIC_REVIEW_COMPLETE_LIVE_BOOT_GUARD_POLICY_AND_IBB_COVERAGE_UNRESOLVED',
      date='2026-11-04',target='ROG MAXIMUS Z790 HERO BIOS 3107 / P5 RC2',
      script_sha256=sha(Path(__file__).read_bytes()),no_device_access=True,no_input_file_mutation=True,
      inputs=dict(original=dict(path=str(ORIGINAL.relative_to(ROOT)),bytes=len(a),sha256=sha(a)),
                  candidate=dict(path=str(CANDIDATE.relative_to(ROOT)),bytes=len(b),sha256=sha(b))),
      address_mapping=ah,fit=af,fit_and_all_six_referenced_microcodes_byte_identical=True,
      byte_changes=dict(count=count,first_cap_offset=hexn(first),last_cap_offset_inclusive=hexn(last),
                        confined_to_cap_half_open_range=['0x12D1000','0x1CC1000'],
                        confined_to_physical_half_open_range=['0xFF2D0000','0xFFCC0000'],
                        outside_range_byte_identical=True,pages=changed_pages(a,b,first,last)),
      comparison_windows=windows,raw_marker_scan=raw,known_vendor_hash_guid_scan=vendors,leaf_scans=scans,
      boot_guard=dict(fit_acm_present=bool(af['startup_acm_entries']),fit_km_present=bool(af['key_manifest_entries']),
        fit_bpm_present=bool(af['boot_policy_manifest_entries']),
        manifest_ibb_ranges=None,manifest_ibb_hashes=None,computed_ibb_hash_matches=None,
        changed_dxe_intersects_authenticated_ibb=None,live_hardware_enabled=None,
        conclusion='The pinned release and candidate have identical FIT tables and referenced microcodes. No FIT ACM/KM/BPM is present. No signed IBB range list/digest can be derived from this FIT, so neither authenticated IBB exclusion nor successful Boot Guard verification is established.',
        reason='A release CAP and a candidate are not a capture of the installed SPI image or fused policy. No BTG_SACM_INFO, ACM_POLICY_STATUS, or manufacturing policy was read.'),
      interpretation_limits=[
        'A zero raw/leaf signature count is a bounded negative search, not proof Boot Guard or BIOS Guard is disabled.',
        'Unchanged reset-vector bytes and firmware outside DXE do not establish that DXE is outside an OEM-authenticated region.',
        'FIT metadata validity is distinct from capsule signature validity and updater/FlashBack acceptance.',
        'No KM/BPM signatures or IBB digest can be cryptographically verified when the relevant manifest is absent.',
        'No other motherboard evidence was used as a statement about HERO policy.'],
      next_evidence_needed=[
        'Read-only provenance-bound live SPI/BIOS-region capture if available, to compare the installed FIT and manifests with this release CAP.',
        'Platform-specific read-only BTG_SACM_INFO and ACM_POLICY_STATUS plus manufacturing/security status to characterize live boot enforcement.',
        'An actual successful candidate update and boot is separate evidence; a recovery operation must also be independently observed.'],
      sources=[
        dict(url='https://cdrdv2-public.intel.com/599500/599500_FW_Interface_Table_BIOS_Spec_Rev1p6.pdf',scope='FIT pointer, field layout, checksum flag and ACM/KM/BPM record types; revision 1.6 March 2025'),
        dict(url='https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/key-usage-in-integrated-firmware-images.html',scope='Boot Guard manifests, IBB trust chain, fused policy and runtime status; article scope through 13th-generation Core or earlier'),
        dict(url='https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/intel_fit.h',scope='Independent open-source parser field/type definitions'),
        dict(url='https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/ffs.h',scope='Known AMI/Phoenix vendor protected-range file GUIDs only'),
        dict(url='https://raw.githubusercontent.com/LongSoft/UEFITool/new_engine/common/fitparser.cpp',scope='IBB/PostIBB/OBB manifests are needed to derive protected ranges and hashes')])
    out=HERE/'bootguard-review.json';out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(out),status=report['status'],fit_types=[v['type'] for v in af['entries']],
      raw_markers=raw,leaf_hit_counts={k:len(v['marker_hits']) for k,v in scans.items()},
      leaf_counts={k:v['leaf_count'] for k,v in scans.items()},vendor_guid_hits=vendors,
      byte_changes=report['byte_changes'],windows=[dict(label=w['label'],byte_identical=w['byte_identical']) for w in windows]),indent=2))

if __name__=='__main__': main()
