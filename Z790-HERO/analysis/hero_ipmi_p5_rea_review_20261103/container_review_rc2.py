"""Read-only RC2 audit, using the independent container parser and extracted bytes."""
from pathlib import Path
from collections import defaultdict, Counter
import argparse, json, re
from container_review import ROOT, HERE, BASE, SIZE, DRIVER, WRAPPER, SETUP, SPF, sha, up, read_image, sections, decode, depex_tokens

def extracted_files(cap):
    folder=cap.with_name(cap.name+'.dump')
    found=defaultdict(list)
    for info in folder.rglob('info.txt'):
        text=info.read_text(encoding='utf-8')
        lines=text.splitlines()
        if not lines or lines[0]!='Type: File': continue
        match=re.search(r'^File GUID: ([0-9A-Fa-f-]{36})$',text,re.M)
        if not match: continue
        header=(info.parent/'header.bin').read_bytes()
        bodyfile=info.parent/'body.bin'
        body=bodyfile.read_bytes() if bodyfile.exists() else b''
        full=re.search(r'^Full size: ([0-9A-Fa-f]+)h',text,re.M)
        assert full and len(header)+len(body)==int(full[1],16)
        found[match[1].lower()].append(dict(path=info.parent,data=header+body))
    assert found
    return found

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--candidate',type=Path,default=HERE/'rc2/HERO-3107-IPMI-P5-RC2-UNSIGNED.CAP')
    parser.add_argument('--report',type=Path,default=HERE/'rc2-container-review.json')
    args=parser.parse_args()
    assert args.report.resolve().is_relative_to(HERE.resolve())
    origpath=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
    rc1path=ROOT/'analysis/hero_ipmi_p5/candidate/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP'
    old=read_image(origpath); rc1=read_image(rc1path); new=read_image(args.candidate)
    assert sha(new['cap'])=='5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521'
    assert len(old['cap'])==len(new['cap'])==len(rc1['cap'])==33558528
    assert old['cap'][:BASE]==new['cap'][:BASE]
    assert old['cap'][BASE+SIZE:]==new['cap'][BASE+SIZE:]
    assert DRIVER not in new['outer_files'] and DRIVER in new['inner_files']
    assert set(new['outer_files'])==set(old['outer_files'])
    assert set(new['inner_files'])-set(old['inner_files'])=={DRIVER}
    assert not set(old['inner_files'])-set(new['inner_files'])
    assert new['inner_files'][DRIVER]['data']==rc1['outer_files'][DRIVER]['data']
    assert new['inner_files'][DRIVER]['offset']==int(rc1['inner_info']['used_end'],16)
    direct_identical=0
    for layer,changed in [('outer',{WRAPPER}),('inner',{SETUP,SPF})]:
        assert old[layer+'_info']['header_sha256']==new[layer+'_info']['header_sha256']
        for key,entry in old[layer+'_files'].items():
            if key not in changed:
                assert entry['data']==new[layer+'_files'][key]['data'];direct_identical+=1
    for key in rc1['inner_files']:
        assert rc1['inner_files'][key]['data']==new['inner_files'][key]['data']
        assert rc1['inner_files'][key]['offset']==new['inner_files'][key]['offset']
    driver=new['inner_files'][DRIVER]; driver_parts=sections(driver['data'][24:])
    assert [s['type'] for s in driver_parts]==[0x13,0x10,0x15]
    driver_depex=depex_tokens(driver_parts[0]['body'])
    expecteddriver=ROOT/'analysis/hero_ipmi_p5/USB/EFI/HERO/HeroIpmiP5.efi'
    assert driver_parts[1]['body']==expecteddriver.read_bytes()
    original_setup=sections(old['inner_files'][SETUP]['data'][24:])
    setup_parts=sections(new['inner_files'][SETUP]['data'][24:])
    assert [s['type'] for s in setup_parts]==[0x13,0x2,0x14]
    assert setup_parts[0]['data']==original_setup[0]['data'] and setup_parts[-1]['data']==original_setup[-1]['data']
    expanded,_=decode(setup_parts[1]); pe_sections=sections(expanded)
    assert len(pe_sections)==1 and pe_sections[0]['type']==0x10
    expectedsetup=ROOT/'analysis/hero_ipmi_p5/Setup-P5-RESOURCE-REVIEW.efi'
    assert pe_sections[0]['body']==expectedsetup.read_bytes()
    spf_parts=sections(new['inner_files'][SPF]['data'][24:]); assert len(spf_parts)==1
    expanded,_=decode(spf_parts[0]); spf_sections=sections(expanded)
    assert [s['type'] for s in spf_sections]==[0x18,0x15]
    expectedspf=ROOT/'analysis/hero_ipmi_p5/AMITSESetupData-P5.bin'
    assert spf_sections[0]['body'][16:]==expectedspf.read_bytes()
    oldfiles=extracted_files(origpath); newfiles=extracted_files(args.candidate); rc1files=extracted_files(rc1path)
    assert set(newfiles)-set(oldfiles)=={DRIVER} and not set(oldfiles)-set(newfiles)
    changed=[]; identical=0
    for key,entries in oldfiles.items():
        assert len(entries)==len(newfiles[key])
        if Counter(sha(e['data']) for e in entries)==Counter(sha(e['data']) for e in newfiles[key]): identical+=len(entries)
        else: changed.append(key)
    assert set(changed)=={SETUP,SPF,WRAPPER}
    assert sum(map(len,oldfiles.values()))==717 and sum(map(len,newfiles.values()))==718 and identical==714
    assert set(newfiles)==set(rc1files)
    rc1changed=[]
    for key in rc1files:
        if Counter(sha(e['data']) for e in rc1files[key])!=Counter(sha(e['data']) for e in newfiles[key]):rc1changed.append(key)
    assert rc1changed==[WRAPPER]
    extracted_exact=[]
    for key,reference in [(SETUP,expectedsetup),(DRIVER,expecteddriver)]:
        assert len(newfiles[key])==1
        bodies=[f for f in newfiles[key][0]['path'].rglob('body.bin') if f.parent.name.endswith('PE32 image section')]
        assert len(bodies)==1 and bodies[0].read_bytes()==reference.read_bytes()
        extracted_exact.append(dict(guid=key,path=str(bodies[0].relative_to(ROOT)),bytes=reference.stat().st_size,sha256=sha(reference.read_bytes())))
    spfmatches=[f for f in newfiles[SPF][0]['path'].rglob('body.bin') if f.read_bytes()==expectedspf.read_bytes()]
    assert len(spfmatches)==1
    extracted_exact.append(dict(guid=SPF,path=str(spfmatches[0].relative_to(ROOT)),bytes=expectedspf.stat().st_size,sha256=sha(expectedspf.read_bytes())))
    report=dict(scope='Independent binary parsing plus whole-CAP comparison of UEFIExtract output; no hardware execution',
        passed=True,target=str(args.candidate.resolve()),target_sha256=sha(new['cap']),original_sha256=sha(old['cap']),
        outside_dxe_volume_byte_identical=True,direct_container_unchanged_ffs=direct_identical,
        original_files=717,candidate_files=718,byte_identical_existing_files=identical,changed_ffs=changed,added_ffs=DRIVER,
        rc1_to_rc2_changed_ffs=rc1changed,rc1_existing_inner_file_offsets_preserved=True,
        driver_only_in_inner_fv=True,driver_ffs_identical_to_rc1=True,
        driver=dict(offset_in_inner_fv=hex(driver['offset']),ffs_bytes=driver['size'],aligned_bytes=up(driver['size'],8),
            depex=driver_depex,
            rc1_extracted_path=str(rc1files[DRIVER][0]['path'].relative_to(ROOT)),
            rc2_extracted_path=str(newfiles[DRIVER][0]['path'].relative_to(ROOT))),
        candidate={key:new[key] for key in ['outer_info','inner_info','wrapper_compression']},
        extracted_payloads_exact=extracted_exact,setup_depex_and_version_preserved=True,
        finding_C1='Resolved structurally by placing the unchanged new driver into the existing inner DXE FV. Actual dispatch remains a hardware validation item.',
        unknowns=['FlashBack acceptance','Native cold/warm boot dispatch and menu rendering','Live platform boot enforcement'])
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ['passed','target_sha256','original_files','candidate_files','byte_identical_existing_files','changed_ffs','added_ffs','driver_only_in_inner_fv','rc1_to_rc2_changed_ffs','finding_C1']},indent=2))

if __name__=='__main__': main()
