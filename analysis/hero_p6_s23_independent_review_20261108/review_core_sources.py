"""Independent frozen S23 source/PE/FFS review; does not rebuild any artifact."""
from pathlib import Path
import difflib,hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
A=ROOT/'analysis/hero_p6_s22_20261108';B=ROOT/'analysis/hero_p6_s23_20261108'
PE_PIN='1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc'
FFS_PIN='15c1e38b0693105a3f2abad917f375cc0d36285d9e4d8402013e5088244766fa'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def rec(p):
    b=p.read_bytes();return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def sections(raw):
    result=[];at=24
    while at<len(raw):
        n=int.from_bytes(raw[at:at+3],'little')
        assert n>=4 and at+n<=len(raw)
        result.append((raw[at+3],raw[at+4:at+n]))
        end=at+n
        if end==len(raw):return result
        at=(end+3)&~3
        assert at<len(raw) and raw[end:at]==bytes(at-end),'trailing/nonzero padding'
    raise AssertionError('no exact final section')
def main():
    changes=[];unchanged=[];patch=[]
    for group in ('source','backend'):
        old={p.relative_to(A/group) for p in (A/group).rglob('*') if p.is_file()}
        new={p.relative_to(B/group) for p in (B/group).rglob('*') if p.is_file()}
        assert not old-new
        for name in sorted(new):
            x,y=A/group/name,B/group/name
            if x.exists() and x.read_bytes()==y.read_bytes():unchanged.append(rec(y));continue
            assert group=='source' and name.as_posix() in {'driver.c','p5.h','publisher.c','expected_p5.h'},name
            changes.append(rec(y))
            if name.as_posix()!='expected_p5.h':
                patch.extend(difflib.unified_diff(x.read_text().splitlines(True) if x.exists() else [],y.read_text().splitlines(True),fromfile=x.relative_to(ROOT).as_posix(),tofile=y.relative_to(ROOT).as_posix()))
    assert {Path(x['path']).name for x in changes}=={'driver.c','p5.h','publisher.c','expected_p5.h'}
    old=(A/'source/driver.c').read_text();new=(B/'source/driver.c').read_text()
    driver_diff=[line for line in difflib.unified_diff(old.splitlines(True),new.splitlines(True)) if line.startswith(('+','-')) and not line.startswith(('+++','---'))]
    assert len(driver_diff)==2 and all('HERO-IPMI-P6-S2' in line for line in driver_diff)
    assert (B/'source/p5.h').read_text().replace('int p5_package_kind(const uint8_t *,UN);\n','')==(A/'source/p5.h').read_text()
    pe_path=B/'HeroIpmiP6.efi';raw=pe_path.read_bytes();assert rec(pe_path)['sha256']==PE_PIN
    pe=pefile.PE(data=raw)
    assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==11
    assert pe.verify_checksum() and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    assert not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    fp=B/'HeroIpmiNativeP6.ffs';ffs=fp.read_bytes();assert rec(fp)['sha256']==FFS_PIN
    assert int.from_bytes(ffs[20:23],'little')==len(ffs)
    assert uuid.UUID(bytes_le=ffs[:16])==uuid.UUID('261135b0-7b73-49c0-bcc8-2f9cf4eef19e')
    assert ffs[18]==7 and ffs[17]==0xaa and ffs[23]==0xf8
    assert (sum(ffs[:24])-ffs[17]-ffs[23])%256==0
    sec=sections(ffs);priorsec=sections((A/'HeroIpmiNativeP6.ffs').read_bytes())
    assert [t for t,_ in sec]==[0x13,0x10,0x15]
    assert sec[0]==priorsec[0] and sec[2]==priorsec[2] and sec[1][1]==raw
    forms=[]
    for name,pin,size in [('P5','b295f8ce9b5f38f366f3cf8c9c8895f218bd009c2a9c9144ea2ff6c5ff3f98c8',326465),('P6','3ec34187a90cfefeac1728a8e7b67e447d6bafc07d5d30d61d4396c94c0fef08',327223)]:
        p=B/'native'/('Setup-forms-'+name+'.bin');r=rec(p)
        assert r['sha256']==pin and r['bytes']==size and raw.count(p.read_bytes())==1
        forms.append(r)
    machine=json.loads((OUT/'dual-resource-actual-pe-review.json').read_text())
    assert machine['passed'] and machine['count']==23 and machine['core_sha256']==PE_PIN
    result={'passed':True,'core':rec(pe_path),'ffs':rec(fp),'exact_forms':forms,
        'changed_source':changes,'unchanged_source_and_backend':unchanged,'driver_change':'Version description only; actual S21S callback/settings/transport logic preserved from S22.',
        'actual_pe_independent_tests':rec(OUT/'dual-resource-actual-pe-review.json'),
        'checks':{'full_forms_embedded_once_each':True,'pe_checksum_machine_subsystem_no_imports':True,'ffs_header_checksum_and_size':True,'strict_section_stream_without_final_padding':True,'depex_and_ui_unchanged':True},
        'review':[
            'Every HII export failure and malformed package aborts full enumeration; uniqueness is not inferred from a partial list.',
            'Exactly one complete known Forms package is accepted. P5 publishes only its 40 existing values; P6 publishes 41.',
            'All ten languages and value IDs are validated before first SetString. Publish re-exports and requires the original exact resource kind.',
            'Diagnostic additions append bounded RAM metadata, with no additional UEFI/BMC service calls.',
            'PCI, BMC command policy, configuration persistence and synchronous AfterBoot state machine remain byte-identical source to reviewed S22.'
        ],
        'remaining_limits':[
            'These local tests use synthetic HII services; they do not establish actual host15 binding or native UI results.',
            'P5 compatibility supplies status strings only; it does not add P6 configuration widgets to old firmware.',
            'No new CAP flashing, first native DXE/SetupEnter timing, F10 configuration write or FlashBack recovery is validated here.'
        ],'no_hardware_actions':True,'frozen_previous_artifacts_modified':False}
    (OUT/'source-differences.patch').write_text(''.join(patch),encoding='utf-8')
    (OUT/'core-review.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'report':rec(OUT/'core-review.json')},indent=2))
if __name__=='__main__':main()
