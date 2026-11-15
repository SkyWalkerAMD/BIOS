"""Validate final artifact bindings and package an explicit file allowlist.

Does not run firmware, flash hardware, or rerun the recorded test matrices.
The unsigned review CAP remains a separate, explicitly identified artifact.
"""
from pathlib import Path
import ast,hashlib,io,json,sys,zipfile

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
import pycdlib

CAP='HERO-3107-IPMI-R2-UNSIGNED-REVIEW.CAP'
ISO='HERO-IPMI-R2-CORE-TEST.iso'
ARCHIVE=ROOT/'analysis/HERO-3107-IPMI-R2-CORE-TEST.zip'
def digest(data):return hashlib.sha256(data).hexdigest()
def sha(path):return digest(path.read_bytes())
def read(name):return json.loads((OUT/name).read_text(encoding='utf-8'))
def write(name,value):
    (OUT/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def info(path):return dict(path=path.relative_to(OUT).as_posix(),bytes=path.stat().st_size,sha256=sha(path))

def validate():
    build=read('build.json')
    for name,h in build['sources'].items():assert sha(OUT/'source'/name)==h,name
    for item in build['outputs']:
        p=OUT/item['path'];assert sha(p)==item['sha256'] and p.stat().st_size==item['bytes'],str(p)
    driver=OUT/'USB/EFI/HERO/HeroIpmiR2.efi';launcher=OUT/'USB/EFI/BOOT/BOOTX64.EFI'
    dh,lh=sha(driver),sha(launcher)
    assert sha(OUT/'HeroIpmiCoreR2.ffs')==build['ffs_sha256']
    assert sha(OUT/ISO)==build['iso_sha256']
    assert sha(OUT/'capture_test.dll')==build['dll_sha256']
    counts={}
    for name,expected in [('verification.json',53),('entry-verification.json',38),('capture-verification.json',18)]:
        report=read(name)
        assert report['all_passed'] and report['count']==len(report['cases'])==expected
        assert all(c['passed'] for c in report['cases'])
        assert report.get('driver_sha256',dh)==dh
        assert report.get('image_sha256',lh)==lh
        assert report.get('dll_sha256',build['dll_sha256'])==build['dll_sha256']
        if 'map_sha256' in report:assert report['map_sha256']==sha(OUT/'driver.map')
        counts[name]=expected
    static=read('static-analysis.json')
    assert len(static)==5 and all(v['returncode']==0 and not v['diagnostics'] for v in static.values())
    vm=read('vm/results.json');assert vm['all_passed'] and len(vm['cases'])==2
    for case in vm['cases']:
        assert case['passed'] and case['driver_sha256']==dh and case['launcher_sha256']==lh
        assert case['iso_sha256']==build['iso_sha256']
        assert case['manual_core'] and case['config_persisted'] and case['core_unload_success']
        for name,h in case['screenshots'].items():assert sha(OUT/'vm'/case['case']/name)==h
        for group in case['groups']:
            assert group['exact_console_match']
            p=OUT/'vm'/case['case']/(group['label']+'.TXT');assert sha(p)==group['sha256']
    iso=pycdlib.PyCdlib();iso.open(str(OUT/ISO))
    try:
        assert iso.eltorito_boot_catalog.validation_entry.platform_id==0xef
        for p in sorted((OUT/'USB').rglob('*')):
            if p.is_file():
                data=io.BytesIO();iso.get_file_from_iso_fp(data,iso_path='/'+p.relative_to(OUT/'USB').as_posix().upper()+';1')
                assert data.getvalue()==p.read_bytes()
    finally:iso.close()
    cap=read('capsule-verification.json')
    original=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
    assert sha(original)==cap['original_sha256'] and sha(OUT/CAP)==cap['candidate_sha256']
    assert cap['originals_byte_identical'] and cap['original_files']==717 and cap['result_files']==718
    first,last=map(lambda x:int(x,16),cap['changed_interval'])
    old=original.read_bytes();new=(OUT/CAP).read_bytes();ffs=(OUT/'HeroIpmiCoreR2.ffs').read_bytes()
    assert len(new)==len(old)==cap['length'] and last-first==len(ffs)==cap['changed_range_bytes']
    assert old[:first]==new[:first] and old[last:]==new[last:]
    assert old[first:last]==b'\xff'*len(ffs) and new[first:last]==ffs
    pe=ROOT/cap['added_module']['path']/'1 PE32 image section/body.bin'
    assert pe.read_bytes()==driver.read_bytes()
    for item in read('reference/index.json')['items']:
        assert sha(OUT/item['path'])==item['sha256']
        assert sha(ROOT/item['source'])==item['sha256']
    for item in read('reference/edk2/sources.json'):
        assert sha(OUT/'reference/edk2'/item['path'])==item['sha256']
    for p in OUT.glob('*.py'):ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
    result=dict(all_passed=True,kind='artifact consistency; not another hardware test',source_hashes_checked=len(build['sources']),
      recorded_test_counts=counts,vm_cases_checked=2,static_analysis_files=5,
      driver_sha256=dh,launcher_sha256=lh,iso_sha256=build['iso_sha256'],capsule_sha256=sha(OUT/CAP),
      original_sha256=sha(original),iso_usb_pe_identical=True,capsule_pe_identical=True,
      original_ffs_count=717,new_ffs_count=718,only_ffs_insertion_changed=True,
      rea_reference_copy_hashes_verified=True,hardware_flashed=False,target_board_validated=False,
      limits=['Source/report/artifact consistency only; cannot establish hardware behavior or ASUS capsule authentication.'])
    write('delivery-verification.json',result)
    return result

def main():
    result=validate()
    names=[ISO,'HeroIpmiCoreR2.ffs','build.py','build_capsule.py','package.py','collect_reference.py',
      'verify.py','verify_entry.py','verify_capture.py','run_vm.py','decode_captures.py',
      'driver.map','launcher.map','build.json','baseline-provenance.json','verification.json',
      'entry-verification.json','capture-verification.json','static-analysis.json','capsule-verification.json',
      'delivery-verification.json','使用步骤.txt','适配与REA解析记录.txt','编译与审查说明.txt',
      'OFFLINE-success.txt','OFFLINE-startup_c1.txt','OFFLINE-postcheck_unchanged.txt','vm/results.json']
    files={OUT/name for name in names}
    for folder in ('source','USB','reference'):
        files.update(p for p in (OUT/folder).rglob('*') if p.is_file())
    for folder in ('iso_sata_1280x800','usb_640x480'):
        files.update(p for p in (OUT/'vm'/folder).iterdir() if p.is_file() and p.suffix.lower() in ('.png','.txt','.json','.log'))
    files=sorted(files,key=lambda p:p.relative_to(OUT).as_posix())
    for p in files:
        assert p.is_file() and p.resolve().is_relative_to(OUT.resolve())
        assert not any(x in p.parts for x in ('runtime-temp','zig-global','zig-local','__pycache__'))
    manifest=dict(version='HERO3107-IPMI-R2',target='ROG MAXIMUS Z790 HERO BIOS 3107 / BMC 1.3.13',
      entries=[info(p) for p in files],separate_review_candidate=info(OUT/CAP),
      excluded=['CAP: separate unsigned review candidate','Host compiler/debugger/runtime caches and credentials',
        'Historical prepare scripts and failed intermediate harness results','QEMU drive images and test DLL'],
      limits=result['limits']+['Rebuild/test scripts require the documented existing BIOS workspace dependencies.'])
    write('package-manifest.json',manifest)
    with zipfile.ZipFile(ARCHIVE,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in files+[OUT/'package-manifest.json']:
            z.write(p,'hero_ipmi_r2/'+p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(ARCHIVE) as z:
        assert len(z.namelist())==len(set(z.namelist()))==len(files)+1
        assert z.testzip() is None
        for item in manifest['entries']:
            data=z.read('hero_ipmi_r2/'+item['path'])
            assert len(data)==item['bytes'] and digest(data)==item['sha256']
        assert z.read('hero_ipmi_r2/package-manifest.json')==(OUT/'package-manifest.json').read_bytes()
        assert all(not n.upper().endswith('.CAP') for n in z.namelist())
    check=dict(archive=str(ARCHIVE.relative_to(ROOT)),bytes=ARCHIVE.stat().st_size,sha256=sha(ARCHIVE),
      entries=len(files)+1,all_entry_hashes_verified=True,zip_crc_verified=True,candidate_separate=True,
      test_counts=result['recorded_test_counts'],hardware_flashed=False)
    ARCHIVE.with_suffix('.zip.sha256').write_text(check['sha256']+'  '+ARCHIVE.name+'\n',encoding='ascii')
    ARCHIVE.with_suffix('.zip.package-check.json').write_text(json.dumps(check,indent=2)+'\n',encoding='utf-8')
    for p in (OUT/ISO,OUT/CAP):p.with_name(p.name+'.sha256').write_text(sha(p)+'  '+p.name+'\n',encoding='ascii')
    print(json.dumps(check,indent=2))
if __name__=='__main__':main()
