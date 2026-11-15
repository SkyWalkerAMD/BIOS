"""Deliver both original file logging and the new read-only optical QR transport."""
from pathlib import Path
import hashlib,json,zipfile,shutil
OUT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    build=json.loads((OUT/'build.json').read_text());tests=json.loads((OUT/'verification.json').read_text())
    capture=json.loads((OUT/'capture-verification.json').read_text());vm=json.loads((OUT/'vm/results.json').read_text())
    image=sha(OUT/'payload/EFI/BOOT/BOOTX64.EFI');iso=OUT/'HERO-HII-M1d-KVM.iso'
    for report in (build,tests,capture,vm):assert report['image_sha256']==image
    assert tests['all_passed'] and capture['all_passed'] and vm['all_passed']
    assert tests['count']==25 and capture['count']==17 and len(vm['cases'])==3
    assert build['iso_sha256']==vm['iso_sha256']==sha(iso)
    assert sha(OUT/'capture_test.dll')==capture['dll_sha256']
    for name,digest in build['sources'].items():assert sha(OUT/'source'/name)==digest
    old=OUT.parent/'hero_hii_m1c'
    preserved={'HERO-HII-M1c-REGISTER-LOG-TEST.zip':'e7ad7c8e1478aafbfb6984dda0568203a7a884ef9699744674e609b923b7d3e5',
               'HERO-IPMI-SETUP-M1b-LAUNCHER-FIX-USB.zip':'2f6859e4fde6bc90c5eb5d30684e34688da606aeb2875490542db0c1de38dbe0'}
    for name,digest in preserved.items():assert sha(OUT.parent/name)==digest
    assert sha(old/'USB/EFI/BOOT/BOOTX64.EFI')=='1830b1ec82a5c4d9c1cde335815ca2507b20ca1ebb0fa30ef43bf2bb555f4509'
    for p in (old/'USB').rglob('*'):
        if p.is_file():
            dest=OUT/'USB-M1c'/p.relative_to(old/'USB');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest);assert sha(dest)==sha(p)
    (OUT/'preserved-artifacts.json').write_text(json.dumps(preserved,indent=2)+'\n')
    files=[p for folder in ('source','USB-M1c','payload') for p in (OUT/folder).rglob('*') if p.is_file()]
    files+=list(OUT.glob('*.py'))
    files+=[OUT/n for n in ('HERO-HII-M1d-KVM.iso','操作步骤.txt','审查说明.txt','case-context.json','build.json',
                            'static-analysis.json','verification.json','capture-verification.json','qr-reuse-provenance.json',
                            'preserved-artifacts.json','diag.map','vm/results.json')]
    for case in vm['cases']:
        assert case['passed'] and case['image_sha256']==image and case['iso_sha256']==sha(iso)
        folder=OUT/'vm'/case['case'];assert json.loads((folder/'result.json').read_text())==case
        files.extend(folder/n for n in ('serial.log','result.json','command.json'))
        for group in ('screenshots','logs'):
            for n,digest in case[group].items():assert sha(folder/n)==digest;files.append(folder/n)
    files=sorted(set(files));assert all(p.is_file() for p in files)
    assert all(p.suffix.lower() not in ('.cap','.img','.fd','.dll','.obj','.ppm') for p in files)
    manifest={'version':'M1d ISO + original M1c USB','image_sha256':image,'iso_sha256':sha(iso),
              'file_logging_efi_sha256':sha(OUT/'USB-M1c/EFI/BOOT/BOOTX64.EFI'),
              'files':{p.relative_to(OUT).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in files}}
    path=OUT/'package-manifest.json';path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');files.append(path)
    dest=OUT.parent/'HERO-IPMI-M1d-KVM-AND-M1c-TXT.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in files:z.write(p,p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(dest) as z:
        assert z.testzip() is None and len(z.infolist())==len(files)
        for n,m in manifest['files'].items():
            data=z.read(n);assert len(data)==m['bytes'] and hashlib.sha256(data).hexdigest()==m['sha256']
    for p in (dest,iso):p.with_suffix(p.suffix+'.sha256').write_text(sha(p)+'  '+p.name+'\n',encoding='ascii')
    print(json.dumps({'zip':str(dest),'bytes':dest.stat().st_size,'files':len(files),'sha256':sha(dest),'iso':str(iso)},indent=2))
if __name__=='__main__':main()
