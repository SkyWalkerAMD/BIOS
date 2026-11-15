"""Package the tested standalone M1c binary, instructions and matching evidence."""
from pathlib import Path
import hashlib,json,zipfile
OUT=Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    build=json.loads((OUT/'build.json').read_text())
    tests=json.loads((OUT/'verification.json').read_text())
    vm=json.loads((OUT/'vm/results.json').read_text())
    context=json.loads((OUT/'case-context.json').read_text())
    binary=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI')
    for report in (build,tests,vm,context):assert report['image_sha256']==binary
    assert tests['all_passed'] and vm['all_passed'] and build['original_form_bytes_preserved']
    assert tests['count']==len(tests['cases'])==35 and len(vm['cases'])==4
    assert all(row['passed'] for row in tests['cases'])
    assert build['static_analysis']=='no diagnostics'
    for name,digest in build['sources'].items():assert sha(OUT/'source'/name)==digest
    assert (OUT/'USB/HERO-IPMI-M1C.TAG').read_bytes()==b'HERO-HII-M1C\r\n'
    preserved={
        'HERO-IPMI-SETUP-M1-USB-TEST.zip':'01e8ed71bcbacd06809ab6eb8c398c5fde33c58b7c1ff36f5b0241913b1784fd',
        'HERO-IPMI-SETUP-M1a-BLACKSCREEN-DIAG.zip':'f2cc3c234c4d18cc14e67c02450cca20aaa96c464635e95b702ef6827d96e997',
        'HERO-IPMI-SETUP-M1b-LAUNCHER-FIX-USB.zip':'2f6859e4fde6bc90c5eb5d30684e34688da606aeb2875490542db0c1de38dbe0',
        'HERO-IPMI-FAN-B2c-KCS-RECOVERY.zip':'da632cb9e07898c267e35b8edee43e01883c0f9dbab5eb5b48e8341990eab69a',
        'HERO-BOOT-S0-USB-DIAG.zip':'5614790f3f31f844dd9871248241f5326fc010622da05dacb95127e17c12acbd'
    }
    for name,digest in preserved.items():assert sha(OUT.parent/name)==digest
    (OUT/'preserved-artifacts.json').write_text(json.dumps(preserved,indent=2)+'\n')
    files=[p for folder in ('USB','source') for p in (OUT/folder).rglob('*') if p.is_file()]
    files+=list(OUT.glob('*.py'))
    files+=[OUT/n for n in ('build.json','verification.json','preserved-artifacts.json',
                           'case-context.json','diag.map','操作步骤.txt','审查说明.txt','vm/results.json')]
    for case in vm['cases']:
        assert case['passed'] and case['image_sha256']==binary
        folder=OUT/'vm'/case['case']
        assert json.loads((folder/'result.json').read_text())==case
        files.extend(folder/n for n in ('serial.log','result.json','command.json'))
        for group in ('logs','screenshots'):
            for name,digest in case[group].items():
                assert sha(folder/name)==digest
                files.append(folder/name)
    files=sorted(set(files));assert all(p.is_file() for p in files)
    assert all(p.suffix.lower() not in ('.cap','.img','.fd') for p in files)
    manifest=dict(version='M1c',purpose='standalone HII registration and log diagnostic',
                  image_sha256=binary,checks=tests['count'],vm_cases=len(vm['cases']),
                  files={p.relative_to(OUT).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p)) for p in files})
    manifest_path=OUT/'package-manifest.json'
    manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    files.append(manifest_path)
    dest=OUT.parent/'HERO-HII-M1c-REGISTER-LOG-TEST.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for p in files:archive.write(p,p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(dest) as archive:
        assert archive.testzip() is None and len(archive.infolist())==len(files)
        for path,meta in manifest['files'].items():
            data=archive.read(path)
            assert len(data)==meta['bytes'] and hashlib.sha256(data).hexdigest()==meta['sha256']
    digest=sha(dest)
    dest.with_suffix('.zip.sha256').write_text(digest+'  '+dest.name+'\n',encoding='ascii')
    print(json.dumps(dict(path=str(dest),bytes=dest.stat().st_size,files=len(files),sha256=digest),indent=2))

if __name__=='__main__':main()
