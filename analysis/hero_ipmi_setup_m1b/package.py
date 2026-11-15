"""Archive final M1b payload, source changes, instructions, and checked evidence."""
from pathlib import Path
import hashlib,json,zipfile,difflib
OUT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    build=json.loads((OUT/'build.json').read_text());tests=json.loads((OUT/'verification.json').read_text());vm=json.loads((OUT/'vm/results.json').read_text())
    launcher=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI');driver=sha(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi')
    for data in (build,tests,vm):assert data['launcher_sha256']==launcher and data['driver_sha256']==driver
    assert tests['all_passed'] and vm['all_passed'] and build['driver_unchanged']
    for name,digest in build['sources'].items():assert sha(OUT/'source'/name)==digest
    preserved={'HERO-IPMI-SETUP-M1-USB-TEST.zip':'01e8ed71bcbacd06809ab6eb8c398c5fde33c58b7c1ff36f5b0241913b1784fd',
               'HERO-IPMI-SETUP-M1a-BLACKSCREEN-DIAG.zip':'f2cc3c234c4d18cc14e67c02450cca20aaa96c464635e95b702ef6827d96e997',
               'HERO-IPMI-FAN-B2c-KCS-RECOVERY.zip':'da632cb9e07898c267e35b8edee43e01883c0f9dbab5eb5b48e8341990eab69a',
               'HERO-BOOT-S0-USB-DIAG.zip':'5614790f3f31f844dd9871248241f5326fc010622da05dacb95127e17c12acbd'}
    for name,digest in preserved.items():assert sha(OUT.parent/name)==digest
    (OUT/'preserved-artifacts.json').write_text(json.dumps(preserved,indent=2)+'\n')
    original=(OUT.parent/'hero_ipmi_setup_m1a/source/launcher.c').read_text().splitlines(keepends=True)
    revised=(OUT/'source/launcher.c').read_text().splitlines(keepends=True)
    (OUT/'launcher-M1a-to-M1b.diff').write_text(''.join(difflib.unified_diff(original,revised,fromfile='M1a/source/launcher.c',tofile='M1b/source/launcher.c')),encoding='utf-8')
    files=[p for folder in ('USB','source') for p in (OUT/folder).rglob('*') if p.is_file()]
    files+=list(OUT.glob('*.py'))
    files+=[OUT/n for n in ('build.json','verification.json','original-audit.json','static-analysis.json','preserved-artifacts.json','case-context.json','launcher.map','launcher-M1a-to-M1b.diff','操作步骤.txt','代码审查与修改说明.txt','vm/results.json')]
    for case in vm['cases']:
        folder=OUT/'vm'/case['case']
        files.extend(folder/n for n in ('serial.log','result.json','command.json'))
        files.extend(folder/n for n in case['logs']);files.extend(folder/n for n in case['screenshots'])
        if (folder/'pixel-check.json').exists():files.append(folder/'pixel-check.json')
    files=sorted(set(files));assert all(p.is_file() for p in files)
    assert all(p.suffix.lower() not in ('.cap','.img','.fd') for p in files)
    manifest=dict(version='M1b',launcher_sha256=launcher,driver_sha256=driver,checks=tests['count'],vm_cases=len(vm['cases']),files={p.relative_to(OUT).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p)) for p in files})
    manifest_path=OUT/'package-manifest.json';manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');files.append(manifest_path)
    dest=OUT.parent/'HERO-IPMI-SETUP-M1b-LAUNCHER-FIX-USB.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for p in files:archive.write(p,p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(dest) as archive:
        assert archive.testzip() is None
        for path,meta in manifest['files'].items():assert hashlib.sha256(archive.read(path)).hexdigest()==meta['sha256']
    digest=sha(dest);dest.with_suffix('.zip.sha256').write_text(digest+'  '+dest.name+'\n',encoding='ascii')
    print(json.dumps(dict(path=str(dest),bytes=dest.stat().st_size,files=len(files),sha256=digest),indent=2))
if __name__=='__main__':main()
