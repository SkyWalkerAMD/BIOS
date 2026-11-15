"""Package only USB payload, reviewable sources and evidence; no CAP in USB ZIP."""
from pathlib import Path
import hashlib,json,zipfile
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    build=json.loads((OUT/'build.json').read_text());tests=json.loads((OUT/'verification.json').read_text());vm=json.loads((OUT/'vm/results.json').read_text());cap=json.loads((OUT/'capsule-verification.json').read_text())
    driver=OUT/'USB/EFI/HERO/HeroIpmiM1.efi'
    assert tests['all_passed'] and vm['all_passed'] and sha(driver)==tests['driver_sha256']==vm['driver_sha256']
    for item in build['outputs']:assert sha(OUT/item['path'])==item['sha256']
    for path,expected in build['sources'].items():assert sha(OUT/path)==expected
    assert sha(OUT/'HERO-3107-IPMI-M1-UNSIGNED-REVIEW.CAP')==cap['candidate_sha256']
    selected=list((OUT/'USB').rglob('*'))+list((OUT/'source').rglob('*'))+list(OUT.glob('*.py'))
    selected += [OUT/n for n in ('使用说明.md','build.json','verification.json','capsule-verification.json','forms.json','HeroIpmiSetupM1.ffs','HERO-M1-HII.bin','driver.map','launcher.map')]
    selected += [OUT/'vm/results.json']+[OUT/'vm'/n for n in vm['screenshots']]+[OUT/'vm'/n for n in vm['logs']]
    selected += list(OUT.glob('OFFLINE-*.txt'))
    files=sorted({p for p in selected if p.is_file()},key=lambda p:str(p.relative_to(OUT)))
    assert not any(p.suffix.lower() in ('.cap','.img','.fd') for p in files)
    manifest={str(p.relative_to(OUT)).replace('\\','/'):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in files}
    (OUT/'package-manifest.json').write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    archive=ROOT/'analysis/HERO-IPMI-SETUP-M1-USB-TEST.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in files+[OUT/'package-manifest.json']:z.write(p,str(p.relative_to(OUT)).replace('\\','/'))
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name,m in manifest.items():
            data=z.read(name);assert len(data)==m['bytes'] and hashlib.sha256(data).hexdigest()==m['sha256']
    (archive.with_name(archive.name+'.sha256')).write_text(sha(archive)+'  '+archive.name+'\n')
    print(json.dumps(dict(archive=str(archive),files=len(files)+1,bytes=archive.stat().st_size,sha256=sha(archive)),indent=2))
if __name__=='__main__':main()
