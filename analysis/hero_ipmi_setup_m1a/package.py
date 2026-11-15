"""Package verified USB bytes and evidence; no CAP, host disk or VM disks."""
from pathlib import Path
import hashlib,json,zipfile
OUT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run():
    build=json.loads((OUT/'build.json').read_text());core=json.loads((OUT/'verification.json').read_text());ui=json.loads((OUT/'ui-verification.json').read_text());vm=json.loads((OUT/'vm/results.json').read_text())
    driver=sha(OUT/'USB/EFI/HERO/HeroIpmiM1a.efi');launcher=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI')
    assert core['all_passed'] and ui['all_passed'] and vm['all_passed']
    assert core['driver_sha256']==ui['driver_sha256']==vm['driver_sha256']==driver
    assert ui['launcher_sha256']==vm['launcher_sha256']==launcher
    for path,digest in build['sources'].items():assert sha(OUT/path)==digest,path
    for p in build['outputs']:assert sha(OUT/p['path'])==p['sha256']
    files=[p for folder in ('USB','source') for p in (OUT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    files+=list(OUT.glob('*.py'))
    files+=[OUT/p for p in ('使用说明.txt','build.json','verification.json','ui-verification.json','forms.json','HERO-M1A-HII.bin','HERO-M1A-MINIMAL-HII.bin','driver.map','launcher.map','vm/results.json')]
    files+=[OUT/'vm'/p for p in vm['logs']]
    files+=[OUT/'vm'/p for p in vm['screenshots']]
    files+=[OUT/'vm'/p for p in ('serial-first-boot.log','serial-second-boot.log','serial.log','commands-first-boot.jsonl','commands-second-boot.jsonl','commands.jsonl','command-first-boot.json','command-second-boot.json','command.json')]
    files=sorted(set(files));assert all(p.is_file() for p in files)
    assert not any(p.suffix.lower() in ('.cap','.img','.fd') for p in files)
    manifest=dict(version='M1a',purpose='USB black-screen diagnosis; target root cause unconfirmed',counts=dict(core_checks=core['count'],ui_checks=ui['count'],vm_checks=vm['count']),files={p.relative_to(OUT).as_posix():dict(sha256=sha(p),bytes=p.stat().st_size) for p in files})
    mp=OUT/'package-manifest.json';mp.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');files.append(mp)
    dest=OUT.parent/'HERO-IPMI-SETUP-M1a-BLACKSCREEN-DIAG.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in files:z.write(p,p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(dest) as z:
        assert z.testzip() is None
        for path,meta in manifest['files'].items():assert hashlib.sha256(z.read(path)).hexdigest()==meta['sha256']
    dest.with_suffix('.zip.sha256').write_text(sha(dest)+'  '+dest.name+'\n',encoding='ascii')
    print(json.dumps(dict(path=str(dest),sha256=sha(dest),bytes=dest.stat().st_size,files=len(files),checks=manifest['counts']),indent=2))
if __name__=='__main__':run()
