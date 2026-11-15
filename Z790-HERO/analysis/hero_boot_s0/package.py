"""Archive only final USB payload, sources and test evidence."""
from pathlib import Path
import json,hashlib,zipfile
OUT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    build=json.loads((OUT/'build.json').read_text());tests=json.loads((OUT/'verification.json').read_text());vm=json.loads((OUT/'vm/results.json').read_text())
    digest=sha(OUT/'USB/EFI/BOOT/BOOTX64.EFI')
    assert build['sha256']==tests['image_sha256']==vm['image_sha256']==digest
    assert tests['all_passed'] and vm['all_passed']
    for name,checksum in build['sources'].items():assert sha(OUT/'source'/name)==checksum
    files=[p for name in ('USB','source') for p in (OUT/name).rglob('*') if p.is_file()]
    files+=list(OUT.glob('*.py'))
    files+=[OUT/name for name in ('build.json','verification.json','probe.map','操作步骤.txt','case-context.json','vm/results.json')]
    for case in vm['cases']:
        folder=OUT/'vm'/case['case']
        files.extend(folder/n for n in ('serial.log','result.json','command.json'))
        files.extend(folder/n for n in case['logs'])
        files.extend(folder/n for n in case['screenshots'])
        if (folder/'pixel-check.json').exists():files.append(folder/'pixel-check.json')
    files=sorted(set(files));assert all(p.is_file() for p in files)
    assert all(p.suffix.lower() not in ('.cap','.img','.fd') for p in files)
    manifest=dict(version='S0',payload_sha256=digest,checks=tests['count'],vm_cases=len(vm['cases']),files={p.relative_to(OUT).as_posix():dict(sha256=sha(p),bytes=p.stat().st_size) for p in files})
    mp=OUT/'package-manifest.json';mp.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');files.append(mp)
    dest=OUT.parent/'HERO-BOOT-S0-USB-DIAG.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in files:z.write(p,p.relative_to(OUT).as_posix())
    with zipfile.ZipFile(dest) as z:
        assert z.testzip() is None
        for path,meta in manifest['files'].items():assert hashlib.sha256(z.read(path)).hexdigest()==meta['sha256']
    dest.with_suffix('.zip.sha256').write_text(sha(dest)+'  '+dest.name+'\n',encoding='ascii')
    print(json.dumps(dict(path=str(dest),bytes=dest.stat().st_size,files=len(files),sha256=sha(dest)),indent=2))
if __name__=='__main__':main()
