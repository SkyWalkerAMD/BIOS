"""Package verified probe bytes and source; no CAP files or flash utilities."""
from pathlib import Path
import hashlib,json,zipfile
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_ipmi_probe'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

if __name__=='__main__':
    build=json.loads((OUT/'build.json').read_text())
    verify=json.loads((OUT/'verification.json').read_text())
    exe=OUT/build['image']
    assert sha(exe)==build['sha256']==verify['image_sha256']
    assert len(verify['scenarios'])==22 and all(v['passed'] for v in verify['scenarios'])
    for name,h in build['source_hashes'].items():assert sha(OUT/'source'/name)==h
    files={p.relative_to(OUT).as_posix():p for p in (OUT/'USB').rglob('*') if p.is_file()}
    files.update({n:OUT/n for n in ('README.md','build.json','verification.json','example-MOCK-log.txt','probe.map')})
    for p in (OUT/'source').glob('*'):
        if p.is_file():files['source/'+p.name]=p
    files['source/reference/sources.json']=OUT/'source/reference/sources.json'
    for name in ('build_hero_ipmi_probe.py','verify_hero_ipmi_probe.py','fetch_uefi_probe_tools.py','package_hero_ipmi_probe.py'):
        files['workspace_scripts/'+name]=ROOT/'analysis'/name
    checks=''.join(f'{sha(p)}  {name}\n' for name,p in sorted(files.items()))
    (OUT/'SHA256SUMS.txt').write_text(checks,encoding='utf-8')
    files['SHA256SUMS.txt']=OUT/'SHA256SUMS.txt'
    archive=ROOT/'analysis/HERO-IPMI-NOFLASH-PROBE-A1.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,p in sorted(files.items()):z.write(p,name)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        assert hashlib.sha256(z.read(build['image'])).hexdigest()==build['sha256']
        assert not any(n.lower().endswith(('.cap','.rom','.bin')) for n in z.namelist())
        assert z.read('USB/HERO-PROBE-USB.TAG')==b'HERO-IPMI-PROBE-A1\r\n'
    (archive.with_suffix('.zip.sha256')).write_text(sha(archive)+'  '+archive.name+'\n',encoding='utf-8')
    print(json.dumps(dict(archive=str(archive),bytes=archive.stat().st_size,sha256=sha(archive),entries=len(files)),indent=2))
