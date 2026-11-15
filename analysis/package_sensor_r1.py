"""Package the concrete experimental result, its evidence and source scripts."""
from pathlib import Path
import hashlib, json, zipfile

root=Path(__file__).resolve().parent.parent
out=root/'analysis/hero_sensor_r1'
manifest=json.loads((out/'manifest.json').read_text())
archive=root/'analysis/HERO-3001-IPMI-SENSOR-R1-EXPERIMENTAL.zip'
paths=[out/'README.md',out/manifest['output'],out/(manifest['output']+'.sha256'),
       out/'manifest.json',out/'verification.json',out/(manifest['output']+'.report.txt')]
paths+=sorted(p for p in (out/'modules').rglob('*') if p.is_file())
paths+=[root/'analysis'/n for n in ['build_sensor_r1.py','verify_sensor_r1.py','inventory.py','fetch_pydeps.py']]
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in paths:z.write(p,p.relative_to(root).as_posix())
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    cap=z.read('analysis/hero_sensor_r1/'+manifest['output'])
    assert hashlib.sha256(cap).hexdigest()==manifest['output_sha256']
    for m in manifest['modules']:
        ffs=z.read('analysis/hero_sensor_r1/modules/'+m['guid']+'/patched.ffs')
        assert hashlib.sha256(ffs).hexdigest()==m['patched_ffs_sha256']
    assert len([n for n in z.namelist() if n.endswith('.CAP')])==1
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix('.zip.sha256').write_text(digest+'  '+archive.name+'\n',encoding='ascii')
print(json.dumps(dict(file=str(archive),bytes=archive.stat().st_size,entries=len(paths),sha256=digest,
                     capsule_sha256=manifest['output_sha256']),indent=2))
