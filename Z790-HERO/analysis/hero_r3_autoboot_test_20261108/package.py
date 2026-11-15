from pathlib import Path
import hashlib,json,zipfile
OUT=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 build=json.loads((OUT/'build.json').read_text())
 assert sha(OUT/'HERO-R3-AUTO-BDS-TEST.iso')==build['iso_sha256']
 for name in ('launcher-verification.json','capture-verification.json'):assert json.loads((OUT/name).read_text())['all_passed']
 for name in ('vm-final','vm-usb'):assert json.loads((OUT/name/'result.json').read_text())['passed']
 files=[p for p in (OUT/'USB').rglob('*') if p.is_file()]+[p for p in (OUT/'source').rglob('*') if p.is_file()]
 files +=[OUT/n for n in ('HERO-R3-AUTO-BDS-TEST.iso','decode_captures.py','build.py','verify_launcher.py','verify_capture.py','run_vm.py','build.json','launcher-verification.json','capture-verification.json','操作与验证说明.txt','package.py')]
 for name in ('vm-final','vm-usb'):files += [p for p in (OUT/name).glob('*') if p.suffix in ('.TXT','.json','.png')]
 rows=[dict(path=p.relative_to(OUT).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(files)]
 manifest=OUT/'package-manifest.json';manifest.write_text(json.dumps(dict(version='R3AUTO',files=rows),indent=2)+'\n');files.append(manifest)
 archive=OUT/'HERO-R3-AUTO-BDS-TEST-20261108.zip'
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for p in files:z.write(p,p.relative_to(OUT).as_posix())
 with zipfile.ZipFile(archive) as z:
  for row in rows:assert hashlib.sha256(z.read(row['path'])).hexdigest()==row['sha256']
 result=dict(verified=True,files=len(files),zip_bytes=archive.stat().st_size,zip_sha256=sha(archive),iso_sha256=build['iso_sha256']);(OUT/'package-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
