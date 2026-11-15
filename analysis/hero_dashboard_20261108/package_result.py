"""Package only selected Dashboard evidence; no credentials or live controller."""
from pathlib import Path
import hashlib,json,zipfile

OUT=Path(__file__).resolve().parent
DEST=OUT/'HERO-DASHBOARD-20261108-实测记录.zip'
files=[
 'Dashboard实机同步结果-20261108.txt','dashboard-verification.json',
 'identity-from-live-smbios.json','dmi-read-before.json','dmi-publication-result.json',
 'publication-plan.json','payload-tests.json','frontend-analysis-summary.json',
 'frontend-focused-rea.json','frontend-focused/dashboard-info.js','frontend-focused/slice-manifest.json',
 'responses/002-evaluate.json','responses/004-get.json','responses/005-evaluate.json',
 'responses/008-login.json','responses/010-stop.json',
 'screens/dashboard-before.png','screens/dashboard-after.png',
 'donor/donor-dmi-machine-code.json','donor/hero71-selector0.request.bin',
 'donor/hero71-selector2.request.bin','donor/evidence-summary.json',
 'donor/B1DA0ADF-4F77-4070-A88E-BFFE1C60529A-39ca0-3a1a0.asm',
 'donor/B1DA0ADF-4F77-4070-A88E-BFFE1C60529A-3a0f4-3ab20.asm','dashboard_payload.py',
]
for p in sorted((OUT/'backend').iterdir()):
 if p.suffix in ('.md','.json','.txt'):files.append(p.relative_to(OUT).as_posix())
for p in sorted((OUT/'donor').iterdir()):
 if p.suffix in ('.md','.txt') and not p.name.endswith('.asm'):files.append(p.relative_to(OUT).as_posix())
rows=[]
for name in files:
 p=OUT/name
 b=p.read_bytes()
 rows.append({'file':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
manifest={'files':rows,'actual_dashboard_verified':True,'automatic_firmware_integration':False,
          'live_controller_or_authentication_material_included':False,
          'firmware_image_included':False,
          'scope':'Readback, source-pinned packets, vendor code evidence and actual browser display; no replay script.'}
manifest_bytes=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
with zipfile.ZipFile(DEST,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name in files:z.write(OUT/name,name)
 z.writestr('MANIFEST.json',manifest_bytes)
with zipfile.ZipFile(DEST) as z:
 assert z.testzip() is None
 for row in rows:
  b=z.read(row['file']);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
 assert z.read('MANIFEST.json')==manifest_bytes
report={'file':DEST.name,'bytes':DEST.stat().st_size,'sha256':hashlib.sha256(DEST.read_bytes()).hexdigest(),
        'members':len(rows)+1,'all_CRC_and_SHA_verified':True,'contains_BIOS_image':False}
(OUT/'package-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
