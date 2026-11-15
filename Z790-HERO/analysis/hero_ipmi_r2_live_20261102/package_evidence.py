"""Package only explicit test evidence. Excludes credentials/browser state/control queues."""
from pathlib import Path
import hashlib,json,zipfile
OUT=Path(__file__).resolve().parent
def sha(data):return hashlib.sha256(data).hexdigest()
files={}
for name in ['实机测试结果.txt','live-verification.json','R2-before-full.TXT','R2-success-full.TXT','R2-final-summary.TXT','R2-reload-summary.TXT']:
    files[name]=OUT/name
for folder in ['R2-before-full','R2-success-full','R2-final-summary','R2-reload-summary']:
    for path in (OUT/'captures'/folder).iterdir():
        assert path.suffix in ('.png','.bin','.json')
        files[path.relative_to(OUT).as_posix()]=path
for name in ['101-key-Enter.png','102-key-D.png','131-key-D.png','135-key-Enter.png','249-key-Enter.png','251-key-Enter.png','263-key-Q.png','268-capture.png','270-key-Enter.png','277-key-Q.png','282-key-ArrowLeft.png','R2-web-sensors-after.png','R2-final-web-sensors.png']:
    files['screens/'+name]=OUT/'screens'/name
for name in ['247a-sensor-sample.json','252b-sensor-sample.json','266a-after-unload-sensors.json','282a-final-sensors.json','138d-redfish-thermal-later.json','137-power-after.json']:
    files['responses/'+name]=OUT/'responses'/name
files['decode_captures.py']=OUT.parent/'hero_ipmi_r2/decode_captures.py'
entries={name:path.read_bytes() for name,path in files.items()}
manifest={name:dict(bytes=len(data),sha256=sha(data)) for name,data in sorted(entries.items())}
entries['evidence-manifest.json']=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
target=OUT.parent/'HERO-3107-IPMI-R2-实机测试证据-20261102.zip'
with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for name,data in sorted(entries.items()):z.writestr(name,data)
with zipfile.ZipFile(target) as z:
    assert z.testzip() is None
    assert set(z.namelist())==set(entries)
    for name,data in entries.items():assert z.read(name)==data
result=dict(package=target.name,files=len(entries),bytes=target.stat().st_size,sha256=sha(target.read_bytes()),zip_verified=True)
(OUT/'evidence-package.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
target.with_suffix('.zip.sha256').write_text(result['sha256']+'  '+target.name+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False))
