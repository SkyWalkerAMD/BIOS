from pathlib import Path
import hashlib,json,zipfile
P=Path(__file__).resolve().parent
assert json.loads((P/'offline-verification.json').read_text())['count']==37
assert json.loads((P/'offline-verification.json').read_text())['passed']
rows=[]
for f in sorted(P.rglob('*')):
 if not f.is_file() or f.suffix=='.zip' or f.name in ('SHA256SUMS.json','handoff.json','package-verification.json'):continue
 assert '__pycache__' not in f.parts
 rows.append(dict(path=f.relative_to(P).as_posix(),bytes=f.stat().st_size,sha256=hashlib.sha256(f.read_bytes()).hexdigest()))
(P/'SHA256SUMS.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
z=P/'HERO-FAN-APPLY-KNOWN-20261108.zip';assert not z.exists()
with zipfile.ZipFile(z,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as a:
 for row in rows:a.write(P/row['path'],row['path'])
 a.write(P/'SHA256SUMS.json','SHA256SUMS.json')
with zipfile.ZipFile(z) as a:
 assert a.testzip() is None
 assert set(a.namelist())=={r['path'] for r in rows}|{'SHA256SUMS.json'}
 for row in rows:
  b=a.read(row['path']);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
report=dict(package=z.name,bytes=z.stat().st_size,sha256=hashlib.sha256(z.read_bytes()).hexdigest(),members=len(rows)+1,
 script='fan_apply_known.py',script_sha256=hashlib.sha256((P/'fan_apply_known.py').read_bytes()).hexdigest(),
 offline_tests=37,hardware_test_of_this_tool=False,source_V3b_hardware_evidence=True,
 max_SET=1,keep_mapping=True,no_hide_unhide=True,no_restore_to_zero=True,no_PWM_type_mode_SET=True,
 full_record_gate=58,zip_and_member_sha_readback_verified=True)
(P/'handoff.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
