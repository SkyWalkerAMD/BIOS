"""Local-only evidence packaging; never imports or runs the live worker."""
from pathlib import Path
import hashlib,json,shutil,zipfile
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
audit=ROOT/'analysis/hero_fan_followup_20261108'
dest=P/'audit';dest.mkdir(exist_ok=True)
for name in ('风扇扫描状态与原厂差距-20261108.txt','source-manifest.json',
 'scanner-transition-verification.json','sdr-backend-verification.json',
 'test_scanner_transitions.py','test_sdr_backend.py','inspect_sources.py','ec-guid-occurrences.json'):
 shutil.copy2(audit/name,dest/name)
for folder in ('sources','disassembly'):
 shutil.copytree(audit/folder,dest/folder,dirs_exist_ok=True)
shutil.copy2(ROOT/'analysis/hero_fan_mapping_20261108/test_vendor_arm.py',dest/'frozen-test_vendor_arm.py')
shutil.copy2(ROOT/'analysis/hero_fan_mapping_v2_20261108/fan-map-trial-v2-01.json',P/'fixtures/fan-map-trial-v2-01.json')
rows=[]
for f in sorted(P.rglob('*')):
 if not f.is_file() or f.suffix=='.zip' or f.name in ('SHA256SUMS.json','handoff.json','package-verification.json'):continue
 if '__pycache__' in f.parts:raise AssertionError('Unexpected cache file')
 rows.append(dict(path=f.relative_to(P).as_posix(),bytes=f.stat().st_size,sha256=hashlib.sha256(f.read_bytes()).hexdigest()))
(P/'SHA256SUMS.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
z=P/'HERO-FAN-REARM-V3-20261108-REVIEW.zip'
assert not z.exists(),'Frozen output must not be overwritten'
with zipfile.ZipFile(z,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as out:
 for row in rows:out.write(P/row['path'],row['path'])
 out.write(P/'SHA256SUMS.json','SHA256SUMS.json')
with zipfile.ZipFile(z) as f:
 assert f.testzip() is None
 assert set(f.namelist())=={r['path'] for r in rows}|{'SHA256SUMS.json'}
 for row in rows:
  b=f.read(row['path']);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
report=dict(schema='hero-fan-rearm-handoff-3',package=z.name,bytes=z.stat().st_size,sha256=hashlib.sha256(z.read_bytes()).hexdigest(),
 member_count=len(rows)+1,zip_readback_verified=True,all_members_sha_verified=True,
 script='fan_rearm_trial.py',script_sha256=hashlib.sha256((P/'fan_rearm_trial.py').read_bytes()).hexdigest(),
 tested_offline=60,arm_state_cases=11,arm_backend_cases=5,hardware_test=False,
 normal_set_count=4,max_requests=384,no_pwm_type_mode_set=True,
 has_sdr_metadata_and_possible_persistent_writes=True,complete_rollback=False,
 known_recovery='Root-validated BMC cold reset then R3AUTO real BDS rebuilds sensor visibility; not an exact inverse and loses volatile inventory.')
(P/'handoff.json').write_text(json.dumps(report,indent=2)+'\n')
(P/'package-verification.json').write_text(json.dumps(dict(passed=True,member_count=len(rows)+1,sha256=report['sha256']),indent=2)+'\n')
print(json.dumps(report,indent=2))
