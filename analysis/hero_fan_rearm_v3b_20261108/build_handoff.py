"""Local-only evidence packaging; never imports or runs the live worker."""
from pathlib import Path
import hashlib,json,shutil,zipfile
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
old=P.parent/'hero_fan_rearm_v3_20261108'
assert hashlib.sha256((old/'fan_rearm_trial.py').read_bytes()).hexdigest()=='2fd8fc13519e51ab98678772d2db03e6c3eb19a1f2ed3f0d962afd09c3041744'
assert hashlib.sha256((old/'HERO-FAN-REARM-V3-20261108-REVIEW.zip').read_bytes()).hexdigest()=='e31c64c60c8c1b62df645821fd1da4f0e27fc5b98eaca31cf289428412e3f6ab'
assert hashlib.sha256((old/'fan-rearm-v3-01.json').read_bytes()).hexdigest()=='c5a15fd519c8e2645c61a8c8ba202627ad14d1705b07c27deb56cd7e0630622a'
for report in ('offline-verification.json','scanner-transition-verification.json','sdr-backend-verification.json','event-mask-verification.json'):
 assert json.loads((P/report).read_text())['passed']
rows=[]
for f in sorted(P.rglob('*')):
 if not f.is_file() or f.suffix=='.zip' or f.name in ('SHA256SUMS.json','handoff.json','package-verification.json'):continue
 if '__pycache__' in f.parts:raise AssertionError('Unexpected cache file')
 rows.append(dict(path=f.relative_to(P).as_posix(),bytes=f.stat().st_size,sha256=hashlib.sha256(f.read_bytes()).hexdigest()))
(P/'SHA256SUMS.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
z=P/'HERO-FAN-REARM-V3B-20261108-REVIEW.zip'
assert not z.exists(),'Frozen output must not be overwritten'
with zipfile.ZipFile(z,'x',zipfile.ZIP_DEFLATED,compresslevel=9) as out:
 for row in rows:out.write(P/row['path'],row['path'])
 out.write(P/'SHA256SUMS.json','SHA256SUMS.json')
with zipfile.ZipFile(z) as f:
 assert f.testzip() is None
 assert set(f.namelist())=={r['path'] for r in rows}|{'SHA256SUMS.json'}
 for row in rows:
  b=f.read(row['path']);assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
report=dict(schema='hero-fan-rearm-handoff-3b',package=z.name,bytes=z.stat().st_size,sha256=hashlib.sha256(z.read_bytes()).hexdigest(),
 member_count=len(rows)+1,zip_readback_verified=True,all_members_sha_verified=True,
 script='fan_rearm_trial.py',script_sha256=hashlib.sha256((P/'fan_rearm_trial.py').read_bytes()).hexdigest(),
 tested_offline=64,arm_state_cases=11,arm_backend_cases=5,arm_event_mask_cases=7,hardware_test=False,
 event_baseline_hex='8005000500',event_fixture_sha256='d40b3896e65dc2ccbd8ea7a6fa2cf24c2b86834766ae64d9638a303c7cbe22f7',
 previous_v3_preserved=True,operational_scope_unchanged_except_exact_baseline_and_schema=True,
 normal_set_count=4,max_requests=384,no_pwm_type_mode_set=True,
 has_sdr_metadata_and_possible_persistent_writes=True,complete_rollback=False,
 known_recovery='Root-validated BMC cold reset then R3AUTO real BDS rebuilds sensor visibility; not an exact inverse and loses volatile inventory.')
(P/'handoff.json').write_text(json.dumps(report,indent=2)+'\n')
(P/'package-verification.json').write_text(json.dumps(dict(passed=True,member_count=len(rows)+1,sha256=report['sha256']),indent=2)+'\n')
print(json.dumps(report,indent=2))
