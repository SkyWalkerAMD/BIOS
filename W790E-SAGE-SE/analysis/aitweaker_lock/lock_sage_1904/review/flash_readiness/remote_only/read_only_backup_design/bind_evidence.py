"""Hash only local design/source evidence; no hardware/network operations."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;CASE=HERE.parents[3];ROOT=CASE.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
design=json.loads((HERE/'design.json').read_text(encoding='utf8'))
log=CASE/design['hardware_evidence']['path']
assert len(log.read_bytes())==design['hardware_evidence']['bytes']
assert sha(log)==design['hardware_evidence']['sha256']
sources={p.name:sha(p) for p in (HERE/'references').iterdir() if p.is_file()}
network={name:sha(ROOT/name) for name in design['hero_reuse']['reviewed_sources']}
result={'status':'OFFLINE_DESIGN_BOUND_TO_LOCAL_EVIDENCE','design_sha256':sha(HERE/'design.json'),'brief_sha256':sha(HERE/'brief.txt'),'hardware_log_sha256':sha(log),'reference_snapshots':sources,'reviewed_hero_sources':network,'limits':['Reference implementations are not executed.','No new collector or receiver, no hardware/network access, and no live capacity or full-read claim.']}
(HERE/'evidence_manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':result['status'],'design_sha256':result['design_sha256']},indent=2))
