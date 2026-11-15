from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;SOURCE=HERE.parent/'diagnostic_guard09'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
meta=json.loads((SOURCE/'build/split_build.json').read_text())
DEST=HERE/'trace_revisions'/meta['template_sha256'][:16]
assert not (DEST/'snapshot.json').exists(),str(DEST)
(DEST/'build').mkdir(parents=True,exist_ok=True);(DEST/'source').mkdir(exist_ok=True)
for name in ['split_build.json','AMITSE.memory-fixture.bin','AMITSE.split-guard.bin','Setup.memory-fixture.bin','Setup.split-guard.bin','guard_template.bin','guard.map','owned-state-fixture.bin']:
 if not (DEST/'build'/name).exists():(DEST/'build'/name).write_bytes((SOURCE/'build'/name).read_bytes())
for name in meta['sources']:
 if not (DEST/'source'/name).exists():(DEST/'source'/name).write_bytes((SOURCE/'source'/name).read_bytes())
if not (DEST/'verify_split.py').exists():(DEST/'verify_split.py').write_bytes((SOURCE/'verify_split.py').read_bytes())
assert sha(DEST/'build/guard_template.bin')==meta['template_sha256']
matches={k:sha(DEST/'source'/k)==v for k,v in meta['sources'].items()}
result={'template_sha256':meta['template_sha256'],'source_binding_matches':matches,'all_sources_match':all(matches.values()),'files':[{'path':p.relative_to(DEST).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(DEST.rglob('*'))if p.is_file()]}
(DEST/'snapshot.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'snapshot':str(DEST),'all_sources_match':all(matches.values())}))
