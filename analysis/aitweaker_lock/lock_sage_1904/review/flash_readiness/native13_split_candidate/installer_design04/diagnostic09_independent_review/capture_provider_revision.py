from pathlib import Path
import hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;SOURCE=HERE.parent/'provider15_diagnostic09'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
meta=json.loads((SOURCE/'build/build.json').read_text())
DEST=HERE/'provider_revisions'/meta['efi_sha256'][:16]
assert not DEST.exists(),str(DEST)
(DEST/'build').mkdir(parents=True);(DEST/'source').mkdir()
for name in ['AiTweakerSplitProvider15.UNSIGNED.local.efi','provider.map','build.json']:
 (DEST/'build'/name).write_bytes((SOURCE/'build'/name).read_bytes())
for name in meta['sources']:(DEST/'source'/name).write_bytes((SOURCE/'source'/name).read_bytes())
assert sha(DEST/'build/AiTweakerSplitProvider15.UNSIGNED.local.efi')==meta['efi_sha256']
matches={k:sha(DEST/'source'/k)==v for k,v in meta['sources'].items()};assert all(matches.values()),matches
result={'efi_sha256':meta['efi_sha256'],'all_sources_match':True,'files':[{'path':p.relative_to(DEST).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(DEST.rglob('*'))if p.is_file()]}
(DEST/'snapshot.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'snapshot':str(DEST),'sources':len(matches)}))
