"""Create isolated P14/TX08 inputs. Never mutate frozen P13/TX05/07 files."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;D04=HERE.parent
P14=D04/'provider14_chrome07';P13=D04/'provider13';OLD=D04/'ram_transaction05'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert not (HERE/'source').exists() and not P14.exists(),'Seed is one-shot'
for root,name in [(P13,'local_candidate_manifest.json'),(OLD,'ram_candidate_manifest.json'),(D04/'static_chrome_candidate07','candidate_manifest.json')]:
 m=json.loads((root/name).read_text())
 base=D04 if root.name!='static_chrome_candidate07' else Path(m['path_base']) if 'path_base' in m else None
 if root.name!='static_chrome_candidate07':
  for row in m['artifacts']:assert sha(D04/row['path'])==row['sha256'],row['path']
assert sha(D04/'static_chrome_candidate07/build/guard_template.bin')=='2aef4bfca4ecb31631c60f9ee01cc2480a5782169524620a502ae0cf2e295efa'
rows=[]
def copy(src,dst):
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
 rows.append({'source':str(src.relative_to(D04)),'destination':str(dst.relative_to(D04)),'sha256':sha(src)})
for src in (P13/'source').iterdir():
 if src.is_file() and src.name not in ['split_profile.h','management_package.h']:copy(src,P14/'source'/src.name)
for name in ['bind_split.py','build_hii.py','build_provider.py','verify_owner.py','copied_p12_sources.json']:
 copy(P13/name,P14/name)
for src in (OLD/'source').rglob('*'):
 if src.is_file() and src.name not in ['provider_asset.h','split_profile.h','platform_readonly.inc','transaction_plan.h']:
  copy(src,HERE/'source'/src.relative_to(OLD/'source'))
for name in ['build_transaction.py','generate_platform_assets.py','build_app.py','verify_transaction.py','verify_integrated_core.py','verify_platform.py','verify_platform_edges.py']:
 copy(OLD/name,HERE/name)
for root in [P14,HERE]:
 for p in root.glob('*.py'):
  if p.name=='seed_candidate.py':continue
  text=p.read_text().replace("'split_core'","'static_chrome_candidate07'").replace('split_core/build/','static_chrome_candidate07/build/')
  text=text.replace('provider13','provider14_chrome07').replace('AiTweakerSplitProvider13','AiTweakerSplitProvider14')
  text=text.replace('SageNative13RamTest05','SageNative13RamTest08').replace('TransactionCore05','TransactionCore08')
  text=text.replace('ram_transaction05','ram_transaction08')
  text=text.replace('P13','P14').replace('p13','p14')
  p.write_text(text)
(HERE/'source_seed.json').write_text(json.dumps({'status':'ISOLATED_COPY_BEFORE_INTEGRATION_EDITS','files':rows},indent=2)+'\n')
print(json.dumps({'copied_files':len(rows),'provider':str(P14),'app':str(HERE)}))
