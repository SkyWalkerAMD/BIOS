"""Seed isolated guard/P15 sources; frozen production artifacts stay read-only."""
from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;D04=HERE.parent;G=D04/'diagnostic_guard09';P=D04/'provider15_diagnostic09'
assert not G.exists() and not P.exists(),'One-shot seed'
rows=[];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def copy(a,b):
 b.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(a,b);rows.append({'source':str(a.relative_to(D04)),'destination':str(b.relative_to(D04)),'sha256':sha(a)})
for old,new in [(D04/'static_chrome_candidate07',G),(D04/'provider14_chrome07',P)]:
 for p in (old/'source').iterdir():
  if p.is_file()and p.name not in ['split_profile.h','management_package.h']:copy(p,new/'source'/p.name)
names=['build_split.py','verify_split.py','verify_chrome.py']
for n in names:copy(D04/'static_chrome_candidate07'/n,G/n)
for n in ['bind_split.py','build_hii.py','build_provider.py','verify_owner.py','copied_p12_sources.json']:copy(D04/'provider14_chrome07'/n,P/n)
for dst in [G,P]:copy(HERE/'diagnostic09.h',dst/'source/diagnostic09.h')
for p in P.glob('*.py'):
 s=p.read_text().replace('static_chrome_candidate07','diagnostic_guard09').replace('AiTweakerSplitProvider14','AiTweakerSplitProvider15').replace('P14','P15').replace('p14','p15');p.write_text(s)
(HERE/'implementation_seed.json').write_text(json.dumps({'files':rows},indent=2)+'\n')
print(json.dumps({'files':len(rows),'guard':str(G),'provider':str(P)}))
