"""Bind the exact source delta to frozen TX05/P13; never rebuild them."""
from pathlib import Path
import difflib,hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent;OLD=D04/'ram_transaction05';P14=D04/'provider14_chrome07';P13=D04/'provider13'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
allowed={'app.h','app.c','platform.c','session_ui.c','split_profile.h','provider_asset.h','transaction_plan.h','transport/kvm.c'}
rows=[];diffs=[]
for p in sorted((HERE/'source').rglob('*')):
 if not p.is_file():continue
 n=p.relative_to(HERE/'source').as_posix();old=OLD/'source'/n;assert old.is_file(),n
 same=sha(p)==sha(old);assert same or n in allowed,n
 rows.append({'path':n,'old_sha256':sha(old),'new_sha256':sha(p),'identical':same})
 if not same and n not in ['split_profile.h','provider_asset.h','transaction_plan.h']:
  diffs.extend(difflib.unified_diff(old.read_text().splitlines(True),p.read_text().splitlines(True),fromfile='frozen_TX05/'+n,tofile='TX08/'+n))
provider=[]
for p in sorted((P14/'source').iterdir()):
 if p.is_file():
  same=sha(p)==sha(P13/'source'/p.name);assert same or p.name=='split_profile.h'
  provider.append({'path':p.name,'identical_to_P13':same,'sha256':sha(p)})
assert sha(HERE/'source/ui_bindings.h')==sha(OLD/'source/ui_bindings.h')
assert (P14/'build/management.pack').read_bytes()==(P13/'build/management.pack').read_bytes()
(HERE/'integration_source.diff').write_text(''.join(diffs))
r={'status':'PASS_EXACT_NEW_SOURCE_DELTA_WITH_FROZEN_PREDECESSORS_UNCHANGED','app_sources':rows,'provider_sources':provider,'changes':['Generated binding/template/loader assets target exact2aef/P14 identities.','UI ActionRequest initial NONE; bounded globals before/after and error aggregation.','Public app helper declaration plus bounded collector, no original-global mutation.','RAM TEST08 title/transport markers only in controller and KVM transport.'],'scope_limit':'Source comparison supports audit; does not transfer binary, OVMF, native UI or physical results across candidates.','diff_sha256':sha(HERE/'integration_source.diff')}
(HERE/'integration_delta.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'status':r['status'],'changed_app_sources':[x['path']for x in rows if not x['identical']],'diff_sha256':r['diff_sha256']}))
