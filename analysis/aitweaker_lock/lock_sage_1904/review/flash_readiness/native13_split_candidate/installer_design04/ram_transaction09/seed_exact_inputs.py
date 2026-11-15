"""One-shot isolated TX09 derivation from frozen TX08 and frozen guard09/P15.

Only this new directory is written. No firmware, device, credential or journal
operation is performed. All previous source and artifacts remain byte-identical.
"""
from pathlib import Path
import hashlib,json,difflib,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;D04=HERE.parent;OLD=D04/'ram_transaction08'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
pins={
 OLD/'ram_candidate_manifest.json':'7f08d975710179f88f953636b1da72db34ebd0c41ef04447bdf40b296a599e96',
 D04/'diagnostic_guard09/candidate_manifest.json':'16b8ece77f0569cf477b4126bde86586a5b8414ef0d06ac1a98915e634564675',
 D04/'provider15_diagnostic09/local_candidate_manifest.json':'3ae77997b6855fe57d2e670bcb119b108a2a717b9586e1c852133aa4d1e29976'}
verified=[]
for path,digest in pins.items():
 assert sha(path)==digest,path
 m=json.loads(path.read_text())
 for row in m['artifacts']:assert sha(D04/row['path'])==row['sha256'],row
 verified.append({'path':str(path.relative_to(D04)),'sha256':digest,'items':len(m['artifacts'])})
contract=D04/'diagnostic_guard09/integration_contract.json';c=json.loads(contract.read_text())
assert c['public_provider_frame_context_binding_unchanged']is True
assert (c['state_page_bytes'],c['public_prefix_bytes'],c['diagnostic_offset'],c['diagnostic_bytes'],c['diagnostic_end_exclusive'])==(4096,32,64,576,640)
assert c['initialize_once_after_state_memset_before_any_detour']=={'magic_offset':64,'magic':'0x3930474149444753','revision_offset':72,'revision':1,'bytes_offset':76,'bytes':576,'remaining_bytes_zero':True}
assert sha(D04/'diagnostic_guard09/build/guard_template.bin')=='d4720f06de39421dfb9f8a4d8394a89968a50213c53ec8c9d552d957744fc2d2'
assert sha(D04/'provider15_diagnostic09/build/AiTweakerSplitProvider15.UNSIGNED.local.efi')=='d15438fde33bf0fada0a33f9f62a9ca8ff72cf21bb924ceaeca0bc75a0b0a5cf'
oldmeta=json.loads((D04/'static_chrome_candidate07/build/split_build.json').read_text())
newmeta=json.loads((D04/'diagnostic_guard09/build/split_build.json').read_text())
keys=['module','rva','kind','length','old']
assert [{k:r[k]for k in keys}for r in oldmeta['patches']]==[{k:r[k]for k in keys}for r in newmeta['patches']]
assert len(newmeta['patches'])==12
assert not (HERE/'source').exists(),'One-shot derivation: source directory already exists'
rows=[]
def put(source,destination,data=None):
 assert not destination.exists(),destination
 destination.parent.mkdir(parents=True,exist_ok=True)
 raw=source.read_bytes();data=raw if data is None else data
 destination.write_bytes(data)
 rows.append({'source':str(source.relative_to(D04)),'source_sha256':sha(source),
              'destination':str(destination.relative_to(HERE)),'sha256':sha(destination),
              'source_equal':raw==data})

for p in sorted((OLD/'source').rglob('*')):
 if not p.is_file():continue
 relative=p.relative_to(OLD/'source')
 if str(relative)in['split_profile.h','provider_asset.h','transaction_plan.h']:continue
 data=p.read_bytes()
 if relative.as_posix()in['app.c','transport/kvm.c']:
  data=data.replace(b'TEST08',b'TEST09')
 if relative.as_posix()=='session_ui.c':
  data=data.replace(b'unique exact independent P14 HII package',b'unique exact independent P15 HII package')
 if relative.as_posix()=='platform.c':
  assert data.count(b'#include "app.h"')==1
  data=data.replace(b'#include "app.h"',b'#include "app.h"\n#include "diagnostic09.h"',1)
  anchor=b'SPLIT_STATE *state=(void *)(uintptr_t)p.state_base;state->magic=SPLIT_STATE_MAGIC;state->phase=1;'
  assert data.count(anchor)==1
  addition=(b'\n /* Private diagnostics use only the existing exclusively owned RW/NX page.\n'
   b'  * The full page was zeroed above; initialize once before any native detour.\n'
   b'  * Neither trace availability nor its contents enter authorization/rollback. */\n'
   b' DIAG09_REGION *diagnostic=(void *)(uintptr_t)(p.state_base+DIAG09_STATE_OFFSET);\n'
   b' diagnostic->magic=DIAG09_MAGIC;diagnostic->revision=DIAG09_REVISION;diagnostic->bytes=DIAG09_REGION_BYTES;')
  data=data.replace(anchor,anchor+addition,1)
 put(p,HERE/'source'/relative,data)
put(D04/'diagnostic_guard09/source/diagnostic09.h',HERE/'source/diagnostic09.h')

scripts=['build_transaction.py','generate_platform_assets.py','build_app.py','verify_transaction.py',
         'verify_integrated_core.py','verify_platform.py','verify_platform_edges.py','verify_globals.py']
for name in scripts:
 raw=(OLD/name).read_text()
 for a,b in [('static_chrome_candidate07','diagnostic_guard09'),('provider14_chrome07','provider15_diagnostic09'),
             ('AiTweakerSplitProvider14','AiTweakerSplitProvider15'),('SageNative13RamTest08','SageNative13RamTest09'),
             ('TransactionCore08','TransactionCore09'),('P14','P15'),('p14','p15')]:raw=raw.replace(a,b)
 raw=raw.replace('Packaging is separately owned by root in ram_test05_delivery.','Packaging is separately owned by root in ram_test09_delivery.')
 if name in['build_transaction.py','generate_platform_assets.py','build_app.py']:
  # Inputs are already fully manifest-checked by the inherited builder. Add
  # explicit frozen-manifest digests so a replacement manifest is also refused.
  anchor="HERE=Path(__file__).resolve().parent;"
  assert raw.count(anchor)==1
  # A standalone check module has no output or imports beyond stdlib.
  lines=raw.splitlines();at=next(i for i,x in enumerate(lines)if x.startswith('HERE='))+1
  lines.insert(at,"exec(compile((HERE/'verify_frozen_inputs.py').read_text(),str(HERE/'verify_frozen_inputs.py'),'exec'),{'__file__':str(HERE/'verify_frozen_inputs.py')})")
  raw='\n'.join(lines)+'\n'
 put(OLD/name,HERE/name,raw.encode())

diff=[]
for p in sorted((HERE/'source').rglob('*')):
 if not p.is_file():continue
 old=OLD/'source'/p.relative_to(HERE/'source')
 if old.exists()and old.read_bytes()!=p.read_bytes():
  diff.extend(difflib.unified_diff(old.read_text().splitlines(True),p.read_text().splitlines(True),fromfile=str(old.relative_to(D04)),tofile=str(p.relative_to(D04))))
(HERE/'initial_source_delta.patch').write_text(''.join(diff))
report={'status':'EXACT_ISOLATED_SOURCE_DERIVATION_NOT_COMPILED_OR_HARDWARE_ACCEPTED','verified_manifests':verified,
 'contract_sha256':sha(contract),'unchanged_original_sites':12,'copied':rows,
 'diagnostic_state_extent':[64,640],'Q_schema_changed':False,'credential_behavior_changed':False,
 'device_actions':0,'source_delta_sha256':sha(HERE/'initial_source_delta.patch'),
 'script_sha256':sha(Path(__file__))}
(HERE/'source_derivation.json').write_text(json.dumps(report,indent=2)+'\n')
for path,digest in pins.items():
 assert sha(path)==digest
 for row in json.loads(path.read_text())['artifacts']:assert sha(D04/row['path'])==row['sha256']
print(json.dumps({'status':report['status'],'copied_files':len(rows),'report_sha256':sha(HERE/'source_derivation.json')}))
