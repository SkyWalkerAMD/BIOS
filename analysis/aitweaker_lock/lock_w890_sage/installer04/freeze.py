"""Bind reviewed final sources, compiled carriers and exact lab evidence."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
paths=set(HERE.joinpath('source').glob('*'))
paths.update(HERE/p for p in ['build.py','build_watch.py','run.py','verify_guard.py','freeze.py','lab.c','lab_watch.c','README.txt'])
for folder in ['build','watch_build']:
 manifest=HERE/folder/'build_manifest.json';m=read(manifest);paths.add(manifest)
 for p,b in m['inputs'].items():
  q=Path(p);assert q.stat().st_size==b['bytes'] and sha(q)==b['sha256'],p;paths.add(q)
 outputs=m.get('outputs',{'tx':m.get('output')})
 for x in outputs.values():
  p=Path(x['path']);assert sha(p)==x['sha256'];paths.add(p)
 guards=[HERE/folder/'entry_guard_tests.json'] if folder=='build' else sorted((HERE/folder).glob('*.guard.json'))
 for p in guards:
  q=read(p);assert q['status']=='PASS_ACTUAL_ENTRY_NON_TCG_REFUSAL' and len(q['cases'])==2;paths.add(p)
run_names=['20261108_023557','20261108_023349_watch0','20261108_023349_watch1','20261108_023434_watch2','20261108_023434_watch3']
tests=[]
for name in run_names:
 d=HERE/'runs'/name;r=read(d/'result.json');assert r['status'].startswith('PASS_') and r['exit_code']==33 and r['iso_before']==r['iso_after']
 assert sha(d/'debug.log')==r['debug_sha256']
 efi=next(d.glob('*.efi'));assert sha(efi)==r['efi_sha256']
 for p in [d/'result.json',d/'debug.log',d/'qemu_command.json',d/'build_manifest.json',efi,next(d.glob('*.iso'))]:paths.add(p)
 tests.append({'path':str((d/'result.json').relative_to(HERE)).replace('\\','/'),'assertions':r['checks'],'scope':r['scope'],'efi_sha256':r['efi_sha256']})
review=HERE.parent/'write_sinks04/installer_review.json'
if review.exists():paths.add(review)
report={'schema':1,'generated_utc':datetime.now(timezone.utc).isoformat(),'target':'ASUS Pro WS W890E-SAGE SE 0603','status':'REVIEWED_TRANSACTION_AND_READ_ONLY_LOADER_COMPONENTS_NOT_DEPLOYABLE','release_ready':False,'hardware_writes':0,'firmware_images_generated':0,'all_lab_entries_require_tcg':True,'tests':tests,
 'remaining':['Real early DXE dispatch/two-stage installer binding; late BootOverride cannot substitute','All navigation/first denial/history and write sinks bound to native lifetimes','Actual machine password integration, supported image trust and tested recovery'],
 'bindings':{str(p.relative_to(ROOT)).replace('\\','/'):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(paths) if p.is_file()}}
(HERE/'component_manifest.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'bindings':len(report['bindings']),'tests':len(tests),'release_ready':False}))
