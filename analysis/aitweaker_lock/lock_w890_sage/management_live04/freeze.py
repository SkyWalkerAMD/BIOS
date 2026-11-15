from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))
dependencies={}
for name in ['password','password_runtime02','password_recovery03']:
    root=H.parent/name;m=read(root/'component_manifest.json')
    for relative,row in m['bindings'].items():assert sha(root/relative)==row['sha256'],str(root/relative)
    dependencies[name]={'manifest_sha256':sha(root/'component_manifest.json'),'verified_bindings':len(m['bindings'])}
build=read(H/'build/build.json');component=H/'build/W890Management04.UNBOUND.TESTONLY.efi';lab=H/'build/W890Management04.QEMU_ONLY.LAB.efi'
assert sha(component)==build['component']['sha256']and sha(lab)==build['lab']['sha256']
for relative,digest in build['sources'].items():assert sha(R/relative)==digest,relative
bridge=read(H/'build/bridge_pe_tests.json');assert bridge['component_sha256']==sha(component)and bridge['count']==20
chain=read(H/'build/observer_chain_tests.json');assert chain['component_sha256']==sha(component)and chain['status']=='PASS_COMPOSED_OBSERVER_MANAGEMENT_RUNTIME'
observer=H.parent/'native_observer04/build/W890NativeObserver04.TESTONLY.dll';assert sha(observer)==chain['observer_sha256']
assert chain['source_sha256']==sha(H/'verify_observer_chain.py')
assert chain['observer_fixture_source_sha256']==sha(H.parent/'native_observer04/verify_observer.py')
runs=[]
for p in sorted((H/'lab/runs').glob('*/result.json')):
    m=read(p)
    if m.get('status')=='PASS_ACTUAL_OVMF_HII_AND_COMPILED_PUBLISHER'and m.get('component_sha256')==sha(component)and m.get('efi_sha256')==sha(lab):runs.append((p,m))
assert runs;path,vm=runs[-1];run=path.parent
assert vm['checks']==114 and vm['debug_sha256']==sha(run/'debug.log')and vm['build_sha256']==sha(run/'build.json')
assert vm['iso_sha256_before']==vm['iso_sha256_after']==sha(run/'W890Management04.TCG_ONLY.iso')
for relative,digest in vm['inputs'].items():assert sha(Path(relative))==digest,relative
files=[p for p in H.glob('*')if p.is_file()and p.name!='component_manifest.json']
files+=[p for p in (H/'lab').glob('*')if p.is_file()]
files+=[p for p in (H/'build').glob('*')if p.is_file()and p.suffix in ['.json','.efi','.map']]
files+=[p for p in run.rglob('*')if p.is_file()]
files+=list((H/'lab/runs').glob('*/result.json'));files=sorted(set(files))
manifest={'status':'FROZEN_COMPOSED_MANAGEMENT_COMPONENT_FOR_REVIEW','release_ready':False,'native_installer_bound_in_entry':False,'physical_operations':0,
          'component':build['component'],'actual_OVMF_result':str(path.relative_to(H)),
          'checks':{'real_OVMF_HII_and_UI':114,'actual_EFI_original_callback_bridge_models':20,'actual_observer_publisher_runtime_composition_models':chain['case_count']},
          'frozen_dependencies':dependencies,'observer_component_sha256':sha(observer),'observer_fixture_sha256':sha(H.parent/'native_observer04/verify_observer.py'),
          'bindings':{str(p.relative_to(H)):{'bytes':p.stat().st_size,'sha256':sha(p)}for p in files},'created_utc':datetime.now(timezone.utc).isoformat()}
out=H/'component_manifest.json';out.write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'status':manifest['status'],'bindings':len(files),'sha256':sha(out),'component_sha256':sha(component),'OVMF_result':manifest['actual_OVMF_result']}))
