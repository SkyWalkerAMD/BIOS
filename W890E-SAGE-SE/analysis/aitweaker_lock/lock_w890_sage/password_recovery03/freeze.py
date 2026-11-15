from pathlib import Path
from datetime import datetime,timezone
import hashlib,json
HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf8'))
parents={}
for name in ['password','password_runtime02']:
    root=HERE.parent/name;manifest=read(root/'component_manifest.json')
    for relative,row in manifest['bindings'].items():assert sha(root/relative)==row['sha256'],str(root/relative)
    parents[name]={'manifest_sha256':sha(root/'component_manifest.json'),'verified_bindings':len(manifest['bindings'])}
build=read(HERE/'build/build.json');component=HERE/'build'/build['component']['file'];lab=HERE/'build'/build['lab']['file']
assert sha(component)==build['component']['sha256']and sha(lab)==build['lab']['sha256']
for relative,expected in (build['sources']|build['lab_sources']).items():assert sha(HERE/relative)==expected,relative
pe=read(HERE/'build/recovery_pe_tests.json');assert pe['efi_sha256']==sha(component)and pe['case_count']==54
assert pe['source_sha256']==sha(HERE/'verify_recovery_pe.py')
handoff=read(HERE/'build/handoff_tests.json');assert handoff['case_count']==8 and handoff['handoff_source_sha256']==sha(HERE/'handoff.py')
run=HERE/'lab/runs/20261108_014611';vm=read(run/'result.json')
assert vm['status']=='PASS_REAL_OVMF_RECOVERY_AND_DPAPI_KEYBOARD_HANDOFF'and vm['check_count']==28
assert vm['component_sha256']==sha(component)and vm['lab_sha256']==sha(lab)and vm['build_sha256']==sha(HERE/'build/build.json')
assert vm['debug_sha256']==sha(run/'debug.log')and vm['vars_sha256']==sha(run/'vars.fd')
assert vm['iso_sha256_before']==vm['iso_sha256_after']==sha(run/'recovery03-lab.iso')
files=[p for p in HERE.glob('*')if p.is_file()and p.name!='component_manifest.json']
files+=list((HERE/'source').glob('*'))
files+=[p for p in (HERE/'lab').glob('*')if p.is_file()]
files+=[HERE/'build'/x for x in ['build.json','recovery_pe_tests.json','handoff_tests.json']]
files+=[component,component.with_suffix('.map'),lab,lab.with_suffix('.map')]
files+=[p for p in run.rglob('*')if p.is_file()]
files+=list((HERE/'lab/runs').glob('*/result.json'))
files=sorted(set(files))
manifest={'status':'FROZEN_IDENTITY_READONLY_RECOVERY_CARRIER_FOR_REVIEW','release_ready':False,
          'physical_operations':0,'hardware_smbios_identity_observed':False,'hardware_writer_exclusion_authority':False,
          'component':build['component'],'frozen_dependencies':parents,
          'checks':{'real_OVMF_and_DPAPI_keyboard_handoff':28,'actual_EFI_with_modeled_boundaries':54,'DPAPI_validation_modeled_key_sink':8},
          'bindings':{str(p.relative_to(HERE)):{'bytes':p.stat().st_size,'sha256':sha(p)}for p in files},
          'created_utc':datetime.now(timezone.utc).isoformat()}
out=HERE/'component_manifest.json';out.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':manifest['status'],'bindings':len(files),'sha256':sha(out),'component_sha256':sha(component)}))
