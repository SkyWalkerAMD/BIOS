"""Freeze this round's owned navigation artifacts without packaging a BIOS."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,re,zlib
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
reports=['native_replay.json','history_replay.json','compiled_native_gate_tests.json','provider_gate_chain_tests.json','first_fallback_tests.json','dispatch_return_tests.json','integration/native02/runtime02_chain_tests.json','input_adapter_tests.json']
tests=[]
for name in reports:
 p=HERE/name;d=json.loads(p.read_text(encoding='utf8'));assert d['status'].startswith('PASS')
 tests.append({'file':name,'sha256':sha(p),'status':d['status'],'cases':d['case_count'],'scope':d.get('scope','See report')})
hardware=[]
for folder in ['hardware-inventory01-1794100431432-3bd796d0','hardware-inventory01-1794101290712-4fbdfdee']:
 p=HERE.parent/'remote_172_20_2_245'/folder/'hardware-log.txt';raw=p.read_bytes();text=raw.decode('utf8');entry={'file':str(p.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(p),'crc32':f'{zlib.crc32(raw):08X}','authorization_or_ownership':False,'modified_code_tested':False}
 if 'STABLE_DOUBLE_SAMPLE'in text:
  fields={k:int(v,16)for k,v in re.findall(r'^Native\.([a-z_]+)=0x([0-9A-Fa-f]+)',text,re.M)}
  entry['observed']=fields;entry['form_label']='Exit';entry['interpretation']='Post-BootOverride diagnostic sample; not the earlier Boot UI, not active-owner authorization.'
 hardware.append(entry)
components=[]
for name in ['W890Navigation.TESTONLY.dll','W890FirstFallback.TESTONLY.dll','W890InputAdapter.TESTONLY.dll']:
 p=HERE/'build'/name;components.append({'file':str(p.relative_to(HERE)),'bytes':p.stat().st_size,'sha256':sha(p),'installable':False})
report={'status':'ROUND_FROZEN_COMPILED_EMULATED_NOT_INSTALLABLE_NOT_FLASHABLE','generated_utc':datetime.now(timezone.utc).isoformat(),'board':'ASUS Pro WS W890E-SAGE SE','BIOS':'0603','components':components,'suites':tests,'overlapping_case_sum_not_coverage':sum(x['cases']for x in tests),'original_hardware_evidence':hardware,'native_layout_sha256':sha(HERE/'native_layout_0603.json'),'control_registry_sha256':sha(HERE/'control_registry_0603.json'),'REA_analyzed_function_records':len(json.loads((HERE/'native_layout_0603.json').read_text())['rea_evidence']),'physical_module_identity_verified_by_root':True,'modified_code_hardware_tested':False,'native_owner_bound':False,'installer_implemented':False,'all_entrypoints_covered':False,'pending_write_authority_bound':False,'flashable_image_produced':False,'hardware_or_firmware_writes_by_this_agent':0,'remaining_detail':'README.txt; final section enumerates owner, installer, all entry/sink, error/history and release requirements.'}
(HERE/'adaptation_report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
extensions={'.py','.c','.h','.s','.mjs','.json','.txt','.tsv','.dll','.efi','.obj'}
files=[]
for p in sorted(HERE.rglob('*')):
 if not p.is_file()or p.name=='navigation_manifest.json'or p.suffix.lower()not in extensions:continue
 if any(part in ['__pycache__','zig-local','zig-global']for part in p.relative_to(HERE).parts):continue
 files.append({'file':str(p.relative_to(HERE)),'bytes':p.stat().st_size,'sha256':sha(p)})
external_paths=[HERE.parent/'password/w890_policy.c',HERE.parent/'password/w890_policy.h',HERE.parent/'password/w890_policy_data.h',HERE.parent/'password/provider/provider.h',HERE.parent/'password/provider/build/W890PasswordProvider01.UNBOUND.TESTONLY.efi',HERE.parent/'password_runtime02/build/W890Runtime02.UNBOUND.TESTONLY.efi',HERE.parent/'password_runtime02/verify_runtime_pe.py',HERE.parent/'password_runtime02/component_manifest.json',HERE.parent/'password_runtime02/lab/runs/20261108_012702/result.json']
external=[{'file':str(p.relative_to(ROOT)),'bytes':p.stat().st_size,'sha256':sha(p)}for p in external_paths]
manifest={'status':report['status'],'owned_artifacts':files,'external_dependencies_read_only':external,'production_deployment_authorized':False,'notes':['Historical pre_pointer_fix result is retained with its old Runtime02 hash, not counted as a current test.','Original modules and raw REA evidence are unmodified.','Manifest excludes itself, caches and transient processes.']}
out=HERE/'navigation_manifest.json';out.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'files':len(files),'case_sum_not_coverage':report['overlapping_case_sum_not_coverage'],'report_sha256':sha(HERE/'adaptation_report.json'),'manifest_sha256':sha(out),'components':components},indent=2))
