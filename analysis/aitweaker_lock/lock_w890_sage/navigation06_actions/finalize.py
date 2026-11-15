"""Freeze review evidence; does not build, install, sign or write firmware."""
from pathlib import Path
import json,hashlib,sys,re
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bind=lambda p:{'path':str(p.relative_to(R)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':sha(p)}
def load(p):return json.loads(p.read_text())
build=load(H/'build/build.json');tests=load(H/'build/actions_tests.json');setup=load(H/'setup_callback_action_tests.json');rea=load(H/'rea_index.json')
binary=H/'build/W890NavigationActions06.TESTONLY.dll'
assert build['component_sha256']==tests['component_sha256']==sha(binary)
assert tests['checks']==15 and all(x['status']=='PASS'for x in tests['cases'])
assert tests['source_sha256']==sha(H/'verify_actions.py')
assert setup['source_sha256']==sha(H/'verify_setup_callbacks.py')and setup['actual_machine_code_cases']==1522
for p,digest in build['sources'].items():assert sha(R/p)==digest,p
assert load(H/'frozen_input_check.json')['status']=='PASS'
sys.path.insert(0,str(R/'tools/pydeps'));import pefile
orig=B/'navigation/modules/AMITSE.efi';pe=pefile.PE(str(orig));originals=[]
for p in [orig,B/'navigation/modules/Setup.efi']:
 q=pefile.PE(str(p));section=next(s for s in q.sections if s.Name.rstrip(b'\0')==b'.text')
 originals.append({**bind(p),'text_rva':section.VirtualAddress,'text_bytes':section.Misc_VirtualSize,'text_sha256':hashlib.sha256(q.get_data(section.VirtualAddress,section.Misc_VirtualSize)).hexdigest()})
hooks={
 'status':'REVIEW_ONLY_NO_INSTALLER_NO_AGGREGATE_CHANGES',
 'original':bind(orig),
 'patches':[
  {'rva':0x748c,'bytes':14,'original_hex':pe.get_data(0x748c,14).hex(),'export':'n06_native_exit','trampoline_pointer_export':'n06_exit_trampoline','continuation':0x749a,'pc_relative_targets':[{'instruction':0x7495,'target':0x189a4,'kind':'CALL rel32'}]},
  {'rva':0x3f414,'bytes':15,'original_hex':pe.get_data(0x3f414,15).hex(),'export':'n05_native_form_open','trampoline_pointer_export':'n05_form_open_trampoline','continuation':0x3f423,'pc_relative_targets':[]}],
 'admitted_callers':{'normal_cleanup_return':0x19a7b,'local_page_transition_return':0x23e05,'private_teardown_batch_return':0x3f6e8},
 'denied_unclosed_callers':{'reset_cleanup_return':0x199eb,'global_open_batch_return':0x3f6e8,'hii_specific_dispatch_return':0x3f8b4},
 'abi':{'n06_native_exit':'Microsoft x64 EFI_STATUS(EFI_STATUS); original748C restores status from RBX','n05_native_form_open':'Microsoft x64 EFI_STATUS(void *raw_page, UINTN action, UINT32 *resume_qid)'},
 'actions':{'2':'RETRIEVE; excluded by this new boundary','3':'FORM_OPEN; exact Main only in active page transition','4':'FORM_CLOSE; exact Main only locally or through private teardown lease'},
 'reset_warning':'Refusing748C cannot stop original199EB continuation. Must close caller control-flow before integration.'}
(H/'hook_plan.json').write_text(json.dumps(hooks,indent=2)+'\n')
groups={}
for x in setup['cases']:
 row=groups.setdefault(str(x['qid']),{'qid':x['qid'],'handlers':x['handlers'],'observations':[],'runtime_authorized':False})
 row['observations'].append({'action':x['action'],'status':x['status'],**{k:x[k]for k in ['reason','pc','write_rva','result','action_request']if k in x}})
(H/'setup_callback_candidates.json').write_text(json.dumps({'original':originals[1],'scope':'Static original2250 dispatcher; dynamic list empty, Type9, fixed zero-initialized runtime globals. Candidate evidence only.','records':list(groups.values())},indent=2)+'\n')
report={
 'status':'PARTIAL_OFFLINE_LIFECYCLE_BOUNDARY_NOT_FLASHABLE',
 'originals':originals,'component':bind(binary),
 'implemented':['genuine normal cleanup caller recognition before destructor','whole admitted batch preflight using private Loop/effect and exact Main original descriptor/IFR identity','one-use ordered private close lease based on actual native_visit/epoch after AFDD0 becomes zero','actual nested-entry/HII revocation and descriptor drift denied','local action3 and action4 distinguished from Retrieve2'],
 'coverage':{'pe_chain_pass_cases':tests['checks'],'original_setup_observations':setup['actual_machine_code_cases'],'original_setup_returned_bounded':1512,'original_setup_unknown_boundaries':10,'actual_rea_dossiers':len(rea['dossiers']),'frozen_navigation_bindings_verified':load(H/'frozen_input_check.json')['checked_bindings']},
 'models':tests['models'],'source_bindings':build['sources'],
 'corrections':[{'prior':'navigation05 Security FormClose2 and corresponding frozen manifest wording','correct':'Action2 was RETRIEVE; no genuine FORM_CLOSE4 coverage in that old result','old_files_edited':False}],
 'remaining_release_blocks':[
  'Complete real BIOS batch includes protected/callback-bearing/foreign pages and is deliberately denied before teardown; ordinary full exit is not complete.',
  'Setup dynamic callback registrations and AMITSE3E700/3E424/ActionRequest consumers not closed by static pure-return observations.',
  'Five static QIDs271E/271F/2BF8/2C03/2C1E reach unclosed helper/global-write boundaries for actions3/4 in the empty-list Type9 fixture.',
  'Initial global FormOpen3/Retrieve2 have different pre-App lifecycle authority; this active-page/teardown component does not cover them.',
  'Normal positive teardown models destructor1D6E8 and four post-close cleanup helpers; original event/allocator failure behavior unverified.',
  'Reset caller199E6 ignores cleanup status; caller cancellation and preexisting cleanup side effects remain unclosed.',
  'Late post-destructor failure blocks callbacks but cannot restore destroyed App; no rollback or cross-service atomicity claim.',
  'Full original parser boundary failure/unknown25FD forms remain blockers; partial snapshot here cannot override them.',
  'No integration into frozen aggregate, hardware install, firmware-update acceptance or recovery validation in this task.'],
 'no_device_access':True,'no_cap_output':True,'no_external_owner_boolean':True}
(H/'review.json').write_text(json.dumps(report,indent=2)+'\n')
files=[]
for p in H.rglob('*'):
 if not p.is_file():continue
 parts=p.relative_to(H).parts
 if any(x in parts for x in ['tmp','zig-local','zig-global','__pycache__']):continue
 if p.name in ['component_manifest.json','manifest_validation.json']or p.suffix in ['.obj','.lib','.exp']:continue
 if 'progress'in p.name or 'selected_tests'in p.name:continue
 files.append(bind(p))
external={R/p for p in build['sources']}
external.update([B/'integration05/parser-snapshot.zip',B/'navigation05/component_manifest.json',orig,B/'navigation/modules/Setup.efi'])
external.update([B/'navigation05'/x for x in ['verify_bridges.py','verify_navigation.py','verify_form_open.py','verify_parser_navigation.py','bridges_build/static_hook_plan.json']])
external.update([B/'native_observer04/verify_observer.py',B/'password_runtime02/verify_runtime_pe.py'])
todo=list(external);seen=set()
while todo:
 p=todo.pop()
 if p in seen or p.suffix not in ['.c','.h','.inc','.S']:continue
 seen.add(p)
 for inc in re.findall(r'^\s*#\s*include\s+"([^"]+)"',p.read_text(encoding='utf-8'),re.M):
  q=(p.parent/inc).resolve()
  if q.is_file()and q.is_relative_to(R):external.add(q);todo.append(q)
manifest={'status':report['status'],'component_sha256':sha(binary),'review_sha256':sha(H/'review.json'),'local_bindings':sorted(files,key=lambda x:x['path']),'external_bindings':sorted([bind(p)for p in external if not p.is_relative_to(H)],key=lambda x:x['path']),'boundaries':'Only exact callback-free Main execution; original factory full-batch exit remains denied. No flash readiness claim.'}
(H/'component_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
for row in manifest['local_bindings']+manifest['external_bindings']:
 p=R/row['path'];assert p.stat().st_size==row['bytes']and sha(p)==row['sha256'],row['path']
validation={'status':'PASS','manifest_sha256':sha(H/'component_manifest.json'),'local_bindings':len(manifest['local_bindings']),'external_bindings':len(manifest['external_bindings']),'mismatches':[]}
(H/'manifest_validation.json').write_text(json.dumps(validation,indent=2)+'\n');print(json.dumps(validation,indent=2))
