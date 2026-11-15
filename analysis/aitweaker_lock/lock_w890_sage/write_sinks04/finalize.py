from pathlib import Path
import sys,json,hashlib
H=Path(__file__).resolve().parent;R=H.parents[3];O=H/'build';M=H/'component_manifest.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def verify(m):
 for path,item in m['bindings'].items():
  p=R/path;assert p.is_file()and p.stat().st_size==item['bytes']and sha(p)==item['sha256'],path
 return len(m['bindings'])
if '--verify' in sys.argv:
 n=verify(read(M));print(json.dumps({'status':'PASS','bindings':n,'manifest_sha256':sha(M)}));raise SystemExit
build=read(O/'build.json');fixture=read(O/'fixture_build.json');policy=read(O/'policy_tests.json');bridge=read(O/'bridge_tests.json');native=read(O/'native_byte_tests.json')
assert policy['status']==bridge['status']==native['status']=='PASS'
assert policy['dll_sha256']==sha(O/'W890WritePolicy04.TESTONLY.dll')==native['policy_sha256']
assert bridge['real_observer_product_sha256']==sha(O/'W890WriteBridge04.DENYONLY.dll')==read(H/'consumer_windows.json')['component_sha256']
assert bridge['fixture_sha256']==sha(O/'W890WriteBridge04.OBSERVER-FIXTURE.dll')==fixture['sha256']
assert bridge['native_bridge_object_sha256']==fixture['native_bridge_object_sha256']==sha(O/'native_bridge04.obj')
for product in build['products']:assert sha(H/product['path'])==product['sha256']
for path,want in build['sources'].items():assert sha(R/path)==want,path
review=read(H/'installer_review.json')
for path,item in review['bindings'].items():assert sha(R/path)==item['sha256']and(R/path).stat().st_size==item['bytes'],path
originals={'AMITSE.efi':'43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe','Setup.efi':'c1cf9d755c2ea043d44f19fdf4009cf8b12b03f85e8939034de19ee18251b72e'}
for name,want in originals.items():assert sha(H.parent/'navigation/modules'/name)==want
assert sha(H/'inputs/AMITSESetupData.bin')=='e9b4799c79e23d75b39a123066c6ab80ed3f9176dfc57a50727968c5b1ec08f3'
files=set(p for p in H.iterdir()if p.is_file()and p.name!='component_manifest.json')
for directory in ['inputs','rea_text']:
 files.update(p for p in(H/directory).iterdir()if p.is_file())
sessions=[]
for name in ['rea','rea02','rea03']:
 d=H/name;responses=sorted(d.glob('response-*.json'));errors=[p.name for p in responses if read(p).get('isError')]
 assert (d/'final-close.json').exists()and not read(d/'final-close.json').get('isError')
 sessions.append(dict(name=name,queued_commands=len(list(d.glob('command-*.json'))),responses=len(responses),errors=errors,clean_close=True,first_session_exit='nonzero after preserved invalid query'if name=='rea'else'zero'))
 files.update(p for p in d.iterdir()if p.is_file()and p.suffix in ['.json','.txt'])
files.update(p for p in O.iterdir()if p.is_file()and p.suffix in ['.dll','.obj','.map','.json'])
files.update(R/path for path in build['sources'])
files.update(R/path for path in review['bindings'])
files.update(H.parent/'navigation/modules'/name for name in originals)
bindings={str(p.resolve().relative_to(R)):{'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)}
report={
 'component':'W890E-SAGE SE 0603 write_sinks04','status':'COMPILED_AND_TESTED_PREFLIGHT_DENY_ONLY_NATIVE_BRIDGE',
 'release_ready':False,'native_write_dispatch_enabled':False,'ordinary_native_save_usable':False,'installed_on_hardware':False,'cap_or_rom_generated':False,
 'tests':{'compiled_policy_checks':policy['checks'],'same_bridge_object_with_observer_fixture_checks':bridge['checks'],'original_native_machine_byte_chain_checks':native['checks'],'test_total_checks_not_features':policy['checks']+bridge['checks']+native['checks']},
 'products':build['products'],'fixture_product':{'sha256':fixture['sha256'],'scope':'TEST_MODEL_ONLY'},
 'native_catalog':{'descriptors':121,'descriptor_bytes':124,'native_oc_index':94,'native_memory_index':99,'these_are_not_ifr_varstore_ids':[35,40]},
 'rea_sessions':sessions,'installer_review':{'path':str((H/'installer_review.json').relative_to(R)),'sha256':sha(H/'installer_review.json'),'scope':'FIXED_FINDINGS_IN_BOUNDED_OFFLINE_LAB_COMPONENT_NOT_PHYSICAL_APPROVAL'},
 'remaining_required':[
  'Live original-caller admission and effect execution binding at a firmware-service-compatible TPL; cached checks do not supply AP/SMM exclusion or atomicity.',
  'Close whole Save callbacks, Boot/Driver direct writes,1D594 bookkeeping and complete defaults/profile/import/notification effect graphs before dispatch.',
  'Complete alias policy and live Setup device-path binding; no unknown or arbitrary partial batch may be committed.',
  'Preserve ordinary native setting saves through the fully bound chain; present deny-only destinations must not be installed.',
  'Bind original HII queue rebuilds/native form lifecycle to observer invalidation; stage7 BootOverride snapshots are not owner permissions.',
  'Root integrated native observer/management/runtime/installer/recovery tests and physical cold-entry validation.',
  'Separate supported modified-image acceptance/signature/deployment/recovery requirements; no CAP produced by this component.'
 ],'bindings':bindings}
M.write_text(json.dumps(report,indent=2)+'\n');n=verify(report);print(json.dumps({'status':report['status'],'bindings':n,'tests':report['tests'],'manifest_sha256':sha(M)}))
