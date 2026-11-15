from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent;R=H.parents[3]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((H/'build/build.json').read_text());test=json.loads((H/'build/observer_pe_tests.json').read_text())
component=H/'build/W890NativeObserver04.TESTONLY.dll'
assert test['status']=='PASS'and test['observer_sha256']==sha(component)==build['sha256']
for p,h in build['sources'].items():assert sha(R/p)==h,(p,'source changed since compile')
assert sha(H/'verify_observer.py')==test['source_sha256']
evidence=[]
for p in (H/'rea').glob('*.json'):
    x=json.loads(p.read_text()).get('structuredContent',{})
    if x.get('evidence_id'):evidence.append({'file':str(p.relative_to(H)),'sha256':sha(p),'evidence_id':x['evidence_id'],'procedure':x.get('parameters',{}).get('procedure')})
owned={str(p.relative_to(H)):{'bytes':p.stat().st_size,'sha256':sha(p)}for p in sorted(H.rglob('*'))if p.is_file()and p.name!='component_manifest.json'and not any(x in p.parts for x in ['__pycache__','zig-local','zig-global'])}
deps={p:h for p,h in build['sources'].items()if 'native_observer04'not in p}
for p in [H.parent/'installer04/source/memory.h',H.parent/'password/provider/provider.h',H.parent/'password/w890_policy.h',H.parent/'password/w890_policy_data.h',H.parent/'password_runtime02/build/W890Runtime02.UNBOUND.TESTONLY.efi',H.parent/'navigation/navigation_manifest.json',H.parent/'password_runtime02/verify_runtime_pe.py']:
    deps[str(p.relative_to(R))]=sha(p)
report={'status':'FROZEN_COMPILED_REAL_OBSERVER_WITH_EXPLICIT_INTEGRATION_GAPS_NO_INSTALL_NO_FLASH','board':'ASUS Pro WS W890E-SAGE SE','bios':'0603','component_sha256':sha(component),'actual_pe_case_count':test['case_count'],'REA_evidence':evidence,'artifacts':owned,'external_bindings':deps,'no_hardware_actions':True,'limits':['No complete native deny/error continuation for first or nonempty history.','No complete gate/write/pending installer and no authorized physical carrier.','Protocol/page-table/native-body fixtures, SHA/KDF oracles in composed test; real observer/provider/wrappers execute.','Initial pre-dispatch installation admission remains a separate installer requirement.']}
(H/'component_manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'manifest_sha256':sha(H/'component_manifest.json'),'component_sha256':report['component_sha256'],'case_count':test['case_count'],'owned':len(owned),'dependencies':len(deps),'REA_records':len(evidence)}))
