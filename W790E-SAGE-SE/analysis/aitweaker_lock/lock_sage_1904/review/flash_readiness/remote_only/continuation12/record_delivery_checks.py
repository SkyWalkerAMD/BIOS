"""Record completed local tool checks separately from the derivation journal."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda p:json.loads(p.read_text(encoding='utf-8-sig'))
derivation=read(HERE/'delivery09_derivation.json')
for binding in derivation['bindings']:
    assert sha(Path(binding['source']))==binding['source_sha256']
    assert sha(Path(binding['output']))==binding['output_sha256']
reports={}
for name,expected in [('decoder09_tests.json',14),('capture09_tests.json',4),
                      ('capture09_stale_tests.json',3),('native12_key_tests.json',6),
                      ('poweroff_ram12_tests.json',4)]:
    p=HERE/name
    r=read(p)
    checks=r.get('checks',r.get('cases'))
    assert r['status'].startswith('PASS') and len(checks)==expected
    reports[name]={'sha256':sha(p),'checks':expected,'status':r['status']}
result={'status':'PASS_LOCAL_TRANSPORT_AND_REMOTE_OPERATION_BOUNDARIES',
        'derivation_sha256':sha(HERE/'delivery09_derivation.json'),'reports':reports,
        'device_calls':0,'EFI_packaged':False,'hardware_approval':False,
        'initial_derivation_failure':'A redundant sequential replacement expected poweroff_ram11 after ram11 had already become ram12. Removed only that redundant replacement before deriving final15 files. Frozen inputs unchanged.',
        'limits':'Local decoder and operation tests only. No production release, installed guard or real remote action is accepted by these tests.'}
(HERE/'delivery09_local_checks.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result))
