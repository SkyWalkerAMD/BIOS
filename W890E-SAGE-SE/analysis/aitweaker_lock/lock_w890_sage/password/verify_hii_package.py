"""Reparse generated HII data independently from its builder's structures."""
from pathlib import Path
import hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock'))
from inspect_forms import packages,decode
from inspect_setup import string_packages
raw=(HERE/'build/management.pack').read_bytes();record=json.loads((HERE/'build/management_package.json').read_text())
checks=[]
def check(name,value):assert value,name;checks.append(name)
check('package identity',str(uuid.UUID(bytes_le=raw[:16]))==record['package_guid'])
check('list length includes end',struct.unpack_from('<I',raw,16)[0]==len(raw))
p=20;kinds=[]
while p<len(raw):
    h=struct.unpack_from('<I',raw,p)[0];n=h&0xffffff;kind=h>>24
    check('bounded package '+str(p),n>=4 and p+n<=len(raw));kinds.append(kind);p+=n
check('forms strings end order',kinds==[2,4,223] and p==len(raw))
strings=string_packages(raw);check('one English string package',len(strings)==1)
check('string content matches explicit UI catalog',list(strings[0]['strings'].values())==record['texts'])
ifr=[decode(raw,x,strings[0]['strings'])for x in packages(raw)]
check('one form package',len(ifr)==1)
r=ifr[0]['records'];formsets=[x for x in r if x['op']==14];forms=[x for x in r if x['op']==1]
check('independent W890 formset',len(formsets)==1 and formsets[0]['guid']==record['formset_guid'])
check('single management form',len(forms)==1 and forms[0]['form_id']==1)
actions=[x for x in r if x['op']==12]
check('three exact action identifiers',[x['question_id']for x in actions]==[0xffd0,0xffd1,0xffd2])
check('actions request callback and no varstore',all(x['flags']==4 and x['varstore_id']==0 and x['var_offset']==65535 for x in actions))
check('passwords not stored as HII string questions',not any(x['op'] in [8,28,36,37,38] for x in r))
check('all prompts and help strings resolve',all(x['prompt'] and x['help'] for x in actions))
check('no earlier board/version in UI text',not any('790' in t or '1904' in t for t in record['texts']))
changed=(HERE/'build/security_actions_0603.TESTONLY.forms').read_bytes()
parsed=packages(changed);check('transformed original scopes valid',len(parsed)==1)
extra=[x for x in parsed[0]['records']if x['op']==12 and int.from_bytes(bytes.fromhex(x['hex'])[6:8],'little')in [0xffd0,0xffd1,0xffd2]]
check('three inserted security actions',len(extra)==3)
for x in extra:
    f=[parsed[0]['records'][i]for i in x['parents']if parsed[0]['records'][i]['op']==1]
    check('action belongs only to original Security',len(f)==1 and int.from_bytes(bytes.fromhex(f[0]['hex'])[2:4],'little')==0x271d)
report={'status':'PASS_STATIC_HII_REPARSE_NOT_NATIVE_GUI_ACCEPTANCE','checks':len(checks),'cases':checks,
        'management_package_sha256':hashlib.sha256(raw).hexdigest(),'security_fixture_sha256':hashlib.sha256(changed).hexdigest(),
        'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'limits':['No live HII NewPackageList/UpdatePackageList or ConfigAccess installation performed.',
                  'Security transformation uses supplied test token numbers; production strings must first be allocated and bound.',
                  'No native password display/input or persisted device record tested.']}
(HERE/'build/hii_test.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks)}))
