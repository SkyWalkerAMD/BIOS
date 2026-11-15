from pathlib import Path
import hashlib,json,struct,sys
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(R/'tools/pydeps'));import pefile,capstone
def bind(p):
 d=p.read_bytes();return {'path':p.relative_to(R).as_posix(),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
p=B/'navigation/modules/AMITSE.efi';pe=pefile.PE(str(p))
assert bind(p)['sha256']=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
calls=[]
for at in (0x239e7,0x3738a,0x3fa96,0x4041e):
 code=pe.get_data(at,5);assert code[0]==0xe8 and at+5+struct.unpack('<i',code[1:])[0]==0x40094
 calls.append({'rva':hex(at),'original_bytes':code.hex(),'target':'0x40094','preserve_native_call':True})
evidence=[]
for p in sorted((H/'rea02').glob('function-*.json'))+sorted((H/'rea02').glob('caller-*.json')):
 j=json.loads(p.read_text());assert not j.get('isError')
 s=j['structuredContent'];evidence.append({'file':p.relative_to(H).as_posix(),'evidence_id':s['evidence_id'],'operation':s['operation']})
assert len(evidence)==10
case=json.loads((H/'pending_cases.json').read_text());assert case['passed'] and case['count']==10
assert case['source_sha256']==bind(H/'replay_pending.py')['sha256']
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
(H/'original_pending.asm.txt').write_text('\n'.join(f'{x.address:05x} {x.bytes.hex():24} {x.mnemonic} {x.op_str}' for x in md.disasm(pe.get_data(0x3fed4,0x4037a-0x3fed4),0x3fed4))+'\n')
report={'status':'PRESERVE_ORIGINAL_HII_QUEUE_LIFECYCLE_NOT_A_NEW_CALLBACK_AUTHORIZER',
 'original_call_sites':calls,'rea_evidence':evidence,'instruction_cases':10,
 'complete_queue_fixture_returns':7,'stops_before_unproved_helper':3,
 'findings':['40094 first calls3FED4 to normalize the notification queue; it is not an empty-only operation.',
  'Native queue head is count/first/last; nodes contain HII,notify kind,package,previous,next.',
  'Kinds1/2/8 reach original add/remove/replacement handling. BAA68/BAA70 optionally select package handles.',
  '426CC invalidates native descriptor HII withFFFF, retires associated controls/events and original package state.',
  '42B78 processes prior AFF22/AFF40 cache work and changes FFFF raw HII entries tozero; this is not a no-effect callback.',
  'A new UI lock should not replace these original functions or discard their statuses just because a helper was not emulated.',
  'Cache-generation invalidation is a lock-local obligation; page proofs must be re-created from actual current HII/native data.'],
 'scope_limits':['The queue and catalog fixtures do not establish physical allocator ownership.',
  'No complete add/remove/rebuild body, nativeGUI or callbacks were supplied as blanket success.',
  'Two caller containment queries returnednot_in_procedure; original CALL bytes remain independently verified.',
  'The catalog-generation component and foreign-page helper require separate integration testing.'],
 'tool_recovery':{'first_attempt':'Default execution: import completed in40s, authenticated local bridge not reached; provider_timeout600000ms, close succeeded.',
  'second_attempt':'Approved local-loopback execution; same original and timeout budget, ten queries succeeded, evidence exported and session closed.',
  'first_evidence_preserved':True,'provider_or_security_checks_disabled':False},
 'firmware_or_hardware_changes':False}
(H/'review.json').write_text(json.dumps(report,indent=2)+'\n')
files=[H/x for x in ('README.md','rea_session.mjs','replay_pending.py','pending_cases.json','original_pending.asm.txt','review.json','freeze.py')]
files += list((H/'rea_text').glob('*.txt'))
for folder in ('rea','rea02'):
 files += [p for p in (H/folder).iterdir() if p.is_file() and p.name!='catalog.json']
ext=[B/'navigation/modules/AMITSE.efi',B/'navigation05/pending_static_review.json',B/'navigation05/visit/observer_visit05.c',B/'navigation05/bridges.c',B/'native_callbacks08/manifest.json']
m={'status':report['status'],'files':[bind(p) for p in sorted(set(files))],'external_bindings':[bind(p) for p in ext]}
p=H/'component_manifest.json';p.write_text(json.dumps(m,indent=2)+'\n');print(json.dumps({'manifest':bind(p),'files':len(m['files']),'external':len(ext)}))
