"""Additive binding of full physical forms to original native replay outputs."""
from pathlib import Path
import json,hashlib,zlib
H=Path(__file__).resolve().parent;D=H.parent;B=D.parent;R=B.parents[2]
sha=lambda b:hashlib.sha256(b).hexdigest()
out=H/'manifest.json';assert not out.exists(),'physical appendix already frozen'
original_manifest=D/'manifest.json';assert sha(original_manifest.read_bytes())=='aadeb51126d829a8d49e8a29b34d7e0c69027979dc7000bfc51270c4a4f92561'
frozen=json.loads(original_manifest.read_text())
for e in frozen['files']:assert sha((D/e['path']).read_bytes())==e['sha256']
for e in frozen['external_read_only_inputs']:assert sha((R/e['path']).read_bytes())==e['sha256']
C=B/'hardware_delta07/capture_6e7a57f9729b082c';capture=json.loads((C/'reconciled.json').read_text())
log=R/capture['log']['path'];raw=log.read_bytes()
assert len(raw)==12989 and sha(raw)=='6e7a57f9729b082ce15931a063d94a32a56f51d78c9dc8097a80984e9487aa00'
assert zlib.crc32(raw)&0xffffffff==0xabfb51bc
results=[]
for module,index,expected in [('NvmeDynamicSetup',2,'06213876bb686f42b602d87fc5c6b10682bb3d20bc6f5bdea02e6d84791d0861'),
 ('SocketSetup',5,'ad272dae6eb1713db3f3a2364bb546bc1d694e7f7f4d435d769f43320177267e')]:
 j=json.loads((D/(module+'.physical_replay.json')).read_text());forms=C/('object_%02d.forms.bin'%index)
 assert sha(forms.read_bytes())==j['captured_sha256']==j['generated_full_sha256']==expected
 assert j['full_byte_equality']and j['original_code_patches']==0 and not j['authorization']
 results.append({k:j[k]for k in ['module','captured_bytes','captured_sha256','observed_prompt_ids','observed_inserted_bytes_hex','insert_package_offset','full_byte_equality','native_target_rva']})
result={'status':'PHYSICAL_FULL_FORMS_EQUAL_ORIGINAL_NATIVE_UPDATE_UNDER_EXPLICIT_MODEL',
 'physical_log_sha256':sha(raw),'physical_log_crc32':'ABFB51BC','results':results,
 'prior_frozen_manifest_sha256':sha(original_manifest.read_bytes()),'prior_frozen_bindings_unchanged':True,
 'limits':['Observed prompt IDs are supplied as NewString return values. Actual HII allocator history is not replayed.',
 'Socket HOB, selected DIMM slots and generated string contents remain synthetic. Exact forms do not establish DIMM identities or actual string text.',
 'Nvme EFI_NOT_FOUND is a modeled branch witness; actual hardware enumeration failure cause is not established.',
 'Isolated original opcode generation/update is verified. No full boot, native callback authorization, password operation or flashability claim.'],
 'hardware_actions_by_this_review':0,'firmware_changes':0,'runtime_authorized':False}
(H/'result.json').write_text(json.dumps(result,indent=2)+'\n')
(H/'REPORT.txt').write_text('W890 original dynamic forms: physical-byte replay confirmed\n\n'
 'NvmeDynamicSetup:266 bytes; observed Prompt0x1F; original2B30 output equals every captured form byte.\n'
 'SocketSetup:135822 bytes; observed Prompts1FEF/1FF0/1FF1/1FF2; original61B0 output equals every captured form byte.\n'
 'Only package length and the independently identified label intervals differ from the originals.\n'
 'The complete physical log is12989 bytes, CRC32 ABFB51BC, SHA256 '+sha(raw)+'.\n\n'
 'This is an additive appendix. All150 files and10 external bindings in the prior frozen checkpoint were checked unchanged.\n'
 'Runtime string allocation and Socket memory attributes remain explicit models; the observed forms IDs are used as inputs.\n'
 'No hardware actions, firmware writes, callback authorization, complete boot proof or flashability claim.\n')
def bind(p):
 b=p.read_bytes();return {'path':p.relative_to(R).as_posix(),'bytes':len(b),'sha256':sha(b)}
paths=[original_manifest,D/'NvmeDynamicSetup.physical_replay.json',D/'SocketSetup.physical_replay.json',
 D/'verify_physical.py',D/'replay_nvme.py',D/'replay_socket.py',C/'reconciled.json',C/'object_02.forms.bin',C/'object_05.forms.bin',
 C/'object_02.changes.json',C/'object_05.changes.json',log,H/'freeze.py',H/'result.json',H/'REPORT.txt']
manifest={'status':result['status'],'bindings':[bind(p)for p in paths],'prior_frozen_checkpoint_unchanged':True,
 'runtime_authorized':False,'hardware_actions':0}
out.write_text(json.dumps(manifest,indent=2)+'\n')
for e in manifest['bindings']:assert sha((R/e['path']).read_bytes())==e['sha256']
print(json.dumps({'manifest_sha256':sha(out.read_bytes()),'result_sha256':sha((H/'result.json').read_bytes()),'bindings':len(paths),'original_checkpoint_unchanged':True,'full_form_equalities':2}))
