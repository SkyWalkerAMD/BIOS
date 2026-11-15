"""Copy independent prior entry VM; audit current codec source without DPAPI calls."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;D04=HERE.parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=D04/'ram_transaction08_independent_review'
source=(old/'verify_app_entry_edges.py').read_text()
prefix=source.split('\ndef build():',1)[0]
body='class VM:'+source.split('\nclass VM:',1)[1].split('\n\ndef main():',1)[0]
header='''"""Inherited independently reviewed VM, used only against full TX09 PE bytes.
No carrier compile, no native host execution and no hardware methods.
"""\n'''
prefix=prefix[prefix.index('from pathlib import Path'):].replace("TX=D04/'ram_transaction05'","TX=D04/'ram_transaction09'")
(HERE/'entry_harness.py').write_text(header+prefix+'\n'+body+'\n')
runner=(old/'verify_final_app_entry.py').read_text().replace("'ram_transaction08'","'ram_transaction09'").replace('SageNative13RamTest08.efi','SageNative13RamTest09.efi').replace("'verify_app_entry_edges.py'","'entry_harness.py'")
(HERE/'verify_final_app_entry.py').write_text(runner)
derivation={'status':'PREPARED_ONLY_WAITING_FINAL_TX09','source_fixture':{'path':str((old/'verify_app_entry_edges.py').relative_to(D04)),'sha256':sha(old/'verify_app_entry_edges.py')},'source_runner':{'path':str((old/'verify_final_app_entry.py').relative_to(D04)),'sha256':sha(old/'verify_final_app_entry.py')},'changes':['VM class copied unchanged; unused carrier-build/main omitted.','Runner names changed to TX09 and independent local fixture filename.'],'outputs':{p.name:sha(p)for p in [HERE/'entry_harness.py',HERE/'verify_final_app_entry.py']}}
(HERE/'entry_derivation.json').write_text(json.dumps(derivation,indent=2)+'\n')
codec=D04/'credential_fixture_durable01';report=codec/'test-20261104_001411/result.json'
result=json.loads(report.read_text())
assert result['bindings']['dpapi_codec.py']=='a8368a7bf6658c116948d77e467c623871e2fa8c53be1859de04ef6218331775'
assert result['bindings']['test_codec.py']=='3184cce76f078b54d0644550062dc44ea5e12ee9cae00d568eb6d53736065c6d'
dest=HERE/'codec_source_review';dest.mkdir(exist_ok=True)
for p in [codec/'dpapi_codec.py',codec/'test_codec.py',report]:
 if p.name in result['bindings']:assert sha(p)==result['bindings'][p.name]
 (dest/p.name).write_bytes(p.read_bytes())
review={
 'status':'SOURCE_ONLY_REVIEW_NO_NEW_DPAPI_EXECUTION_NO_RELEASE_CLAIM',
 'source_sha256':sha(codec/'dpapi_codec.py'),'test_source_sha256':sha(codec/'test_codec.py'),'author_report_sha256':sha(report),
 'author_test_count':len(result['checks']),'new_blocking_findings':[],
 'observations':['Public protect/unprotect reject wrong types, empty/oversized plaintext/context and oversized ciphertext before native API invocation.','Native flags are1; LOCAL_MACHINE flag4 is not set. The review does not independently test another Windows user or key/profile loss.','Context and fixed domain are supplied as DPAPI optional entropy; envelope additionally checks exact magic, bounded size and inner digest.','Native output copy is bounded before ctypes.string_at; cleanup skips zeroing an invalid oversized native result while still freeing it.','The library has no file, command, network or firmware calls and no plaintext logging. Test data is explicitly synthetic.','The current author report binds14 checks and explicitly separates modeled malformed-native-result tests from actual DPAPI roundtrip/fresh process. The older13-check report is superseded.'],
 'unimplemented_release_prerequisites':['Durable atomic journal/ACL and readback barrier before password input','Bind journal to exact machine/session/package context','Independent original-firmware recovery flow and authentication','Power-loss/interrupted-write recovery verification','Recovery when Windows current-user profile/DPAPI keys are lost'],
 'limits':['Read source and verified current file/report hashes; did not rerun API tests or create a credential fixture.','This is a codec library review, not approval to write a firmware password or a completed recovery implementation.','Python immutable bytes are not reliably wiped; source explicitly disclaims total process-memory zeroization.'],
 'hardware_actions':False}
(dest/'review.json').write_text(json.dumps(review,indent=2)+'\n')
print(json.dumps({'entry_vm_prepared':True,'codec_review_sha256':sha(dest/'review.json')}))
