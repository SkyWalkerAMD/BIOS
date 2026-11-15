"""Actual local DPAPI tests with synthetic bytes, never a firmware credential."""
from pathlib import Path
import datetime,hashlib,json,os,subprocess,sys
from dpapi_codec import protect,unprotect,CodecError
HERE=Path(__file__).resolve().parent

if len(sys.argv)==3 and sys.argv[1]=='--fresh-process':
    cipher=Path(sys.argv[2]).read_bytes()
    expected=sys.stdin.buffer.read(8193)
    plain=unprotect(cipher,b'LOCAL_SYNTHETIC_TEST_ONLY')
    if len(expected)>8192 or plain!=expected:
        raise SystemExit(2)
    # Never emit plaintext, its digest or a real fixture's verification token.
    print(json.dumps({'fresh_process_equal':True}))
    raise SystemExit(0)

run=HERE/('test-'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
run.mkdir()
data=b'NOT-A-FIRMWARE-PASSWORD\x00'+os.urandom(64)
context=b'LOCAL_SYNTHETIC_TEST_ONLY'
cipher=protect(data,context)
assert unprotect(cipher,context)==data
checks=['Actual current-user DPAPI roundtrip']
path=run/'synthetic-fixture.dpapi'
with path.open('xb') as stream:
    stream.write(cipher);stream.flush();os.fsync(stream.fileno())
child=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--fresh-process',str(path)],
                     input=data,capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
assert child.returncode==0 and json.loads(child.stdout)=={'fresh_process_equal':True}
checks.append('Ciphertext file decrypts and equals expected synthetic bytes in a fresh process')
for label,call in [
    ('different context',lambda:unprotect(cipher,b'WRONG_CONTEXT')),
    ('truncated ciphertext',lambda:unprotect(cipher[:-9],context)),
    ('corrupted ciphertext',lambda:unprotect(cipher[:len(cipher)//2]+bytes([cipher[len(cipher)//2]^1])+cipher[len(cipher)//2+1:],context)),
    ('empty plaintext',lambda:protect(b'',context)),
    ('oversize plaintext',lambda:protect(b'x'*4097,context)),
    ('empty context',lambda:protect(data,b'')),
    ('oversize context',lambda:protect(data,b'x'*1025)),
    ('oversize ciphertext',lambda:unprotect(b'x'*32769,context)),
]:
    try:call()
    except CodecError:checks.append(label+' rejected')
    else:raise AssertionError(label)
# Exercise the application envelope independently of DPAPI error-code details.
import dpapi_codec as codec
real=codec._operation
for label,wrapped in [('wrong envelope',b'x'*80),('invalid declared size',codec.MAGIC+b'\0'*40),
                      ('wrong inner digest',codec.MAGIC+(1).to_bytes(4,'little')+b'\0'*32+b'x')]:
    codec._operation=lambda *args,body=wrapped:body
    try:codec.unprotect(b'x'*32,context)
    except CodecError:checks.append(label+' rejected after modeled DPAPI result')
    else:raise AssertionError(label)
codec._operation=real
# Model an invalid native length so the cleanup path cannot perform an
# unbounded memset on a result that has already failed its length check.
import ctypes,types
real_dll=ctypes.WinDLL
native_buffer=(ctypes.c_ubyte*16)()
released=[]
def invalid_native(*arguments):
    outgoing=arguments[-1]._obj
    outgoing.cbData=codec.MAX_CIPHERTEXT+1
    outgoing.pbData=ctypes.cast(native_buffer,ctypes.POINTER(ctypes.c_ubyte))
    return 1
def local_free(pointer):
    released.append(bool(pointer))
    return None
ctypes.WinDLL=lambda *args,**kwargs:types.SimpleNamespace(CryptProtectData=invalid_native,CryptUnprotectData=invalid_native,LocalFree=local_free)
try:
    try:codec._operation(b'SYNTHETIC',context,False)
    except CodecError:checks.append('Invalid native length rejected with bounded cleanup')
    else:raise AssertionError('invalid native length')
finally:ctypes.WinDLL=real_dll
assert released==[True]
result={'status':'PASS_LOCAL_DPAPI_CODEC_SYNTHETIC_DATA_ONLY','checks':checks,
        'new_hardware_fixture_created':False,'device_calls':0,'firmware_writes':0,
        'file_contains_ciphertext_only':data not in path.read_bytes(),
        'same_user_fresh_process_tested':True,'other_account_or_profile_loss_tested':False,
        'journal_workflow_implemented':False,'firmware_recovery_tool_implemented':False,
        'bindings':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [HERE/'dpapi_codec.py',HERE/'test_codec.py',path]},
        'limits':['Same-user fresh-process recovery tested; loss of Windows profile/account/DPAPI keys is not covered.',
                  'DPAPI current-user APIs may have platform key-store effects; no firmware or BMC access.',
                  'No plaintext or its verification digest is printed or stored. Python immutable memory is not guaranteed wiped.']}
(run/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'run':str(run),**result}))
