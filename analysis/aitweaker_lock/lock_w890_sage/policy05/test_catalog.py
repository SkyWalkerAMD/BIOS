"""Compile the descriptive policy and check aliases, identity and mutation cases.

No native callback or firmware service executes. Passing is NOT runtime entry
coverage. Every successful match explicitly retains LIVE_IDENTITY_REQUIRED.
"""
from pathlib import Path
import ctypes as C, hashlib, json, os, subprocess, sys, uuid
H=Path(__file__).resolve().parent;B=H.parent;ROOT=B.parents[2]
Z=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe';O=H/'build';O.mkdir(exist_ok=True)
env=os.environ.copy();env.update(ZIG_LOCAL_CACHE_DIR=str(O/'zig-local'),ZIG_GLOBAL_CACHE_DIR=str(O/'zig-global'),TEMP=str(O),TMP=str(O))
sources=[H/'catalog.c',B/'password/core/password_crypto.c'];commands=[];objects=[]
for p in sources:
 obj=O/(p.stem+'.obj')
 cmd=[str(Z),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(Z.parent/'lib/include'),'-O2','-std=c11','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-red-zone','-mno-stack-arg-probe','-c',str(p),'-o',str(obj)]
 commands.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
 if r.returncode:print((r.stdout+r.stderr).decode('utf8','replace'));r.check_returncode()
 objects.append(obj)
dll=O/'W890Catalog05.DESCRIPTIVE.TESTONLY.dll'
cmd=[str(Z),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/timestamp:0','/export:fh05_describe','/out:'+str(dll),*[str(p)for p in objects]]
commands.append(cmd);r=subprocess.run(cmd,env=env,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
if r.returncode:print((r.stdout+r.stderr).decode('utf8','replace'));r.check_returncode()
class Description(C.Structure):
 _fields_=[('risk',C.c_int32),('flags',C.c_uint32)]
lib=C.CDLL(str(dll));fn=lib.fh05_describe
fn.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_uint16,C.c_uint32,C.c_uint,C.POINTER(Description)];fn.restype=C.c_int
policy=json.loads((H/'storage_policy.json').read_text());packages=policy['packages'];cases=[]

def check(name,condition):
 assert condition,name
 cases.append({'name':name,'pass':True})

def call(p,q,control=True,blob=None,fs=None,form=None,offset=None,kind=None):
 data=(ROOT/p['blob_path']).read_bytes() if blob is None else blob
 a=C.create_string_buffer(data);g=C.create_string_buffer(uuid.UUID(fs or q['formset']).bytes_le)
 d=Description(99,0)
 r=fn(a,len(data),g,q['form'] if form is None else form,q['offset'] if offset is None else offset,int(control) if kind is None else kind,C.byref(d))
 return r,d.risk,d.flags

by_name={p['module']:p for p in packages}
socket=by_name['SocketSetup'];platform=by_name['Platform'];setup=by_name['Setup']
ocmr=[q for q in socket['controls']if q['reason']=='EXACT_PROTECTED_GUID_AND_NAME']
mem=[q for q in socket['controls']if q['reason']=='SHARED_MEMORY_PROTECTED_BYTE_OVERLAP']
outside=[q for q in socket['controls']if q['reason']=='SHARED_MEMORY_OUTSIDE_PROTECTED_BYTES']
oc=[q for q in platform['controls']if q['reason']=='EXACT_PROTECTED_GUID_AND_NAME']
check('All nine SocketSetup OCMR controls classified protected',len(ocmr)==9 and all(call(socket,q)[1]==1 for q in ocmr))
check('All nine shared SocketMemory byte aliases classified protected',len(mem)==9 and all(call(socket,q)[1]==1 for q in mem))
check('Other shared-memory fields retain separate storage scope',len(outside)==199 and all(call(socket,q)[1]==0 for q in outside))
check('All 825 Platform OcSetup controls classified protected',len(oc)==825 and all(call(platform,q)[1]==1 for q in oc))
sample=ocmr[0];original=(ROOT/socket['blob_path']).read_bytes();mut=bytearray(original);mut[sample['offset']+8]^=1
check('Changed local VarStoreId invalidates the complete original package',call(socket,sample,blob=bytes(mut))==(0,-1,16))
mut=bytearray(original);mut[-1]^=1
check('Unrelated package-byte mutation cannot reuse a cached digest',call(socket,sample,blob=bytes(mut))==(0,-1,16))
check('Same opcode under a different form is rejected',call(socket,sample,form=65534)==(0,-1,16))
check('Same form under a different formset is rejected',call(socket,sample,fs='00000000-0000-0000-0000-000000000001')==(0,-1,16))
check('Interior opcode offsets are rejected',call(socket,sample,offset=sample['offset']+1)==(0,-1,16))
check('Truncated package is rejected',call(socket,sample,blob=original[:-1])==(0,-1,16))
check('Trailing data outside declared package is rejected',call(socket,sample,blob=original+b'\0')==(0,-1,16))
check('Out-of-domain query is rejected',call(socket,sample,kind=2)==(0,-1,16))
extensions=[q for q in platform['controls']if q['reason']=='GUID_EXTENSION_STORAGE_SEMANTICS_UNRESOLVED']
check('Both extended-width fields remain unknown',len(extensions)==2 and all(call(platform,q)[1:]==(-1,18) for q in extensions))
for name in ['Ip4Dxe','Ip6Dxe','ServerMgmtSetup','EventLogsSetupPage']:
 p=by_name[name];q=next(q for q in p['controls']if q['review_flags']&1)
 check(name+' ordinary storage still requires callback review',call(p,q)==(1,0,17))
ref=next(q for q in socket['controls']if q['reason']=='REFERENCE_TO_DIRECTLY_PROTECTED_FORM')
check('REF to a protected target requires protection',call(socket,ref)[1]==1)
ordinary_parent=next(f for f in socket['forms']if f['form']==ref['form'] and f['formset']==ref['formset'])
check('Protected child REF does not label the entire parent as protected',ordinary_parent['storage_risk']==0 and call(socket,ordinary_parent,False)[1]==0)
check('A FORM at a different offset cannot impersonate the same form identity',call(socket,ordinary_parent,False,offset=ordinary_parent['offset']+1)==(0,-1,16))
unknown_ref=next(q for q in socket['controls']if q['reason']=='REFERENCE_TARGET_NOT_UNIQUE_OR_ABSENT')
parent=next(f for f in socket['forms']if f['form']==unknown_ref['form'] and f['formset']==unknown_ref['formset'])
check('Unresolved child REF propagates review flag without locking parent storage',call(socket,parent,False)[2]&4 and parent['storage_risk']==0)
# Whole table output agreement exercises form/offset/guid dispatch, not native
# execution. Keep this mechanical record count separate from scenario count.
records=0
for p in packages:
 for f in p['forms']:
  assert call(p,f,False)==(1,f['storage_risk'],f['review_flags']);records+=1
 # Questions chosen at every classification transition and both ends; all
 # protected-alias rows above execute the real C function, not a Python model.
 previous=None
 for q in p['controls']:
  signature=(q['formset'],q['form'],q['storage_risk'],q['review_flags'])
  if signature!=previous:
   assert call(p,q)==(1,q['storage_risk'],q['review_flags']);records+=1
  previous=signature
check('Every form and every control classification transition matches table',records>900)
check('All matches retain live-identity-required flag',all(q['review_flags']&16 for p in packages for q in p['controls']+p['forms']))
hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources+[H/'catalog.h',H/'catalog_data.h',H/'storage_policy.json',Path(__file__)]}
result={'status':'PASS_STATIC_DESCRIPTION_ONLY','scope':__doc__,'checks':cases,'check_count':len(cases),'mechanical_records':records,'sources':hashes,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'dll_bytes':dll.stat().st_size,'commands':commands,'runtime_authorization_implemented':False,'hardware_actions':0}
(H/'test_results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items()if k not in ['sources','commands']},indent=2))
