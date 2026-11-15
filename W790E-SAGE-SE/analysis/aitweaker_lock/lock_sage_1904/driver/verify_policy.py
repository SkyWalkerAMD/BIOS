"""Execute only pure, bounded policy functions in the host DLL. Never calls
UEFI entry points, private OEM code, privileged helpers, or UI on the host."""
from pathlib import Path
import ctypes as C,hashlib,json,os,random,struct,subprocess,sys,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'build'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-global');env['ZIG_LOCAL_CACHE_DIR']=str(ROOT/'tools/zig-cache-local')
exports=['policy_ifr_insert','policy_form','policy_question','policy_inert_ifr','protection_for_variable']
cmd=[str(ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/timestamp:0','/out:'+str(OUT/'policy_test.dll')]+['/export:'+x for x in exports]+[str(OUT/(x+'.obj')) for x in ['entry','services','cpu_entropy','ui','policy','hii','platform','password_core','password_crypto','probe_core']]
subprocess.run(cmd,check=True,env=env)
lib=C.CDLL(str(OUT/'policy_test.dll'))
f=lib.policy_ifr_insert;f.argtypes=[C.c_void_p,C.c_uint64]+[C.c_uint16]*4+[C.c_void_p,C.c_uint64,C.POINTER(C.c_uint64)];f.restype=C.c_int
count=0
def check(v):
 global count
 assert v;count+=1
def run(data,capacity=None):
 n=len(data);src=C.create_string_buffer(data);cap=n+30 if capacity is None else capacity
 dst=C.create_string_buffer(b'\xa5'*max(cap,1),max(cap,1));written=C.c_uint64(999)
 result=f(src,n,0x100,0x101,0x102,0x103,dst,cap,C.byref(written))
 check(src.raw[:n]==data)
 if not result:check(written.value==0 and dst.raw==b'\xa5'*max(cap,1))
 return result,dst.raw[:written.value]
case=HERE.parent/'analysis'
ifr=json.loads((case/'modules/Setup_IFR.json').read_text(encoding='utf8'))[0]
binary=(case/'modules/Setup.efi').read_bytes();package=binary[ifr['offset']:ifr['offset']+ifr['length']]
data=uuid.UUID('899407d7-99fe-43d8-9a21-79ec328cac21').bytes_le+struct.pack('<I',24+len(package))+package+b'\x04\0\0\xdf'
check(int.from_bytes(package[:3],'little')==len(package) and package[3]==2)
result,changed=run(data);check(result==1);check(len(changed)==len(data)+30)
security=next(r for r in ifr['records'] if r.get('form_id')==0x271e)
insert=20+security['end']-ifr['offset']-2
expected=bytearray(data[:insert]+bytes.fromhex('0c0f00010101e0ff0000ffff0400000c0f02010301e1ff0000ffff040000')+data[insert:])
struct.pack_into('<I',expected,16,len(data)+30);expected[20:23]=(len(package)+30).to_bytes(3,'little')
check(changed==expected)
check(run(changed)[0]==0)
check(run(data,len(data)+29)[0]==0)
for pos in [16,20,21,22,23,24,25,insert-2,insert-1,len(data)-4,len(data)-1]:
 b=bytearray(data);b[pos]^=0xff;run(bytes(b))
rng=random.Random(1904)
for _ in range(2048):
 size=rng.randrange(0,512);b=bytearray(rng.randbytes(size))
 if size>=20:struct.pack_into('<I',b,16,size)
 check(run(bytes(b))[0]==0)
for n in [24,25,30,100,1000,2000,180000,len(data)-1]:
 b=bytearray(data[:n]);struct.pack_into('<I',b,16,len(b));check(run(bytes(b))[0]==0)
lib.policy_form.argtypes=[C.c_uint16];lib.policy_form.restype=C.c_int
for x in [0x2714,0x2712,0x272c,0x2e96,0x2e9c]:check(lib.policy_form(x)==1)
for x in [0x2713,0x271e,0x271b,0x2e8c,0,0xffff]:check(lib.policy_form(x)==0)
lib.policy_question.argtypes=[C.c_uint16];lib.policy_question.restype=C.c_int
lib.policy_inert_ifr.argtypes=[C.c_void_p,C.c_uint64];lib.policy_inert_ifr.restype=C.c_int
for x in json.loads((HERE/'policy.json').read_text(encoding='utf8'))['permanently_disabled_exit_descriptors']:
 b=bytes.fromhex(x['ifr_hex'])
 check(lib.policy_question(int(x['question_id'],16))==0)
 check(lib.policy_inert_ifr(C.create_string_buffer(b),len(b))==1)
 for i in range(len(b)):
  altered=bytearray(b);altered[i]^=0x80
  check(lib.policy_inert_ifr(C.create_string_buffer(bytes(altered)),len(b))==0)
 check(lib.policy_inert_ifr(C.create_string_buffer(b),len(b)-1)==0)
lib.protection_for_variable.argtypes=[C.c_void_p,C.c_void_p];lib.protection_for_variable.restype=C.c_int
for name,guid,want in [('VARSTORE_OCMR_SETTINGS_NAME','a3a3b874-7636-4182-ba1e-f52c584494e3',1),('SocketMemoryConfig','98cf19ed-4109-4681-b79d-9196757c7824',2),('AiTweakerPassword1904','750e9d9d-f2d8-4e14-9b53-8923a7190461',3),('Setup','a3a3b874-7636-4182-ba1e-f52c584494e3',0),('SocketMemoryConfig','a3a3b874-7636-4182-ba1e-f52c584494e3',0)]:
 check(lib.protection_for_variable(C.create_string_buffer(name.encode('utf-16-le')+b'\0\0'),C.create_string_buffer(uuid.UUID(guid).bytes_le))==want)
result={'status':'PASS','assertions':count,'scope':'Actual compiled pure policy functions; official 1904 IFR transformed exactly and re-entry/malformed/fuzz input rejection; no host EFI execution.','driver_efi_sha256':hashlib.sha256((OUT/'AiTweakerLock1904.efi').read_bytes()).hexdigest(),'source_ifr_sha256':hashlib.sha256(package).hexdigest(),'output_ifr_list_sha256':hashlib.sha256(changed).hexdigest(),'original_bytes_preserved_except_two_package_lengths_and_30_byte_insert':True}
(OUT/'policy_test.json').write_text(json.dumps(result,indent=2),encoding='utf8');(OUT/'setup_hii_policy_fixture.bin').write_bytes(data)
print(json.dumps(result,indent=2))
