"""Run frozen production password core + AP_ENV read/persist with local providers.

The DLL has no entry point/imports. Only pure password/storage code is called;
no privileged, console, event-handoff or host firmware function is executed.
Passwords are freshly random, memory-only and never reported. Stage 2 below is
a new local DLL instance, NOT a hardware receipt or simulated physical success.
"""
from pathlib import Path
import ctypes as C,hashlib,json,os,secrets,shutil,struct,subprocess,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'));import pefile
OUT=HERE/'stage1/build';REVIEW=HERE/'password_chain_fixture';REVIEW.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
manifest=json.loads((OUT/'build.json').read_text(encoding='utf8'))
assert sha(OUT/'BOOTX64.EFI')==manifest['efi_sha256']
assert all(sha(HERE/n)==h for n,h in manifest['local_sources'].items())
exports=['initialize_services','nv_prepare','nv_activate','nv_begin_action','nv_end_action','nv_guard_set','nv_cleanup_tombstone',
         'begin_console_session','end_console_session','platform_session_owned','platform_can_enter',
         'ap_set_password','ap_clear_password','ap_unlock','ap_can_enter','ap_record_valid',
         'system_table,DATA','password_core,DATA','original_set_variable,DATA']
dll_path=REVIEW/'stage1-local-fixture.dll'
objects=[a for a in manifest['commands'][-1] if a.lower().endswith('.obj')]
assert objects
cmd=[manifest['commands'][-1][0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0',
     '/out:'+str(dll_path),'/map:'+str(REVIEW/'fixture.map')]+['/export:'+e for e in exports]+objects
subprocess.run(cmd,check=True,cwd=HERE,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
pe=pefile.PE(str(dll_path));assert pe.OPTIONAL_HEADER.AddressOfEntryPoint==0 and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT');pe.close()
other=REVIEW/'stage2-local-fixture.dll';shutil.copyfile(dll_path,other)
ERR=lambda n:0x8000000000000000|n
READ=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p)
WRITE=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_void_p,C.c_uint32,C.c_uint64,C.c_void_p)
CREATE=C.CFUNCTYPE(C.c_uint64,C.c_uint32,C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p)
CREATE_EX=C.CFUNCTYPE(C.c_uint64,C.c_uint32,C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p)
ENTROPY=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p,C.c_size_t)
NOW=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p)
class ENV(C.Structure):_fields_=[('opaque',C.c_void_p),('read',C.c_void_p),('persist',C.c_void_p),('entropy',C.c_void_p),('now',C.c_void_p)]
class CORE(C.Structure):
    _fields_=[('env',ENV),('record',C.c_ubyte*128),('token',C.c_uint64),('last',C.c_uint64),('retry',C.c_uint64),('failed',C.c_uint32),('mode',C.c_uint32),('active',C.c_ubyte),('unlocked',C.c_ubyte),('busy',C.c_ubyte),('clock_valid',C.c_ubyte)]
assert CORE.record.offset==40 and CORE.token.offset==168 and CORE.mode.offset==196
variables={};writes=[];clock=[1];errors=[];pins=[]
credential_guid=bytes.fromhex('9d9d0e75d8f2144e9b538923a7190461')
def key(name,guid):
    chars=[]
    for i in range(128):
        n=C.c_uint16.from_address(name+i*2).value
        if not n:break
        chars.append(chr(n))
    return ''.join(chars),C.string_at(guid,16)
KEY=('AiTweakerPassword1904',credential_guid)
@READ
def get_var(name,guid,attrs,size,data):
    try:
        k=key(name,guid)
        if k not in variables:return ERR(14)
        a,v=variables[k];cap=C.c_uint64.from_address(size).value;C.c_uint64.from_address(size).value=len(v)
        if attrs:C.c_uint32.from_address(attrs).value=a
        if cap<len(v):return ERR(5)
        C.memmove(data,v,len(v));return 0
    except BaseException:errors.append('get-provider-exception');return ERR(7)
@WRITE
def set_var(name,guid,attrs,size,data):
    try:
        k=key(name,guid)
        if k!=KEY:errors.append('non-credential-write');return ERR(8)
        if size:
            if attrs!=3 or size!=128:return ERR(8)
            variables[k]=(attrs,C.string_at(data,size))
        else:
            if attrs or data:return ERR(8)
            variables.pop(k,None)
        writes.append((attrs,size));return 0
    except BaseException:errors.append('set-provider-exception');return ERR(7)
@CREATE
def event(kind,tpl,notify,context,out):C.c_void_p.from_address(out).value=0x1001;return 0
@CREATE_EX
def event_ex(kind,tpl,notify,context,guid,out):C.c_void_p.from_address(out).value=0x1002;return 0
@ENTROPY
def entropy(context,out,size):C.memmove(out,secrets.token_bytes(size),size);return 0
@NOW
def now(context,out):C.c_uint64.from_address(out).value=clock[0];return 0
def pointer(fn):return C.cast(fn,C.c_void_p).value
def store(buf,offset,value):C.memmove(C.addressof(buf)+offset,struct.pack('<Q',value),8)
def setup(path,stage,digest=None):
    dll=C.CDLL(str(path));core=CORE.in_dll(dll,'password_core')
    st=C.create_string_buffer(0x80);bs=C.create_string_buffer(0x180);rt=C.create_string_buffer(0x88)
    C.memmove(rt,struct.pack('<QIIII',0x56524553544e5552,0x200b0,0x88,0,0),24)
    store(rt,0x48,pointer(get_var));store(rt,0x58,pointer(set_var));C.memmove(C.addressof(rt)+16,struct.pack('<I',zlib.crc32(rt.raw)),4)
    store(bs,0x50,pointer(event));store(bs,0x170,pointer(event_ex));store(st,0x58,C.addressof(rt));store(st,0x60,C.addressof(bs))
    C.c_void_p.in_dll(dll,'system_table').value=C.addressof(st)
    for name in ['nv_prepare','ap_set_password','ap_clear_password','ap_unlock','ap_can_enter','ap_record_valid']:
        getattr(dll,name).restype=C.c_int
    dll.nv_prepare.argtypes=[C.c_void_p,C.c_void_p,C.c_uint32,C.c_void_p]
    dll.ap_set_password.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]
    dll.ap_clear_password.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t]
    dll.ap_unlock.argtypes=dll.ap_clear_password.argtypes
    dll.ap_can_enter.argtypes=[C.c_void_p];dll.ap_record_valid.argtypes=[C.c_void_p,C.c_size_t]
    assert dll.initialize_services()==1
    read_pin,persist_pin=core.env.read,core.env.persist
    expected=C.create_string_buffer(digest) if digest else None
    assert dll.nv_prepare(pointer(get_var),pointer(set_var),stage,C.addressof(expected) if expected else None)==1
    C.c_void_p.in_dll(dll,'original_set_variable').value=pointer(dll.nv_guard_set)
    core.env.entropy=pointer(entropy);core.env.now=pointer(now)
    assert dll.nv_activate()==1 and dll.begin_console_session()==1
    assert core.env.read==read_pin and core.env.persist==persist_pin
    pins.append((dll,core,st,bs,rt,expected))
    return dll,core
checks=[]
def check(label,value):assert value,label;checks.append(label)
passwords=[C.create_string_buffer(secrets.token_hex(32).encode('ascii')) for _ in range(3)]
first,next_password,wrong=passwords
try:
    a,core=setup(dll_path,1);cp=C.addressof(core)
    check('production core starts unconfigured and console locked',core.mode==0 and not core.unlocked)
    assert a.nv_begin_action(1)==1
    check('actual 600000-iteration production enrollment persists through unchanged AP_ENV',a.ap_set_password(cp,core.token,None,0,first,64)==0)
    a.nv_end_action();check('record is exact native readback attrs3/128 and validates',writes==[(3,128)] and variables[KEY][0]==3 and a.ap_record_valid(C.addressof(core)+40,128)==1)
    check('enrollment does not implicitly unlock',core.mode==1 and not core.unlocked)
    digest=hashlib.sha256(variables[KEY][1]).digest();a.end_console_session()
    check('stage1 console exit removes owner/grant',not core.active and not core.unlocked and not a.platform_session_owned())
    b,cold=setup(other,2,digest);cp=C.addressof(cold)
    check('fresh local instance loads only exact phase1 test record and relocks',cold.mode==1 and not cold.unlocked and bytes(cold.record)==variables[KEY][1])
    check('wrong password rejected by actual production core',b.ap_unlock(cp,cold.token,wrong,64)==1)
    check('immediate retry rate limited',b.ap_unlock(cp,cold.token,first,64)==7)
    clock[0]+=5001
    check('correct password succeeds after retry interval',b.ap_unlock(cp,cold.token,first,64)==0 and b.platform_can_enter()==1)
    check('same console session reuses granted access',b.ap_can_enter(cp)==1 and b.platform_can_enter()==1)
    old_token=cold.token;check('new console session retires grant and advances token',b.begin_console_session()==1 and cold.token!=old_token and not cold.unlocked and not b.platform_can_enter())
    assert b.nv_begin_action(1)==1
    check('authenticated production password change persists',b.ap_set_password(cp,cold.token,first,64,next_password,64)==0)
    b.nv_end_action();check('change retains one variable and produces generation2',len(variables)==1 and struct.unpack_from('<Q',variables[KEY][1],24)[0]==2)
    check('old password no longer authenticates',b.ap_unlock(cp,cold.token,first,64)==1)
    clock[0]+=5001
    check('replacement password authenticates',b.ap_unlock(cp,cold.token,next_password,64)==0)
    assert b.nv_begin_action(2)==1
    check('authenticated production clear writes disabled tombstone',b.ap_clear_password(cp,cold.token,next_password,64)==0 and cold.mode==2)
    b.nv_end_action();check('disabled tombstone is valid generation3 and secret fields zero',b.ap_record_valid(C.addressof(cold)+40,128)==1 and bytes(cold.record)[32:96]==bytes(64) and struct.unpack_from('<Q',bytes(cold.record),24)[0]==3)
    check('cleanup refused while console owner is active',b.nv_cleanup_tombstone()==0)
    b.end_console_session();check('known tombstone cleanup restores original missing state',b.nv_cleanup_tombstone()==1 and not variables)
    check('exact native write sequence limited to credential then deletion',writes==[(3,128),(3,128),(3,128),(0,0)] and not errors)
finally:
    for p in passwords:C.memset(C.addressof(p),0,C.sizeof(p))
    for _,c,*_ in pins:C.memset(C.addressof(c),0,C.sizeof(c))
    variables.clear()
report={'status':'PASS_NATIVE_PRODUCTION_PASSWORD_PERSIST_CHAIN_LOCAL_PROVIDERS','checks':len(checks),'check_names':checks,
    'efi_sha256':manifest['efi_sha256'],'production_driver_sha256':manifest['production_driver_sha256'],
    'build_manifest_sha256':sha(OUT/'build.json'),'dll_sha256':sha(dll_path),'dll_copy_sha256':sha(other),
    'source_sha256':sha(Path(__file__)),'all_linked_object_hashes':{str(Path(o).relative_to(ROOT)):sha(o) for o in objects},
    'host_firmware_services_called':False,'bmc_accessed':False,'passwords_stored_or_reported':False,
    'stage2_media_receipt_generated':False,'hardware_cold_power_test':False,
    'limits':['Get/SetVariable, entropy, time and event registration are local memory providers.',
       'Read/persist AP_ENV callbacks remain the exact frozen production functions; only entropy and time are injected.',
       'A new DLL instance demonstrates reload logic, not physical cold-power persistence.',
       'No console UI, privileged instruction, event handoff or host UEFI function is invoked in this native process.'],
    'command':cmd}
(REVIEW/'password_chain_validation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','checks','efi_sha256']},indent=2))
