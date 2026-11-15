"""Execute the actual compiled W890 pure backend; synthetic memory only."""
from pathlib import Path
import ctypes as C
import hashlib
import json
import struct
import sys
import uuid
from build_adapter import build, HERE, ROOT, OUT

sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE/'core'))
import verify_core as core_test
build_report=build()
lib=C.CDLL(str(OUT/'w890_password_pure_test.dll'))
profile=json.loads((HERE/'profile_0603.json').read_text(encoding='utf8'))
recs=[r for p in json.loads((ROOT/'analysis/aitweaker_lock/W890_SAGE_0603/Setup_IFR.json').read_text(encoding='utf8'))for r in p['records']]
groups={};checks=0
def check(value,label,group):
    global checks
    assert value,label
    checks+=1;groups[group]=groups.get(group,0)+1
def buf(data):return None if data is None else C.create_string_buffer(data,max(1,len(data)))
def sig(name,args,rest=C.c_int):
    f=getattr(lib,name);f.argtypes=args;f.restype=rest;return f
match=sig('w890_profile_matches',[C.c_void_p,C.c_void_p])
form=sig('w890_form',[C.c_uint16]);question=sig('w890_question',[C.c_uint16])
inert=sig('w890_inert_ifr',[C.c_void_p,C.c_size_t])
class_form=sig('w890_classify_form',[C.c_void_p,C.c_uint16])
control=sig('w890_classify_control',[C.c_void_p,C.c_uint16,C.c_void_p,C.c_size_t])
kind=sig('w890_variable_kind',[C.c_void_p,C.c_size_t,C.c_void_p])
change=sig('w890_variable_change',[C.c_void_p,C.c_size_t,C.c_void_p,C.c_uint32,C.c_void_p,C.c_size_t,C.c_uint32,C.c_void_p,C.c_size_t])
insert=sig('w890_security_insert',[C.c_void_p,C.c_size_t,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)])
setup=bytes.fromhex(profile['sources']['Setup']['sha256']);tse=bytes.fromhex(profile['sources']['AMITSE']['sha256'])
sg=uuid.UUID(profile['setup_formset_guid']).bytes_le
check(match(buf(setup),buf(tse))==1,'0603 module pair bound','identity')
check(match(None,buf(tse))==0,'null Setup digest refused','identity')
for name,sha in [('Setup',setup),('AMITSE',tse)]:
    for i in range(32):
        altered=bytearray(sha);altered[i]^=1
        check(match(buf(bytes(altered) if name=='Setup' else setup),buf(bytes(altered) if name=='AMITSE' else tse))==0,
              name+' digest mutation refused','identity')
check(form(0x2713)==1 and form(0x2712)==0 and form(0x271d)==0,'W890 root Main and Security differ from W790','identity')
check(form(0x2711)==1 and form(0x2bfc)==1,'Favorites and profile gated','identity')
protected={x['id']for x in profile['protected_forms']}
for r in recs:
    if r['op']==1:
        fid=r['form_id'];want=int(fid in protected)
        check(form(fid)==want,'profile form matches C table','form_identity')
        check(class_form(buf(sg),fid)==want,'bound original form classification','form_identity')
        check(class_form(buf(bytes(16)),fid)==-1,'same numeric form foreign formset refused','form_identity')
check(class_form(buf(sg),0xffff)==-1,'unknown form denied','form_identity')
check(class_form(None,0x2713)==-1,'missing form owner denied','form_identity')
for q in profile['protected_questions']:
    check(question(q)==1,'protected question represented','question_map')
for q in [0xffd0,0xffd1,0xffd2,0xffff]:
    check(question(q)==0,'new management IDs not accidentally protected','question_map')
for r in recs:
    if 'question_id' not in r:continue
    raw=bytes.fromhex(r['hex']);fid=r['form']
    if fid in protected or r['question_id'] in profile['protected_questions']:
        check(control(buf(sg),fid,buf(raw),len(raw))==1,'protected original control','control_map')
for item in profile['inert_exit_descriptors']:
    raw=bytes.fromhex(item['ifr_hex'])
    check(inert(buf(raw),len(raw))==1,'exact inert descriptor recognized','inert_exit')
    check(control(buf(sg),0x271a,buf(raw),len(raw))==0,'literal-disabled Exit exception bound to owner form','inert_exit')
    check(control(buf(sg),0x2712,buf(raw),len(raw))==1,'moving descriptor outside Exit does not gain exception','inert_exit')
    check(control(buf(bytes(16)),0x271a,buf(raw),len(raw))==-1,'foreign owner cannot use Exit exception','inert_exit')
    for i in range(len(raw)):
        altered=bytearray(raw);altered[i]^=0x40
        check(inert(buf(bytes(altered)),len(raw))==0,'mutated inert descriptor no exemption','inert_exit')
# A dynamically supplied numeric field can overlap a protected byte even when
# its starting offset is not one of the original one-byte fields.
numeric=bytearray.fromhex('07910000000000fc28000d000001000000')
numeric+=bytes(3);numeric[1]=20;numeric[13]=1
check(control(buf(sg),0x2712,buf(bytes(numeric)),20)==1,'two-byte range overlaps protected byte0e','dynamic_ranges')
numeric[10:12]=(1218).to_bytes(2,'little')
check(control(buf(sg),0x2712,buf(bytes(numeric)),20)==-1,'out-of-range dynamic field refused','dynamic_ranges')
numeric=numeric[:17];numeric[1]=17;numeric[10:12]=(32).to_bytes(2,'little');numeric[13]=0
check(control(buf(sg),0x2712,buf(bytes(numeric)),17)==0,'verified one-byte nonprotected memory field classified','dynamic_ranges')
check(control(buf(sg),0x2712,buf(bytes(numeric)),16)==-1,'truncated IFR control refused','dynamic_ranges')
check(control(buf(sg),0x2712,None,17)==-1,'missing IFR refused','dynamic_ranges')
numeric[13]=3
check(control(buf(sg),0x2712,buf(bytes(numeric)),17)==-1,'declared numeric width without matching min/max/step refused','dynamic_ranges')

def variable(name,guid,before,after,old_attr=7,new_attr=7):
    return change(buf(name.encode('utf-16le')),len(name),buf(uuid.UUID(guid).bytes_le),old_attr,buf(before),0 if before is None else len(before),
                  new_attr,buf(after),0 if after is None else len(after))
oc=profile['oc_store'];mem=profile['memory_store'];cred=profile['credential']
check(kind(buf(cred['name'].encode('utf-16le')),len(cred['name']),buf(uuid.UUID(cred['guid']).bytes_le))==2,'private namespace needs exclusive writer','variable_policy')
check(kind(buf('AiTweakerPassword1904'.encode('utf-16le')),20,buf(uuid.UUID('750e9d9d-f2d8-4e14-9b53-8923a7190461').bytes_le))==0,'W790 namespace is not adopted','variable_policy')
for store in [oc,mem]:
    before=bytes(store['varstore_size'])
    check(variable(store['name'],store['guid'],before,before)==0,'unchanged protected store allowed','variable_policy')
    for b,a,oa,na in [(before,None,7,7),(None,before,7,7),(before,before[:-1],7,7),(before,before,7,3),(before,before,7,0x47)]:
        check(variable(store['name'],store['guid'],b,a,oa,na)==-1,'malformed/delete/append/attribute write refused','variable_policy')
before=bytes(oc['varstore_size'])
for off in [0,1873,1874,2168,2172,2174,len(before)-1]:
    after=bytearray(before);after[off]=1
    check(variable(oc['name'],oc['guid'],before,bytes(after))==1,'OC changed including inert descriptor bytes guarded','variable_policy')
before=bytes(mem['varstore_size']);expected_offsets={14,147,148,248,249,341,365,366,801}
check(set(profile['protected_memory_byte_offsets'])==expected_offsets,'W890 memory offsets independent known values','variable_policy')
for off in range(len(before)):
    after=bytearray(before);after[off]=1
    check(variable(mem['name'],mem['guid'],before,bytes(after))==int(off in expected_offsets),'every SocketMemory byte classified','variable_policy')

raw=(HERE/'official_forms_0603.pack').read_bytes()
tokens=(C.c_uint16*6)(0x5000,0x5001,0x5002,0x5003,0x5004,0x5005)
def do_insert(data,cap=None,token=tokens):
    cap=len(data)+45 if cap is None else cap
    out=buf(bytes([0xa5])*cap);written=C.c_size_t(999);source=buf(data)
    result=insert(source,len(data),token,out,cap,C.byref(written))
    check(source.raw[:len(data)]==data,'source unchanged','security_insert')
    if not result:check(written.value==0 and out.raw[:cap]==bytes([0xa5])*cap,'error has no partial output','security_insert')
    return result,out.raw[:written.value]
result,modified=do_insert(raw)
check(result==1 and len(modified)==len(raw)+45,'three actions inserted','security_insert')
at=profile['original_forms_package']['security_insert_offset']
payload=b''.join(bytes([12,15])+struct.pack('<5HBH',0x5000+i*2,0x5001+i*2,q,0,0xffff,4,0)for i,q in enumerate([0xffd0,0xffd1,0xffd2]))
expected=bytearray(raw[:at]+payload+raw[at:]);expected[:3]=len(expected).to_bytes(3,'little')
check(modified==bytes(expected),'exact package length plus45B edit, all other bytes preserved','security_insert')
check(do_insert(modified)[0]==0,'second insertion refused','security_insert')
check(do_insert(raw,len(raw)+44)[0]==0,'short destination refused','security_insert')
check(do_insert(raw,token=(C.c_uint16*6)(0,1,2,3,4,5))[0]==0,'missing HII string token refused','security_insert')
for off in [0,3,20,at-1,at,len(raw)-1]:
    altered=bytearray(raw);altered[off]^=0x40
    check(do_insert(bytes(altered))[0]==0,'changed original package refused','security_insert')
shared=buf(raw+bytes(45));written=C.c_size_t(99)
check(insert(shared,len(raw),tokens,shared,len(raw)+45,C.byref(written))==0 and written.value==0 and shared.raw[:len(raw)]==raw,
      'in-place insertion refused without modification','security_insert')
(OUT/'security_actions_0603.TESTONLY.forms').write_bytes(modified)

# Bind existing comprehensive AP_CORE fixture callbacks to the new linked DLL.
oldlib=core_test.load()
for name in ['ap_init','ap_fault','ap_session_begin','ap_session_end','ap_can_enter','ap_unlock','ap_set_password','ap_clear_password','ap_cancel','ap_retry_remaining_ms','ap_record_valid']:
    actual,old=getattr(lib,name),getattr(oldlib,name);actual.restype=old.restype;actual.argtypes=old.argtypes
core_test.LIB=lib
manage=sig('w890_management_action',[C.POINTER(core_test.Core),C.c_uint64,C.c_uint16,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t])
def m(f,q,old=None,new=None,confirm=None,token=None):
    return manage(C.byref(f.core),f.core.session_token if token is None else token,q,
                  buf(old),len(old)if old else 0,buf(new),len(new)if new else 0,buf(confirm),len(confirm)if confirm else 0)
f=core_test.Fixture();check(f.initialize()==6,'absent is unconfigured','management');f.begin()
pw=core_test.PW;new=core_test.NEW_PW;bad=core_test.WRONG_PW
check(m(f,0xffd0,new=pw,confirm=bad)==2 and f.writes==0,'confirmation mismatch never persists','management')
check(m(f,0xffd0,new=pw,confirm=pw)==0 and f.writes==1 and not f.access(),'enrollment persists but stays locked','management')
check(m(f,0xffd2,old=pw)==0 and f.access(),'verification unlocks same session','management')
f.end();f.begin()
check(not f.access(),'next BIOS session relocks','management')
check(m(f,0xffd0,old=bad,new=new,confirm=new)==1 and f.writes==1,'wrong current password cannot change','management')
check(m(f,0xffd2,old=pw)==7,'failed attempt delay applies to other action','management')
f.now+=5000
check(m(f,0xffd0,old=pw,new=new,confirm=new)==0 and f.writes==2,'authenticated change','management')
check(m(f,0xffd2,old=new)==0,'replacement password verifies','management')
fresh=core_test.Fixture(f.stored)
check(fresh.initialize()==0,'new boot reloads committed record','management');fresh.begin()
check(not fresh.access() and m(fresh,0xffd2,old=new)==0,'new boot requires replacement password','management')
check(m(fresh,0xffd1,old=new,new=new)==2 and fresh.writes==0,'clear rejects stray replacement','management')
check(m(fresh,0xffd1,old=new)==0 and fresh.writes==1 and fresh.core.mode==2,'clear authenticates and writes disabled record','management')
check(m(fresh,0xffff,old=new)==2,'unknown action refused','management')
f=core_test.Fixture();f.initialize();f.begin();f.persist_fail=True
check(m(f,0xffd0,new=pw,confirm=pw)==8 and f.stored is None,'atomic persistence failure leaves absent','management')
f.persist_fail=False;f.persist_uncertain=True
check(m(f,0xffd0,new=pw,confirm=pw)==8 and f.core.mode==3 and not f.access(),'ambiguous persistence faults closed','management')
f=core_test.Fixture();f.initialize();token=f.begin();f.end();f.begin()
check(m(f,0xffd0,new=pw,confirm=pw,token=token)==4 and f.writes==0,'stale management token cannot enroll','management')
check(m(f,0xffd0,new=pw,confirm=pw+b'x')==2 and f.writes==0,'different confirmation length never persists','management')

report={'status':'PASS_ACTUAL_COMPILED_PURE_W890_BACKEND','checks':checks,'groups':groups,
        'scope':'Actual C x64 DLL, official0603 IFR data and synthetic memory/storage callbacks. No BMC, native AMITSE execution, firmware/NVRAM access or hardware writes.',
        'build':build_report,'profile_sha256':hashlib.sha256((HERE/'profile_0603.json').read_bytes()).hexdigest(),
        'test_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'security_fixture_sha256':hashlib.sha256(modified).hexdigest()}
(OUT/'adaptation_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'checks':checks,'groups':groups}))
