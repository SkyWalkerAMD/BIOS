from pathlib import Path
import ctypes as C,json,hashlib,uuid,struct
H=Path(__file__).resolve().parent;O=H/'build';cat=json.loads((H/'native_variable_catalog.json').read_text());items=cat['items'];D=C.CDLL(str(O/'W890WriteBridge04.OBSERVER-FIXTURE.dll'))
U8=C.c_uint8;U16=C.c_uint16;U32=C.c_uint32;U64=C.c_uint64;P=C.c_void_p
class ID(C.Structure):_fields_=[(n,P)for n in ['st','database','hii','setup_driver','tse_driver','config','setup_base','tse_base']]+[('setup_size',U64),('tse_size',U64),('epoch',U64)]+[(n,U32)for n in ['loop_depth','send_depth','fault','ended']]
class Install(C.Structure):_fields_=[('revision',U32),('size',U32),('provider',P)]
class Policy(C.Structure):_fields_=[('result',U32),('first',U32),('changed',U32),('protected',U32)]
class Report(C.Structure):_fields_=[('operation',U32),('reason',U32),('observed',U32),('checked',U32),('policy',Policy),('epoch',U64)]
def bind(n,args,ret=C.c_int):f=getattr(D,n);f.argtypes=args;f.restype=ret;return f
reset=bind('fixture_reset',[P,U32],None);prov=bind('fixture_provider',[],P);add=bind('fixture_add',[P,P,P,U64,U32]);flags=bind('fixture_flags',[U32],None);owner=bind('fixture_owner',[U32],None);fault=bind('fixture_fail',[U32,U32],None);mutate=bind('fixture_mutate',[U64,U32,U8],None);counts=bind('fixture_counts',[],U64)
prepare=bind('ws04_prepare',[P],U64);commit=bind('ws04_check_commit',[U32,P,U64,P]);route=bind('ws04_check_route',[P,P,P]);save=bind('ws04_check_save',[P]);nativecommit=bind('ws04_native_commit',[U32,P,U64],U64);nativeroute=bind('ws04_setup_route',[P,P,P],U64);nativesave=bind('ws04_native_save',[],U8)
image=(U8*0xde000)();config=(U64*3)();setup=(U8*0x4a000)();id=ID();id.tse_base=C.addressof(image);id.tse_size=len(image);id.setup_base=C.addressof(setup);id.setup_size=len(setup);id.hii=0x12345678;id.config=C.addressof(config);id.epoch=17;id.loop_depth=1
table_raw=(H/'inputs/AMITSESetupData.bin').read_bytes()[cat['variable_table_offset']:cat['variable_table_offset']+488+121*124]
table=(U8*len(table_raw)).from_buffer_copy(table_raw);cache=(U64*(121*2))();all_refs=[];cases=[]
def check(label,ok,**detail):assert ok,(label,detail);cases.append(dict(name=label,pass_=True,**detail))
def initialize(flags=3):
 C.memmove(table,table_raw,len(table_raw));C.memset(cache,0,C.sizeof(cache))
 for e in items:
  at=e['descriptor_offset']-cat['variable_table_offset'];C.c_uint64.from_address(C.addressof(table)+at+0x70).value=id.hii
 C.c_uint64.from_address(C.addressof(image)+0xbaaf8).value=C.addressof(table);C.c_uint64.from_address(C.addressof(image)+0xafcd8).value=C.addressof(cache)
 reset(C.byref(id),flags)
def variable(index,change=1,offset=0):
 e=items[index];size=e['declared_size'];before=(U8*size)();after=(U8*size)();after[offset]=change
 guid=(U8*16).from_buffer_copy(uuid.UUID(e['guid']).bytes_le);name=(U16*40)();name[:len(e['name'])]=list(map(ord,e['name']))
 assert add(guid,name,before,size,e['attributes']);all_refs.extend([before,after,guid,name]);cache[index*2]=C.addressof(after);cache[index*2+1]=size;return before,after
initialize();ins=Install(4,C.sizeof(Install),prov());check('one-time immutable provider provision',prepare(C.byref(ins))==0);check('duplicate provision refused',prepare(C.byref(ins))!=0)
initialize();old,new=variable(2);r=Report();check('live Timeout preflight exact descriptor and GetVariable',commit(2,new,len(new),C.byref(r))==1 and r.checked==1 and r.reason==8,reason=r.reason)
check('accepted preflight never executes commit',nativecommit(2,new,len(new))==0x8000000000000003)
initialize();old,new=variable(94);r=Report();check('live native94 protected OCMR denies while locked',commit(94,new,len(new),C.byref(r))==0 and r.reason==1 and r.policy.result==1)
initialize(7);old,new=variable(94);r=Report();check('live native94 actual grant only passes observation',commit(94,new,len(new),C.byref(r))==1 and r.reason==8)
initialize();old,new=variable(2);owner(0);r=Report();check('private owner rejection',commit(2,new,len(new),C.byref(r))==0 and r.reason==2)
initialize();old,new=variable(2);fault(1,0);r=Report();check('GetVariable failure denies',commit(2,new,len(new),C.byref(r))==0 and r.reason==4)
initialize();old,new=variable(2);mutate(C.addressof(old),2,4);r=Report();check('changed persisted bytes between samples denied',commit(2,new,len(new),C.byref(r))==0 and r.reason==6)
initialize();old,new=variable(2);mutate(C.addressof(new),2,4);r=Report();check('changed cache data during second NV read denied',commit(2,new,len(new),C.byref(r))==0 and r.reason==6)
initialize();old,new=variable(2);at=items[2]['descriptor_offset']-cat['variable_table_offset'];mutate(C.addressof(table)+at,1,0);r=Report();check('native descriptor changes denied',commit(2,new,len(new),C.byref(r))==0 and r.reason==6)
initialize();old,new=variable(2);r=Report();check('wrong variable size denied before NV read',commit(2,new,1,C.byref(r))==0 and r.reason==4 and counts()&65535==0)
initialize();old,new=variable(2);r=Report();check('native IFR35 confusion rejected',commit(35,new,2,C.byref(r))==0 and r.reason==4)
initialize();old,new=variable(2);r=Report();check('native IFR40 confusion rejected',commit(40,new,2,C.byref(r))==0 and r.reason==4)
initialize();old,new=variable(2);r=Report();check('complete ordinary cache inspected yet Save remains closed',save(C.byref(r))==1 and r.checked==1 and r.reason==7)
check('native Save returns false even when policy passed',nativesave()==0)
initialize();variable(2);variable(94);r=Report();check('full cache late OC rejected before any native dispatch',save(C.byref(r))==0 and r.policy.first==1)
initialize(7);variable(2);variable(94);r=Report();check('unlocked still denies unknown Save effect graph',save(C.byref(r))==1 and r.checked==2 and r.reason==7 and nativesave()==0)
initialize();variable(2);cache[7*2]=C.addressof(image);cache[7*2+1]=2;r=Report();check('BootOrder special graph is not misclassified',save(C.byref(r))==0 and r.reason==7)
initialize();variable(2);cache[23*2]=C.addressof(image);cache[23*2+1]=2;r=Report();check('DriverOrder special graph is not misclassified',save(C.byref(r))==0 and r.reason==7)
initialize();old,new=variable(2);mutate(C.addressof(cache)+2*2*8,1,0);r=Report();check('changed whole cache pointer array denied',save(C.byref(r))==0 and r.reason==6)
def config_text(index,blocks):
 e=items[index];t='GUID='+uuid.UUID(e['guid']).bytes_le.hex()+'&NAME='+''.join(f'{ord(c):04X}'for c in e['name'])+'&PATH=7FFF0400'+blocks;s=(U16*65536)();s[:len(t)]=list(map(ord,t));all_refs.append(s);return s
initialize();old,new=variable(0,0);text=config_text(0,'&OFFSET=0&WIDTH=1&VALUE=01');r=Report();check('Setup Route copies strict config and checks real old bytes',route(id.config,text,C.byref(r))==1 and r.checked==1 and r.reason==8)
progress=U64(0x1122334455667788);check('Route production destination refuses without changing Progress',nativeroute(id.config,text,C.byref(progress))==0x8000000000000003 and progress.value==0x1122334455667788)
initialize();old,new=variable(0,0);text=config_text(0,'&OFFSET=0&WIDTH=1&VALUE=01&OFFSET=0&WIDTH=1&VALUE=02');r=Report();check('Route overlap refused',route(id.config,text,C.byref(r))==0)
initialize();old,new=variable(0,0);text=config_text(0,'&OFFSET=0&WIDTH=1&VALUE=01');r=Report();check('Route foreign ConfigAccess refused',route(C.addressof(config)+8,text,C.byref(r))==0 and r.reason==3)
initialize();old,new=variable(0,0);text=config_text(0,'&OFFSET=0&WIDTH=1&VALUE=01');mutate(C.addressof(old),2,3);r=Report();check('Route NV changes denied',route(id.config,text,C.byref(r))==0 and r.reason==6)
initialize();old,new=variable(2);bind('ws04_end_boot',[],None)();r=Report();check('EBS closes commit and save',commit(2,new,2,C.byref(r))==0 and nativesave()==0)
# Same bridge object linked with REAL observer: no fabricated initialization.
real=C.CDLL(str(O/'W890WriteBridge04.DENYONLY.dll'));f=real.ws04_native_commit;f.argtypes=[U32,P,U64];f.restype=U64;check('real observer-linked component denies absent real owner',f(2,new,2)==0x800000000000000f)
report={'status':'PASS','checks':len(cases),'fixture_sha256':hashlib.sha256((O/'W890WriteBridge04.OBSERVER-FIXTURE.dll').read_bytes()).hexdigest(),'real_observer_product_sha256':hashlib.sha256((O/'W890WriteBridge04.DENYONLY.dll').read_bytes()).hexdigest(),'native_bridge_object_sha256':hashlib.sha256((O/'native_bridge04.obj').read_bytes()).hexdigest(),'cases':cases,'limits':['Observer/variable/memory-range services are explicit fixture models; no real native ownership demonstrated.','Exact same bridge object is linked in both artifacts.','No SetVariable or native dispatch exists in this bridge version.','Preflight uses bounded repeated observations; no atomic transaction or AP/SMM exclusion is claimed.']}
(O/'bridge_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='cases'}))
