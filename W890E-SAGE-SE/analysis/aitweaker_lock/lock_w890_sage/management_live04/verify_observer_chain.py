"""Composed actual observer, MP04 publisher/bridge and Runtime02 instruction chain.

UEFI HII/String/memory-map services and native application/control construction
are explicit models. Original entry/loop prologues, actual ConfigAccess CALL,
observer ownership, publisher and password core run compiled instructions.
SHA/KDF and memcpy/memset/memcmp use named Python oracles. Real HII/UI services are separately tested in
OVMF. No ownership booleans are supplied to Runtime02 in this composition.
"""
from pathlib import Path
import ast,ctypes as C,hashlib,json,re,struct,sys,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;N=H.parent/'native_observer04';ROOT=H.parents[3]
source=N/'verify_observer.py';fixture_bytes=source.read_bytes();fixture_sha256=hashlib.sha256(fixture_bytes).hexdigest();self_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();tree=ast.parse(fixture_bytes.decode('utf8'));nodes=[]
for node in tree.body:
    if isinstance(node,ast.FunctionDef)and node.name=='main':break
    nodes.append(node)
scope={'__file__':str(source),'__name__':'observer_fixture_definitions'};exec(compile(ast.Module(nodes,type_ignores=[]),str(source),'exec'),scope)
ns=scope['ns'];pefile=scope['pefile'];EFI=H/'build/W890Management04.UNBOUND.TESTONLY.efi';PE=pefile.PE(str(EFI));BASE=PE.OPTIONAL_HEADER.ImageBase
component_sha256=hashlib.sha256(bytes(PE.__data__)).hexdigest();observer_sha256=hashlib.sha256(bytes(scope['OP'].__data__)).hexdigest()
symbols={n:int(a,16)for n,a in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',EFI.with_suffix('.map').read_text(),re.M)}
ns.update(PE=PE,EFI=EFI,BASE=BASE,SYMBOLS=symbols)
VM=scope['VM'];OS=scope['OS'];SY=scope['SY'];TSE,SETUP,DATA=scope['TSE'],scope['SETUP'],scope['DATA'];Q,I,G=scope['Q'],scope['I'],scope['G'];ERR=ns['ERR'];FORMS=scope['FORMS'];SETGUID=scope['SETGUID']
from unicorn.x86_const import UC_X86_REG_RAX,UC_X86_REG_RSP,UC_X86_REG_RIP
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock'));from inspect_setup import string_packages
profile=json.loads((H.parent/'password/profile_0603.json').read_text());setup_file=ROOT/profile['sources']['Setup']['path'];raw=setup_file.read_bytes();assert hashlib.sha256(raw).hexdigest()==profile['sources']['Setup']['sha256'];ss=string_packages(raw)[0];ENGLISH=raw[ss['offset']:ss['offset']+ss['length']];MAX_ID=max(map(int,ss['strings']))
ORIGINAL=SETGUID+I(24+len(FORMS)+len(ENGLISH))+FORMS+ENGLISH+bytes.fromhex('040000df')
class Binding(C.Structure):_fields_=[(x,C.c_uint64)for x in ['st','db','strings','hii','driver','config','setup','setup_size','tse_driver','tse','tse_size','patches']]+[('count',C.c_uint32),('reserved',C.c_uint32)]
class Authority(C.Structure):_fields_=[('revision',C.c_uint32),('size',C.c_uint32)]+[(x,C.c_uint64)for x in ['context','window','published','restored','enter','valid','leave']]
def packages(data):
    result=[];at=20
    while at<len(data):n=int.from_bytes(data[at:at+3],'little');assert n>=4;result.append(data[at:at+n]);at+=n
    assert at==len(data);return result
def pack(parts):return SETGUID+I(20+sum(map(len,parts)))+b''.join(parts)
def c16(v,p):
    b=bytearray()
    while len(b)<1024:
        c=v.r(p+len(b),2)
        if c==b'\0\0':return bytes(b)
        b+=c
    raise AssertionError('unterminated fixture text')
class Composed(VM):
    def __init__(self):
        super().__init__();self.package=ORIGINAL;self.new_strings={};self.pool=0x52000000;self.u.mem_map(self.pool,0x2000000);self.descriptors.append((4,self.pool,0x2000000));self.pool_next=self.pool
        self.state=DATA+0x50000;self.mp_binding=DATA+0x100000;self.mp_authority=DATA+0x100100;self.strings=DATA+0x100200;self.value=DATA+0x100300;self.requestout=DATA+0x100400
        self.mh={n:ns['HOOK']+0x5000+i*0x100 for i,n in enumerate(['update','new','string','setstring','languages','notifydone'])}
        for a in self.mh.values():self.w(a,b'\xc3')
        self.w(self.hii+16,Q(self.mh['update']))
        for off,name in [(0,'new'),(8,'string'),(16,'setstring'),(24,'languages')]:self.w(self.strings+off,Q(self.mh[name]))
        self.hii_updates=0;self.notification_results=[];self.service_steps=[];self.call_statuses=[];self.foreign_notify=False;self.fake_update=False;self.restore_on_publish=False
        self.callbacks=0;self.native_call_active=False;self.native_bad_type=False;self.native_bad_qid=False;self.after_publication=False
        self.interesting=set(self.mh.values())|set(self.oh.values())|set(self.hooks.values())|{symbols.get(x)for x in ['memcpy','memset','memcmp','ap_sha256']}|{SY.get(x)for x in ['memcpy','memset','ap_sha256']}|{TSE+x['resume_rva']for x in scope['WINDOWS']}|{TSE+0x3e4ed,TSE+0x3e4f0,TSE+0x37126,ns['TAIL'],ns['STOP']}
    def hook(self,u,address,size,opaque):
        if hasattr(self,'interesting')and address!=self.target_stop and address not in self.interesting:return
        if hasattr(self,'mh')and address in [symbols.get('memcpy'),SY.get('memcpy')]:
            dst,src,n=self.arg(0),self.arg(1),self.arg(2);self.w(dst,self.r(src,n));self.ret(dst);return
        if hasattr(self,'mh')and address in [symbols.get('memset'),SY.get('memset')]:
            dst,c,n=self.arg(0),self.arg(1),self.arg(2);self.w(dst,bytes([c&255])*n);self.ret(dst);return
        if hasattr(self,'mh')and address==symbols.get('memcmp'):
            a,b,n=self.arg(0),self.arg(1),self.arg(2);aa,bb=self.r(a,n),self.r(b,n);self.ret(next((x-y for x,y in zip(aa,bb)if x!=y),0));return
        if hasattr(self,'mh')and address==symbols['ap_sha256']:
            self.w(self.arg(2),hashlib.sha256(self.r(self.arg(0),self.arg(1))).digest());self.ret(0);return
        if hasattr(self,'mh')and address==self.hooks['allocate']:
            n=self.arg(1);assert 0<n<=8*1024*1024;p=self.pool_next;self.pool_next=(p+n+15)&~15;assert self.pool_next<self.pool+0x2000000;self.w(self.arg(2),Q(p));self.ret(0);return
        if hasattr(self,'mh')and address==self.oh['export']:
            cap=self.q(self.arg(2));self.w(self.arg(2),Q(len(self.package)))
            if not self.arg(3)or cap<len(self.package):self.ret(ERR(5))
            else:self.w(self.arg(3),self.package);self.ret(0)
            return
        if hasattr(self,'mh')and address in self.mh.values():
            name=next(n for n,a in self.mh.items()if a==address)
            if name=='new':
                sid=MAX_ID+len(self.new_strings)+1;text=c16(self,self.arg(5));self.new_strings[sid]=text;self.w(self.arg(2),struct.pack('<H',sid))
                ps=packages(self.package)
                for i,p in enumerate(ps):
                    if p[3]==4:
                        p=p[:-1]+b'\x14'+text+b'\0\0\0';ps[i]=len(p).to_bytes(3,'little')+p[3:]
                self.package=pack(ps);self.ret(0)
            elif name=='languages':
                data=b'en-US\0';assert self.q(self.arg(3))>=len(data);self.w(self.arg(2),data);self.ret(0)
            elif name=='string':
                data=self.new_strings.get(self.arg(3));cap=self.q(self.arg(5))
                if data is None:self.ret(ERR(14))
                else:
                    data+=b'\0\0';self.w(self.arg(5),Q(len(data)))
                    if cap<len(data):self.ret(ERR(5))
                    else:self.w(self.arg(4),data);self.ret(0)
            elif name=='setstring':raise AssertionError('single language fixture must not SetString')
            elif name=='update':
                self.hii_updates+=1;data=self.r(self.arg(2),int.from_bytes(self.r(self.arg(2)+16,4),'little'))
                if self.fake_update and self.hii_updates==1:self.ret(0);return
                incoming=packages(data);bytype={x[3]:[]for x in incoming if x[3]!=0xdf}
                for p in incoming:
                    if p[3]!=0xdf:bytype[p[3]].append(p)
                result=[];added=set()
                for p in packages(self.package):
                    if p[3]in bytype:
                        if p[3]not in added:result.extend(bytype[p[3]]);added.add(p[3])
                    else:result.append(p)
                self.package=pack(result)
                if self.package==ORIGINAL:self.new_strings={}
                self.service_sp=self.u.reg_read(UC_X86_REG_RSP);handle=self.setup_hii if not self.foreign_notify else self.setup_hii+1
                self.service_steps=[(self.notify_callback,[2,0,0,handle,2]),(self.notify_callback,[2,0,0,handle,8])];self.next_service();return
            elif name=='notifydone':self.notification_results.append(self.u.reg_read(UC_X86_REG_RAX));self.next_service();return
            return
        if hasattr(self,'mh')and address==TSE+0x3e4ed and self.native_call_active:
            # VM.inside enters functions with a callee-style synthetic stack.
            # This target is an original CALL instruction, so build the real
            # caller-side x64 shadow space and stack arguments before it runs.
            sp=self.u.reg_read(UC_X86_REG_RSP);value,request=self.q(sp+40),self.q(sp+48);sp-=8
            self.w(sp+32,Q(value)+Q(request));self.u.reg_write(UC_X86_REG_RSP,sp)
            self.u.reg_write(UC_X86_REG_RAX,self.config);self.callbacks+=1
        if hasattr(self,'mh')and address==TSE+0x3e4f0 and self.native_call_active:
            self.call_statuses.append(self.u.reg_read(UC_X86_REG_RAX));self.native_call_active=False;self.body_rsp=self.outer_rsp;self.finish_body();return
        return super().hook(u,address,size,opaque)
    def next_service(self):
        if not self.service_steps:self.u.reg_write(UC_X86_REG_RSP,self.service_sp);self.ret(0);return
        fn,args=self.service_steps.pop(0);sp=self.service_sp-0x108;self.w(sp,Q(self.mh['notifydone']));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
        for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
        self.u.reg_write(UC_X86_REG_RIP,fn)
    def prepare_composed(self):
        specs=[];tr=[]
        for i,w in enumerate(scope['WINDOWS']):
            target=OS[{'cold_entry':'no_native_entry','browser_loop':'no_native_loop','send_form':'no_native_send_form'}[w['role']]];before=bytes.fromhex(w['hex']);after=b'\xff\x25'+bytes(4)+Q(target)+b'\x90'*(len(before)-14)
            specs.append(struct.pack('<4I',0,w['rva'],len(before),0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'));a=self.tramps+i*0x100;tr.append(a);self.w(a,before+b'\xff\x25'+bytes(4)+Q(TSE+w['resume_rva']))
        before=Q(SETUP+0x2250);after=Q(symbols['mp_callback']);specs.append(struct.pack('<4I',1,0x2fd50,8,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'));self.specs=specs;self.w(self.patches,b''.join(specs))
        start=symbols['call_provider'];data=self.r(start,128);sites=[start+i+5 for i in range(124)if data[i]==0xe8 and start+i+5+int.from_bytes(data[i+1:i+5],'little',signed=True)==symbols['w890_config_callback']];assert len(sites)==1;self.provider_site=sites[0]
        self.w(self.callers,Q(sites[0])+I(4)+I(0)+self.r(sites[0]-16,32))
        self.w(self.inst,struct.pack('<IIQQQQQIIQIIQQQ',4,96,tr[1],tr[2],tr[0],self.p,self.patches,len(specs),0,self.callers,1,0,symbols['mp_callback'],symbols['mp_native_publish'],self.state))
        b=Binding(self.st,self.hii,self.strings,self.setup_hii,self.setup_handle,self.config,SETUP,2154496,self.tse_handle,TSE,909312,self.patches,3,0)
        a=Authority(4,C.sizeof(Authority),0,*[OS[n]for n in ['no_publication_validate','no_publication_finished','no_restoration_finished','no_management_enter','no_management_valid','no_management_leave']])
        self.w(self.mp_binding,bytes(b));self.w(self.mp_authority,bytes(a))
        assert self.run('mp_bind',self.state,self.mp_binding,self.mp_authority)==0
        return self.run('no_prepare',self.inst)
    def publish(self):
        assert self.initialize()==0 and self.prepare_composed()==0;self.apply();return self.run('no_native_entry',self.tse_handle,self.st)
    def management(self,qid=0xffd0,action=1,wrong_type=False,wrong_control=False):
        self.setup_page(0x271d)
        forms=next(x for x in packages(self.package)if x[3]==2);at=4;opcode=None
        while at<len(forms):
            n=forms[at+1]&127
            if forms[at]==0x0c and n==15 and int.from_bytes(forms[at+6:at+8],'little')==qid:opcode=forms[at:at+n];break
            at+=n
        assert opcode;self.w(self.opcode,opcode);self.w(self.control,Q(TSE+0x93f90));self.w(self.control+0x20,Q(self.setup_hii));self.w(self.control+0x34,struct.pack('<H',10));self.w(self.control+0x48,Q(self.opcode));self.w(self.cb,Q(self.setup_hii));self.w(self.cb+0x14,struct.pack('<H',10));self.w(self.cb+0x28,Q(self.opcode+(128 if wrong_control else 0)))
        self.w(TSE+0xafeb8,Q(action));self.w(TSE+0xafd88,b'\1');self.w(TSE+0xafff8,b'\1');self.w(self.value,b'\0\0');self.w(self.requestout,Q(0xffffffffffffffff));self.native_call_active=True
        self.inside=(TSE+0x3e4ed,[self.config,action,qid,0 if wrong_type else 10,self.value,self.requestout]);return self.run('no_native_loop',return_to=TSE+0xb8e1)
cases=[]
def case(name,fn):
    start=time.monotonic();v=Composed();ok=fn(v)
    if not ok:print(json.dumps({'failed':name,'callbacks':v.callbacks,'statuses':[hex(x)for x in v.call_statuses],'body':v.original_body,'updates':v.hii_updates,'notifications':v.notification_results,'set_calls':v.set_count}),flush=True)
    assert ok,name;cases.append({'name':name,'status':'PASS','seconds':round(time.monotonic()-start,3)});print(name,flush=True)
def good(v):
    assert v.publish()==0
    return v.original_body==['cold_entry']and v.notification_results==[0,0]and v.hii_updates==1 and len(v.new_strings)==6
case('actual observer cold wrapper publishes via actual MP04 and handles synchronous REMOVE ADD',good)
def management(v,qid,action,deny=False):
    assert v.publish()==0 and v.bind_real_host()==0
    if action==0:v.queue('\x1b')
    assert v.management(qid,action,wrong_control=deny)==0
    return v.callbacks==1 and v.call_statuses==([ERR(15)]if deny or action==0 else [0])and v.set_count==0 and v.run('w890_provider_query',v.p)==1
case('actual native ConfigAccess CALL and observer ticket acknowledge published management action',lambda v:management(v,0xffd0,1))
case('actual native ConfigAccess CALL enters Runtime02 masked UI and Escape cancels',lambda v:management(v,0xffd0,0))
case('actual native management caller with forged raw descriptor denied before provider',lambda v:management(v,0xffd0,1,True))
def badtype(v):
    assert v.publish()==0 and v.bind_real_host()==0 and v.management(wrong_type=True)==0
    return v.call_statuses==[ERR(3)]and v.set_count==0
case('wrong original callback value type denied in composed bridge',badtype)
def late(v):
    assert v.initialize()==0 and v.prepare_composed()==0;v.apply();v.setup_page()
    return v.run('no_native_entry',v.tse_handle,v.st)==ERR(15)and v.hii_updates==0 and not v.new_strings
case('late native application cannot manufacture publisher cold window',late)
def foreign(v):
    v.foreign_notify=True;r=v.publish()
    return r==ERR(15)and v.hii_updates==1 and not v.original_body and len(v.new_strings)==6
case('foreign synchronous notification revokes real observer and prevents unsafe rollback',foreign)
def false_success(v):
    v.fake_update=True;r=v.publish()
    return r==ERR(15)and v.hii_updates==2 and v.package==ORIGINAL and not v.new_strings and not v.original_body
case('false-success forms update rolls back actual publisher strings and refuses native continuation',false_success)
report={'status':'PASS_COMPOSED_OBSERVER_MANAGEMENT_RUNTIME','case_count':len(cases),'cases':cases,'component_sha256':component_sha256,'observer_sha256':observer_sha256,'source_sha256':self_sha256,'observer_fixture_source_sha256':fixture_sha256,'scope':__doc__,'hardware_operations':0,'uefi_services_modeled':True,'native_application_objects_modeled':True,'native_owner_boolean_injected':False}
(H/'build/observer_chain_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(cases)}))
