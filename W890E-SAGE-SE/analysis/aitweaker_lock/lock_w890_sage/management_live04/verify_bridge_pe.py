"""Actual MP04 EFI bridge with modeled UEFI identity services and original callback.

The SHA/KDF oracle is Python; real SHA, HII and UI execute in the OVMF lab.
Original ASUS callback is intercepted, never claimed to execute its side effects.
"""
from pathlib import Path
import ast,ctypes as C,hashlib,json,re,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE_DIR=HERE.parent;ROOT=HERE.parents[3]
src=BASE_DIR/'password_runtime02/verify_runtime_pe.py';tree=ast.parse(src.read_text());nodes=[]
for node in tree.body:
    if isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Name)and node.value.func.id=='check':break
    nodes.append(node)
env={'__file__':str(src),'__name__':'fixture_definitions'};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(src),'exec'),env)
pefile=env['pefile'];EFI=HERE/'build/W890Management04.UNBOUND.TESTONLY.efi';PE=pefile.PE(str(EFI));BASE=PE.OPTIONAL_HEADER.ImageBase
SYMBOLS={n:int(a,16)for n,a in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',EFI.with_suffix('.map').read_text(),re.M)}
env.update(PE=PE,BASE=BASE,SYMBOLS=SYMBOLS)
VM=env['VM'];Q=env['Q'];I=env['I'];ERR=env['ERR'];HOOK=env['HOOK'];HEAP=env['HEAP'];STOP=env['STOP'];REGS=env['REGS']
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX
P=BASE_DIR/'password';profile=json.loads((P/'profile_0603.json').read_text())
class Binding(C.Structure):_fields_=[(x,C.c_uint64)for x in ['st','db','strings','hii','driver','config','setup','setup_size','tse_driver','tse','tse_size','patches']]+[('count',C.c_uint32),('reserved',C.c_uint32)]
class Authority(C.Structure):_fields_=[('revision',C.c_uint32),('size',C.c_uint32)]+[(x,C.c_uint64)for x in ['context','window','published','restored','enter','valid','leave']]
M=0x51000000;SETUP=0x80000000;TSE=0x81000000
class BridgeVM(VM):
    def __init__(self):
        super().__init__(None);self.u.mem_map(M,0x200000);self.original_calls=[];self.identity_calls=[];self.hii_owner=True;self.protocol_owner=True
        self.db,self.strings,self.config,self.binding,self.authority=M+0xa0000,M+0xa0100,M+0xa0200,M+0xa0300,M+0xa0400
        self.li=[M+0xa1000,M+0xa1100];self.paths=[M+0xa1200,M+0xa1300]
        for index,name in enumerate(['Setup','AMITSE']):
            path=ROOT/profile['sources'][name]['path'];assert hashlib.sha256(path.read_bytes()).hexdigest()==profile['sources'][name]['sha256']
            pe=pefile.PE(str(path));base=[SETUP,TSE][index];size=pe.OPTIONAL_HEADER.SizeOfImage
            self.u.mem_map(base,(size+4095)&~4095);self.w(base,pe.get_memory_mapped_image());self.w(self.li[index],I(0x1000));self.w(self.li[index]+0x20,Q(self.paths[index]));self.w(self.li[index]+0x40,Q(base)+Q(size))
            guid=['899407d7-99fe-43d8-9a21-79ec328cac21','b1da0adf-4f77-4070-a88e-bffe1c60529a'][index]
            self.w(self.paths[index],b'\x04\x06\x14\0'+uuid.UUID(guid).bytes_le+b'\x7f\xff\x04\0')
        names=['hp','export','update','driver','new','get_string','set_string','languages','window','published','restored','enter','valid','leave']
        self.extra={name:HOOK+0x3000+i*0x100 for i,name in enumerate(names)};self.extra['sha']=SYMBOLS['ap_sha256'];self.extra['original']=SETUP+0x2250
        for name,address in self.extra.items():
            if HOOK<=address<HOOK+0x10000:self.w(address,b'\xc3')
        self.w(self.bs+0x98,Q(self.extra['hp']))
        for off,name in [(16,'update'),(32,'export'),(80,'driver')]:self.w(self.db+off,Q(self.extra[name]))
        for off,name in [(0,'new'),(8,'get_string'),(16,'set_string'),(24,'languages')]:self.w(self.strings+off,Q(self.extra[name]))
        self.w(self.config,Q(SETUP+0x2240)+Q(SETUP+0x2248)+Q(SETUP+0x2250))
        b=Binding(self.st,self.db,self.strings,0x1234,0x1111,self.config,SETUP,2154496,0x2222,TSE,909312,0,0,0)
        a=Authority(4,C.sizeof(Authority),M,*[self.extra[x]for x in ['window','published','restored','enter','valid','leave']])
        self.w(self.binding,bytes(b));self.w(self.authority,bytes(a))
    def hook(self,u,address,size,opaque):
        extra=getattr(self,'extra',{});name=next((n for n,a in extra.items()if a==address),None)
        if name is None:return super().hook(u,address,size,opaque)
        if name=='sha':self.w(self.arg(2),hashlib.sha256(self.r(self.arg(0),self.arg(1))).digest());self.ret(0);return
        self.identity_calls.append(name)
        if name=='hp':
            h,g,out=self.arg(0),self.r(self.arg(1),16),self.arg(2)
            if g==uuid.UUID('330d4706-f2a0-4e4f-a369-b66fa8d54385').bytes_le:self.w(out,Q(self.config if self.protocol_owner else self.config+0x80));self.ret(0)
            elif h in (0x1111,0x2222):self.w(out,Q(self.li[h==0x2222]));self.ret(0)
            else:self.ret(ERR(14))
        elif name=='driver':self.w(self.arg(2),Q(0x1111 if self.hii_owner else 0x3333));self.ret(0)
        elif name=='original':
            args=[self.arg(i)for i in range(6)];self.original_calls.append(args)
            if args[5]:self.w(args[5],Q(0xaabbccdd11223344))
            self.ret(ERR(17))
        elif name in ['window','published','restored','enter','valid']:self.ret(0)
        elif name=='leave':self.ret(0)
        else:raise AssertionError('unexpected HII mutation '+name)
    def call(self,name,*args):
        self.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)));sp=env['STACK']+0x1ff008;self.w(sp,bytes(0x200));self.w(sp,Q(STOP));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i in range(4):self.u.reg_write(REGS[i],args[i]if i<len(args)else 0)
        for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
        self.u.emu_start(SYMBOLS[name],STOP+1,count=30000000);assert self.u.reg_read(UC_X86_REG_RIP)==STOP
        return self.u.reg_read(UC_X86_REG_RAX)
    def bound(self):
        assert self.call('mp_bind',M,self.binding,self.authority)==0;self.w(self.config+16,Q(SYMBOLS['mp_callback']));return self
checks=[]
def check(name,value):assert value,name;checks.append(name)
v=BridgeVM().bound();request=HEAP+0x1800;value=HEAP+0x1900
check('original callback return status preserved',v.call('mp_callback',v.config,4,0x1111,7,value,request)==ERR(17))
check('all six original callback arguments preserved',v.original_calls==[[v.config,4,0x1111,7,value,request]])
check('entire UINTN ActionRequest output preserved',v.q(request)==0xaabbccdd11223344)
check('Extract and Route remain exact original pointers',v.r(v.config,16)==Q(SETUP+0x2240)+Q(SETUP+0x2248))
check('wrong ConfigAccess object denied before original callback',v.call('mp_callback',v.config+24,0,0x1111,0,value,request)==ERR(15)and len(v.original_calls)==1)
for qid in [0xffd0,0xffd1,0xffd2]:check('unpublished management ID '+hex(qid)+' never forwards original',v.call('mp_callback',v.config,0,qid,10,value,request)==ERR(15)and len(v.original_calls)==1)
v.hii_owner=False;check('HII owner substitution denied',v.call('mp_callback',v.config,0,0x1111,0,value,request)==ERR(15));v.hii_owner=True
v.protocol_owner=False;check('ConfigAccess protocol substitution denied',v.call('mp_callback',v.config,0,0x1111,0,value,request)==ERR(15));v.protocol_owner=True
v.w(TSE+0x1010,bytes([v.r(TSE+0x1010,1)[0]^1]));check('original module text mismatch denied',v.call('mp_callback',v.config,0,0x1111,0,value,request)==ERR(15));v.w(TSE+0x1010,bytes([v.r(TSE+0x1010,1)[0]^1]))
v.w(v.db+80,Q(0xffffffffffffffff));check('unmapped substituted method rejects without execution',v.call('mp_callback',v.config,0,0x1111,0,value,request)==ERR(15));v.w(v.db+80,Q(v.extra['driver']))
start=SYMBOLS['call_provider'];raw=v.r(start,128);sites=[start+i+5 for i in range(124)if raw[i]==0xe8 and start+i+5+int.from_bytes(raw[i+1:i+5],'little',signed=True)==SYMBOLS['w890_config_callback']]
check('exactly one reviewed direct provider call in private thunk',len(sites)==1)
check('actual provider caller label accepted',v.call('mp_provider_caller',sites[0])==1)
for bad in [sites[0]-1,sites[0]+1,0,1,0xffffffffffffffff]:check('fabricated caller '+hex(bad)+' denied',v.call('mp_provider_caller',bad)==0)
v.call('mp_end_boot',M);before=len(v.identity_calls);check('end-boot denies without any additional protocol calls',v.call('mp_callback',v.config,0,0x1111,0,value,request)==ERR(15)and len(v.identity_calls)==before)
report={'status':'PASS_ACTUAL_MP04_EFI_BRIDGE','checks':checks,'count':len(checks),'component_sha256':hashlib.sha256(EFI.read_bytes()).hexdigest(),'provider_call_return_rva':sites[0]-BASE,'call_window_hex':v.r(sites[0]-16,32).hex(),'boundaries':['UEFI identity services and original ASUS callback are explicit models','SHA-256 identity hashing replaced with Python oracle; actual C SHA tested in OVMF','No browser/native caller authority or password writes inferred']}
(HERE/'build/bridge_pe_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':len(checks),'provider_call_return_rva':report['provider_call_return_rva']}))
