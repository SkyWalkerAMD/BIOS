"""Execute compiled observer + Runtime02 and exact original entry windows.

UEFI services, CPU page tables and native browser body are explicit fixtures.
Module/HII lookup, bounds, ownership/wrappers, provider, control policy execute
actual PE instructions. SHA256/PBKDF2 are independent Python oracles in the
composed tests; the frozen core and separate OVMF tests execute their C code.
No injected boolean owner callback is used by Runtime02 after no_host binds.
"""
from pathlib import Path
import ast,hashlib,json,struct,sys,re,uuid,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;R=H.parents[3]
rp=H.parent/'password_runtime02/verify_runtime_pe.py'
t=ast.parse(rp.read_text());prefix=[]
for node in t.body:
    if isinstance(node,ast.FunctionDef)and node.name=='check':break
    prefix.append(node)
ns={'__file__':str(rp),'__name__':'runtime04_test_dependency'}
exec(compile(ast.Module(prefix,type_ignores=[]),str(rp),'exec'),ns)
sys.path.insert(0,str(R/'tools/pydeps'))
import pefile
from unicorn import UC_HOOK_INSN
from unicorn.x86_const import *
Q=lambda n:struct.pack('<Q',n);I=lambda n:struct.pack('<I',n)
G=lambda x:uuid.UUID(x).bytes_le
OP=pefile.PE(str(H/'build/W890NativeObserver04.TESTONLY.dll'));OB=OP.OPTIONAL_HEADER.ImageBase
OS={e.name.decode():OB+e.address for e in OP.DIRECTORY_ENTRY_EXPORT.symbols}
SY={n:int(a,16)for n,a in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s',(H/'build/observer.map').read_text(),re.M)}
TSE,SETUP,DATA=0x2000000,0x2400000,0x51000000
WINDOWS=json.loads((H/'hook_windows.json').read_text())['windows']
SETGUID=G('899407d7-99fe-43d8-9a21-79ec328cac21');TSEGUID=G('b1da0adf-4f77-4070-a88e-bffe1c60529a')
source=H.parent/'navigation/modules'
FORMS=(H.parent/'password/official_forms_0603.pack').read_bytes()
assert hashlib.sha256(FORMS).hexdigest()=='0111abd4e9914a32b865fc95af15990687a9d05f984df533c30e028e38cbba2f'
PACKAGE=SETGUID+I(24+len(FORMS))+FORMS+bytes.fromhex('040000df')

class VM(ns['VM']):
    def __init__(self):
        super().__init__();self.u.mem_map(OB,(OP.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.w(OB,OP.get_memory_mapped_image())
        self.u.mem_map(DATA,0x400000)
        self.descriptors=[(4,ns['STACK'],0x200000),(4,ns['HEAP'],0x40000),(3,ns['HOOK'],0x10000),(4,0x70000000,0x10000),(3,OB,(OP.OPTIONAL_HEADER.SizeOfImage+4095)&~4095),(4,DATA,0x400000),(3,ns['BASE'],(ns['PE'].OPTIONAL_HEADER.SizeOfImage+4095)&~4095)]
        for base,name in [(TSE,'AMITSE'),(SETUP,'Setup')]:
            p=pefile.PE(str(source/(name+'.efi')));p.relocate_image(base);size=(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
            self.u.mem_map(base,size);self.w(base,p.get_memory_mapped_image());self.descriptors.append((3,base,size))
        self.current_tpl=4;self.map_failure=False;self.map_overlap=False;self.bad_driver=False;self.bad_forms=False;self.notify_callback=None;self.notify_kinds=[];self.original_body=[];self.inside=None;self.return_values=[];self.nested_loop=False;self.send_rsp=None;self.outer_rsp=None;self.publish_mode=None;self.script=None;self.script_values=[]
        self.w(self.st,Q(0x5453595320494249));self.w(self.bs,Q(0x56524553544f4f42))
        self.hii=DATA+0x100;self.li_tse=DATA+0x300;self.li_setup=DATA+0x400;self.handles=DATA+0x500;self.fv_tse=DATA+0x600;self.fv_setup=DATA+0x700;self.config=SETUP+0x2fd40
        self.setup_hii=0x900013;self.tse_handle=0x900011;self.setup_handle=0x900012
        self.w(self.handles,Q(self.tse_handle)+Q(self.setup_handle))
        for li,base,size,dp,guid in [(self.li_tse,TSE,0xde000,self.fv_tse,TSEGUID),(self.li_setup,SETUP,0x20e000,self.fv_setup,SETGUID)]:
            self.w(li,I(0x1000));self.w(li+0x10,Q(self.st));self.w(li+0x20,Q(dp));self.w(li+0x40,Q(base)+Q(size));self.w(dp,b'\x04\x06\x14\x00'+guid+b'\x7f\xff\x04\x00')
        names=['map','raise','restore','handles','handle','hiilist','export','driver','hregister','hunregister','bridge','publisher','bodydone','scriptdone']
        self.oh={n:ns['HOOK']+0x3000+i*0x100 for i,n in enumerate(names)}
        for a in self.oh.values():self.w(a,b'\xc3')
        for off,n in [(0x18,'raise'),(0x20,'restore'),(0x38,'map'),(0x98,'handle'),(0x138,'handles')]:self.w(self.bs+off,Q(self.oh[n]))
        for off,n in [(0x18,'hiilist'),(0x20,'export'),(0x28,'hregister'),(0x30,'hunregister'),(0x50,'driver')]:self.w(self.hii+off,Q(self.oh[n]))
        self.w(TSE+0xafbc0,Q(self.st));self.w(TSE+0xafbc8,Q(self.bs));self.w(TSE+0xafbd8,Q(self.rt))
        self.u.reg_write(UC_X86_REG_CR0,0x80010011);self.u.reg_write(UC_X86_REG_CR4,0x620)
        self.u.reg_write(UC_X86_REG_MSR,(0xc0000080,0xd00));self.u.reg_write(UC_X86_REG_MSR,(0x277,0x0007040600070406))
        self.u.hook_add(UC_HOOK_INSN,self.cpuid,None,1,0,UC_X86_INS_CPUID)
        self.inst=DATA+0x1000;self.patches=DATA+0x2000;self.tramps=ns['HOOK']+0x7000;self.callers=DATA+0x3000
        self.app=DATA+0x10000;self.page=DATA+0x11000;self.pa=DATA+0x12000;self.fa=DATA+0x13000;self.framep=DATA+0x14000;self.ca=DATA+0x15000;self.control=DATA+0x16000;self.pt=DATA+0x17000;self.blob=DATA+0x18000;self.cb=DATA+0x19000;self.opcode=DATA+0x20000
        self.obs=DATA+0x21000;self.idbuf=DATA+0x22000;self.package=PACKAGE
        self.hash_calls=0;self.target_stop=ns['STOP'];self.trace_native=[]
    def cpuid(self,u,opaque):
        leaf=u.reg_read(UC_X86_REG_EAX)
        values={1:(0,0,0,(1<<5)|(1<<16)),0x80000000:(0x80000008,0,0,0),0x80000008:(48,0,0,0)}.get(leaf,(0,0,0,0))
        for reg,v in zip([UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX],values):u.reg_write(reg,v)
        return True
    def hook(self,u,address,size,opaque):
        if hasattr(self,'target_stop')and address==self.target_stop:u.emu_stop();return
        if hasattr(self,'oh')and address==SY.get('ap_sha256'):
            self.hash_calls+=1;self.w(self.arg(2),hashlib.sha256(self.r(self.arg(0),self.arg(1))).digest());self.ret(0);return
        if hasattr(self,'oh')and address==self.hooks['locate']and self.r(self.arg(0),16)==G('ef9fc172-a1b2-4693-b327-6d32fc416042'):
            self.w(self.arg(2),Q(self.hii));self.ret(0);return
        if hasattr(self,'oh')and address==self.hooks['create']and self.arg(1)==16:
            self.event_serial+=1;handle=0x71000000+self.event_serial*16;self.event_callbacks[handle]=(self.arg(2),self.arg(3));self.w(self.arg(4),Q(handle));self.ret(0);return
        if hasattr(self,'oh')and address in self.oh.values():
            name=next(n for n,a in self.oh.items()if a==address);self.uefi_calls.append('observer:'+name);value=0
            if name=='map':
                if self.map_failure:value=ns['ERR'](7)
                else:
                    ds=list(self.descriptors)
                    if self.map_overlap:ds.append(ds[0])
                    data=b''.join(struct.pack('<IIQQQQ',ty,0,base,0,n//4096,0)for ty,base,n in sorted(ds,key=lambda x:x[1]))
                    self.w(self.arg(1),data);self.w(self.arg(0),Q(len(data)));self.w(self.arg(2),Q(1));self.w(self.arg(3),Q(40));self.w(self.arg(4),I(1))
            elif name=='raise':value=self.current_tpl;self.current_tpl=self.arg(0)
            elif name=='restore':self.current_tpl=self.arg(0)
            elif name=='handles':self.w(self.arg(3),Q(2));self.w(self.arg(4),Q(self.handles))
            elif name=='handle':
                handle,guid=self.arg(0),self.r(self.arg(1),16)
                if guid==G('5b1b31a1-9562-11d2-8e3f-00a0c969723b')and handle in [self.setup_handle,self.tse_handle]:self.w(self.arg(2),Q(self.li_setup if handle==self.setup_handle else self.li_tse))
                elif guid==G('330d4706-f2a0-4e4f-a369-b66fa8d54385')and handle==self.setup_handle:self.w(self.arg(2),Q(self.config))
                else:value=ns['ERR'](14)
            elif name=='hiilist':self.w(self.arg(3),Q(8));self.w(self.arg(4),Q(self.setup_hii))
            elif name=='export':
                data=self.package
                if self.bad_forms:data=data[:40]+bytes([data[40]^1])+data[41:]
                self.w(self.arg(2),Q(len(data)));self.w(self.arg(3),data)
            elif name=='driver':self.w(self.arg(2),Q(0 if self.bad_driver else self.setup_handle))
            elif name=='hregister':self.notify_callback=self.arg(3);self.notify_kinds.append(self.arg(4));self.w(self.arg(5),Q(0xdead04+len(self.notify_kinds)))
            elif name=='hunregister':pass
            elif name=='publisher':
                if self.publish_mode:
                    ticket=self.arg(1);tokens=list(range(0x7000,0x7006));ta=DATA+0x28000;ha=ta+32
                    actions=b''.join(b'\x0c\x0f'+struct.pack('<HHHHHBH',tokens[i*2],tokens[i*2+1],0xffd0+i,0,0xffff,4,0)for i in range(3))
                    f=bytearray(FORMS[:3938]+actions+FORMS[3938:]);f[:3]=len(f).to_bytes(3,'little')
                    self.package=SETGUID+I(24+len(f))+f+bytes.fromhex('040000df');self.w(ta,struct.pack('<6H',*tokens));digest=hashlib.sha256(f).digest()
                    if self.publish_mode=='bad_hash':digest=bytes(32)
                    self.w(ha,digest);handle=self.setup_hii if self.publish_mode!='foreign'else 0x9000ff
                    self.script=[(self.notify_callback,[2,0,0,handle,2]),(OS['no_publication_validate'],[0,ticket]),(self.notify_callback,[2,0,0,handle,8]),(OS['no_publication_validate'],[0,ticket]),(OS['no_publication_finished'],[0,ticket,ta,ha])]
                    self.script_sp=self.u.reg_read(UC_X86_REG_RSP);self.start_script();return
                value=ns['ERR'](3)
            elif name=='bridge':value=ns['ERR'](15)
            elif name=='bodydone':
                self.return_values.append(self.u.reg_read(UC_X86_REG_RAX));self.body_rsp=self.outer_rsp;self.finish_body();return
            elif name=='scriptdone':
                self.script_values.append(self.u.reg_read(UC_X86_REG_RAX));self.start_script();return
            else:raise AssertionError(name)
            self.ret(value);return
        if hasattr(self,'tramps')and address in [TSE+x['resume_rva']for x in WINDOWS]:
            role=next(x['role']for x in WINDOWS if address==TSE+x['resume_rva']);self.original_body.append(role)
            if role=='browser_loop'and self.inside:
                fn,args=self.inside;self.inside=None;self.body_rsp=self.u.reg_read(UC_X86_REG_RSP);self.outer_rsp=self.body_rsp
                sp=self.body_rsp-0x100;self.w(sp,Q(self.oh['bodydone']));self.u.reg_write(UC_X86_REG_RSP,sp)
                for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
                for i in range(4,len(args)):self.w(sp+40+(i-4)*8,Q(args[i]))
                self.u.reg_write(UC_X86_REG_RIP,OS[fn]if isinstance(fn,str)else fn);return
            if role=='send_form'and self.nested_loop:
                self.send_rsp=self.u.reg_read(UC_X86_REG_RSP);self.u.reg_write(UC_X86_REG_RSP,self.send_rsp-40);self.u.reg_write(UC_X86_REG_RIP,TSE+0x37121);return
            self.body_rsp=self.u.reg_read(UC_X86_REG_RSP);self.finish_body(role);return
        if hasattr(self,'send_rsp')and self.send_rsp is not None and address==TSE+0x37126:
            self.u.reg_write(UC_X86_REG_RSP,self.send_rsp);self.send_rsp=None;self.ret(0);return
        return super().hook(u,address,size,opaque)
    def start_script(self):
        if not self.script:
            status=(1 if self.publish_mode=='warning'else 0)if self.script_values==[0,1,0,1,1]else ns['ERR'](15)
            self.u.reg_write(UC_X86_REG_RSP,self.script_sp);self.ret(status);return
        fn,args=self.script.pop(0);sp=self.script_sp-0x108
        self.w(sp,Q(self.oh['scriptdone']));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
        for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
        self.u.reg_write(UC_X86_REG_RIP,fn)
    def finish_body(self,role='browser_loop'):
        sp=self.body_rsp;self.u.reg_write(UC_X86_REG_RSP,sp)
        if role=='browser_loop':
            for reg in [UC_X86_REG_R15,UC_X86_REG_R14,UC_X86_REG_R13,UC_X86_REG_R12,UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RBX,UC_X86_REG_RBP]:self.u.reg_write(reg,self.q(sp));sp+=8
            self.u.reg_write(UC_X86_REG_RSP,sp)
        elif role=='cold_entry':
            sp+=0x20;self.u.reg_write(UC_X86_REG_RDI,self.q(sp));sp+=8;self.u.reg_write(UC_X86_REG_RBX,self.q(sp+8));self.u.reg_write(UC_X86_REG_RSP,sp)
        self.ret(0)
    def run(self,name,*args,return_to=None):
        self.w(0x70001000,b''.join(Q((i<<30)|0x83)for i in range(8)))
        address=OS[name]if name in OS else ns['SYMBOLS'][name]
        sp=ns['STACK']+0x1ff008;stop=return_to or ns['STOP'];self.target_stop=stop
        self.w(sp,bytes(0x400));self.w(sp,Q(stop));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i,r in enumerate(ns['REGS']):self.u.reg_write(r,args[i]if i<len(args)else 0)
        for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
        self.u.emu_start(address,0,count=20000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==stop,('instruction budget',name,hex(self.u.reg_read(UC_X86_REG_RIP)))
        return self.u.reg_read(UC_X86_REG_RAX)
    def initialize(self):return self.run('no_initialize',self.st)
    def prepare(self):
        specs=[];tr=[]
        for i,w in enumerate(WINDOWS):
            target=OS[{'cold_entry':'no_native_entry','browser_loop':'no_native_loop','send_form':'no_native_send_form'}[w['role']]]
            before=bytes.fromhex(w['hex']);after=b'\xff\x25'+bytes(4)+Q(target)+b'\x90'*(len(before)-14)
            specs.append(struct.pack('<4I',0,w['rva'],len(before),0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
            a=self.tramps+i*0x100;tr.append(a);self.w(a,before+b'\xff\x25'+bytes(4)+Q(TSE+w['resume_rva']))
        before=Q(SETUP+0x2250);after=Q(self.oh['bridge']);specs.append(struct.pack('<4I',1,0x2fd50,8,0)+before.ljust(32,b'\0')+after.ljust(32,b'\0'))
        self.specs=specs;self.w(self.patches,b''.join(specs))
        self.w(self.inst,struct.pack('<IIQQQQQIIQIIQQQ',4,96,tr[1],tr[2],tr[0],self.p,self.patches,len(specs),0,0,0,0,self.oh['bridge'],self.oh['publisher'],0))
        return self.run('no_prepare',self.inst)
    def apply(self):
        for p in self.specs:
            module,rva,n,_=struct.unpack_from('<4I',p);self.w((SETUP if module else TSE)+rva,p[48:48+n])
    def bind_real_host(self):
        self.run('no_host',self.host)
        return self.run('w890_runtime_bind',self.st,self.host,self.sd,self.td)
    def setup_page(self,form=0x2713):
        self.w(TSE+0xafdd0,Q(self.app));self.w(self.app+0x28,I(0)+I(1)+Q(self.pa));self.w(self.pa,Q(self.page))
        self.w(self.page+0x20,Q(self.setup_hii));self.w(self.page+0x2a,struct.pack('<H',form));self.w(self.page+0x30,bytes(4));self.w(self.page+0x4c,I(1)+Q(self.fa));self.w(self.fa,Q(self.framep));self.w(self.framep+0x3c,I(1));self.w(self.framep+0x44,I(0)+Q(self.ca));self.w(self.ca,Q(self.control))
        self.w(TSE+0xbaaf0,Q(self.pt));self.w(TSE+0xbabc0,Q(self.blob));self.w(TSE+0xbab08,Q(self.cb));self.w(self.pt,I(1)+I(0x100));self.w(self.blob+0x100,Q(self.setup_hii));self.w(self.blob+0x10a,struct.pack('<H',form));self.w(self.blob+0x11c,I(1)+I(0))
        # Pick an actual original numeric opcode within the real form scope.
        current=0;at=4;op=None
        while at<len(FORMS):
            n=FORMS[at+1]&127
            if FORMS[at]==1:current=struct.unpack_from('<H',FORMS,at+2)[0]
            if current==form and FORMS[at]in (5,7):op=FORMS[at:at+n];break
            at+=n
        if op:
            self.w(self.opcode,op);self.w(self.control,Q(TSE+0xa5380));self.w(self.control+0x20,Q(self.setup_hii));self.w(self.control+0x34,struct.pack('<H',4));self.w(self.control+0x48,Q(self.opcode));self.w(self.cb,Q(self.setup_hii));self.w(self.cb+0x14,struct.pack('<H',4));self.w(self.cb+0x28,Q(self.opcode))
        return op

def main():
    cases=[]
    def case(name,fn):
        started=time.time();v=VM();assert fn(v),name;cases.append({'name':name,'status':'PASS','seconds':round(time.time()-started,3)});print(name,flush=True)
    case('original LoadedImage HII ConfigAccess identity succeeds',lambda v:v.initialize()==0 and v.hash_calls>=3 and v.notify_kinds==[1,2,8])
    case('wrong Setup FV GUID rejected',lambda v:(v.w(v.fv_setup+4,bytes(16)),v.initialize()==ns['ERR'](15))[1])
    case('original module .text mutation rejected',lambda v:(v.w(TSE+0x5000,b'\x00'),v.initialize()==ns['ERR'](15))[1])
    case('wrong HII driver never treated as a pointer',lambda v:(setattr(v,'bad_driver',True),v.initialize()==ns['ERR'](15))[1])
    case('wrong FORMS digest rejected',lambda v:(setattr(v,'bad_forms',True),v.initialize()==ns['ERR'](15))[1])
    case('overlapping map descriptors rejected',lambda v:(setattr(v,'map_overlap',True),v.initialize()==ns['ERR'](15))[1])
    case('memory map failure rejects',lambda v:(setattr(v,'map_failure',True),v.initialize()==ns['ERR'](15))[1])
    case('compiled exact hooks and relocated original trampolines prepare',lambda v:v.initialize()==0 and v.prepare()==0)
    case('unhooked loop refuses; no provider Begin',lambda v:v.initialize()==0 and v.prepare()==0 and v.run('no_native_loop',return_to=TSE+0xb8e1)==ns['ERR'](15)and not v.original_body)
    def entered(v,point=2,control=False):
        assert v.initialize()==0 and v.prepare()==0;v.apply();assert v.bind_real_host()==0
        v.setup_page();v.inside=('no_observe',[0,point,v.control if control else v.page,0,v.obs]);r=v.run('no_native_loop',return_to=TSE+0xb8e1)
        return r==0 and v.return_values==[1]and v.original_body==['browser_loop']and v.run('w890_provider_query',v.p)==1
    case('actual Begin End wraps compiled native prologue and page observation',entered)
    case('real control frame descriptor IFR chain accepted',lambda v:entered(v,4,True))
    def stale(v):
        assert v.initialize()==0 and v.prepare()==0;v.apply();assert v.bind_real_host()==0;v.setup_page();v.w(TSE+0xafcb0,Q(7));v.w(TSE+0xafde8,Q(DATA+0x24000));v.w(TSE+0xafe00,I(1));v.w(TSE+0xafddc,I(70))
        return v.run('no_observe',0,2,v.page,0,v.obs)==0 and v.run('no_lease_begin',v.out)==0 and v.run('w890_provider_query',v.p)==1
    case('hardware-shaped stage7 nonempty history cannot mint ownership',stale)
    def bad_control(v,mutation):
        assert v.initialize()==0 and v.prepare()==0;v.apply();assert v.bind_real_host()==0;v.setup_page();mutation(v)
        v.inside=('no_observe',[0,4,v.control,0,v.obs]);r=v.run('no_native_loop',return_to=TSE+0xb8e1)
        return r==0 and v.return_values==[0]
    case('same opcode absent from page raw descriptor refuses',lambda v:bad_control(v,lambda w:w.w(w.cb+0x28,Q(w.opcode+128))))
    case('control IFR content mismatch refuses',lambda v:bad_control(v,lambda w:w.w(w.opcode+2,b'\xff\xff')))
    case('unknown native vtable refuses',lambda v:bad_control(v,lambda w:w.w(w.control,Q(TSE+0x95680))))
    case('unmapped current page is not dereferenced',lambda v:bad_control(v,lambda w:w.w(w.pa,Q(0x12345000))))
    def notify(v):
        assert v.initialize()==0 and v.prepare()==0;v.apply();assert v.bind_real_host()==0;v.setup_page()
        v.inside=(v.notify_callback,[2,0,0,v.setup_hii,2]);v.run('no_native_loop',return_to=TSE+0xb8e1)
        return v.run('w890_provider_query',v.p)&32 and v.run('no_observe',0,2,v.page,0,v.obs)==0
    case('actual REMOVE notification revokes active epoch and provider',notify)
    def nested(v):
        assert v.initialize()==0 and v.prepare()==0;v.apply();assert v.bind_real_host()==0;v.setup_page();v.nested_loop=True
        hs=DATA+0x25000;v.w(hs,Q(v.setup_hii));v.inside=('no_native_send_form',[TSE+0x943a8,hs,1,0,0x2713,0,0]);r=v.run('no_native_loop',return_to=TSE+0xb8e1)
        return r==0 and v.return_values==[0]and v.original_body==['browser_loop','send_form','browser_loop']and v.run('w890_provider_query',v.p)==1
    case('SendForm seven arguments nested BrowserLoop actual Begin End',nested)
    case('direct unknown loop caller denied before native body',lambda v:v.initialize()==0 and v.prepare()==0 and (v.apply(),v.bind_real_host()==0 and v.run('no_native_loop')==ns['ERR'](15)and not v.original_body)[1])
    case('cold publication ticket cannot be manufactured outside entry',lambda v:v.initialize()==0 and v.prepare()==0 and (v.apply(),v.run('no_publication_validate',0,1)==0)[1])
    def publish(v,mode):
        assert v.initialize()==0 and v.prepare()==0;v.apply();v.publish_mode=mode
        r=v.run('no_native_entry',v.tse_handle,v.st)
        if mode=='good':
            assert r==0 and v.script_values==[0,1,0,1,1]and v.original_body==['cold_entry'],(hex(r),v.script_values,v.original_body)
            return True
        return r==ns['ERR'](15)and not v.original_body and v.script_values[-1]==(1 if mode=='warning'else 0)
    case('cold REMOVE ADD renew only live private publication window',lambda v:publish(v,'good'))
    case('cold modified forms arbitrary supplied digest refused',lambda v:publish(v,'bad_hash'))
    case('cold foreign HII mutation revokes publication window',lambda v:publish(v,'foreign'))
    case('positive publisher warning after publication cannot start native entry',lambda v:publish(v,'warning'))
    case('shutdown keeps component resident while installed detours exist',lambda v:v.initialize()==0 and v.prepare()==0 and (v.apply(),v.run('no_shutdown')==ns['ERR'](20))[1])
    def service_changed(v):
        assert v.initialize()==0 and v.prepare()==0;v.apply();assert v.bind_real_host()==0;v.setup_page();v.w(v.bs+0x98,Q(ns['HOOK']+0x2f00))
        return v.run('no_native_loop',return_to=TSE+0xb8e1)==ns['ERR'](15)and not v.original_body
    case('Boot Services substitution refuses before calling replacement',service_changed)
    def cpu_changed(v):
        assert v.initialize()==0;v.w(0x70002000,Q(0x70001003));v.u.reg_write(UC_X86_REG_CR3,0x70002000);before=len(v.uefi_calls)
        return v.run('no_prepare',v.inst)==ns['ERR'](15)and len(v.uefi_calls)==before
    case('changed CR3 rejected before saved Boot Services dereference',cpu_changed)
    report={'status':'PASS','case_count':len(cases),'cases':cases,'scope':__doc__,'observer_sha256':hashlib.sha256((H/'build/W890NativeObserver04.TESTONLY.dll').read_bytes()).hexdigest(),'runtime_sha256':hashlib.sha256(ns['EFI'].read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'hardware_validation':False}
    (H/'build/observer_pe_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'case_count':len(cases),'status':'PASS'}))
if __name__=='__main__':main()
