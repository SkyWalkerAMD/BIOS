"""Actual Runtime02 UI/provider/storage + gate + original W890 menu/first bytes.

UEFI console/GOP/input/services, native owner/HII authority and memory extents are
modeled. The actual password dialog and AP_CORE authorization execute. Only the
expensive PBKDF primitive is replaced with an independent hashlib oracle; the
matching native KDF is separately executed by the runtime02 OVMF lab.
"""
from pathlib import Path
import ast,ctypes,hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;NAV=HERE.parents[1];ROOT=NAV.parents[3]
sys.path[:0]=[str(NAV),str(ROOT/'tools/pydeps')]
import pefile
from unicorn.x86_const import *
from verify_provider_gate_chain import Chain,Snapshot,Gate,BASE,GBASE,DATA,APP,CONTROL,COOKIE,BS,HIST,ROWS,ARRAY,GATE,PAGES,OBSERVE,FREE,ORIGINAL,GATEDLL,GATE_SHA,ORIGINAL_SHA,sha,q
from verify_first_fallback import First,Binding,FBASE,FB,IDENTITY,SESSION,RANGE,HII,FAULT,FALLBACK

FIXTURE=NAV.parent/'password_runtime02/verify_runtime_pe.py'
tree=ast.parse(FIXTURE.read_text(encoding='utf8'),str(FIXTURE));nodes=[]
for node in tree.body:
    if isinstance(node,ast.FunctionDef)and node.name=='check':break
    nodes.append(node)
rt={'__name__':'runtime_fixture_definitions_only','__file__':str(FIXTURE)}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(FIXTURE),'exec'),rt)
VM=rt['VM'];SYMBOLS=rt['SYMBOLS'];STOP=rt['STOP'];HEAP=rt['HEAP'];HOOK=rt['HOOK'];STACK=rt['STACK'];ERR=rt['ERR'];CORE=rt['core']
RUNTIME_SHA='ec718d44fd088b1fb241ced5602bbea8b71ea07798b8226d05e4af5c0c2c15d6'
assert sha(rt['EFI'])==RUNTIME_SHA
OVMF_RESULT=NAV.parent/'password_runtime02/lab/runs/20261108_012702/result.json'
assert json.loads(OVMF_RESULT.read_text())['component_sha256']==RUNTIME_SHA
TEXT_OUT=HEAP+0x2000;TEXT_IN=HEAP+0x2100;OUT_MODE=HEAP+0x2200;GOP=HEAP+0x2300;GOP_MODE=HEAP+0x2400;GOP_INFO=HEAP+0x2500
UI={name:HOOK+0x4000+i*0x100 for i,name in enumerate(['out','attribute','clear','cursor','enable','read_key','blt'])}
WIDTH=64;HEIGHT=48;PIXELS=WIDTH*HEIGHT*4

class RuntimeChain(VM):
    Q=VM.q
    dword=lambda self,a:struct.unpack('<I',self.r(a,4))[0]
    reset_native_state=Chain.reset_native_state
    menu=Chain.menu
    first=First.first
    def __init__(self,record=rt['ENABLED'],*,first=False):
        self.native=[];self.gate_trace=[];self.runtime_trace=[];self.observations=0;self.frees=[];self.auth_callers=[];self.prompt_entries=0;self.outputs=[]
        self.change=None;self.keys=[];self.output_text=[];self.ui_calls=[];self.read_keys=0;self.screen_capture=0;self.screen_restores=0
        self.initial_screen=bytes((i*37+19)&255 for i in range(PIXELS));self.framebuffer=self.initial_screen
        self.restore_error=False;self.key_owner_loss=False;self.end_on_ui=None;self.management_authorized=False
        self.ident=True;self.session_ok=True;self.hii_ok=True;self.epoch=11;self.range_deny=None;self.hii_calls=0;self.session_calls=0
        self.mutate_hii_call=None;self.mutate_session_call=None;self.mutator=None;self.faulted=False;self.first_complete=False;self.first_mode=first
        super().__init__(record)
        self.addresses=self.hooks
        for path,base in [(ORIGINAL,BASE),(GATEDLL,GBASE)]+([(FALLBACK,FBASE)]if first else []):
            p=pefile.PE(str(path));p.relocate_image(base);self.u.mem_map(base,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.w(base,p.get_memory_mapped_image())
            if base==GBASE:self.exports={e.name.decode():base+e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
            if base==FBASE:self.fexports={e.name.decode():base+e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
        self.u.mem_map(DATA,0x20000)
        self.gate=Gate(0x3130304730393857,DATA,self.p,OBSERVE,SYMBOLS['w890_provider_query'],SYMBOLS['w890_provider_request'],BASE,0,0)
        self.w(GATE,bytes(self.gate));self.w(self.exports['wg_binding'],q(GATE))
        assert self.Q(BASE+0x94408)==BASE+0x22818;self.w(BASE+0x94408,q(self.exports['wg_native_menu_thunk']))
        self.w(CONTROL+8,q(self.Q(BASE+0x94408)));self.w(CONTROL+0x10,q(APP));self.w(CONTROL+0x18,q(COOKIE));self.w(CONTROL+0x80,q(ROWS))
        self.w(COOKIE,struct.pack('<I',8));self.w(ROWS+2*16+8,struct.pack('<H',4))
        self.w(BASE+0xafdd0,q(APP));self.w(APP+0x2c,struct.pack('<I',6));self.w(APP+0x30,q(ARRAY))
        for i,page in enumerate(PAGES):
            self.w(ARRAY+i*8,q(page));self.w(page+0x20,q(DATA+0xc000));self.w(page+0x2a,struct.pack('<H',0x2713 if i==4 else 0x2712 if i==2 else 0x2714));self.w(page+0x30,struct.pack('<H',i))
        self.w(BASE+0xafbc8,q(BS));self.w(BS+0x48,q(FREE));self.reset_native_state()
        if first:
            assert self.r(BASE+0x19463,8)==bytes.fromhex('8b7928ba06000503')
            target=self.fexports['wf_native_first_entry'];self.w(BASE+0x19463,b'\xe9'+struct.pack('<i',target-(BASE+0x19468))+b'\x90'*3)
            for name,value in [('wf_binding_pointer',FB),('wf_first_function',self.fexports['wf_first']),('wf_native_resume',BASE+0x1946b),('wf_fail_closed',FAULT)]:self.w(self.fexports[name],q(value))
            self.w(APP+0x28,struct.pack('<I',4));self.w(BASE+0xafde8,q(0));self.w(BASE+0xafe00,bytes(4));self.w(BASE+0xafddc,bytes(4));self.w(BASE+0xafde0,struct.pack('<I',20))
            self.binding=Binding(0x3130304630393857,BASE,APP,1,DATA,self.p,GATE,SYMBOLS['w890_provider_query'],self.exports['wg_check'],IDENTITY,SESSION,RANGE,HII,0,0)
            self.w(FB,bytes(self.binding))
        self.w(self.st+0x30,q(TEXT_IN));self.w(self.st+0x40,q(TEXT_OUT))
        self.w(TEXT_IN+8,q(UI['read_key']))
        for off,name in [(8,'out'),(0x28,'attribute'),(0x30,'clear'),(0x38,'cursor'),(0x40,'enable')]:self.w(TEXT_OUT+off,q(UI[name]))
        self.w(TEXT_OUT+0x48,q(OUT_MODE));self.w(OUT_MODE,struct.pack('<iiiiiB3x',1,0,7,3,4,1));self.original_mode=self.r(OUT_MODE,24)
        self.w(GOP+0x10,q(UI['blt']));self.w(GOP+0x18,q(GOP_MODE));self.w(GOP_MODE,struct.pack('<IIQQQQ',1,0,GOP_INFO,36,0,PIXELS))
        self.w(GOP_INFO,struct.pack('<9I',0,WIDTH,HEIGHT,0,0,0,0,0,WIDTH))
        self.w(0x70001000,b''.join(q((i<<30)|0x83)for i in range(8)))
    def key_text(self,text,ack=False):
        self.keys=[(0,ord(c))for c in text]+[(0,13)]+([(0,32)]if ack else [])
    def cancel(self):self.keys=[(0x17,0)]
    def end(self):return self.call('w890_provider_end',self.p,self.Q(self.out))
    def manage(self,operation):
        self.management_authorized=True
        try:return self.call('w890_provider_manage',self.p,operation)
        finally:self.management_authorized=False
    def hook(self,u,a,size,data):
        if BASE<=a<BASE+0xde000:self.native.append(a-BASE)
        if GBASE<=a<GBASE+0x7000:self.gate_trace.append(a-GBASE)
        if rt['BASE']<=a<rt['BASE']+rt['PE'].OPTIONAL_HEADER.SizeOfImage:self.runtime_trace.append(a-rt['BASE'])
        if a==SYMBOLS['w890_console_prompt']:self.prompt_entries+=1;self.outputs.append(self.arg(0)&0xffffffff)
        if a==self.hooks['caller']:
            self.calls.append('caller');self.ret(int(self.arg(0)==STOP));return
        if a==self.hooks['authorized']:
            caller=self.arg(0);self.auth_callers.append(caller);self.calls.append('authorized')
            allowed=caller==GBASE+0x1248 or(self.management_authorized and caller==STOP)
            self.ret(int(allowed));return
        if self.first_mode and(a in [IDENTITY,SESSION,RANGE,HII,FAULT,BASE+0x1946b]or(a==OBSERVE and self.arg(1)==1)):
            First.hook(self,u,a,size,data);return
        if a in [OBSERVE,FREE]:Chain.hook(self,u,a,size,data);return
        if a==self.hooks['locate'] and self.r(self.arg(0),16)==uuid.UUID('9042a9de-23dc-4a38-96fb-7aded080516a').bytes_le:
            self.uefi_calls.append('locate_gop');self.w(self.arg(2),q(GOP));self.ret(0);return
        name=next((n for n,p in UI.items()if p==a),None)
        if name:
            self.ui_calls.append(name);self.uefi_calls.append('ui_'+name);value=0
            if name=='out':
                p=self.arg(1);b=bytearray()
                for i in range(2048):
                    c=self.r(p+i*2,2)
                    if c==b'\0\0':break
                    b+=c
                else:raise AssertionError('unterminated console output')
                self.output_text.append(b.decode('utf-16-le'))
            elif name=='attribute':self.w(OUT_MODE+8,struct.pack('<i',self.arg(1)))
            elif name=='clear':self.framebuffer=bytes(PIXELS);self.w(OUT_MODE+12,bytes(8))
            elif name=='cursor':self.w(OUT_MODE+12,struct.pack('<ii',self.arg(1),self.arg(2)))
            elif name=='enable':self.w(OUT_MODE+20,bytes([self.arg(1)&255]))
            elif name=='read_key':
                assert self.keys,'fixture key queue exhausted';self.w(self.arg(1),struct.pack('<HH',*self.keys.pop(0)));self.read_keys+=1
                if self.key_owner_loss:self.active=False
            elif name=='blt':
                buffer,operation=self.arg(1),self.arg(2)
                assert [self.arg(i)for i in range(3,7)]==[0,0,0,0]and self.arg(7)==WIDTH and self.arg(8)==HEIGHT and self.arg(9)==0
                if operation==1:self.w(buffer,self.framebuffer);self.screen_capture+=1
                elif operation==2:
                    self.framebuffer=self.r(buffer,PIXELS);self.screen_restores+=1
                    if self.restore_error:value=ERR(7)
                else:raise AssertionError('unexpected GOP operation')
            if self.end_on_ui==name:
                self.end_on_ui=None;handle=next(reversed(self.event_callbacks));callback,context=self.event_callbacks[handle];self.nested(callback,[handle,context],value)
            else:self.ret(value)
            return
        VM.hook(self,u,a,size,data)
    def screen_restored(self):
        assert self.framebuffer==self.initial_screen and self.r(OUT_MODE,24)==self.original_mode
        assert self.screen_capture==self.screen_restores
        text=''.join(self.output_text)
        for password in [CORE.PW,CORE.NEW_PW,CORE.WRONG_PW]:assert password.decode()not in text
        if self.read_keys and CORE.PW in [self.record]:raise AssertionError('plaintext stored as record')
        assert self.r(HEAP+0x10000,PIXELS)==bytes(PIXELS)
        return {'captured':self.screen_capture,'restored':self.screen_restores,'password_echoed':False}

def main():
    cases=[]
    def new(record=rt['ENABLED'],first=False):
        v=RuntimeChain(record,first=first);assert v.bind()==(6 if record is None else 0)and v.begin()==0;return v
    def record_case(name,v,**detail):
        cases.append({'name':name,'status':'PASS','prompts':v.prompt_entries,'read_keys':v.read_keys,'KDF_oracle_calls':v.calls.count('kdf'),'credential_writes':v.set_count,'runtime_instructions':len(v.runtime_trace),'native_instructions':len(v.native),**detail})
    for first in [False,True]:
        prefix='first_'if first else'menu_'
        for mode in ['correct','cancel','wrong','unconfigured','disabled']:
            record=None if mode=='unconfigured'else rt['DISABLED']if mode=='disabled'else rt['ENABLED'];v=new(record,first)
            if mode=='correct':v.key_text(CORE.PW.decode())
            elif mode=='cancel':v.cancel()
            elif mode=='wrong':v.key_text(CORE.WRONG_PW.decode(),ack=True)
            elif mode=='unconfigured':v.keys=[(0,32)]
            allowed=mode in ['correct','disabled']
            detail=v.first('allow'if allowed else'main')if first else v.menu(allowed)
            if mode!='disabled':detail['screen']=v.screen_restored()
            assert v.set_count==0 and v.query()&(4 if allowed else 0)==(4 if allowed else 0)
            if not allowed:assert not(v.query()&4)
            assert not v.keys
            record_case(prefix+mode+'_actual_masked_UI',v,**detail)
    v=new();v.key_text(CORE.PW.decode());v.menu(True);v.screen_restored();prompts=v.prompt_entries
    v.reset_native_state();v.menu(True);assert v.prompt_entries==prompts
    assert v.end()==0 and v.begin()==0;v.reset_native_state();v.cancel();v.menu(False);assert v.prompt_entries==prompts+1 and not(v.query()&4);v.screen_restored()
    record_case('runtime_session_same_visit_no_reprompt_new_visit_relocks',v)
    for first in [False,True]:
        for fault in ['restore_error','key_owner_loss','ExitBootServices']:
            v=new(first=first);v.key_text(CORE.PW.decode())
            if fault=='ExitBootServices':v.end_on_ui='read_key'
            else:setattr(v,fault,True)
            detail=v.first('fault')if first else v.menu(False)
            assert v.query()&(64 if fault=='ExitBootServices' else 32)
            assert v.set_count==0
            if fault=='ExitBootServices':
                count=len(v.uefi_calls);v.query();assert len(v.uefi_calls)==count
            record_case(('first_'if first else'menu_')+fault+'_never_reaches_protected_native_effect',v,**detail)
    v=new(None,True);v.keys=[(0,32)];v.first('main');v.screen_restored()
    # Management caller ownership is explicitly a fixture. The actual runtime
    # masked setup dialog, record construction, SetVariable/readback and later
    # native-entry password verification all execute in this same address space.
    text=CORE.NEW_PW.decode()+'\r'+CORE.NEW_PW.decode()+'\r'+' '
    v.keys=[(0,ord(c))for c in text];assert v.manage(0)==0 and v.set_count==1 and v.record!=rt['ENABLED'];v.screen_restored()
    assert v.end()==0 and v.begin()==0;v.binding.session_token=v.Q(v.out);v.w(FB,bytes(v.binding));v.w(APP+0x28,struct.pack('<I',4));v.first_complete=False
    v.native.clear();v.key_text(CORE.NEW_PW.decode());v.first('allow');v.screen_restored();assert not v.keys
    record_case('unconfigured_to_actual_password_enrollment_then_next_visit_unlock',v)
    output={'status':'PASS_ACTUAL_RUNTIME02_UI_PROVIDER_GATE_NATIVE_CHAIN','case_count':len(cases),'cases':cases,'runtime02_sha256':RUNTIME_SHA,'gate_sha256':GATE_SHA,'first_component_sha256':sha(FALLBACK),'original_amitse_sha256':ORIGINAL_SHA,'source_sha256':sha(__file__),'runtime_fixture_sha256':sha(FIXTURE),'scope':__doc__,'native_owner_and_HII_modeled':True,'UEFI_services_and_GOP_modeled':True,'password_auth_result_modeled':False,'PBKDF_primitive_independent_python_oracle':True,'actual_native_KDF_verified_separately':str(OVMF_RESULT.relative_to(NAV.parent)),'separate_OVMF_result_sha256':sha(OVMF_RESULT),'first_fault_continuation':'emulator stop only, no production error UI','hardware_or_firmware_writes':0,'not_verified':['Real ASUS owner/physical UI / writable-map / HII provenance','Native Security action hook publication','All native entry/save/FORM_OPEN paths','Full browser loop after first 1946B resume','Hook installation and flashable capsule trust/recovery']}
    (HERE/'runtime02_chain_tests.json').write_text(json.dumps(output,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':output['status'],'case_count':len(cases),'runtime02_sha256':RUNTIME_SHA}))

if __name__=='__main__':main()
