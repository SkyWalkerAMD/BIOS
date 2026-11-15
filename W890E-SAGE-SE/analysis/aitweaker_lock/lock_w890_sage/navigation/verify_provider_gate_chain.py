"""Execute original W890 menu -> compiled gate -> actual Provider01 PE.

Only the HII/native-owner observer, firmware services and prompt authentication
result are fixtures. No sibling reports are rewritten, no EFI runs on hardware.
"""
from pathlib import Path
import ast,ctypes,hashlib,json,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile,capstone
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *
from verify_gate_native import Snapshot,Gate

FIXTURE=HERE.parent/'password/provider/verify_provider_pe.py'
tree=ast.parse(FIXTURE.read_text(encoding='utf8'),str(FIXTURE))
# Reuse only the fixture definition. Its top-level tests and report writes are
# intentionally not executed; they are independently run by the password agent.
nodes=[]
for node in tree.body:
    if isinstance(node,ast.FunctionDef) and node.name=='check':break
    nodes.append(node)
ns={'__name__':'provider_fixture_definition_only','__file__':str(FIXTURE)}
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(FIXTURE),'exec'),ns)
ProviderVM=ns['VM'];SYMBOLS=ns['SYMBOLS'];q=ns['q'];STOP=ns['STOP']
HEAP=ns['HEAP'];HOOK=ns['HOOK'];STACK=ns['STACK'];DENIED=ns['DENIED']
BASE=0x02000000;GBASE=0x06000000;DATA=0x05000000
APP=DATA+0x2000;CONTROL=DATA+0x3000;COOKIE=DATA+0x4000;BS=DATA+0x5000
HIST=DATA+0x6000;ROWS=DATA+0x7000;ARRAY=DATA+0x8000;GATE=DATA+0xa000
PAGES=[DATA+0xb000+i*0x100 for i in range(6)]
OBSERVE=HOOK+0x2000;FREE=HOOK+0x2100
ORIGINAL=HERE/'modules/AMITSE.efi';GATEDLL=HERE/'build/W890Navigation.TESTONLY.dll'
ORIGINAL_SHA='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
GATE_SHA='eb46bd5db1608da2651c57296b1b11281cb0b71edc6074706a23a3175e8fe9e4'
PROVIDER_SHA='971ae6208bb75bdbe15a859adf46b1e68ca2e232bb618cca5f476994d6465a9e'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(ORIGINAL)==ORIGINAL_SHA and sha(GATEDLL)==GATE_SHA and ns['BUILD']['sha256']==PROVIDER_SHA
NONVOL=[UC_X86_REG_RBX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
ARGS=[UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]

class Chain(ProviderVM):
    def __init__(self,record=ns['ENABLED'],*,form=0x2713):
        self.native=[];self.gate_trace=[];self.provider_trace=[];self.observations=0;self.frees=[]
        self.target_form=form;self.change=None;self.auth_callers=[];self.strict_caller=True
        self.gate_requests=[];self.gate_queries=[]
        super().__init__(record)
        for path,base in [(ORIGINAL,BASE),(GATEDLL,GBASE)]:
            p=pefile.PE(str(path));p.relocate_image(base)
            self.u.mem_map(base,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095)
            self.w(base,p.get_memory_mapped_image())
            if base==GBASE:
                self.exports={e.name.decode():GBASE+e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
                self.gate_image_size=p.OPTIONAL_HEADER.SizeOfImage
                # Freeze the one exact indirect request CALL return site from
                # the reviewed compiled wg_check body, not a whole image range.
                ins=list(capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(p.get_data(0x1000,0x630),GBASE+0x1000))
                callsites=[i.address+i.size for i in ins if i.mnemonic=='call' and i.op_str=='qword ptr [rdi + 0x28]']
                assert callsites==[GBASE+0x1248],[(hex(i.address),i.mnemonic,i.op_str) for i in ins if i.mnemonic=='call']
                self.request_callsite=callsites[0]
        self.u.mem_map(DATA,0x20000)
        self.u.reg_write(UC_X86_REG_CR4,0x600)
        self.gate=Gate(0x3130304730393857,DATA,self.p,OBSERVE,SYMBOLS['w890_provider_query'],SYMBOLS['w890_provider_request'],BASE,0,0)
        self.w(GATE,bytes(self.gate));self.w(self.exports['wg_binding'],q(GATE))
        assert self.Q(BASE+0x94408)==BASE+0x22818
        self.w(BASE+0x94408,q(self.exports['wg_native_menu_thunk']))
        self.w(CONTROL+8,q(self.Q(BASE+0x94408)));self.w(CONTROL+0x10,q(APP));self.w(CONTROL+0x18,q(COOKIE));self.w(CONTROL+0x80,q(ROWS))
        self.w(COOKIE,struct.pack('<I',8));self.w(ROWS+2*16+8,struct.pack('<H',4))
        self.w(BASE+0xafdd0,q(APP));self.w(APP+0x2c,struct.pack('<I',6));self.w(APP+0x30,q(ARRAY))
        for i,page in enumerate(PAGES):
            self.w(ARRAY+i*8,q(page));self.w(page+0x20,q(DATA+0xc000));self.w(page+0x2a,struct.pack('<H',form if i==4 else 0x2712));self.w(page+0x30,struct.pack('<H',i))
        self.w(BASE+0xafbc8,q(BS));self.w(BS+0x48,q(FREE));self.reset_native_state()
    def dword(self,a):return struct.unpack('<I',self.r(a,4))[0]
    def reset_native_state(self):
        self.w(APP+0x28,struct.pack('<I',2));self.w(APP+0x58,bytes(8))
        self.w(BASE+0xafde8,q(HIST));self.w(BASE+0xafe00,struct.pack('<I',3));self.w(BASE+0xafddc,struct.pack('<I',2))
    def hook(self,u,a,size,data):
        if BASE<=a<BASE+0xde000:self.native.append(a-BASE)
        if GBASE<=a<GBASE+0x7000:self.gate_trace.append(a-GBASE)
        if ns['BASE']<=a<ns['BASE']+ns['PE'].OPTIONAL_HEADER.SizeOfImage:self.provider_trace.append(a-ns['BASE'])
        if a==SYMBOLS['w890_provider_request']:self.gate_requests.append(self.Q(u.reg_read(UC_X86_REG_RSP)))
        if a==SYMBOLS['w890_provider_query']:self.gate_queries.append(self.Q(u.reg_read(UC_X86_REG_RSP)))
        if a==self.addresses['authorized']:
            caller=self.arg(0);self.auth_callers.append(caller);self.calls.append('authorized')
            self.ret(int(self.authorized and self.strict_caller and caller==self.request_callsite));return
        if a==OBSERVE:
            self.observations+=1
            assert self.arg(1)==5 and self.arg(2)==CONTROL and self.arg(3)==COOKIE
            s=Snapshot();s.session=self.Q(self.out);s.native_base=BASE;s.application=APP
            idx=struct.unpack('<H',self.r(COOKIE+8,2))[0];s.page_index=idx;s.application_index=self.dword(APP+0x28)
            s.page=PAGES[idx];s.hii=self.Q(s.page+0x20);s.form=struct.unpack('<H',self.r(s.page+0x2a,2))[0]
            s.control=CONTROL;s.history=self.Q(BASE+0xafde8);s.history_count=self.dword(BASE+0xafe00);s.history_root=self.dword(BASE+0xafddc);s.owner=1;s.proof=31
            s.formset[:]=uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le
            if self.change and self.observations==2:
                setattr(s,self.change,getattr(s,self.change)+1)
            self.w(self.arg(4),bytes(s));self.ret(1);return
        if a==FREE:self.frees.append(self.arg(0));self.ret(0);return
        super().hook(u,a,size,data)
    def menu(self,allow):
        first=len(self.native);frees=len(self.frees);observed=self.observations
        sp=STACK+0x1ff008;self.w(sp,bytes(0x200));self.w(sp,q(STOP));self.w(sp+40,b'CANARY-ABOVE-SHADOW-SPACE!')
        self.u.reg_write(UC_X86_REG_RSP,sp)
        for i,r in enumerate(NONVOL):self.u.reg_write(r,0x11110000+i)
        for r,v in zip(ARGS,[CONTROL,2,0,0]):self.u.reg_write(r,v)
        self.u.emu_start(BASE+0x6af54,STOP+1,count=4000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==STOP
        assert self.dword(APP+0x28)==(4 if allow else 2)
        assert self.Q(BASE+0xafde8)==(0 if allow else HIST)
        assert self.dword(BASE+0xafe00)==(0 if allow else 3)
        assert self.dword(BASE+0xafddc)==(0 if allow else 2)
        assert self.dword(APP+0x5c)==int(allow)
        assert self.frees[frees:]==([HIST]if allow else [])
        assert (0x22818 in self.native[first:])==allow
        assert self.u.reg_read(UC_X86_REG_RSP)==sp+8
        assert [self.u.reg_read(r)for r in NONVOL]==[0x11110000+i for i in range(len(NONVOL))]
        assert self.r(sp+40,26)==b'CANARY-ABOVE-SHADOW-SPACE!'
        assert self.dword(GATE+56)==0
        return {'allowed':allow,'native_instructions':len(self.native)-first,'observations':self.observations-observed}

def main():
    cases=[]
    def single(name,allow,mode='deny',record=ns['ENABLED'],**changes):
        v=Chain(record,form=changes.pop('form',0x2713))
        assert v.init()==(6 if record is None else 0) and v.begin()==0
        v.prompt=mode
        for k,val in changes.items():setattr(v,k,val)
        detail=v.menu(allow)
        cases.append({'name':name,'status':'PASS',**detail,'prompt_count':len(v.outputs),'provider_instructions':len(v.provider_trace),'gate_instructions':len(v.gate_trace),'request_callers':[hex(x-GBASE) for x in v.auth_callers]})
        return v
    single('cancelled_password_preserves_original_page_and_history',False)
    single('prompt_success_without_core_unlock_denied',False,'success_without_unlock')
    single('modeled_authentication_result_reaches_original_menu',True,'grant')
    single('unconfigured_credential_denies_protected_menu',False,record=None)
    single('disabled_credential_allows_without_prompt',True,record=ns['DISABLED'])
    single('unprotected_main_allows_without_prompt',True,form=0x2712)
    single('unknown_form_denies_without_prompt',False,form=0xfffe)
    single('unauthorized_native_callsite_denies_before_prompt',False,'grant',strict_caller=False)
    single('profile_lost_during_prompt_denies_original_menu',False,'profile_lost')
    single('owner_lost_during_prompt_denies_original_menu',False,'owner_lost')
    single('owner_invalid_before_gate_denies',False,'grant',active=False)
    single('wrong_tpl_denies_prompt',False,'grant',tpl=False)
    for field in ['session','page','hii','history_count','application_index']:
        single('stale_'+field+'_after_actual_provider_request',False,'grant',change=field)
    v=single('end_boot_during_prompt_denies_original_menu',False,'grant',end_on='prompt')
    count=len(v.calls);assert v.query()==64 and v.request_call()==DENIED and len(v.calls)==count
    v=single('first_entry_unlocks_current_visit',True,'grant')
    prompts=len(v.outputs);v.reset_native_state();v.menu(True)
    assert len(v.outputs)==prompts
    cases.append({'name':'same_visit_reentry_does_not_prompt','status':'PASS','prompt_count':len(v.outputs)})
    firsttoken=v.Q(v.out);assert v.end()==0 and v.begin()==0 and v.Q(v.out)==firsttoken+1 and v.query()==3
    v.reset_native_state();v.prompt='deny';v.menu(False)
    assert len(v.outputs)==prompts+1
    cases.append({'name':'outer_visit_end_relocks_and_next_entry_prompts','status':'PASS','prompt_count':len(v.outputs)})
    report={'status':'PASS_ACTUAL_PROVIDER_GATE_AND_ORIGINAL_MENU_BYTES','case_count':len(cases),'cases':cases,
        'source_sha256':sha(__file__),'fixture_source_sha256':sha(FIXTURE),'original_amitse_sha256':ORIGINAL_SHA,'gate_sha256':GATE_SHA,'provider_sha256':PROVIDER_SHA,
        'request_callsite':{'image':'compiled gate','return_rva':'0x1248','binding':'one exact reviewed indirect CALL return address'},
        'emulator_patch':{'original_slot_rva':'0x94408','original_target_rva':'0x22818','target':'compiled wg_native_menu_thunk'},
        'native_owner_modeled':True,'HII_pointer_extent_observer_modeled':True,'prompt_authentication_result_modeled':True,
        'scope':__doc__,'hardware_or_firmware_writes':0,
        'not_verified':['Native observer authority / HII package identity / real caller ownership','Actual password dialog and persistent storage','Initial display, all input paths, HII updates and native save hooks','Real hook installation, production capsule signing or ASUS hardware acceptance']}
    (HERE/'provider_gate_chain_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':report['status'],'case_count':len(cases),'native_original_sha256':ORIGINAL_SHA,'provider_sha256':PROVIDER_SHA}))

if __name__=='__main__':main()
