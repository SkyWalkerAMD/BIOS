"""Execute first-entry branch + actual gate/provider + native Main navigation.

This is an offline byte test. Native identity, session authority, HII ownership
and firmware memory permissions are explicit test fixtures. The error branch is
an emulator stop, not an ASUS error UI or an approved hardware continuation.
"""
from verify_provider_gate_chain import *
FBASE=0x08000000;FB=DATA+0xd000;IDENTITY=HOOK+0x3000;SESSION=HOOK+0x3100;RANGE=HOOK+0x3200;HII=HOOK+0x3300;FAULT=HOOK+0x3400
FALLBACK=HERE/'build/W890FirstFallback.TESTONLY.dll'
BUILD=json.loads((HERE/'build/fallback_build.json').read_text(encoding='utf8'))
assert sha(FALLBACK)==BUILD['sha256']
class Binding(ctypes.Structure):
    _fields_=[(n,ctypes.c_uint64)for n in ['abi','native_base','application','session_token','opaque','provider','gate','query','check_first','identity','session','range','hii']]+[('busy',ctypes.c_uint32),('reserved',ctypes.c_uint32)]

class First(Chain):
    def __init__(self,record=ns['ENABLED']):
        self.ident=True;self.session_ok=True;self.hii_ok=True;self.epoch=11;self.range_deny=None;self.hii_calls=0;self.session_calls=0
        self.mutate_hii_call=None;self.mutate_session_call=None;self.mutator=None;self.faulted=False;self.first_complete=False
        super().__init__(record)
        p=pefile.PE(str(FALLBACK));p.relocate_image(FBASE);self.u.mem_map(FBASE,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095);self.w(FBASE,p.get_memory_mapped_image())
        self.fexports={e.name.decode():FBASE+e.address for e in p.DIRECTORY_ENTRY_EXPORT.symbols}
        assert self.r(BASE+0x19463,8)==bytes.fromhex('8b7928ba06000503')
        target=self.fexports['wf_native_first_entry'];self.w(BASE+0x19463,b'\xe9'+struct.pack('<i',target-(BASE+0x19468))+b'\x90'*3)
        self.w(self.fexports['wf_binding_pointer'],q(FB));self.w(self.fexports['wf_first_function'],q(self.fexports['wf_first']))
        self.w(self.fexports['wf_native_resume'],q(BASE+0x1946b));self.w(self.fexports['wf_fail_closed'],q(FAULT))
        for i,page in enumerate(PAGES):self.w(page+0x2a,struct.pack('<H',0x2712 if i==2 else 0x2713 if i==4 else 0x2714))
        self.w(APP+0x28,struct.pack('<I',4));self.w(BASE+0xafde8,q(0));self.w(BASE+0xafe00,bytes(4));self.w(BASE+0xafddc,bytes(4));self.w(BASE+0xafde0,struct.pack('<I',20))
        self.binding=Binding(0x3130304630393857,BASE,APP,1,DATA,self.p,GATE,SYMBOLS['w890_provider_query'],self.exports['wg_check'],IDENTITY,SESSION,RANGE,HII,0,0)
        self.w(FB,bytes(self.binding))
    def hook(self,u,a,size,data):
        if a==BASE+0x1946b:self.first_complete=True;u.emu_stop();return
        if a==FAULT:self.faulted=True;u.emu_stop();return
        if a==OBSERVE and self.arg(1)==1:
            self.observations+=1;assert self.arg(2)==APP and self.arg(3)==0
            s=Snapshot();s.session=self.Q(self.out);s.native_base=BASE;s.application=APP;s.application_index=self.dword(APP+0x28);s.page_index=s.application_index
            s.page=PAGES[s.page_index] if s.page_index<len(PAGES)else 0;s.hii=DATA+0xc000;s.form=struct.unpack('<H',self.r(s.page+0x2a,2))[0]if s.page else 0
            s.history=self.Q(BASE+0xafde8);s.history_count=self.dword(BASE+0xafe00);s.history_root=self.dword(BASE+0xafddc);s.owner=1;s.proof=31
            s.formset[:]=uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le;self.w(self.arg(4),bytes(s));self.ret(1);return
        if a==IDENTITY:self.ret(int(self.ident and self.arg(1)==BASE and self.arg(2)==APP));return
        if a==SESSION:
            self.session_calls+=1
            if self.mutate_session_call==self.session_calls:self.mutator(self)
            self.ret(int(self.session_ok and self.arg(1)==self.Q(self.out) and self.arg(2)==APP));return
        if a==RANGE:
            address=self.arg(1);n=self.arg(2);mode=self.arg(3)
            readable=(BASE<=address and address+n<=BASE+0xde000)or(DATA<=address and address+n<=DATA+0x20000)
            writable=(DATA<=address and address+n<=DATA+0x20000)or any(address==BASE+rva and n==length for rva,length in [(0xafde8,8),(0xafe00,4),(0xafddc,4)])
            okay=readable if mode==1 else writable if mode==2 else False
            if self.range_deny is not None and address<=self.range_deny<address+n:okay=False
            self.ret(int(okay));return
        if a==HII:
            self.hii_calls+=1
            if self.mutate_hii_call==self.hii_calls:self.mutator(self)
            okay=self.hii_ok and self.arg(1)==DATA+0xc000
            if okay:
                self.w(self.arg(2),uuid.UUID('7b59104a-c00d-4158-87ff-f04d6396a915').bytes_le)
                self.w(self.arg(3),q(self.epoch))
            self.ret(int(okay));return
        super().hook(u,a,size,data)
    def first(self,expected):
        sp=STACK+0x1fe000;self.w(sp,bytes([0xa5])*0x200);self.u.reg_write(UC_X86_REG_RSP,sp)
        registers=NONVOL+[UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11]
        before={r:0x11110000+i for i,r in enumerate(registers)};before[UC_X86_REG_RCX]=APP
        for r,v in before.items():self.u.reg_write(r,v)
        xmms=[UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3,UC_X86_REG_XMM4,UC_X86_REG_XMM5]
        for i,r in enumerate(xmms):self.u.reg_write(r,0x123456789abcdef123456789abc0000+i)
        self.u.reg_write(UC_X86_REG_EFLAGS,0x246)
        self.u.emu_start(BASE+0x19463,STOP+1,count=5000000)
        assert self.u.reg_read(UC_X86_REG_RSP)==sp and self.r(sp,0x200)==bytes([0xa5])*0x200
        assert [self.u.reg_read(r)for r in xmms]==[0x123456789abcdef123456789abc0000+i for i in range(6)]
        assert self.dword(FB+104)==0 and not self.frees
        if expected=='fault':
            assert self.faulted and not self.first_complete and 0x22818 not in self.native
            for r,v in before.items():assert self.u.reg_read(r)==v
        else:
            assert self.first_complete and not self.faulted
            idx=4 if expected=='allow'else 2
            assert self.dword(APP+0x28)==idx and self.u.reg_read(UC_X86_REG_RDI)==idx
            assert self.u.reg_read(UC_X86_REG_RDX)==0x03050006
            assert self.u.reg_read(UC_X86_REG_EFLAGS)==0x246
            for r,v in before.items():
                if r not in [UC_X86_REG_RDI,UC_X86_REG_RDX]:assert self.u.reg_read(r)==v
            assert (0x22818 in self.native)==(expected=='main')
        # No forced exit, native save, ResetSystem tail, history allocator or
        # renderer is reached by this first-entry component under any outcome.
        for forbidden in [0x19994,0x19a33,0x19a47,0x1fcb4,0x1c958,0x2372c,0x194cf]:assert forbidden not in self.native
        return {'result':expected,'native_instructions':len(self.native),'prompts':len(self.outputs),'hii_attestations':self.hii_calls,'range_model':True,'continued_rva':'0x1946b'if self.first_complete else None,'fault_continuation_modeled':self.faulted}

def main():
    cases=[]
    def check(name,expected,*,mode='deny',record=ns['ENABLED'],mutate=None,**changes):
        v=First(record);assert v.init()==(6 if record is None else 0) and v.begin()==0;v.prompt=mode
        for k,value in changes.items():setattr(v,k,value)
        if mutate:mutate(v)
        detail=v.first(expected);cases.append({'name':name,'status':'PASS',**detail});return v
    check('initial_protected_page_granted_continues_exact_native_window','allow',mode='grant')
    check('initial_protected_page_cancel_selects_main_without_exit','main')
    check('initial_unconfigured_page_selects_main_without_exit','main',record=None)
    check('initial_disabled_policy_continues_without_prompt','allow',record=ns['DISABLED'])
    check('success_without_unlock_returns_to_main','main',mode='success_without_unlock')
    check('wrong_module_binding_does_not_resume_protected_page','fault',ident=False)
    check('unknown_hii_does_not_resume_protected_page','fault',hii_ok=False)
    check('stale_session_does_not_resume_protected_page','fault',session_ok=False)
    check('lost_provider_owner_cannot_fallback','fault',mode='owner_lost')
    check('endboot_during_prompt_cannot_fallback','fault',mode='grant',end_on='prompt')
    check('history_pointer_nonzero_not_freed','fault',mutate=lambda v:v.w(BASE+0xafde8,q(HIST)))
    check('history_used_nonzero_rejected','fault',mutate=lambda v:v.w(BASE+0xafe00,struct.pack('<I',1)))
    check('history_root_nonzero_rejected','fault',mutate=lambda v:v.w(BASE+0xafddc,struct.pack('<I',1)))
    check('missing_main_rejected','fault',mutate=lambda v:v.w(PAGES[2]+0x2a,struct.pack('<H',0x2714)))
    check('duplicate_main_rejected','fault',mutate=lambda v:v.w(PAGES[1]+0x2a,struct.pack('<H',0x2712)))
    check('hidden_main_rejected','fault',mutate=lambda v:v.w(PAGES[2]+0x34,b'\1'))
    check('nonroot_main_rejected','fault',mutate=lambda v:v.w(PAGES[2]+0x32,struct.pack('<H',1)))
    check('mismatched_main_index_rejected','fault',mutate=lambda v:v.w(PAGES[2]+0x30,struct.pack('<H',3)))
    check('foreign_hii_main_rejected','fault',mutate=lambda v:v.w(PAGES[2]+0x20,q(DATA+0xc100)))
    check('unreadable_page_array_rejected','fault',range_deny=ARRAY)
    check('unreadable_main_rejected','fault',range_deny=PAGES[2])
    check('read_only_application_rejected','fault',range_deny=APP+0x28)
    check('huge_page_count_rejected','fault',mutate=lambda v:v.w(APP+0x2c,struct.pack('<I',0x80000000)))
    check('bad_array_pointer_rejected_before_deref','fault',mutate=lambda v:v.w(APP+0x30,q(0xfffffffffffffff8)))
    check('main_changes_after_snapshot_rejected','fault',mutate_hii_call=3,mutator=lambda v:v.w(PAGES[2]+0x34,b'\1'))
    check('HII_epoch_changes_between_snapshots_rejected','fault',mutate_hii_call=3,mutator=lambda v:setattr(v,'epoch',12))
    check('application_changes_in_last_host_callback_rejected','fault',mutate_session_call=3,mutator=lambda v:v.w(APP+0x28,struct.pack('<I',1)))
    check('history_changes_in_last_host_callback_rejected','fault',mutate_session_call=3,mutator=lambda v:v.w(BASE+0xafde8,q(HIST)))
    out={'status':'PASS_FIRST_ENTRY_STUB_GATE_PROVIDER_MAIN_FALLBACK_BYTES','case_count':len(cases),'cases':cases,'source_sha256':sha(__file__),'fallback_sha256':sha(FALLBACK),'gate_sha256':GATE_SHA,'provider_sha256':PROVIDER_SHA,'original_amitse_sha256':ORIGINAL_SHA,'binding_bytes':ctypes.sizeof(Binding),'original_window':{'rva':'0x19463','bytes':'8b7928ba06000503','resume_rva':'0x1946b','phase':'selected first page; before native history and initial navigation'},'scope':__doc__,'unsupported':['Nonempty first-entry history','Unknown/lost native identity, owner or HII','Production error UI / safe failure continuation','Complete browser-loop resume and all alternate input/save hooks','Real hook installation and ASUS hardware acceptance'],'hardware_or_firmware_writes':0}
    (HERE/'first_fallback_tests.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':out['status'],'case_count':len(cases),'fallback_sha256':out['fallback_sha256']}))

if __name__=='__main__':main()
