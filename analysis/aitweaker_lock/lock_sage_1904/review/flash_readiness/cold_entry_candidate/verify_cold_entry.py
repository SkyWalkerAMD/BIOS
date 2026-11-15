"""Bounded execution of original DXE scheduling and unchanged e41 discovery.

Only Unicorn executes PE instructions. Firmware services, image loading,
allocation, TPL and the complete browser body are explicit fixtures. No device,
network, host firmware entry, production mutation, or candidate driver is used.
"""
from pathlib import Path
import hashlib, json, re, struct, sys, uuid
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CASE = HERE.parents[2]
ROOT = HERE.parents[5]
sys.path.insert(0, str(ROOT/'tools/pydeps'))
import pefile, capstone, unicorn as U
from unicorn import x86_const as R

CORE = HERE.parent/'runtime_navigation/OriginalDxeCore.efi'
CANDIDATE = HERE.parent/'late_attach_candidate'
EFI = CANDIDATE/'build/AiTweakerLock1904.efi'
TSE_FILE = CASE/'analysis/modules/AMITSE.efi'
SETUP_FILE = CASE/'analysis/modules/Setup.efi'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
EXPECTED = {
    CORE: 'd8684ae913fe44bfcb950c0635299465d7813b1f60407a733f7cce34e50f584d',
    EFI: 'e41ac0009a5658aff0546e637d0cf89a16edd1d16d726ee97dadf675f46c67d1',
    TSE_FILE: '531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1',
    SETUP_FILE: '719bad779e9ae60340187c7aae6c12ab9dff3ee398c58a9fca2a4e027a33f21d',
}
for p, digest in EXPECTED.items():
    assert sha(p) == digest, p

checks = []
def check(label, condition):
    assert condition, label
    checks.append(label)

Q = lambda x: struct.pack('<Q', x)
D = lambda x: struct.pack('<I', x)
ERR = lambda x: (1 << 63) | x
CB, CH, CS, CE = 0x30000000, 0x61000000, 0x71000000, 0x51000000
TSE_GUID = uuid.UUID('b1da0adf-4f77-4070-a88e-bffe1c60529a').bytes_le
LOCK_GUID = uuid.UUID('8b4e0d52-28b5-4d1f-b4bc-750e9d9d1904').bytes_le

class CoreVM:
    def __init__(self):
        self.u = U.Uc(U.UC_ARCH_X86, U.UC_MODE_64)
        pe = pefile.PE(str(CORE)); pe.relocate_image(CB)
        blob = pe.get_memory_mapped_image()
        self.u.mem_map(CB, (len(blob)+4095)&~4095); self.u.mem_write(CB, blob)
        for a, n in [(CH, 0x10000), (CS, 0x10000), (CE, 0x1000)]: self.u.mem_map(a, n)
        self.u.reg_write(R.UC_X86_REG_CR4, 0x600)
        self.events = []; self.load_status = {}; self.start_status = {}
        self.nodes = {'lock': CH+0x1000, 'AMITSE': CH+0x2000}
        self.handles = {0x1111: 'lock', 0x2222: 'AMITSE'}
        self.paths = {CH+0x5000: 'lock', CH+0x5100: 'AMITSE'}
        self.dep = b'\x00' + TSE_GUID + b'\x08'
        self.u.mem_write(CH+0x6000, self.dep)
        self.u.mem_write(CH+0x7000+0x18, Q(CE+0x100))
        self.init_list(CB+0x16b78, [])
        self.init_list(CB+0x16b98, [x+8 for x in self.nodes.values()])
        for i, (name, node) in enumerate(self.nodes.items()):
            self.u.mem_write(node+0x30, LOCK_GUID if name == 'lock' else TSE_GUID)
            self.u.mem_write(node+0x40, Q(CH+0x5000+i*0x100))
            self.u.mem_write(node+0x48, Q(CH+0x7000))
            self.u.mem_write(node+0x74, b'\x01')
        addresses = [CE, CE+0x100] + [CB+x for x in [0xe6ec, 0xcc98, 0x9354, 0x9560, 0x9760, 0x8620, 0x8720, 0x11258]]
        for address in addresses: self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)
    def getq(self, a): return int.from_bytes(self.u.mem_read(a, 8), 'little')
    def arg(self, i):
        if i < 4: return self.u.reg_read([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i])
        return self.getq(self.u.reg_read(R.UC_X86_REG_RSP)+40+(i-4)*8)
    def ret(self, x):
        sp = self.u.reg_read(R.UC_X86_REG_RSP)
        self.u.reg_write(R.UC_X86_REG_RAX, x)
        self.u.reg_write(R.UC_X86_REG_RIP, self.getq(sp)); self.u.reg_write(R.UC_X86_REG_RSP, sp+8)
    def hook(self, u, a, n, data):
        if a == CE: u.emu_stop(); return
        if a == CE+0x100:
            self.events.append('ReadSection(BEFORE AMITSE)')
            u.mem_write(self.arg(4), Q(CH+0x6000)); u.mem_write(self.arg(5), Q(len(self.dep))); u.mem_write(self.arg(6), D(0)); self.ret(0); return
        if a == CB+0x9354:
            u.mem_write(self.arg(5), Q(CH+0x8000)); self.ret(0); return
        if a == CB+0x8620:
            name = self.paths[self.arg(2)]; status = self.load_status.get(name, 0)
            self.events.append({'LoadImage':name,'status':hex(status)})
            if not status: u.mem_write(self.arg(5), Q(next(h for h, v in self.handles.items() if v == name)))
            self.ret(status); return
        if a == CB+0x8720:
            name = self.handles[self.arg(0)]; status = self.start_status.get(name, 0)
            self.events.append({'StartImage':name,'status':hex(status)}); self.ret(status); return
        self.ret(0)  # TPL lock/restore, event close/signal, and status reporting fixtures.
    def init_list(self, head, entries):
        for i, a in enumerate([head]+entries):
            chain = [head]+entries
            self.u.mem_write(a, Q(chain[(i+1)%len(chain)])+Q(chain[(i-1)%len(chain)]))
    def call(self, rva, *args):
        sp = CS+0xfe08; self.u.mem_write(sp, Q(CE)+bytes(0x100)); self.u.reg_write(R.UC_X86_REG_RSP, sp)
        for i, a in enumerate(args):
            if i < 4: self.u.reg_write([R.UC_X86_REG_RCX,R.UC_X86_REG_RDX,R.UC_X86_REG_R8,R.UC_X86_REG_R9][i], a)
            else: self.u.mem_write(sp+40+(i-4)*8, Q(a))
        self.u.emu_start(CB+rva, 0, count=1000000)
        assert self.u.reg_read(R.UC_X86_REG_RIP) == CE, hex(self.u.reg_read(R.UC_X86_REG_RIP))
        return self.u.reg_read(R.UC_X86_REG_RAX)
    def queue(self):
        head = CB+0x16b78; p = self.getq(head); names=[]
        while p != head:
            assert len(names) < 4
            names.append(next(name for name, node in self.nodes.items() if node+0x18 == p)); p=self.getq(p)
        return names
    def before(self):
        self.call(0x988c, self.nodes['lock'])
        assert self.u.mem_read(self.nodes['lock']+0x60, 1) == b'\x01'
        self.call(0x9ccc, self.nodes['AMITSE'])
        return self.queue()

v=CoreVM(); order=v.before()
check('Original Core parses BEFORE and schedules lock before AMITSE', order == ['lock','AMITSE'])
dispatch_results=[]
for label, load_error, entry_error in [('both success',0,0), ('lock LoadImage security violation',ERR(26),0), ('lock LoadImage out of resources',ERR(9),0), ('lock entry failure',0,ERR(7))]:
    v=CoreVM(); assert v.before() == ['lock','AMITSE']; v.events=[]
    v.load_status['lock']=load_error; v.start_status['lock']=entry_error
    returned=v.call(0x9a74)
    loaded=[x['LoadImage'] for x in v.events if isinstance(x,dict) and 'LoadImage' in x]
    started=[x['StartImage'] for x in v.events if isinstance(x,dict) and 'StartImage' in x]
    check(label+': AMITSE loading continues',loaded==['lock','AMITSE'])
    check(label+': AMITSE start continues',started==(['AMITSE'] if load_error else ['lock','AMITSE']))
    check(label+': native dispatcher consumes both queue nodes',v.queue()==[])
    dispatch_results.append({'case':label,'actual_native_dispatcher_return':hex(returned),'events':v.events,'AMITSE_still_started':True})

# No DEPEX is a dependency on all architectural protocols, not unconditional TRUE.
v=CoreVM(); table=CB+0x162e0; arch=[]
while v.getq(table+len(arch)*0x28):
    assert len(arch)<64
    arch.append(table+len(arch)*0x28)
for p in arch: v.u.mem_write(p+0x20,b'\x01')
check('Original Core empty-DEPEX eligible after all arch flags ready',v.call(0xf004,v.nodes['AMITSE'])&0xff==1)
for i in range(len(arch)):
    v.u.mem_write(arch[i]+0x20,b'\x00')
    check('Original Core empty-DEPEX waits for architectural flag '+str(i),v.call(0xf004,v.nodes['AMITSE'])&0xff==0)
    v.u.mem_write(arch[i]+0x20,b'\x01')

# Reuse only the fixture class definitions. Redirect both EFI and map to the exact
# e41 candidate; do not run or write the older runtime suite's report.
runtime=HERE.parent/'runtime_navigation/verify_runtime_paths.py'
source=runtime.read_text(encoding='utf8').split('\nv=RuntimeVM();v.guard()',1)[0]
marker="ns={'__file__':str(DRIVER/'verify_adapter.py')};"
replacement="prefix=prefix.replace(\"HERE/'build/driver.map'\",\"CANDIDATE/'build/driver.map'\").replace(\"HERE/'build/AiTweakerLock1904.efi'\",\"CANDIDATE/'build/AiTweakerLock1904.efi'\")\nns={'__file__':str(DRIVER/'verify_adapter.py'),'CANDIDATE':CANDIDATE};"
assert source.count(marker)==1; source=source.replace(marker,replacement)
ns={'__file__':str(runtime),'CANDIDATE':CANDIDATE};exec(compile(source,str(runtime),'exec'),ns)
RuntimeVM=ns['RuntimeVM']; TSE=ns['TSE']; symbols=ns['symbols']; d=ns['d']; q=ns['q']

class DiscoveryVM(RuntimeVM):
    def __init__(self): self.allocation_fail=False; super().__init__()
    def hook(self,u,a,n,data):
        if a==ns['STOP']+0x100 and self.allocation_fail: self.ret(ERR(9)); return
        super().hook(u,a,n,data)

v=DiscoveryVM(); original_slots={hex(x):bytes(v.u.mem_read(TSE+x,n)).hex() for x,n in [(0xe1b8,18),(0x15320,15),(0x6b928,8),(0x6b930,8),(0x6b840,8),(0x7d4f8,8),(0x837d8,8)]}
native_stage=bytes(v.u.mem_read(TSE+0xe655,11))
check('Native browser stage5 instruction is exact',native_stage==bytes.fromhex('48c705084e070005000000'))
v.u.emu_start(TSE+0xe655,TSE+0xe660,count=1)
check('Execute native stage5 store before discover',v.getd(TSE+0x83468)==5)
v.discover(); stage5=v.observation()
check('e41 first stage5 leaves attempted and platform_ready clear',stage5['attempted']==0 and stage5['platform_ready']==0)
check('e41 first stage5 installs no SetVariable guard',not stage5['runtime_guard_installed'])
check('e41 first stage5 leaves all target hook bytes unchanged',all(bytes(v.u.mem_read(TSE+int(x,16),len(bytes.fromhex(b)))).hex()==b for x,b in original_slots.items()))
v.current(1);v.call(v.getq(TSE+0x6b928),v.pages[1])
check('Unhooked stage5 protected-page dispatch reaches original renderer entry',v.calls['render']==1 and v.calls['ui']==0)
v.u.mem_write(TSE+0x83468,d(7));v.discover()
check('A later post-browser discovery can attach but not retroactively cover first call',v.observation()['platform_ready']==1)

waiting=[]
for missing in ['browser','loaded_images','SMBIOS']:
    v=DiscoveryVM()
    if missing=='browser':v.browser_ready=False
    elif missing=='loaded_images':v.images_ready=False
    else:v.u.mem_write(v.st+0x68,q(0))
    v.discover(); first=v.observation()
    check(missing+' absent before entry does not attach',first['attempted']==0 and first['platform_ready']==0)
    if missing=='browser':v.browser_ready=True
    elif missing=='loaded_images':v.images_ready=True
    else:v.u.mem_write(v.st+0x68,q(1))
    v.u.emu_start(TSE+0xe655,TSE+0xe660,count=1);v.discover()
    check(missing+' becomes ready only after native stage5 remains uncovered',v.observation()['platform_ready']==0)
    waiting.append({'missing':missing,'before':first,'after_prerequisite_arrives_at_stage5':v.observation()})

failures=[]
for failure in ['allocate_pages','first_UI_slot_patch']:
    v=DiscoveryVM()
    if failure=='allocate_pages':v.allocation_fail=True
    else:v.patch_fail_target=TSE+0x6b928
    v.discover(); first=v.observation(); count=len(v.patches)
    check(failure+': first failure latches attempted',first['attempted']==1 and first['platform_ready']==0)
    v.allocation_fail=False;v.patch_fail_target=None;v.discover()
    check(failure+': resolved transient condition is not retried',len(v.patches)==count and v.observation()['platform_ready']==0)
    if failure=='allocate_pages':check('Pre-mutation allocation failure still disables all later attempts',not first['runtime_guard_installed'] and count==0)
    else:check('Post-guard UI attach failure leaves variable guard but no complete UI protection',first['runtime_guard_installed'] and first['platform_ready']==0)
    failures.append({'fault':failure,'first':first,'after_resolved':v.observation(),'patch_calls':count,'retry':False})

preserve=[CASE/'driver/build/AiTweakerLock1904.efi',CASE/'lab/asus_review_exp02/W790E-SAGE-SE-1904-lock-EXP02.review.bin',CASE/'lab/asus_review_exp03_ebs/W790E-SAGE-SE-1904-lock-EXP03-EBS-SESSION-UNSIGNED.review.bin']
preserved={str(p.relative_to(CASE)):sha(p) for p in preserve}
assert preserved[str(preserve[0].relative_to(CASE))]=='da52a08f0e477867f4f08e3d1514b156be1ac67fa3bc9c47d09272a869aaf2e2'
assert preserved[str(preserve[1].relative_to(CASE))]=='95a95856ae9ed393c8ab313ae7763edf9d30534f423f77c894d11d7be6a46a0e'
assert preserved[str(preserve[2].relative_to(CASE))]=='1ddac5400265f4c0bd928cc2cc3b2a8b802d22ae20d134f11aa01352385def2c'

report={'status':'CONFIRMED_LOCAL_COUNTEREXAMPLES_NOT_COLD_ENTRY_ACCEPTANCE','checks':len(checks),'check_names':checks,
 'input_sha256':{str(p.relative_to(CASE)):d for p,d in EXPECTED.items()},
 'fixture_sources_sha256':{str(p.relative_to(CASE)):sha(p) for p in [runtime,CASE/'driver/verify_adapter.py',CANDIDATE/'build/driver.map',CANDIDATE/'build/build.json',Path(__file__)]},
 'original_core_rvas':{'parse_depex':'0x988c','schedule_before_after':'0x9ccc','dispatcher':'0x9a74','empty_depex_evaluator':'0xf004','LoadImage_call':'0x9b31','StartImage_call':'0x9ca8','StartImage_return_discarded':'0x9cad..0x9cc7'},
 'before_queue':order,'before_dependency_is_not_failure_dependency':dispatch_results,'empty_depex_architectural_entries':len(arch),
 'first_stage5':{'native_store_bytes':native_stage.hex(),'observation':stage5,'original_hook_bytes':original_slots,'original_renderer_entry_reached':True,'post_exit_attachment_succeeded':True},
 'late_prerequisites':waiting,'first_attach_failures':failures,'preserved_files':preserved,
 'limits':['This is not a complete ASUS cold boot or an observation of physical failure frequency.',
 'Core scheduler and dispatcher instructions execute unchanged; services, image loading and status returns are deliberate fixtures.',
 'The ORIGINAL renderer is stopped at entry. Reaching it proves absence of the added gate, not full pixel rendering or NVRAM commit.',
 'Native stage5 store is executed in a constructed browser state; the prior entire native browser initialization is not replayed.',
 'Memory permissions, allocator, HII and other firmware services are fixtures. A passing fixture does not validate real memory attributes or error recovery.',
 'No production/candidate source or firmware modified; no new driver, ISO, CAP, BMC activity or flash write.']}
(HERE/'native_counterexamples.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'checks':len(checks),'report_sha256':sha(HERE/'native_counterexamples.json')}))
