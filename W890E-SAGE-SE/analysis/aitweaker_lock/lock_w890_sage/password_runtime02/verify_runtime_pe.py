"""Actual runtime PE control flow under explicitly modeled UEFI failure cases.

No native ASUS owner or physical input is inferred. Page tables and RDSEED are
modeled; password KDF calls use the independent Python oracle. The matching
linked objects execute actual KDF/UI/page-walk/UEFI services in separate OVMF
tests. Model callbacks cannot be linked into the component EFI.
"""
from pathlib import Path
import hashlib, json, re, struct, sys, uuid
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
P = HERE.parent/'password'
sys.path[:0] = [str(ROOT/'tools/pydeps'), str(P/'core')]
import pefile
import verify_core as core
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_CR3, UC_X86_REG_CR4

BUILD = json.loads((HERE/'build/build.json').read_text())
EFI = HERE/'build'/BUILD['component_file']
assert hashlib.sha256(EFI.read_bytes()).hexdigest() == BUILD['component']['sha256']
PE = pefile.PE(str(EFI)); BASE = PE.OPTIONAL_HEADER.ImageBase
SYMBOLS = {name: int(address, 16) for name, address in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9A-Fa-f]{16})\s', EFI.with_suffix('.map').read_text(), re.M)}
STACK, HEAP, HOOK = 0x40000000, 0x50000000, 0x60000000
STOP, TAIL = HOOK+0xf000, HOOK+0xe000
REGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
ERR = lambda n: (1 << 63) | n
Q = lambda n: struct.pack('<Q', n)
I = lambda n: struct.pack('<I', n)
GUID = uuid.UUID('7aa1505b-ef11-4c41-9002-427f826903e6').bytes_le
NAME = 'AiTweakerPasswordW890V1'
PROFILE = json.loads((P/'profile_0603.json').read_text())
ENABLED, NEXT, DISABLED = core.signed_record(), core.signed_record(generation=2), core.signed_record(disabled=True)
CASES = []

class VM:
    def __init__(self, record=ENABLED):
        self.u = Uc(UC_ARCH_X86, UC_MODE_64)
        self.u.mem_map(BASE, (PE.OPTIONAL_HEADER.SizeOfImage+4095)&~4095)
        self.u.mem_write(BASE, PE.get_memory_mapped_image())
        self.u.mem_map(STACK, 0x200000); self.u.mem_map(HEAP, 0x40000); self.u.mem_map(HOOK, 0x10000)
        # Execute the actual page walker against an explicit synthetic four-
        # level identity map. Only RDSEED/KDF are replaced as named below.
        self.u.mem_map(0x70000000, 0x10000)
        self.w(0x70000000, Q(0x70001003))
        self.u.reg_write(UC_X86_REG_CR3, 0x70000000)
        self.u.reg_write(UC_X86_REG_CR4, (self.u.reg_read(UC_X86_REG_CR4)&~(1<<12))|0x600)
        self.record, self.attributes = record, 3
        self.calls = []; self.pending = None; self.event_callbacks = {}; self.event_serial = 0
        self.end_on = None; self.get_count = 0; self.set_count = 0; self.uefi_calls = []
        self.profile = self.active = self.tpl = True
        self.get_status = None; self.set_status = 0; self.write_mode = 'normal'; self.read_change = None
        self.create_status = self.close_status = self.locate_status = self.rng_status = 0
        self.rng_present = self.memory = self.rdseed_ok = True
        self.timer_ticks, self.timer_period, self.timer_status = 1000000000, 1000000, 0
        self.timer_step = 1000
        self.keys=[];self.transcript='';self.frame=bytes([0x35])*(96*64*4)
        self.ui_error={};self.cursor_unsupported=False
        self.mutate_on=None;self.mutated_at=None;self.hook_counts={}
        names = ['get', 'set', 'create', 'close', 'allocate', 'free', 'locate', 'stall', 'rng', 'timer',
                 'profile', 'tpl', 'caller', 'active', 'writable', 'prompt', 'authorized',
                 'text','attribute','clear','cursor','enable','key','blt']
        self.hooks = {name: HOOK+index*0x100 for index,name in enumerate(names)}
        self.hooks.update({'rdseed': SYMBOLS['cpu_entropy'], 'kdf': SYMBOLS['ap_pbkdf2_sha256']})
        for address in self.hooks.values():
            if HOOK <= address < HOOK+0x10000:
                self.w(address, b'\xc3')
        self.w(STOP, b'\xf4'); self.w(TAIL, b'\xc3')
        self.u.hook_add(UC_HOOK_CODE, self.hook)
        self.st, self.rt, self.bs, self.host = HEAP, HEAP+0x100, HEAP+0x200, HEAP+0x400
        self.out, self.sd, self.td, self.buf, self.length, self.pw = [HEAP+n for n in [0x500,0x600,0x640,0x700,0x800,0x900]]
        self.rng, self.cpu = HEAP+0xa00, HEAP+0xb00
        self.console,self.input,self.gop,self.outmode,self.gopmode,self.gopinfo=[HEAP+n for n in [0xc00,0xd00,0xe00,0xf00,0x1000,0x1100]]
        self.p, self.cp = SYMBOLS['w890_provider'], SYMBOLS['w890_password_core']
        self.w(self.st+0x58, Q(self.rt)+Q(self.bs))
        self.w(self.rt+0x48, Q(self.hooks['get'])); self.w(self.rt+0x58, Q(self.hooks['set']))
        for offset, name in [(0x40,'allocate'),(0x48,'free'),(0x50,'create'),(0x70,'close'),(0xf8,'stall'),(0x140,'locate')]:
            self.w(self.bs+offset,Q(self.hooks[name]))
        self.w(self.host,struct.pack('<II',1,64)+b''.join(Q(self.hooks[x])for x in ['profile','tpl','caller','active','writable','prompt','authorized']))
        self.w(self.sd,bytes.fromhex(PROFILE['sources']['Setup']['sha256']));self.w(self.td,bytes.fromhex(PROFILE['sources']['AMITSE']['sha256']))
        self.w(self.rng+8,Q(self.hooks['rng']));self.w(self.cpu+0x30,Q(self.hooks['timer']));self.w(self.cpu+0x40,I(1))
        self.w(self.st+0x30,Q(self.input));self.w(self.st+0x40,Q(self.console))
        self.w(self.input+8,Q(self.hooks['key']))
        for offset,name in [(8,'text'),(40,'attribute'),(48,'clear'),(56,'cursor'),(64,'enable')]:self.w(self.console+offset,Q(self.hooks[name]))
        self.w(self.console+72,Q(self.outmode));self.w(self.outmode,struct.pack('<iiiiiBxxx',1,0,7,0,0,0))
        self.w(self.gop+16,Q(self.hooks['blt'])+Q(self.gopmode))
        self.w(self.gopmode,struct.pack('<IIQQQQ',1,0,self.gopinfo,36,0,len(self.frame)))
        self.w(self.gopinfo,struct.pack('<IIIIIIIIII',0,96,64,0,0,0,0,0,96,0))
        self.w(self.pw,core.PW)
    def w(self,a,b):self.u.mem_write(a,bytes(b))
    def r(self,a,n):return bytes(self.u.mem_read(a,n))
    def q(self,a):return struct.unpack('<Q',self.r(a,8))[0]
    def arg(self,i):return self.u.reg_read(REGS[i])if i<4 else self.q(self.u.reg_read(UC_X86_REG_RSP)+40+8*(i-4))
    def ret(self,value):
        sp=self.u.reg_read(UC_X86_REG_RSP);self.u.reg_write(UC_X86_REG_RAX,value&((1<<64)-1));self.u.reg_write(UC_X86_REG_RIP,self.q(sp));self.u.reg_write(UC_X86_REG_RSP,sp+8)
    def namespace(self):
        name=self.r(self.arg(0),(len(NAME)+1)*2).decode('utf-16-le')
        assert name==NAME+'\0' and self.r(self.arg(1),16)==GUID,'must only access exact W890 credential namespace'
    def nested(self,address,args,value):
        sp=self.u.reg_read(UC_X86_REG_RSP);self.pending=(sp,value);self.w(sp-40,Q(TAIL));self.u.reg_write(UC_X86_REG_RSP,sp-40)
        for i in range(4):self.u.reg_write(REGS[i],args[i]if i<len(args)else 0)
        self.u.reg_write(UC_X86_REG_RIP,address)
    def hook(self,u,address,size,opaque):
        if address==STOP:u.emu_stop();return
        if address==TAIL:
            sp,value=self.pending;self.pending=None;self.u.reg_write(UC_X86_REG_RSP,sp);self.ret(value);return
        name=next((n for n,a in self.hooks.items()if a==address),None)
        if name is None:return
        self.calls.append(name)
        self.hook_counts[name]=self.hook_counts.get(name,0)+1
        if name in ['get','set','create','close','allocate','free','locate','stall','rng','timer']:
            self.uefi_calls.append(name)
        if name=='get':
            self.namespace();self.get_count+=1
            if self.read_change and self.get_count==self.read_change[0]:self.record=self.read_change[1]
            cap=self.q(self.arg(3))
            if self.record is None:value=ERR(14)
            else:
                self.w(self.arg(2),I(self.attributes));self.w(self.arg(3),Q(len(self.record)))
                value=ERR(5)if cap<len(self.record)else 0
                if not value:self.w(self.arg(4),self.record)
            if self.get_status is not None:value=self.get_status
        elif name=='set':
            self.namespace();self.set_count+=1
            attrs,n,data=self.arg(2),self.arg(3),self.arg(4)
            assert (attrs==3 and n==128 and data)or(attrs==0 and n==0 and data==0)
            if self.write_mode=='normal':self.record=self.r(data,n)if n else None;self.attributes=attrs
            elif self.write_mode=='other':self.record=NEXT if not n else ENABLED
            elif self.write_mode=='unchanged':pass
            else:raise AssertionError(self.write_mode)
            value=self.set_status
        elif name=='create':
            assert self.arg(0)==0x201 and self.arg(1)==8
            self.event_serial+=1;handle=0x70000000+16*self.event_serial
            if not self.create_status:self.w(self.arg(4),Q(handle));self.event_callbacks[handle]=(self.arg(2),self.arg(3))
            value=self.create_status
        elif name=='close':value=self.close_status
        elif name=='allocate':self.w(self.arg(2),Q(HEAP+0x10000));value=0
        elif name=='free':value=0
        elif name=='locate':
            guid=self.r(self.arg(0),16)
            if guid==uuid.UUID('3152bca5-eade-433d-862e-c01cdc291f44').bytes_le:
                self.w(self.arg(2),Q(self.rng if self.rng_present else 0));value=0 if self.rng_present else ERR(14)
            elif guid==uuid.UUID('26baccb1-6f42-11d4-bce7-0080c73c8881').bytes_le:self.w(self.arg(2),Q(self.cpu));value=0
            elif guid==uuid.UUID('9042a9de-23dc-4a38-96fb-7aded080516a').bytes_le:self.w(self.arg(2),Q(self.gop));value=0
            else:raise AssertionError('unexpected protocol '+guid.hex())
            if self.locate_status:value=self.locate_status
        elif name=='rng':self.w(self.arg(3),bytes((0x7b+i)%256 for i in range(self.arg(2))));value=self.rng_status
        elif name=='rdseed':self.w(self.arg(0),bytes([0xb7])*self.arg(1));value=0 if self.rdseed_ok else 1
        elif name=='memory':value=int(self.memory)
        elif name=='stall':self.timer_ticks+=self.arg(0)*1000;value=0
        elif name=='timer':
            self.timer_ticks+=self.timer_step;self.w(self.arg(2),Q(self.timer_ticks))
            if self.arg(3):self.w(self.arg(3),Q(self.timer_period))
            value=self.timer_status
        elif name=='kdf':
            password=self.r(self.arg(0),self.arg(1));salt=self.r(self.arg(2),self.arg(3));rounds=self.arg(4)&0xffffffff
            assert rounds==600000
            self.w(self.arg(5),hashlib.pbkdf2_hmac('sha256',password,salt,rounds,32));value=0
        elif name=='profile':value=int(self.profile)
        elif name=='tpl':value=int(self.tpl)
        elif name=='caller':value=1
        elif name=='active':value=int(self.active)
        elif name=='writable':value=int(HEAP<=self.arg(0)<HEAP+0x40000 and self.arg(1)<=HEAP+0x40000-self.arg(0))
        elif name=='authorized':value=1
        elif name=='prompt':raise AssertionError('runtime must replace modeled prompt with real UI')
        elif name=='text':
            chars=[];p=self.arg(1)
            for i in range(1024):
                ch=struct.unpack('<H',self.r(p+2*i,2))[0]
                if not ch:break
                chars.append(chr(ch))
            else:raise AssertionError('unterminated console string')
            self.transcript+=''.join(chars);self.frame=bytes([0x57])*len(self.frame);value=self.ui_error.get(name,0)
        elif name=='attribute':self.w(self.outmode+8,I(self.arg(1)&0xffffffff));value=self.ui_error.get(name,0)
        elif name=='clear':self.frame=bytes(len(self.frame));self.w(self.outmode+20,b'\1');value=self.ui_error.get(name,0)
        elif name=='cursor':self.w(self.outmode+12,I(self.arg(1)&0xffffffff)+I(self.arg(2)&0xffffffff));value=self.ui_error.get(name,0)
        elif name=='enable':self.w(self.outmode+20,bytes([self.arg(1)&255]));value=ERR(3)if self.cursor_unsupported else self.ui_error.get(name,0)
        elif name=='key':
            assert self.keys,'synthetic input exhausted: real UI waited for input'
            ch=self.keys.pop(0);self.w(self.arg(1),struct.pack('<HH',0x17 if ch==27 else 0,ch));value=self.ui_error.get(name,0)
        elif name=='blt':
            assert self.arg(7)==96 and self.arg(8)==64
            if self.arg(2)==1:self.w(self.arg(1),self.frame)
            elif self.arg(2)==2:self.frame=self.r(self.arg(1),len(self.frame))
            else:raise AssertionError('unexpected GOP operation')
            value=self.ui_error.get('blt'+str(self.arg(2)),0)
        else:raise AssertionError(name)
        if self.mutate_on and self.mutate_on[:2]==(name,self.hook_counts[name]):
            _,_,target,replacement=self.mutate_on;self.mutate_on=None
            self.w(target,replacement);self.mutated_at=len(self.calls)
        trigger=(name,self.get_count if name=='get'else self.set_count if name=='set'else 1)
        if self.end_on==name or self.end_on==trigger:
            self.end_on=None
            handle=next(reversed(self.event_callbacks));callback,context=self.event_callbacks[handle]
            self.nested(callback,[handle,context],value)
        else:self.ret(value)
    def call(self,name,*args):
        self.w(0x70001000,b''.join(Q((i<<30)|0x83 if self.memory else 0)for i in range(8)))
        address=BASE+PE.OPTIONAL_HEADER.AddressOfEntryPoint if name=='entry'else SYMBOLS[name]
        sp=STACK+0x1ff008;self.w(sp,bytes(0x200));self.w(sp,Q(STOP));self.u.reg_write(UC_X86_REG_RSP,sp)
        for i in range(4):self.u.reg_write(REGS[i],args[i]if i<len(args)else 0)
        for i in range(4,len(args)):self.w(sp+40+8*(i-4),Q(args[i]))
        self.u.emu_start(address,STOP+1,count=6000000)
        assert self.u.reg_read(UC_X86_REG_RIP)==STOP,'execution did not return'
        return self.u.reg_read(UC_X86_REG_RAX)
    def bind(self):return self.call('w890_runtime_bind',self.st,self.host,self.sd,self.td)
    def begin(self):return self.call('w890_provider_begin',self.p,self.out)
    def query(self):return self.call('w890_provider_query',self.p)
    def read(self):self.w(self.buf,bytes([0xaa])*128);return self.call('w890_read_record',0,self.buf,128,self.length)
    def persist(self,record=NEXT):self.w(self.buf,record);return self.call('w890_persist_record',0,self.buf,len(record))
    def entropy(self):self.w(self.buf,bytes([0xaa])*32);return self.call('w890_entropy',0,self.buf,32)
    def clock(self):return self.call('w890_now_ms',0,self.out)
    def recover(self,password=core.PW):self.w(self.pw,password);return self.call('w890_recover_known_record',self.st,self.pw,len(password))
    def queue(self,text):self.keys=[ord(x)for x in text]
    def request(self):return self.call('w890_provider_request',self.p)
    def manage(self,operation=0):return self.call('w890_provider_manage',self.p,operation)

def check(name, fn, record=ENABLED):
    vm=VM(record);assert fn(vm),name;CASES.append({'name':name,'status':'PASS'})

check('unbound entry refuses before UEFI services',lambda v:v.call('entry',0,v.st)==ERR(3)and not v.uefi_calls)
check('unbound read and persist perform no variable IO',lambda v:v.read()==2 and v.persist()==1 and not v.uefi_calls)
check('bind reads exact namespace and registers actual end event',lambda v:v.bind()==0 and v.query()==1 and v.get_count==1 and len(v.event_callbacks)==1)
check('repeat bind cannot replace service owner',lambda v:v.bind()==0 and v.bind()==11 and v.get_count==1)
check('unknown owner refuses before credential read',lambda v:(setattr(v,'profile',False),v.bind()==5 and v.get_count==0)[1])
check('missing create event service refuses before credential read',lambda v:(v.w(v.bs+0x50,Q(0)),v.bind()==2 and not v.uefi_calls)[1])
check('create event failure prevents initialization',lambda v:(setattr(v,'create_status',ERR(9)),v.bind()==2 and v.get_count==0)[1])
check('absent credential explicitly unconfigured',lambda v:v.bind()==6 and v.query()==1,None)
check('disabled credential distinct mode',lambda v:v.bind()==0 and v.query()==9,DISABLED)
for record in [b'bad',ENABLED+bytes(1)]:
    check('malformed size '+str(len(record))+' faults',lambda v:v.bind()==5 and v.query()&32,record)
for attributes in [0,1,2,7,0x23]:
    check('wrong attributes '+str(attributes)+' reject and wipe',lambda v,a=attributes:v.bind()==0 and (setattr(v,'attributes',a),v.read()==2 and v.r(v.buf,128)==bytes(128))[1])
for status in [ERR(5),ERR(7),ERR(26)]:
    check('read error '+str(status)+' wipes output',lambda v,s=status:v.bind()==0 and (setattr(v,'get_status',s),v.read()==2 and v.r(v.buf,128)==bytes(128))[1])
check('NOT_FOUND read wipes output and returns absence',lambda v:v.bind()==0 and (setattr(v,'record',None),v.read()==1 and v.r(v.buf,128)==bytes(128)and v.q(v.length)==0)[1])
check('before session persist refuses without SetVariable',lambda v:v.bind()==0 and v.persist()==1 and v.set_count==0)
check('valid enabled transition writes exact attr3 and reads back',lambda v:v.bind()==0 and v.begin()==0 and v.persist()==0 and v.record==NEXT and v.set_count==1 and v.get_count==3)
check('valid first enrollment persists after explicit absence',lambda v:v.bind()==6 and v.begin()==0 and v.persist(ENABLED)==0 and v.record==ENABLED,None)
check('prewrite record change faults before write',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'record',NEXT),v.persist()==1 and v.set_count==0 and v.query()&32)[1])
check('lost owner before commit performs no write',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'active',False),v.persist()==1 and v.set_count==0)[1])
check('invalid candidate rejected before persistence',lambda v:v.bind()==0 and v.begin()==0 and v.persist(b'x'*128)==1 and v.set_count==0)
def write_case(v,status,mode,want_fault):
    assert v.bind()==0 and v.begin()==0
    v.set_status=status;v.write_mode=mode
    return v.persist()==1 and v.set_count==1 and bool(v.query()&32)==want_fault
check('SetVariable error with unchanged bytes remains retryable',lambda v:write_case(v,ERR(9),'unchanged',False))
check('SetVariable error with changed bytes faults',lambda v:write_case(v,ERR(9),'normal',True))
check('SetVariable success without committed bytes faults',lambda v:write_case(v,0,'unchanged',True))
check('SetVariable success with different readback faults',lambda v:write_case(v,0,'other',True))
check('RNG success fills requested bytes',lambda v:v.bind()==0 and v.begin()==0 and v.entropy()==0 and v.r(v.buf,32)==bytes((0x7b+i)%256 for i in range(32)))
check('RNG missing uses explicit RDSEED fallback',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'rng_present',False),v.entropy()==0 and 'rdseed'in v.calls)[1])
check('RNG lookup failure never falls back',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'locate_status',ERR(7)),v.entropy()==1 and v.r(v.buf,32)==bytes(32)and'rdseed'not in v.calls)[1])
check('RNG present failure wipes partial output',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'rng_status',ERR(7)),v.entropy()==1 and v.r(v.buf,32)==bytes(32)and'rdseed'not in v.calls)[1])
check('RDSEED failure wipes partial output',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'rng_present',False),setattr(v,'rdseed_ok',False),v.entropy()==1 and v.r(v.buf,32)==bytes(32))[2])
check('RNG unreadable protocol refused',lambda v:v.bind()==0 and v.begin()==0 and (setattr(v,'memory',False),v.entropy()==1 and'rng'not in v.calls)[1])
check('timer calibrates three stalls and returns monotonic milliseconds',lambda v:v.bind()==0 and v.begin()==0 and v.clock()==0 and v.calls.count('stall')==3 and v.clock()==0)
for period in [0,1000000000001]:
    check('invalid timer period '+str(period)+' refused',lambda v,p=period:v.bind()==0 and v.begin()==0 and (setattr(v,'timer_period',p),v.clock()==1)[1])
check('timer period change refused',lambda v:v.bind()==0 and v.begin()==0 and v.clock()==0 and (setattr(v,'timer_period',1000001),v.clock()==1)[1])
check('timer regression refused',lambda v:v.bind()==0 and v.begin()==0 and v.clock()==0 and (setattr(v,'timer_ticks',1),v.clock()==1)[1])
for service,operation in [('get','read'),('set','persist'),('locate','entropy'),('rng','entropy'),('timer','clock'),('stall','clock')]:
    def ended(v,service=service,operation=operation):
        assert v.bind()==0 and v.begin()==0;v.end_on=service;getattr(v,operation)()
        count=len(v.uefi_calls)
        return v.query()==64 and v.read()==2 and v.persist()==1 and v.entropy()==1 and v.clock()==1 and len(v.uefi_calls)==count and v.r(v.cp+core.Core.record.offset,128)==bytes(128)
    check('ExitBootServices during '+service+' terminates future services',ended)

check('recovery absent does not delete',lambda v:v.recover()==1 and v.set_count==0,None)
check('recovery wrong password preserves exact enabled record',lambda v:v.recover(core.WRONG_PW)==2 and v.record==ENABLED and v.set_count==0)
check('recovery disabled record cannot be claimed by old password',lambda v:v.recover()==2 and v.record==DISABLED and v.set_count==0,DISABLED)
check('recovery exact enabled record authenticated and absence readback',lambda v:v.recover()==0 and v.record is None and v.set_count==1 and v.get_count==3)
check('recovery wrong attributes preserved',lambda v:(setattr(v,'attributes',7),v.recover()==3 and v.record==ENABLED and v.set_count==0)[1])
check('recovery oversized record preserved',lambda v:v.recover()==3 and v.set_count==0,ENABLED+bytes(1))
check('recovery changed after authentication preserved',lambda v:(setattr(v,'read_change',(2,NEXT)),v.recover()==4 and v.record==NEXT and v.set_count==0)[1])
check('recovery create event failure makes no variable calls',lambda v:(setattr(v,'create_status',ERR(9)),v.recover()==5 and v.get_count==v.set_count==0)[1])
def delete_case(v,status,mode,want):
    v.set_status=status;v.write_mode=mode
    return v.recover()==want and v.set_count==1
check('delete error unchanged is explicit IO failure',lambda v:delete_case(v,ERR(9),'unchanged',5))
check('delete error but absent is uncertain',lambda v:delete_case(v,ERR(9),'normal',6))
check('delete success but still present is uncertain',lambda v:delete_case(v,0,'unchanged',6))
check('delete success but different record is uncertain',lambda v:delete_case(v,0,'other',6))
for trigger in [('get',1),('get',2),('set',1),('get',3),'close']:
    def recover_end(v,trigger=trigger):
        v.end_on=trigger;result=v.recover();before=len(v.uefi_calls)
        # A successful deletion was already independently read back before
        # closing the event. EBS at close need not undo that completed result.
        expected=result==0 if trigger=='close'else result!=0
        return expected and v.recover()==3 and len(v.uefi_calls)==before
    check('recovery end event at '+str(trigger)+' blocks followup',recover_end)
check('failed CloseEvent retains live stable context and blocks repeat',lambda v:(setattr(v,'close_status',ERR(7)),v.recover()==5 and v.recover()==3)[1])

def ui_case(v,text,want,granted=False):
    assert v.bind() in [0,6] and v.begin()==0
    before=v.frame;metadata=v.r(v.outmode,24);v.queue(text)
    result=v.request()
    return result==want and bool(v.query()&4)==granted and v.frame==before and v.r(v.outmode,24)==metadata and core.PW.decode()not in v.transcript
check('actual UI Escape restores screen and cancels grant',lambda v:ui_case(v,'\x1b',ERR(15)))
check('actual UI wrong password remains locked restores screen',lambda v:ui_case(v,core.WRONG_PW.decode()+'\r!',ERR(15)))
check('actual UI correct input grants through actual core using KDF oracle',lambda v:ui_case(v,core.PW.decode()+'\r',0,True))
check('actual UI unconfigured message cancels to original screen',lambda v:ui_case(v,'!',ERR(15)),None)
check('actual UI optional cursor UNSUPPORTED accepted only after exact reported state',lambda v:(setattr(v,'cursor_unsupported',True),ui_case(v,'\x1b',ERR(15)))[1])
check('actual UI does not silently truncate overlong password',lambda v:ui_case(v,'x'*129+'\r!',ERR(15)))
check('actual UI rejects non-ASCII password',lambda v:ui_case(v,'eightgood'+chr(0x80)+'\r!',ERR(15)))
def ui_enroll(v):
    assert v.bind()==6 and v.begin()==0;before=v.frame
    v.queue(core.PW.decode()+'\r'+core.PW.decode()+'\r!')
    return v.manage()==0 and v.frame==before and v.record is not None and not(v.query()&4)and'********'in v.transcript and core.PW.decode()not in v.transcript
check('actual UI new password confirm entropy persistence chain',ui_enroll,None)
def ui_cancel_change(v):
    assert v.bind()==0 and v.begin()==0;before=v.frame;v.queue(core.PW.decode()+'\rnew-password\r\x1b')
    return v.manage()==ERR(15)and v.frame==before and v.set_count==0 and v.record==ENABLED
check('actual UI cancel at confirmation never commits',ui_cancel_change)
def ui_error(v,operation):
    assert v.bind()==0 and v.begin()==0;before=v.frame;v.queue('\x1b');v.ui_error[operation]=ERR(7)
    status=v.request()
    return status==ERR(15)and not(v.query()&4)and v.set_count==0 and (operation=='blt2'or v.frame==before)
for operation in ['text','attribute','clear','cursor','enable','blt2']:
    check('actual UI '+operation+' error never grants',lambda v,o=operation:ui_error(v,o))

# Presence is checked by actual C against the modeled page tables. Address
# 0xA00000000 has a nonpresent PDPT entry and no Unicorn mapping; dereferencing
# it would raise instead of completing the test.
UNMAPPED=0xA00000000
for field in ['gop-mode','gop-info','console-mode']:
    for replacement in [0,UNMAPPED]:
        for callback,number in [('key',1),('attribute',2),('cursor',1),('enable',1),('blt',2)]:
            def stale_ui(v,field=field,replacement=replacement,callback=callback,number=number):
                assert v.bind()==0 and v.begin()==0
                addresses={'gop-mode':v.gop+24,'gop-info':v.gopmode+8,'console-mode':v.console+72}
                v.queue('\x1b');v.mutate_on=(callback,number,addresses[field],Q(replacement))
                result=v.request();forbidden={'text','key','blt','attribute','clear','cursor','enable'}
                return result==ERR(15)and v.query()&32 and v.set_count==0 and v.mutated_at is not None and not(forbidden&set(v.calls[v.mutated_at:]))
            check('stale '+field+' '+hex(replacement)+' after '+callback+str(number)+' refuses without dereference',stale_ui)

def stale_cached_clock(v):
    assert v.bind()==0 and v.begin()==0 and v.clock()==0
    previous=v.calls.count('timer');v.w(SYMBOLS['clock_cpu'],Q(UNMAPPED))
    return v.clock()==1 and v.calls.count('timer')==previous
check('unmapped cached CPU protocol refused before timer call',stale_cached_clock)
for field in ['timer','count']:
    for callback,number in [('timer',1),('stall',1)]:
        def stale_clock(v,field=field,callback=callback,number=number):
            assert v.bind()==0 and v.begin()==0
            target=v.cpu+0x30 if field=='timer'else v.cpu+0x40
            value=Q(UNMAPPED)if field=='timer'else I(0)
            v.mutate_on=(callback,number,target,value);result=v.clock()
            return result==1 and v.mutated_at is not None and not({'timer','stall'}&set(v.calls[v.mutated_at:]))
        check('cached CPU '+field+' lost after '+callback+' refuses before next service',stale_clock)

report={'status':'PASS_ACTUAL_RUNTIME02_PE_MODELED_SERVICE_FAILURES','case_count':len(CASES),'cases':CASES,
        'efi_sha256':BUILD['component']['sha256'],'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'native_owner_modeled':True,'page_tables_modeled_actual_walker_executed':True,'RDSEED_modeled':True,'PBKDF2_independent_python_oracle':True,
        'physical_hardware_or_firmware_writes':0,
        'scope':'Actual linked x64 PE variable wrappers, commit verification, lifetime, UI/input/masking/restore, entropy/timing error handling and known-password recovery control flow. Standard UEFI Console/GOP and keyboard input modeled. OVMF separately executes actual KDF and UEFI/UI objects; no ASUS native owner acceptance.'}
(HERE/'build/runtime_pe_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'case_count':len(CASES),'efi_sha256':BUILD['component']['sha256']}))
