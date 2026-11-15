"""Actual recovery EFI control flow with explicit UEFI/authority/hash oracles.

Frozen runtime02 VM definitions are reused without executing its test suite or
writing its reports. Actual C SHA/PBKDF2 and real services run in OVMF separately.
"""
from pathlib import Path
import hashlib,json,re,struct,sys,uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
fixture=HERE.parent/'password_runtime02/verify_runtime_pe.py'
environment={'__file__':str(fixture)}
exec(compile(fixture.read_text().split("check('unbound entry")[0],str(fixture),'exec'),environment)
build=json.loads((HERE/'build/build.json').read_text());file=HERE/'build'/build['component']['file']
assert hashlib.sha256(file.read_bytes()).hexdigest()==build['component']['sha256']
pe=environment['pefile'].PE(str(file));base=pe.OPTIONAL_HEADER.ImageBase
symbols={name:int(address,16)for name,address in re.findall(r'^\s*\w+:\w+\s+(\w+)\s+([0-9a-fA-F]{16})\s',file.with_suffix('.map').read_text(),re.M)}
symbols.update(w890_provider=0x50003900,w890_password_core=0x50003a00,cpu_entropy=0x60009900)
environment.update(PE=pe,BASE=base,SYMBOLS=symbols)
Base=environment['VM'];Q=environment['Q'];I=environment['I'];ERR=environment['ERR'];core=environment['core']
ENABLED=environment['ENABLED'];NEXT=environment['NEXT'];DISABLED=environment['DISABLED'];HEAP=environment['HEAP'];HOOK=environment['HOOK']
profile=environment['PROFILE'];CASES=[]
original=[]
for name in ['Setup','AMITSE']:
    item=profile['sources'][name];path=ROOT/item['path'];assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256']
    image=environment['pefile'].PE(str(path));original.append(image.get_memory_mapped_image().ljust(image.OPTIONAL_HEADER.SizeOfImage,b'\0'))

def smbios():
    return bytes([0,18,0,0,0,1])+bytes(12)+b'0603\0\0'+bytes([2,8,1,0,1,2,0,0])+b'ASUSTeK COMPUTER INC.\0Pro WS W890E-SAGE SE\0\0'+bytes([127,4,2,0,0,0])

class VM(Base):
    def __init__(self,record=ENABLED):
        super().__init__(record)
        self.proof=True;self.proof_calls=0;self.proof_deny_at=0;self.kdf_change=None
        self.load_error=0;self.handle_error=0;self.duplicate=False
        self.observe_hold=False;self.held=False
        self.extra={'loaded_locate':HOOK+0x5000,'loaded_handle':HOOK+0x5100,'proof':HOOK+0x5200,'sha':symbols['ap_sha256']}
        for name,address in self.extra.items():
            if name!='sha':self.w(address,b'\xc3')
        self.w(self.bs+0x138,Q(self.extra['loaded_locate']));self.w(self.bs+0x98,Q(self.extra['loaded_handle']))
        self.li=[HEAP+0x2200,HEAP+0x2300];self.paths=[HEAP+0x2400,HEAP+0x2500]
        self.modules=[0x1000000,0x2000000]
        for index,name in enumerate(['Setup','AMITSE']):
            data=original[index];self.u.mem_map(self.modules[index],(len(data)+4095)&~4095);self.w(self.modules[index],data)
            self.w(self.li[index],I(0x1000));self.w(self.li[index]+0x20,Q(self.paths[index]));self.w(self.li[index]+0x40,Q(self.modules[index])+Q(len(data)))
            self.w(self.paths[index],bytes([4,6,20,0])+uuid.UUID(profile['sources'][name]['guid']).bytes_le+bytes([0x7f,0xff,4,0]))
        self.table=HEAP+0x2600;self.sm_entry=HEAP+0x2800;self.ct=HEAP+0x2900
        table=smbios();self.w(self.table,table)
        entry=bytearray(b'_SM3_'+bytes([0,24,3,2,0,0,0])+I(len(table))+Q(self.table));entry[5]=(-sum(entry))&255
        self.w(self.sm_entry,entry);self.w(self.ct,uuid.UUID('f2fd1544-9794-4a2c-992e-e5bbcf20e394').bytes_le+Q(self.sm_entry))
        self.w(self.st+0x68,Q(1)+Q(self.ct))
    def hook(self,u,address,size,opaque):
        if address==symbols['rc_hold_resident']and self.observe_hold:
            self.held=True;u.emu_stop();return
        name=next((name for name,addr in self.extra.items()if addr==address),None)if hasattr(self,'extra')else None
        if name:
            self.calls.append(name)
            if name=='sha':self.w(self.arg(2),hashlib.sha256(self.r(self.arg(0),self.arg(1))).digest());value=0
            elif name=='loaded_locate':
                self.w(self.arg(3),Q(3 if self.duplicate else 2));self.w(self.arg(4),Q(HEAP+0x2000));self.w(HEAP+0x2000,Q(self.li[0])+Q(self.li[1])+Q(self.li[0]));value=self.load_error
            elif name=='loaded_handle':self.w(self.arg(2),Q(self.arg(0)));value=self.handle_error
            elif name=='proof':self.proof_calls+=1;value=int(self.proof and (not self.proof_deny_at or self.proof_calls<self.proof_deny_at))
            else:raise AssertionError(name)
            if self.end_on==name:
                self.end_on=None;handle=next(reversed(self.event_callbacks));callback,context=self.event_callbacks[handle];self.nested(callback,[handle,context],value)
            else:self.ret(value)
            return
        super().hook(u,address,size,opaque)
        if address==self.hooks['kdf']and self.kdf_change:
            change=self.kdf_change;self.kdf_change=None
            if change=='record':self.record=NEXT
            if change=='module':self.w(self.modules[0]+4096,b'\xff')
            if change=='proof':self.proof=False
    def bind(self,proof=True):return self.call('rc_initialize',self.st,self.extra['proof']if proof else 0,self.out,0x8900603 if proof else 0)
    def identity(self):return self.call('rc_identity')
    def authorized(self):return self.call('rc_authorized')
    def recover(self,password=core.PW):self.w(self.pw,password);return self.call('rc_delete_known',self.pw,len(password))
    def read(self):self.w(self.buf,bytes([0xaa])*128);return self.call('rc_read',self.buf)
    def ui(self):return self.call('rc_ui_attempt')
    def entry_holds(self):
        self.observe_hold=True
        try:self.call('entry',1,self.st)
        except AssertionError as e:
            if str(e)!='execution did not return':raise
        else:return False
        if not self.held:return False
        count=len(self.uefi_calls);self.observe_hold=False
        # Execute the actual PAUSE/JMP loop, not a synthetic return value.
        self.u.emu_start(symbols['rc_hold_resident'],0,count=100)
        return len(self.uefi_calls)==count and not self.call('rc_alive')

def check(name,function,record=ENABLED):
    value=VM(record);assert function(value),name;CASES.append({'name':name,'status':'PASS'})

check('exact static module and SMBIOS parser identity succeeds',lambda v:v.bind()and v.identity()==3)
check('actual entry with exact identity still supplies no writer authority',lambda v:(v.queue('!'),v.call('entry',1,v.st)==ERR(15)and v.set_count==0 and'Known test password'not in v.transcript)[1])
check('missing authority prevents direct recovery before reading credential',lambda v:v.bind(False)and v.identity()==3 and not v.authorized()and v.recover()==8 and v.get_count==v.set_count==0)
check('modeled writer exclusion plus identity permits test boundary',lambda v:v.bind()and v.authorized()==1)
check('wrong board product rejects identity',lambda v:v.bind()and (v.w(v.table+smbios().index(b'W890'),b'W790'),v.identity()==2 and v.recover()==8 and v.set_count==0)[1])
check('wrong BIOS version rejects identity',lambda v:v.bind()and (v.w(v.table+18,b'1904'),v.identity()==2 and not v.authorized())[1])
check('SMBIOS checksum corruption rejects identity',lambda v:v.bind()and (v.w(v.sm_entry+5,b'\xff'),v.identity()==2)[1])
check('unmapped SMBIOS table refuses without dereference',lambda v:v.bind()and (v.w(v.st+0x70,Q(0xa00000000)),v.identity()==2)[1])
check('duplicate target module rejects identity',lambda v:v.bind()and (setattr(v,'duplicate',True),v.identity()==1 and not v.authorized())[1])
check('loaded-image enumeration failure refuses',lambda v:v.bind()and (setattr(v,'load_error',ERR(7)),v.identity()==1)[1])
check('loaded-image protocol failure refuses',lambda v:v.bind()and (setattr(v,'handle_error',ERR(7)),v.identity()==1)[1])
check('wrong Setup text SHA refuses',lambda v:v.bind()and (v.w(v.modules[0]+4096,b'\xff'),v.identity()==1 and v.recover()==8)[1])
check('wrong AMITSE text SHA refuses',lambda v:v.bind()and (v.w(v.modules[1]+4096,b'\xff'),v.identity()==1 and v.recover()==8)[1])
check('unmapped image base refuses',lambda v:v.bind()and (v.w(v.li[0]+0x40,Q(0xa00000000)),v.identity()==1)[1])
check('invalid loaded image shape refuses',lambda v:v.bind()and (v.w(v.li[0]+0x48,Q(4096)),v.identity()==1)[1])
check('malformed device path refuses',lambda v:v.bind()and (v.w(v.paths[0]+2,b'\0\0'),v.identity()==1)[1])
check('known enabled record exact deletion verifies absence',lambda v:v.bind()and v.recover()==0 and v.record is None and v.set_count==1)
check('wrong password preserves exact bytes',lambda v:v.bind()and v.recover(core.WRONG_PW)==2 and v.record==ENABLED and v.set_count==0)
check('disabled record remains unclaimed',lambda v:v.bind()and v.recover()==2 and v.record==DISABLED and v.set_count==0,DISABLED)
check('absent record not rewritten',lambda v:v.bind()and v.recover()==1 and v.set_count==0,None)
for record in [b'broken',ENABLED+bytes(1)]:check('malformed size '+str(len(record))+' preserved',lambda v:v.bind()and v.recover()==3 and v.set_count==0,record)
for attr in [1,7,0x23]:check('wrong attributes '+str(attr)+' preserved',lambda v,a=attr:v.bind()and(setattr(v,'attributes',a),v.recover()==3 and v.set_count==0)[1])
for change,expected in [('record',4),('module',8),('proof',8)]:
    check('changed '+change+' during KDF refuses final write',lambda v,c=change,e=expected:v.bind()and(setattr(v,'kdf_change',c),v.recover()==e and v.set_count==0)[1])
for status,mode,result in [(ERR(9),'unchanged',5),(ERR(9),'normal',6),(0,'unchanged',6),(0,'other',6)]:
    def error(v,status=status,mode=mode,result=result):v.set_status=status;v.write_mode=mode;return v.bind()and v.recover()==result
    check('delete status '+str(status)+' mode '+mode+' verified explicitly',error)
for point in ['loaded_locate','loaded_handle','proof',('get',1),('get',2),('set',1),('get',3)]:
    def end_event(v,point=point):
        assert v.bind();v.end_on=point;result=v.recover();count=len(v.uefi_calls)
        return result!=0 and v.recover()==8 and len(v.uefi_calls)==count
    check('end event during '+str(point)+' terminates recovery',end_event)
def ui_cancel(v):
    assert v.bind();frame=v.frame;v.queue('\x1b');first=v.ui();v.queue('\x1b')
    return first==7 and v.ui()==7 and v.frame==frame and v.set_count==0
check('repeated cancel preserves original screen',ui_cancel)
check('disabled record rejected before password request',lambda v:v.bind()and(v.queue('!'),v.ui()==2 and'Known test password'not in v.transcript and v.set_count==0)[1],DISABLED)
check('read-only UI never requests a secret',lambda v:v.bind(False)and(v.queue('!'),v.ui()==8 and'Known test password'not in v.transcript and v.set_count==0)[1])
def ui_correct(v):
    assert v.bind();frame=v.frame;v.queue(core.PW.decode()+'\ry!')
    return v.ui()==0 and v.set_count==1 and v.frame==frame and core.PW.decode()not in v.transcript and'********'in v.transcript
check('actual UI correct masked input exact deletion and screen restoration',ui_correct)
for field in ['gop-mode','gop-info','console-mode']:
    for replacement in [0,0xa00000000]:
        def stale(v,field=field,replacement=replacement):
            assert v.bind();addresses={'gop-mode':v.gop+24,'gop-info':v.gopmode+8,'console-mode':v.console+72}
            v.queue('\x1b');v.mutate_on=('key',1,addresses[field],Q(replacement))
            return v.ui()==5 and v.set_count==0 and not v.call('rc_alive')
        check('stale '+field+' '+hex(replacement)+' safely stops carrier',stale)
check('shutdown revokes authority and future IO',lambda v:v.bind()and(v.call('rc_shutdown'),v.recover()==8 and v.set_count==0)[1])
check('failed event close returns a retained-image indication',lambda v:v.bind()and(setattr(v,'close_status',ERR(7)),v.call('rc_shutdown')==0 and v.recover()==8)[1])
check('actual application stays resident if event close fails',lambda v:(v.queue('!'),setattr(v,'close_status',ERR(7)),v.entry_holds()and v.set_count==0)[2])
check('actual application stays resident after EBS during close',lambda v:(v.queue('!'),setattr(v,'end_on','close'),v.entry_holds()and v.set_count==0)[2])
def ambiguous_create(v):
    v.create_status=ERR(9);v.mutate_on=('create',1,symbols['event'],Q(0x70000010))
    return v.entry_holds()and v.get_count==v.set_count==0
check('ambiguous created-event failure cannot unload callback code',ambiguous_create)

report={'status':'PASS_ACTUAL_RECOVERY03_EFI_MODELED_BOUNDARIES','case_count':len(CASES),'cases':CASES,
        'efi_sha256':build['component']['sha256'],'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'inherited_fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'physical_operations':0,
        'scope':'Actual compiled identity parser, UI, namespace/deletion, rechecks and lifetime. SHA256/PBKDF2, UEFI services and writer exclusion modeled; original module bytes supplied as inert fixtures. Real SHA/KDF/UI/NVRAM/DPAPI keyboard handoff separately executed under OVMF. Actual carrier entry has no authority and remains read-only.'}
(HERE/'build/recovery_pe_tests.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':report['status'],'cases':len(CASES),'efi_sha256':report['efi_sha256']}))
